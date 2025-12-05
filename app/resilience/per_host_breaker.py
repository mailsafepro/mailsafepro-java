"""
Per-Host Circuit Breaker

Provides circuit breaking at the individual host level, allowing fine-grained
fault isolation for services like SMTP where different MX hosts may have
different reliability characteristics.

Unlike standard circuit breakers which operate at the service level, this
implementation tracks failures per host using Redis for distributed state.
"""

import time
from typing import Optional, Dict, Any
from contextlib import asynccontextmanager
from redis.asyncio import Redis

from app.logger import logger


class PerHostCircuitBreaker:
    """
    Circuit breaker with per-host failure tracking.
    
    Tracks failures for individual hosts (e.g., MX servers) and automatically
    opens the circuit for hosts that exceed the failure threshold. Uses Redis
    for distributed state tracking across multiple workers.
    
    Example:
        >>> breaker = PerHostCircuitBreaker(
        ...     service_name="smtp",
        ...     redis_client=redis,
        ...     fail_max=5,
        ...     timeout_duration=60
        ... )
        >>> 
        >>> # Check if host is available
        >>> if await breaker.is_open("mail.example.com"):
        ...     print("Circuit open, skipping host")
        ... else:
        ...     # Try connection
        ...     async with breaker.protect("mail.example.com"):
        ...         await smtp_connect("mail.example.com")
    """
    
    def __init__(
        self,
        service_name: str,
        redis_client: Redis,
        fail_max: int = 5,
        timeout_duration: int = 60
    ):
        """
        Initialize per-host circuit breaker.
        
        Args:
            service_name: Identifier for this service (e.g., "smtp", "dns")
            redis_client: Redis connection for state storage
            fail_max: Number of failures before opening circuit
            timeout_duration: Seconds to keep circuit open before half-open retry
        """
        self.service_name = service_name
        self.redis = redis_client
        self.fail_max = fail_max
        self.timeout_duration = timeout_duration
        
        logger.info(
            f"Initialized PerHostCircuitBreaker for {service_name}",
            extra={
                "service": service_name,
                "fail_max": fail_max,
                "timeout_duration": timeout_duration
            }
        )
    
    def _failure_key(self, host: str) -> str:
        """Generate Redis key for failure counter."""
        return f"cb:{self.service_name}:{host}:failures"
    
    def _opened_key(self, host: str) -> str:
        """Generate Redis key for circuit open timestamp."""
        return f"cb:{self.service_name}:{host}:opened_at"
    
    async def is_open(self, host: str) -> bool:
        """
        Check if circuit is open for this host.
        
        A circuit is open if:
        1. The host has an active opened_at timestamp, AND
        2. The timeout period hasn't expired yet
        
        Args:
            host: Host to check
            
        Returns:
            True if circuit is open (host unavailable), False otherwise
        """
        try:
            opened_at_str = await self.redis.get(self._opened_key(host))
            
            if not opened_at_str:
                # No opened_at timestamp = circuit is closed
                return False
            
            opened_at = float(opened_at_str)
            now = time.time()
            elapsed = now - opened_at
            
            if elapsed >= self.timeout_duration:
                # Timeout expired, circuit enters half-open state
                # Clean up the opened_at key
                await self.redis.delete(self._opened_key(host))
                await self.redis.delete(self._failure_key(host))
                
                logger.info(
                    f"Circuit breaker half-open: {self.service_name}:{host}",
                    extra={
                        "service": self.service_name,
                        "host": host,
                        "elapsed_seconds": elapsed
                    }
                )
                return False
            
            # Circuit is still open
            logger.debug(
                f"Circuit breaker open: {self.service_name}:{host}",
                extra={
                    "service": self.service_name,
                    "host": host,
                    "remaining_seconds": self.timeout_duration - elapsed
                }
            )
            return True
            
        except Exception as e:
            logger.error(
                f"Error checking circuit breaker for {host}: {e}",
                extra={
                    "service": self.service_name,
                    "host": host,
                    "error": str(e)
                }
            )
            # Fail open: if Redis is down, don't block requests
            return False
    
    async def record_success(self, host: str) -> None:
        """
        Record successful operation for host.
        
        Resets failure counter and closes circuit if it was open.
        
        Args:
            host: Host that succeeded
        """
        try:
            # Delete both failure counter and opened_at timestamp
            await self.redis.delete(self._failure_key(host))
            await self.redis.delete(self._opened_key(host))
            
            logger.debug(
                f"Circuit breaker success: {self.service_name}:{host}",
                extra={
                    "service": self.service_name,
                    "host": host
                }
            )
        except Exception as e:
            logger.error(
                f"Error recording success for {host}: {e}",
                extra={
                    "service": self.service_name,
                    "host": host,
                    "error": str(e)
                }
            )
    
    async def record_failure(self, host: str) -> None:
        """
        Record failed operation for host.
        
        Increments failure counter. If counter reaches fail_max, opens the circuit
        by setting the opened_at timestamp.
        
        Args:
            host: Host that failed
        """
        try:
            # Increment failure counter
            failure_key = self._failure_key(host)
            failures = await self.redis.incr(failure_key)
            
            # Set expiry on failure counter (2x timeout to allow recovery)
            await self.redis.expire(failure_key, self.timeout_duration * 2)
            
            logger.debug(
                f"Circuit breaker failure recorded: {self.service_name}:{host}",
                extra={
                    "service": self.service_name,
                    "host": host,
                    "failures": failures,
                    "threshold": self.fail_max
                }
            )
            
            # Check if we've reached the threshold
            if failures >= self.fail_max:
                # Open the circuit
                opened_key = self._opened_key(host)
                await self.redis.set(
                    opened_key,
                    str(time.time()),
                    ex=self.timeout_duration
                )
                
                logger.warning(
                    f"Circuit breaker OPENED: {self.service_name}:{host}",
                    extra={
                        "service": self.service_name,
                        "host": host,
                        "failures": failures,
                        "threshold": self.fail_max,
                        "timeout_duration": self.timeout_duration,
                        "security_event": True
                    }
                )
        except Exception as e:
            logger.error(
                f"Error recording failure for {host}: {e}",
                extra={
                    "service": self.service_name,
                    "host": host,
                    "error": str(e)
                }
            )
    
    @asynccontextmanager
    async def protect(self, host: str):
        """
        Context manager for automatic success/failure tracking.
        
        Usage:
            >>> async with breaker.protect("mail.example.com"):
            ...     await smtp_connect("mail.example.com")
        
        If the block completes without exception, records success.
        If an exception is raised, records failure and re-raises.
        
        Args:
            host: Host being protected
            
        Yields:
            None
            
        Raises:
            Any exception raised within the context block
        """
        try:
            yield
            # Success - reset failures
            await self.record_success(host)
        except Exception as e:
            # Failure - increment counter
            await self.record_failure(host)
            raise
    
    async def get_stats(self, host: str) -> Dict[str, Any]:
        """
        Get circuit breaker statistics for a specific host.
        
        Args:
            host: Host to get stats for
            
        Returns:
            Dictionary with state, failure_count, and opened_at info
        """
        try:
            is_open = await self.is_open(host)
            
            failures_str = await self.redis.get(self._failure_key(host))
            failures = int(failures_str) if failures_str else 0
            
            opened_at_str = await self.redis.get(self._opened_key(host))
            opened_at = float(opened_at_str) if opened_at_str else None
            
            state = "open" if is_open else "closed"
            
            return {
                "state": state,
                "failure_count": failures,
                "threshold": self.fail_max,
                "opened_at": opened_at,
                "timeout_duration": self.timeout_duration,
                "host": host,
                "service": self.service_name
            }
        except Exception as e:
            logger.error(
                f"Error getting stats for {host}: {e}",
                extra={
                    "service": self.service_name,
                    "host": host,
                    "error": str(e)
                }
            )
            return {
                "state": "unknown",
                "failure_count": 0,
                "error": str(e)
            }
    
    async def reset(self, host: str) -> bool:
        """
        Manually reset circuit breaker for a specific host.
        
        Useful for administrative operations.
        
        Args:
            host: Host to reset
            
        Returns:
            True if reset successful
        """
        try:
            await self.redis.delete(self._failure_key(host))
            await self.redis.delete(self._opened_key(host))
            
            logger.info(
                f"Circuit breaker manually reset: {self.service_name}:{host}",
                extra={
                    "service": self.service_name,
                    "host": host
                }
            )
            return True
        except Exception as e:
            logger.error(
                f"Error resetting circuit breaker for {host}: {e}",
                extra={
                    "service": self.service_name,
                    "host": host,
                    "error": str(e)
                }
            )
            return False

"""
Centralized Circuit Breaker Management

Uses pybreaker for consistent fault tolerance across all external services.
Prevents cascading failures by automatically opening circuits after repeated failures.
"""

import pybreaker
from typing import Dict, Optional
from app.logger import logger

# Circuit breaker configurations by service
CIRCUIT_BREAKER_CONFIGS = {
    "smtp": {
        "fail_max": 5,           # Open circuit after 5 failures
        "timeout_duration": 60,   # Stay open for 60 seconds
        "name": "SMTP Service"
    },
    "dns": {
        "fail_max": 3,           # DNS is critical, fail fast
        "timeout_duration": 30,
        "name": "DNS Resolution"
    },
    "redis": {
        "fail_max": 10,          # Redis can tolerate more failures
        "timeout_duration": 10,   # Recover quickly
        "name": "Redis Cache"
    },
    "breach_api": {
        "fail_max": 3,
        "timeout_duration": 120,  # External API, longer recovery
        "name": "Breach Detection API"
    },
    "whois": {
        "fail_max": 5,
        "timeout_duration": 90,
        "name": "WHOIS Service"
    },
    "provider_analysis": {
        "fail_max": 5,
        "timeout_duration": 60,
        "name": "Provider Analysis"
    }
}

class CircuitBreakerListener(pybreaker.CircuitBreakerListener):
    """
    Custom listener for circuit breaker state changes.
    
    Logs all state transitions for monitoring and alerting.
    """
    
    def state_change(self, cb, old_state, new_state):
        """Called when circuit breaker changes state."""
        logger.warning(
            f"Circuit breaker state change: {cb.name}",
            extra={
                "circuit_breaker": cb.name,
                "old_state": str(old_state),
                "new_state": str(new_state),
                "failure_count": cb.fail_counter,
                "security_event": True
            }
        )
    
    def failure(self, cb, exc):
        """Called on each failure."""
        logger.debug(
            f"Circuit breaker failure: {cb.name}",
            extra={
                "circuit_breaker": cb.name,
                "exception": str(exc),
                "failure_count": cb.fail_counter
            }
        )
    
    def success(self, cb):
        """Called on successful call."""
        logger.debug(
            f"Circuit breaker success: {cb.name}",
            extra={
                "circuit_breaker": cb.name,
                "state": str(cb.current_state)
            }
        )

class CircuitBreakerManager:
    """
    Centralized circuit breaker management.
    
    Provides singleton access to circuit breakers for different services.
    Prevents cascading failures by opening circuits after repeated failures.
    
    Usage:
        smtp_breaker = CircuitBreakerManager.get_breaker("smtp")
        
        @smtp_breaker
        async def check_smtp(email):
            # SMTP verification logic
            pass
    """
    
    _breakers: Dict[str, pybreaker.CircuitBreaker] = {}
    _listener = CircuitBreakerListener()
    
    @classmethod
    def get_breaker(cls, service_name: str) -> pybreaker.CircuitBreaker:
        """
        Get or create circuit breaker for service.
        
        Args:
            service_name: Service identifier (smtp, dns, redis, breach_api, whois)
        
        Returns:
            Configured circuit breaker instance
        
        Example:
            >>> breaker = CircuitBreakerManager.get_breaker("smtp")
            >>> @breaker
            ... async def smtp_call():
            ...     # Your SMTP logic
        """
        if service_name not in cls._breakers:
            config = CIRCUIT_BREAKER_CONFIGS.get(service_name, {
                "fail_max": 5,
                "timeout_duration": 60,
                "name": f"{service_name.upper()} Service"
            })
            
            breaker = pybreaker.CircuitBreaker(
                fail_max=config["fail_max"],
                reset_timeout=config["timeout_duration"],  # Correct parameter name
                name=config["name"],
                listeners=[cls._listener]
            )
            
            cls._breakers[service_name] = breaker
            
            logger.info(
                f"Created circuit breaker: {config['name']}",
                extra={
                    "service": service_name,
                    "fail_max": config["fail_max"],
                    "timeout_duration": config["timeout_duration"]
                }
            )
        
        return cls._breakers[service_name]
    
    @classmethod
    def get_all_breakers(cls) -> Dict[str, pybreaker.CircuitBreaker]:
        """
        Get all registered circuit breakers.
        
        Useful for monitoring dashboards.
        
        Returns:
            Dict mapping service names to circuit breakers
        """
        return cls._breakers.copy()
    
    @classmethod
    def get_breaker_stats(cls, service_name: str) -> Optional[Dict[str, any]]:
        """
        Get statistics for a circuit breaker.
        
        Args:
            service_name: Service identifier
        
        Returns:
            {
                "state": "closed" | "open" | "half_open",
                "failure_count": int,
                "name": str
            }
        """
        if service_name not in cls._breakers:
            return None
        
        breaker = cls._breakers[service_name]
        
        return {
            "state": str(breaker.current_state),
            "failure_count": breaker.fail_counter,
            "name": breaker.name
        }
    
    @classmethod
    def reset_breaker(cls, service_name: str) -> bool:
        """
        Manually reset a circuit breaker.
        
        Useful for admin operations.
        
        Args:
            service_name: Service to reset
        
        Returns:
            True if reset successful, False if breaker not found
        """
        if service_name not in cls._breakers:
            return False
        
        cls._breakers[service_name].close()
        logger.info(f"Manually reset circuit breaker: {service_name}")
        return True

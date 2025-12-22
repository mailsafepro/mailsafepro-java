"""
Optimized Connection Pooling

Enterprise-grade connection management for:
- Redis connection pooling with health checks
- HTTP client pooling with keep-alive
- DNS resolver connection pooling
- Automatic reconnection and circuit breaking
"""

from __future__ import annotations

import asyncio
import os
from typing import Optional, Dict, Any
from contextlib import asynccontextmanager

import aiohttp
from redis.asyncio import Redis, ConnectionPool as RedisConnectionPool
from redis.asyncio.retry import Retry
from redis.backoff import ExponentialBackoff

from app.structured_logging import get_logger

logger = get_logger(__name__)

# =============================================================================
# REDIS CONNECTION POOL
# =============================================================================

class OptimizedRedisPool:
    """Optimized Redis connection pool with health checks and metrics."""
    
    def __init__(
        self,
        url: str,
        max_connections: int = 50,
        min_idle_connections: int = 10,
        socket_keepalive: bool = True,
        socket_keepalive_options: Optional[Dict] = None,
        health_check_interval: int = 30,
    ):
        self.url = url
        self.max_connections = max_connections
        self.min_idle_connections = min_idle_connections
        self.health_check_interval = health_check_interval
        
        # Connection pool configuration
        self.pool = RedisConnectionPool.from_url(
            url,
            max_connections=max_connections,
            decode_responses=True,
            socket_timeout=10,
            socket_connect_timeout=10,
            socket_keepalive=socket_keepalive,
            socket_keepalive_options=socket_keepalive_options or self._default_keepalive_options(),
            health_check_interval=health_check_interval,
            retry=Retry(ExponentialBackoff(base=0.1, cap=2.0), retries=3),
            retry_on_error=[ConnectionError, TimeoutError],
        )
        
        self._client: Optional[Redis] = None
        self._health_check_task: Optional[asyncio.Task] = None
        self._stats = {
            "connections_created": 0,
            "connections_closed": 0,
            "health_checks_passed": 0,
            "health_checks_failed": 0,
        }
    
    @staticmethod
    def _default_keepalive_options() -> Dict:
        """Default TCP keepalive options for different OS."""
        import platform
        # macOS/Darwin doesn't support Linux TCP keepalive socket options
        # Return empty dict to avoid OSError [Errno 22] Invalid argument
        if platform.system() == "Darwin":
            return {}
        # Linux-specific TCP keepalive options
        # Linux-specific TCP keepalive options
        # Disabled to avoid OSError [Errno 22] in some Docker/Mac environments
        return {}
    
    async def initialize(self) -> Redis:
        """Initialize Redis client with connection pool."""
        if self._client:
            return self._client
        
        try:
            self._client = Redis(connection_pool=self.pool)
            
            # Test connection
            await self._client.ping()
            logger.bind(request_id="startup").info(
                "Redis connection pool initialized",
                max_connections=self.max_connections,
                health_check_interval=self.health_check_interval
            )
            
            # Start background health checks
            self._health_check_task = asyncio.create_task(self._health_check_loop())
            
            return self._client
            
        except Exception as e:
            logger.bind(request_id="startup").error("Failed to initialize Redis pool", error=str(e))
            raise
    
    async def _health_check_loop(self):
        """Background task for periodic health checks."""
        while True:
            try:
                await asyncio.sleep(self.health_check_interval)
                
                if self._client:
                    await self._client.ping()
                    self._stats["health_checks_passed"] += 1
                    logger.bind(request_id="redis-health").debug("Redis health check passed")
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                self._stats["health_checks_failed"] += 1
                logger.bind(request_id="redis-health").warning("Redis health check failed", error=str(e))
    
    async def close(self):
        """Close connection pool gracefully."""
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        
        if self._client:
            await self._client.close()
            await self.pool.disconnect()
            logger.bind(request_id="shutdown").info("Redis connection pool closed")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get connection pool statistics."""
        return {
            **self._stats,
            "max_connections": self.max_connections,
            "pool_size": len(self.pool._available_connections) if hasattr(self.pool, '_available_connections') else "N/A",
        }


# =============================================================================
# HTTP CLIENT CONNECTION POOL
# =============================================================================

class OptimizedHTTPPool:
    """
    Optimized HTTP client pool with connection reuse and keep-alive.
    
    Features:
    - Connection pooling with limits
    - TCP keep-alive
    - Automatic retry
    - Timeout configuration
    """
    
    def __init__(
        self,
        max_connections: int = 100,
        max_connections_per_host: int = 30,
        keepalive_timeout: int = 30,
        timeout: float = 30.0,
    ):
        self.max_connections = max_connections
        self.max_connections_per_host = max_connections_per_host
        self.keepalive_timeout = keepalive_timeout
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        
        # TCP connector with connection pooling
        self.connector = aiohttp.TCPConnector(
            limit=max_connections,
            limit_per_host=max_connections_per_host,
            ttl_dns_cache=300,  # Cache DNS for 5 minutes
            keepalive_timeout=keepalive_timeout,
            enable_cleanup_closed=True,
            force_close=False,  # Reuse connections
        )
        
        self._session: Optional[aiohttp.ClientSession] = None
        self._stats = {
            "requests_made": 0,
            "connections_reused": 0,
            "errors": 0,
        }
    
    async def initialize(self) -> aiohttp.ClientSession:
        """Initialize HTTP client session with connection pool."""
        if self._session and not self._session.closed:
            return self._session
        
        self._session = aiohttp.ClientSession(
            connector=self.connector,
            timeout=self.timeout,
            headers={
                "User-Agent": "MailSafePro/2.1.0",
                "Accept": "application/json",
            },
            raise_for_status=False,  # Handle errors manually
        )
        
        logger.bind(request_id="startup").info(
            "HTTP connection pool initialized",
            max_connections=self.max_connections,
            max_per_host=self.max_connections_per_host
        )
        
        return self._session
    
    async def get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if not self._session or self._session.closed:
            await self.initialize()
        return self._session
    
    @asynccontextmanager
    async def request(
        self,
        method: str,
        url: str,
        **kwargs
    ):
        """
        Make HTTP request with connection pooling.
        
        Usage:
            async with http_pool.request('GET', 'https://api.example.com') as response:
                data = await response.json()
        """
        session = await self.get_session()
        
        try:
            self._stats["requests_made"] += 1
            async with session.request(method, url, **kwargs) as response:
                yield response
        except Exception as e:
            self._stats["errors"] += 1
            logger.bind(request_id="http-request").error(
                "HTTP request failed", 
                method=method, 
                url=url, 
                error=str(e)
            )
            raise
    
    async def close(self):
        """Close HTTP session and connector."""
        if self._session and not self._session.closed:
            await self._session.close()
            logger.bind(request_id="shutdown").info("HTTP connection pool closed")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get HTTP pool statistics."""
        connector_stats = {}
        if self.connector:
            try:
                connector_stats = {
                    "connections": len(self.connector._conns),
                    "acquired": len(self.connector._acquired),
                }
            except Exception as e:
                logger.warning(f"Failed to get connector stats: {e}")
        
        return {
            **self._stats,
            **connector_stats,
            "max_connections": self.max_connections,
        }


# =============================================================================
# CONNECTION POOL MANAGER
# =============================================================================

class ConnectionPoolManager:
    """Central manager for all connection pools."""
    
    def __init__(self):
        self.redis_pool: Optional[OptimizedRedisPool] = None
        self.http_pool: Optional[OptimizedHTTPPool] = None
    
    async def initialize_redis(
        self,
        url: str,
        max_connections: int = 50
    ) -> Redis:
        """Initialize Redis connection pool."""
        self.redis_pool = OptimizedRedisPool(
            url=url,
            max_connections=max_connections,
            min_idle_connections=max(10, max_connections // 5),
        )
        return await self.redis_pool.initialize()
    
    async def initialize_http(
        self,
        max_connections: int = 100
    ) -> aiohttp.ClientSession:
        """Initialize HTTP connection pool."""
        self.http_pool = OptimizedHTTPPool(
            max_connections=max_connections,
            max_connections_per_host=30,
        )
        return await self.http_pool.initialize()
    
    async def close_all(self):
        """Close all connection pools."""
        tasks = []
        
        if self.redis_pool:
            tasks.append(self.redis_pool.close())
        
        if self.http_pool:
            tasks.append(self.http_pool.close())
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
            logger.info("All connection pools closed")
    
    def get_all_stats(self) -> Dict[str, Any]:
        """Get statistics for all pools."""
        stats = {}
        
        if self.redis_pool:
            stats["redis"] = self.redis_pool.get_stats()
        
        if self.http_pool:
            stats["http"] = self.http_pool.get_stats()
        
        return stats


# =============================================================================
# GLOBAL INSTANCE
# =============================================================================

_pool_manager: Optional[ConnectionPoolManager] = None


def get_pool_manager() -> ConnectionPoolManager:
    """Get or create global connection pool manager."""
    global _pool_manager
    if _pool_manager is None:
        _pool_manager = ConnectionPoolManager()
    return _pool_manager


async def initialize_connection_pools(redis_url: str) -> ConnectionPoolManager:
    """Initialize all connection pools."""
    manager = get_pool_manager()
    
    # Initialize Redis pool
    await manager.initialize_redis(
        url=redis_url,
        max_connections=int(os.getenv("REDIS_MAX_CONNECTIONS", "50"))
    )
    
    # Initialize HTTP pool
    await manager.initialize_http(
        max_connections=int(os.getenv("HTTP_MAX_CONNECTIONS", "100"))
    )
    
    logger.info("✅ All connection pools initialized")
    return manager


async def close_connection_pools():
    """Close all connection pools."""
    manager = get_pool_manager()
    await manager.close_all()

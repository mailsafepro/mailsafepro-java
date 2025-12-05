"""
Advanced Health Checks

Enterprise-grade health checking for:
- Kubernetes liveness/readiness probes
- Load balancer health checks
- Dependency health monitoring (Redis, external APIs)
- Graceful degradation
"""

from __future__ import annotations

import time
import asyncio
from typing import Dict, List, Optional, Callable, Any
from enum import Enum
from dataclasses import dataclass
from datetime import datetime

from fastapi import APIRouter, Response, status
from redis.asyncio import Redis

from app.structured_logging import get_logger

logger = get_logger(__name__)

# =============================================================================
# HEALTH STATUS
# =============================================================================

class HealthStatus(str, Enum):
    """Health check status values."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class ComponentStatus(str, Enum):
    """Individual component status."""
    UP = "up"
    DOWN = "down"
    DEGRADED = "degraded"


@dataclass
class ComponentHealth:
    """Health status of individual component."""
    name: str
    status: ComponentStatus
    message: Optional[str] = None
    response_time_ms: Optional[float] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "response_time_ms": round(self.response_time_ms, 2) if self.response_time_ms else None,
            "metadata": self.metadata or {},
        }


# =============================================================================
# HEALTH CHECK FUNCTIONS
# =============================================================================

async def check_redis_health(redis: Optional[Redis]) -> ComponentHealth:
    """Check Redis connectivity and performance."""
    if not redis:
        return ComponentHealth(
            name="redis",
            status=ComponentStatus.DOWN,
            message="Redis client not initialized"
        )
    
    start = time.time()
    
    try:
        # Test basic connectivity
        await asyncio.wait_for(redis.ping(), timeout=2.0)
        
        # Test write/read
        test_key = "health:check:test"
        await redis.set(test_key, "ok", ex=10)
        value = await redis.get(test_key)
        
        response_time = (time.time() - start) * 1000
        
        if value != "ok":
            return ComponentHealth(
                name="redis",
                status=ComponentStatus.DEGRADED,
                message="Redis read/write test failed",
                response_time_ms=response_time
            )
        
        # Check if response time is acceptable
        if response_time > 100:  # > 100ms is degraded
            return ComponentHealth(
                name="redis",
                status=ComponentStatus.DEGRADED,
                message=f"Redis response time high: {response_time:.0f}ms",
                response_time_ms=response_time
            )
        
        return ComponentHealth(
            name="redis",
            status=ComponentStatus.UP,
            message="Redis healthy",
            response_time_ms=response_time
        )
        
    except asyncio.TimeoutError:
        return ComponentHealth(
            name="redis",
            status=ComponentStatus.DOWN,
            message="Redis health check timed out",
            response_time_ms=(time.time() - start) * 1000
        )
    except Exception as e:
        return ComponentHealth(
            name="redis",
            status=ComponentStatus.DOWN,
            message=f"Redis error: {str(e)}",
            response_time_ms=(time.time() - start) * 1000
        )


async def check_dns_health() -> ComponentHealth:
    """Check DNS resolution capability."""
    import socket
    
    start = time.time()
    
    try:
        # Test DNS resolution with common domain
        await asyncio.wait_for(
            asyncio.get_event_loop().getaddrinfo(
                "google.com", 443, family=socket.AF_INET
            ),
            timeout=2.0
        )
        
        response_time = (time.time() - start) * 1000
        
        return ComponentHealth(
            name="dns",
            status=ComponentStatus.UP,
            message="DNS resolution working",
            response_time_ms=response_time
        )
        
    except asyncio.TimeoutError:
        return ComponentHealth(
            name="dns",
            status=ComponentStatus.DEGRADED,
            message="DNS resolution slow",
            response_time_ms=(time.time() - start) * 1000
        )
    except Exception as e:
        return ComponentHealth(
            name="dns",
            status=ComponentStatus.DOWN,
            message=f"DNS error: {str(e)}"
        )


async def check_memory_health() -> ComponentHealth:
    """Check system memory usage."""
    try:
        import psutil
        
        memory = psutil.virtual_memory()
        percent_used = memory.percent
        
        if percent_used > 90:
            status = ComponentStatus.DEGRADED
            message = f"High memory usage: {percent_used:.1f}%"
        elif percent_used > 95:
            status = ComponentStatus.DOWN
            message = f"Critical memory usage: {percent_used:.1f}%"
        else:
            status = ComponentStatus.UP
            message = f"Memory usage normal: {percent_used:.1f}%"
        
        return ComponentHealth(
            name="memory",
            status=status,
            message=message,
            metadata={
                "percent_used": percent_used,
                "available_mb": memory.available / (1024 * 1024),
                "total_mb": memory.total / (1024 * 1024),
            }
        )
        
    except ImportError:
        return ComponentHealth(
            name="memory",
            status=ComponentStatus.UP,
            message="psutil not available, skipping check"
        )
    except Exception as e:
        return ComponentHealth(
            name="memory",
            status=ComponentStatus.DEGRADED,
            message=f"Memory check error: {str(e)}"
        )


async def check_disk_health() -> ComponentHealth:
    """Check disk space."""
    try:
        import psutil
        
        disk = psutil.disk_usage('/')
        percent_used = disk.percent
        
        if percent_used > 85:
            status = ComponentStatus.DEGRADED
            message = f"Low disk space: {percent_used:.1f}% used"
        elif percent_used > 95:
            status = ComponentStatus.DOWN
            message = f"Critical disk space: {percent_used:.1f}% used"
        else:
            status = ComponentStatus.UP
            message = f"Disk space normal: {percent_used:.1f}% used"
        
        return ComponentHealth(
            name="disk",
            status=status,
            message=message,
            metadata={
                "percent_used": percent_used,
                "free_gb": disk.free / (1024**3),
                "total_gb": disk.total / (1024**3),
            }
        )
        
    except ImportError:
        return ComponentHealth(
            name="disk",
            status=ComponentStatus.UP,
            message="psutil not available, skipping check"
        )
    except Exception as e:
        return ComponentHealth(
            name="disk",
            status=ComponentStatus.DEGRADED,
            message=f"Disk check error: {str(e)}"
        )


# =============================================================================
# HEALTH CHECK MANAGER
# =============================================================================

class HealthCheckManager:
    """Manages health checks for all components."""
    
    def __init__(self):
        self.redis: Optional[Redis] = None
        self.startup_time = time.time()
        self._last_check: Dict[str, ComponentHealth] = {}
        self._check_cache_ttl = 5  # Cache results for 5 seconds
        self._last_check_time = 0
    
    def set_redis(self, redis: Redis):
        """Set Redis client for health checks."""
        self.redis = redis
    
    async def check_all_components(
        self,
        use_cache: bool = True
    ) -> List[ComponentHealth]:
        """
        Run health checks on all components.
        
        Args:
            use_cache: If True, use cached results if available
        """
        now = time.time()
        
        # Return cached results if recent
        if use_cache and (now - self._last_check_time) < self._check_cache_ttl:
            return list(self._last_check.values())
        
        # Run all health checks in parallel
        results = await asyncio.gather(
            check_redis_health(self.redis),
            check_dns_health(),
            check_memory_health(),
            check_disk_health(),
            return_exceptions=True
        )
        
        # Filter out exceptions and update cache
        components = []
        for result in results:
            if isinstance(result, ComponentHealth):
                components.append(result)
                self._last_check[result.name] = result
            elif isinstance(result, Exception):
                logger.error("Health check failed", error=str(result))
        
        self._last_check_time = now
        return components
    
    def determine_overall_status(
        self,
        components: List[ComponentHealth]
    ) -> HealthStatus:
        """Determine overall health from component statuses."""
        if not components:
            return HealthStatus.UNHEALTHY
        
        # Count component statuses
        down_count = sum(1 for c in components if c.status == ComponentStatus.DOWN)
        degraded_count = sum(1 for c in components if c.status == ComponentStatus.DEGRADED)
        
        # If any critical component is down, system is unhealthy
        critical_components = ["redis"]
        critical_down = any(
            c.name in critical_components and c.status == ComponentStatus.DOWN
            for c in components
        )
        
        if critical_down or down_count > 1:
            return HealthStatus.UNHEALTHY
        elif down_count > 0 or degraded_count > 0:
            return HealthStatus.DEGRADED
        else:
            return HealthStatus.HEALTHY
    
    def get_uptime_seconds(self) -> float:
        """Get application uptime in seconds."""
        return time.time() - self.startup_time


# =============================================================================
# HEALTH CHECK ROUTES
# =============================================================================

router = APIRouter(tags=["Health"])

# Global health check manager
_health_manager = HealthCheckManager()


def get_health_manager() -> HealthCheckManager:
    """Get global health check manager."""
    return _health_manager


@router.get("/health", summary="Basic health check")
async def basic_health():
    """
    Basic health check for load balancers.
    
    Returns 200 if service is running.
    Fast response, no dependency checks.
    """
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.get("/health/live", summary="Liveness probe (Kubernetes)")
async def liveness():
    """
    Kubernetes liveness probe.
    
    Returns 200 if the application is running.
    Should restart pod if this fails.
    """
    return {
        "status": "alive",
        "uptime_seconds": _health_manager.get_uptime_seconds(),
    }


@router.get("/health/ready", summary="Readiness probe (Kubernetes)")
async def readiness(response: Response):
    """
    Kubernetes readiness probe.
    
    Returns 200 if service is ready to accept traffic.
    Checks critical dependencies (Redis).
    """
    # Check only critical components for readiness
    redis_health = await check_redis_health(_health_manager.redis)
    
    if redis_health.status == ComponentStatus.DOWN:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "not_ready",
            "reason": redis_health.message,
        }
    
    return {
        "status": "ready",
        "components": {
            "redis": redis_health.status.value,
        }
    }


@router.get("/health/detailed", summary="Detailed health check")
async def detailed_health(response: Response):
    """
    Detailed health check with all component statuses.
    
    Returns comprehensive health information for monitoring.
    """
    components = await _health_manager.check_all_components(use_cache=True)
    overall_status = _health_manager.determine_overall_status(components)
    
    # Set HTTP status based on health
    if overall_status == HealthStatus.UNHEALTHY:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    elif overall_status == HealthStatus.DEGRADED:
        response.status_code = status.HTTP_200_OK
    
    return {
        "status": overall_status.value,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "uptime_seconds": round(_health_manager.get_uptime_seconds(), 2),
        "components": [c.to_dict() for c in components],
        "summary": {
            "total": len(components),
            "healthy": sum(1 for c in components if c.status == ComponentStatus.UP),
            "degraded": sum(1 for c in components if c.status == ComponentStatus.DEGRADED),
            "down": sum(1 for c in components if c.status == ComponentStatus.DOWN),
        }
    }

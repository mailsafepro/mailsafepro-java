"""
Advanced Rate Limiting Module - INTEGRATED VERSION

Integrates with existing resilience infrastructure:
- Uses CircuitBreakerManager for Redis failures
- Uses RedisFallback for cache operations
- Fail-closed strategy with local fallback
"""

from __future__ import annotations
import time
import hashlib
from typing import Optional, Dict, Tuple, List
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict
import threading
import sys

from fastapi import Request, HTTPException, status
from redis.asyncio import Redis

from app.structured_logging import get_logger
from app.resilience.circuit_breakers import CircuitBreakerManager
from app.resilience.fallbacks import RedisFallback

logger = get_logger(__name__)

# =============================================================================
# RATE LIMIT CONFIGURATION
# =============================================================================

class RateLimitTier(str, Enum):
    """Rate limit tiers by user plan."""
    FREE = "free"
    PREMIUM = "premium"
    ENTERPRISE = "enterprise"
    ANONYMOUS = "anonymous"

@dataclass
class RateLimitRule:
    """Rate limiting rule definition."""
    requests: int
    window: int
    cost: int = 1

ENDPOINT_LIMITS: Dict[str, Dict[RateLimitTier, RateLimitRule]] = {
    "/auth/login": {
        RateLimitTier.ANONYMOUS: RateLimitRule(requests=5, window=300),
        RateLimitTier.FREE: RateLimitRule(requests=10, window=300),
        RateLimitTier.PREMIUM: RateLimitRule(requests=20, window=300),
        RateLimitTier.ENTERPRISE: RateLimitRule(requests=50, window=300),
    },
    "/auth/register": {
        RateLimitTier.ANONYMOUS: RateLimitRule(requests=3, window=3600),
        RateLimitTier.FREE: RateLimitRule(requests=5, window=3600),
        RateLimitTier.PREMIUM: RateLimitRule(requests=10, window=3600),
        RateLimitTier.ENTERPRISE: RateLimitRule(requests=20, window=3600),
    },
    "/validate/email": {
        RateLimitTier.FREE: RateLimitRule(requests=100, window=60),
        RateLimitTier.PREMIUM: RateLimitRule(requests=1000, window=60),
        RateLimitTier.ENTERPRISE: RateLimitRule(requests=10000, window=60),
    },
    "/validate/batch": {
        RateLimitTier.FREE: RateLimitRule(requests=50, window=60, cost=2),
        RateLimitTier.PREMIUM: RateLimitRule(requests=500, window=60, cost=2),
        RateLimitTier.ENTERPRISE: RateLimitRule(requests=5000, window=60, cost=2),
    },
    "/v1/jobs": {
        RateLimitTier.PREMIUM: RateLimitRule(requests=10, window=60),
        RateLimitTier.ENTERPRISE: RateLimitRule(requests=100, window=60),
    },
    "/api-keys": {
        RateLimitTier.FREE: RateLimitRule(requests=10, window=3600),
        RateLimitTier.PREMIUM: RateLimitRule(requests=50, window=3600),
        RateLimitTier.ENTERPRISE: RateLimitRule(requests=200, window=3600),
    },
    # ✅ NUEVA REGLA ESPECÍFICA PARA USAGE
    "/api-keys/usage": {
        RateLimitTier.FREE: RateLimitRule(requests=120, window=3600),  # 1 cada 30s
        RateLimitTier.PREMIUM: RateLimitRule(requests=500, window=3600),
        RateLimitTier.ENTERPRISE: RateLimitRule(requests=2000, window=3600),
    },
    "default": {
        RateLimitTier.ANONYMOUS: RateLimitRule(requests=30, window=60),
        RateLimitTier.FREE: RateLimitRule(requests=100, window=60),
        RateLimitTier.PREMIUM: RateLimitRule(requests=1000, window=60),
        RateLimitTier.ENTERPRISE: RateLimitRule(requests=10000, window=60),
    },
}



# =============================================================================
# LOCAL FALLBACK RATE LIMITER
# =============================================================================

class LocalRateLimiterFallback:
    """
    In-memory rate limiter for when Redis is unavailable.
    Uses conservative limits (10% of normal) for security.
    Thread-safe and recursion-safe implementation.
    """
    def __init__(self):
        self._counters: Dict[str, List[float]] = {}
        self._lock = threading.RLock()  # Use RLock for thread safety in recursive calls
        self._last_cleanup = time.time()
        self._cleanup_interval = 60
        self._in_cleanup = False  # Prevent recursive cleanup
        self._in_check = threading.local()  # Thread-local storage for recursion detection

    def _cleanup_old_entries(self) -> None:
        """Remove expired entries to prevent memory bloat."""
        # Prevent recursive cleanup
        if getattr(self, '_in_cleanup', False):
            return
            
        try:
            self._in_cleanup = True
            now = time.time()
            
            # Only cleanup every _cleanup_interval seconds
            if now - self._last_cleanup < self._cleanup_interval:
                return

            cutoff = now - 3600  # 1 hour TTL for entries
            
            # Make a copy of keys to avoid modifying dict during iteration
            keys = list(self._counters.keys())
            
            for key in keys:
                try:
                    with self._lock:
                        if key in self._counters:  # Check again after acquiring lock
                            # Filter out old timestamps
                            self._counters[key] = [
                                ts for ts in self._counters[key] if ts > cutoff
                            ]
                            # Remove empty lists
                            if not self._counters[key]:
                                del self._counters[key]
                except Exception as e:
                    # Log error but don't fail
                    try:
                        print(f"Error cleaning up rate limit key {key}: {str(e)}", file=sys.stderr)
                    except:
                        pass

            self._last_cleanup = now
            
        except Exception as e:
            # Log error but don't fail
            try:
                print(f"Error in rate limit cleanup: {str(e)}", file=sys.stderr)
            except:
                pass
        finally:
            self._in_cleanup = False

    def check_limit(
        self,
        key: str,
        limit: int,
        window: int,
        cost: int = 1
    ) -> Tuple[bool, Dict[str, int]]:
        """
        Check rate limit using local memory.
        CONSERVATIVE: Uses 10% of normal limit.
        Thread-safe and recursion-safe implementation.
        """
        # Initialize thread-local state if not exists
        if not hasattr(self._in_check, 'active'):
            self._in_check.active = False
            
        # Detect recursion
        if self._in_check.active:
            # If we're already in a check, fail closed for safety
            return False, {
                "current": 0,
                "limit": 1,
                "remaining": 0,
                "reset_in": 60,
                "fallback_mode": True,
                "error": "recursion_detected"
            }
            
        try:
            self._in_check.active = True
            now = time.time()
            window_start = now - window
            
            # CRITICAL: Use 10% of normal limit as fallback, minimum 1
            fallback_limit = max(1, limit // 10)
            
            with self._lock:
                # Clean up old entries (with recursion protection)
                self._cleanup_old_entries()
                
                # Initialize key if not exists
                if key not in self._counters:
                    self._counters[key] = []
                
                # Filter out old timestamps
                self._counters[key] = [
                    ts for ts in self._counters[key] if ts > window_start
                ]
                
                current = len(self._counters[key])
                
                # Check if we're over the limit
                if current + cost > fallback_limit:
                    return False, {
                        "current": current,
                        "limit": fallback_limit,
                        "remaining": 0,
                        "reset_in": int(window - (now - self._counters[key][0])) if self._counters[key] else window,
                        "fallback_mode": True,
                        "error": "rate_limit_exceeded"
                    }
                
                # Add new request timestamps
                self._counters[key].extend([now] * cost)
                
                # Calculate remaining requests
                remaining = fallback_limit - (current + cost)
                
                return True, {
                    "current": current + cost,
                    "limit": fallback_limit,
                    "remaining": max(0, remaining),
                    "reset_in": window,
                    "fallback_mode": True
                }
                
        except Exception as e:
            # Log error but fail closed for security
            try:
                print(f"Rate limit check error for key {key}: {str(e)}", file=sys.stderr)
            except:
                pass
                
            return False, {
                "current": 0,
                "limit": 1,
                "remaining": 0,
                "reset_in": 60,
                "fallback_mode": True,
                "error": str(e)
            }
            
        finally:
            self._in_check.active = False


# =============================================================================
# SLIDING WINDOW RATE LIMITER (INTEGRATED)
# =============================================================================

class SlidingWindowRateLimiter:
    """
    Sliding window rate limiter using Redis.

    INTEGRATIONS:
    - Uses CircuitBreakerManager for Redis failures
    - Uses LocalRateLimiterFallback when Redis unavailable
    - Fail-closed strategy for security
    """
    def __init__(self, redis: Redis):
        self.redis = redis
        self.fallback = LocalRateLimiterFallback()
        # ✅ REUSE existing circuit breaker infrastructure
        self.redis_breaker = CircuitBreakerManager.get_breaker("redis")

    async def check_rate_limit(
        self,
        key: str,
        limit: int,
        window: int,
        cost: int = 1
    ) -> Tuple[bool, Dict[str, int]]:
        """
        Check rate limit with circuit breaker protection.
        Falls back to local limiter if Redis fails.
        """
        # Lua script for atomic sliding window
        lua_script = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])

local window_start = now - window
redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)
local current = redis.call('ZCARD', key)

if current + cost > limit then
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local reset_in = window
    if #oldest > 0 then
        reset_in = math.ceil(tonumber(oldest[2]) + window - now)
    end
    return {0, current, limit, 0, reset_in}
end

for i = 1, cost do
    redis.call('ZADD', key, now + (i * 0.000001), now .. ':' .. i)
end
redis.call('EXPIRE', key, window + 10)

local remaining = limit - (current + cost)
return {1, current + cost, limit, remaining, window}
"""

        # ✅ TRY Redis with circuit breaker protection
        try:
            now = time.time()

            # Wrap in circuit breaker
            @self.redis_breaker
            async def check_redis():
                return await self.redis.eval(
                    lua_script, 1, key,
                    str(now), str(window), str(limit), str(cost)
                )

            result = await check_redis()
            allowed = bool(result[0])
            current = int(result[1])
            limit_val = int(result[2])
            remaining = int(result[3])
            reset_in = int(result[4])

            return allowed, {
                "current": current,
                "limit": limit_val,
                "remaining": max(0, remaining),
                "reset_in": reset_in,
                "fallback_mode": False,
            }

        except Exception as e:
            # Redis falla: optamos por fail-closed relativo (10% del límite) y explicitamos modo fallback
            logger.error(
                "Rate limit check failed - using LOCAL FALLBACK (fail-closed 10%)",
                extra={"error": str(e)[:200], "key": key[:30]},
            )
            allowed, metadata = self.fallback.check_limit(key, limit, window, cost)
            # Forzamos 10% del límite original para consistencia
            fallback_limit = max(1, limit // 10)
            return allowed, {
                "current": metadata.get("current", 0),
                "limit": fallback_limit,
                "remaining": max(0, fallback_limit - metadata.get("current", 0)),
                "reset_in": metadata.get("reset_in", window),
                "fallback_mode": True,
            }

    async def get_current_usage(self, key: str, window: int) -> int:
        """
        Get current usage count for a key.
        Returns 0 on error.
        """
        try:
            now = time.time()
            window_start = now - window

            # Clean old entries
            await self.redis.zremrangebyscore(key, '-inf', window_start)

            # Get current count
            count = await self.redis.zcard(key)
            return int(count)

        except Exception as e:
            logger.error(
                "Failed to get current usage",
                error=str(e)[:200],
                key=key[:30]
            )
            return 0


# =============================================================================
# RATE LIMIT MANAGER
# =============================================================================

class RateLimitManager:
    """Manages rate limiting for different endpoints and tiers."""

    def __init__(self, redis: Redis):
        self.limiter = SlidingWindowRateLimiter(redis)
        self.redis = redis

    def _get_tier(self, request: Request) -> RateLimitTier:
        """Determine user's rate limit tier from request."""
        user = getattr(request.state, "user", None)
        if user:
            plan = getattr(user, "plan", "FREE").upper()
            tier_map = {
                "FREE": RateLimitTier.FREE,
                "PREMIUM": RateLimitTier.PREMIUM,
                "ENTERPRISE": RateLimitTier.ENTERPRISE,
            }
            return tier_map.get(plan, RateLimitTier.FREE)

        return RateLimitTier.ANONYMOUS

    def _get_limit_rule(
        self,
        endpoint: str,
        tier: RateLimitTier
    ) -> Optional[RateLimitRule]:
        """Get rate limit rule for endpoint and tier."""
        if endpoint in ENDPOINT_LIMITS:
            rule = ENDPOINT_LIMITS[endpoint].get(tier)
            if rule:
                return rule

        return ENDPOINT_LIMITS["default"].get(tier)

    def _get_rate_limit_key(self, request: Request, endpoint: str) -> str:
        """Generate unique rate limit key."""
        user = getattr(request.state, "user", None)
        if user:
            user_id = getattr(user, "id", "unknown")
            return f"ratelimit:user:{user_id}:{endpoint}"

        client_ip = request.client.host if request.client else "unknown"
        ip_hash = hashlib.sha256(client_ip.encode()).hexdigest()[:16]
        return f"ratelimit:ip:{ip_hash}:{endpoint}"

    async def check_rate_limit(self, request: Request) -> None:
        """
        Check rate limit for current request.
        Raises HTTPException if exceeded.
        """
        endpoint = request.url.path
        tier = self._get_tier(request)
        rule = self._get_limit_rule(endpoint, tier)

        if not rule:
            logger.debug("No rate limit configured", endpoint=endpoint, tier=tier.value)
            return

        key = self._get_rate_limit_key(request, endpoint)

        allowed, metadata = await self.limiter.check_rate_limit(
            key=key,
            limit=rule.requests,
            window=rule.window,
            cost=rule.cost
        )

        request.state.rate_limit = metadata

        if not allowed:
            logger.warning(
                "Rate limit exceeded",
                endpoint=endpoint,
                tier=tier.value,
                current=metadata["current"],
                limit=metadata["limit"],
                fallback_mode=metadata.get("fallback_mode", False)
            )

            headers = {
                "Retry-After": str(metadata["reset_in"]),
                "X-RateLimit-Limit": str(metadata["limit"]),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(time.time()) + metadata["reset_in"]),
            }

            if metadata.get("fallback_mode"):
                headers["X-RateLimit-Fallback"] = "true"

            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": "Rate limit exceeded",
                    "message": f"Too many requests. Limit: {metadata['limit']} per {rule.window}s",
                    "limit": metadata["limit"],
                    "remaining": metadata["remaining"],
                    "reset_in": metadata["reset_in"],
                    "tier": tier.value,
                    "fallback_mode": metadata.get("fallback_mode", False),
                },
                headers=headers
            )


# =============================================================================
# MIDDLEWARE
# =============================================================================

async def add_rate_limit_headers(request: Request, call_next):
    """Add rate limit headers to response (RFC 6585)."""
    response = await call_next(request)

    rate_limit = getattr(request.state, "rate_limit", None)
    if rate_limit:
        response.headers["X-RateLimit-Limit"] = str(rate_limit["limit"])
        response.headers["X-RateLimit-Remaining"] = str(rate_limit["remaining"])
        response.headers["X-RateLimit-Reset"] = str(
            int(time.time()) + rate_limit["reset_in"]
        )

        if rate_limit.get("fallback_mode"):
            response.headers["X-RateLimit-Fallback"] = "true"

    return response


# =============================================================================
# STATISTICS & MONITORING
# =============================================================================

async def get_rate_limit_stats(
    redis: Redis,
    user_id: Optional[str] = None
) -> Dict:
    """
    Get rate limit statistics.

    Args:
        redis: Redis client
        user_id: Optional user ID to filter stats

    Returns:
        Dictionary with statistics
    """
    try:
        pattern = f"ratelimit:user:{user_id}:*" if user_id else "ratelimit:*"

        keys = []
        cursor = 0

        # Scan for keys
        while True:
            cursor, batch = await redis.scan(
                cursor=cursor,
                match=pattern,
                count=100
            )
            keys.extend(batch)

            if cursor == 0:
                break

        stats = {
            "total_keys": len(keys),
            "keys": []
        }

        for key in keys[:50]:  # Limit to first 50 for performance
            try:
                key_str = key.decode() if isinstance(key, bytes) else key
                count = await redis.zcard(key_str)

                stats["keys"].append({
                    "key": key_str,
                    "count": int(count)
                })
            except Exception:
                continue

        return stats

    except Exception as e:
        logger.error("Failed to get rate limit stats", error=str(e)[:200])
        return {
            "error": str(e)[:200],
            "total_keys": 0,
            "keys": []
        }


async def get_circuit_breaker_status() -> Dict:
    """Get Redis circuit breaker status."""
    stats = CircuitBreakerManager.get_breaker_stats("redis")
    return stats if stats else {"state": "unknown"}
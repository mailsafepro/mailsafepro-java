"""
Advanced Rate Limiting Module

Enterprise-grade rate limiting with:
- Sliding window algorithm (more accurate than fixed window)
- Per-endpoint limits
- Per-user and per-IP limits
- Distributed rate limiting with Redis
- Graceful degradation
- Rate limit headers (RFC 6585)
"""

from __future__ import annotations

import time
import hashlib
from typing import Optional, Dict, Tuple
from dataclasses import dataclass
from enum import Enum

from fastapi import Request, HTTPException, status
from redis.asyncio import Redis

from app.structured_logging import get_logger

logger = get_logger(__name__)

# =============================================================================
# RATE LIMIT CONFIGURATION
# =============================================================================

class RateLimitTier(str, Enum):
    """Rate limit tiers by user plan."""
    FREE = "free"
    PREMIUM = "premium"
    ENTERPRISE = "enterprise"
    ANONYMOUS = "anonymous"  # No auth


@dataclass
class RateLimitRule:
    """Rate limiting rule definition."""
    requests: int  # Max requests
    window: int  # Window in seconds
    cost: int = 1  # Cost per request (for weighted limits)


# Per-endpoint rate limits (requests per window)
ENDPOINT_LIMITS: Dict[str, Dict[RateLimitTier, RateLimitRule]] = {
    # Authentication endpoints (prevent brute force)
    "/auth/login": {
        RateLimitTier.ANONYMOUS: RateLimitRule(requests=5, window=300),  # 5 per 5min
        RateLimitTier.FREE: RateLimitRule(requests=10, window=300),
        RateLimitTier.PREMIUM: RateLimitRule(requests=20, window=300),
        RateLimitTier.ENTERPRISE: RateLimitRule(requests=50, window=300),
    },
    "/auth/register": {
        RateLimitTier.ANONYMOUS: RateLimitRule(requests=3, window=3600),  # 3 per hour
        RateLimitTier.FREE: RateLimitRule(requests=5, window=3600),
        RateLimitTier.PREMIUM: RateLimitRule(requests=10, window=3600),
        RateLimitTier.ENTERPRISE: RateLimitRule(requests=20, window=3600),
    },
    
    # Email validation (main product)
    "/v1/validate-email": {
        RateLimitTier.FREE: RateLimitRule(requests=100, window=60),  # 100/min
        RateLimitTier.PREMIUM: RateLimitRule(requests=1000, window=60),  # 1000/min
        RateLimitTier.ENTERPRISE: RateLimitRule(requests=10000, window=60),  # 10k/min
    },
    "/v1/validate-advanced": {
        RateLimitTier.FREE: RateLimitRule(requests=50, window=60, cost=2),  # More expensive
        RateLimitTier.PREMIUM: RateLimitRule(requests=500, window=60, cost=2),
        RateLimitTier.ENTERPRISE: RateLimitRule(requests=5000, window=60, cost=2),
    },
    
    # Batch operations (heavyweight)
    "/v1/jobs": {
        RateLimitTier.PREMIUM: RateLimitRule(requests=10, window=60),
        RateLimitTier.ENTERPRISE: RateLimitRule(requests=100, window=60),
    },
    
    # API key management (security-sensitive)
    "/api-keys": {
        RateLimitTier.FREE: RateLimitRule(requests=10, window=3600),  # 10/hour
        RateLimitTier.PREMIUM: RateLimitRule(requests=50, window=3600),
        RateLimitTier.ENTERPRISE: RateLimitRule(requests=200, window=3600),
    },
    
    # Default limits for unspecified endpoints
    "default": {
        RateLimitTier.ANONYMOUS: RateLimitRule(requests=30, window=60),
        RateLimitTier.FREE: RateLimitRule(requests=100, window=60),
        RateLimitTier.PREMIUM: RateLimitRule(requests=1000, window=60),
        RateLimitTier.ENTERPRISE: RateLimitRule(requests=10000, window=60),
    },
}


# =============================================================================
# SLIDING WINDOW RATE LIMITER
# =============================================================================

class SlidingWindowRateLimiter:
    """
    Sliding window rate limiter using Redis sorted sets.
    
    More accurate than fixed windows as it counts requests in a rolling time window.
    """
    
    def __init__(self, redis: Redis):
        self.redis = redis
    
    async def check_rate_limit(
        self,
        key: str,
        limit: int,
        window: int,
        cost: int = 1
    ) -> Tuple[bool, Dict[str, int]]:
        """
        Check if request should be rate limited using sliding window.
        
        Args:
            key: Unique identifier (user_id:endpoint or ip:endpoint)
            limit: Maximum requests allowed in window
            window: Time window in seconds
            cost: Cost of this request (for weighted limits)
            
        Returns:
            Tuple of (allowed: bool, metadata: dict)
            metadata contains: current, limit, remaining, reset_in
        """
        now = time.time()
        window_start = now - window
        
        # Lua script for atomic sliding window check
        lua_script = """
        local key = KEYS[1]
        local now = tonumber(ARGV[1])
        local window = tonumber(ARGV[2])
        local limit = tonumber(ARGV[3])
        local cost = tonumber(ARGV[4])
        local window_start = now - window
        
        -- Remove old entries outside window
        redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)
        
        -- Count current requests in window
        local current = redis.call('ZCARD', key)
        
        -- Check if adding cost would exceed limit
        if current + cost > limit then
            -- Get oldest timestamp for reset calculation
            local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
            local reset_in = window
            if #oldest > 0 then
                reset_in = math.ceil(tonumber(oldest[2]) + window - now)
            end
            return {0, current, limit, 0, reset_in}  -- Not allowed
        end
        
        -- Add current request (use microsecond precision for uniqueness)
        for i = 1, cost do
            redis.call('ZADD', key, now + (i * 0.000001), now .. ':' .. i)
        end
        
        -- Set expiration
        redis.call('EXPIRE', key, window + 10)
        
        local remaining = limit - (current + cost)
        return {1, current + cost, limit, remaining, window}  -- Allowed
        """
        
        try:
            result = await self.redis.eval(
                lua_script,
                1,
                key,
                str(now),
                str(window),
                str(limit),
                str(cost)
            )
            
            allowed = bool(result[0])
            current = int(result[1])
            limit_val = int(result[2])
            remaining = int(result[3])
            reset_in = int(result[4])
            
            metadata = {
                "current": current,
                "limit": limit_val,
                "remaining": max(0, remaining),
                "reset_in": reset_in,
            }
            
            return allowed, metadata
            
        except Exception as e:
            logger.error("Rate limit check failed", error=str(e), key=key)
            # On Redis failure, allow request (fail open)
            return True, {
                "current": 0,
                "limit": limit,
                "remaining": limit,
                "reset_in": window,
            }
    
    async def get_current_usage(self, key: str, window: int) -> int:
        """Get current request count in window."""
        try:
            now = time.time()
            window_start = now - window
            
            # Remove expired and count
            await self.redis.zremrangebyscore(key, '-inf', window_start)
            count = await self.redis.zcard(key)
            return count
        except Exception:
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
        # Check if user is authenticated
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
        # Try exact endpoint match
        if endpoint in ENDPOINT_LIMITS:
            return ENDPOINT_LIMITS[endpoint].get(tier)
        
        # Try default limits
        return ENDPOINT_LIMITS["default"].get(tier)
    
    def _get_rate_limit_key(self, request: Request, endpoint: str) -> str:
        """Generate unique rate limit key."""
        # Prefer user-based limiting over IP
        user = getattr(request.state, "user", None)
        
        if user:
            user_id = getattr(user, "id", "unknown")
            return f"ratelimit:user:{user_id}:{endpoint}"
        
        # Fall back to IP-based limiting
        client_ip = request.client.host if request.client else "unknown"
        ip_hash = hashlib.sha256(client_ip.encode()).hexdigest()[:16]
        return f"ratelimit:ip:{ip_hash}:{endpoint}"
    
    async def check_rate_limit(self, request: Request) -> None:
        """
        Check rate limit for current request.
        
        Raises HTTPException if rate limit exceeded.
        Adds rate limit headers to request state for middleware.
        """
        endpoint = request.url.path
        tier = self._get_tier(request)
        rule = self._get_limit_rule(endpoint, tier)
        
        # No limit configured for this endpoint/tier
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
        
        # Store metadata in request state for response headers
        request.state.rate_limit = metadata
        
        if not allowed:
            logger.warning(
                "Rate limit exceeded",
                endpoint=endpoint,
                tier=tier.value,
                current=metadata["current"],
                limit=metadata["limit"]
            )
            
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": "Rate limit exceeded",
                    "message": f"Too many requests. Limit: {metadata['limit']} per {rule.window}s",
                    "limit": metadata["limit"],
                    "remaining": metadata["remaining"],
                    "reset_in": metadata["reset_in"],
                    "tier": tier.value,
                },
                headers={
                    "Retry-After": str(metadata["reset_in"]),
                    "X-RateLimit-Limit": str(metadata["limit"]),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(time.time()) + metadata["reset_in"]),
                }
            )
        
        logger.debug(
            "Rate limit check passed",
            endpoint=endpoint,
            tier=tier.value,
            current=metadata["current"],
            remaining=metadata["remaining"]
        )


# =============================================================================
# RATE LIMIT HEADERS MIDDLEWARE
# =============================================================================

async def add_rate_limit_headers(request: Request, call_next):
    """Add rate limit headers to response (RFC 6585 compliant)."""
    response = await call_next(request)
    
    # Check if rate limit metadata is available
    rate_limit = getattr(request.state, "rate_limit", None)
    
    if rate_limit:
        response.headers["X-RateLimit-Limit"] = str(rate_limit["limit"])
        response.headers["X-RateLimit-Remaining"] = str(rate_limit["remaining"])
        response.headers["X-RateLimit-Reset"] = str(int(time.time()) + rate_limit["reset_in"])
    
    return response


# =============================================================================
# ADMIN ENDPOINTS FOR MONITORING
# =============================================================================

async def get_rate_limit_stats(redis: Redis, user_id: Optional[str] = None) -> Dict:
    """Get rate limiting statistics."""
    try:
        if user_id:
            pattern = f"ratelimit:user:{user_id}:*"
        else:
            pattern = "ratelimit:*"
        
        keys = []
        cursor = 0
        while True:
            cursor, batch = await redis.scan(cursor=cursor, match=pattern, count=100)
            keys.extend(batch)
            if cursor == 0:
                break
        
        stats = {
            "total_keys": len(keys),
            "endpoints": {},
        }
        
        # Sample some keys for endpoint stats
        for key in keys[:50]:  # Limit to avoid overload
            parts = key.decode() if isinstance(key, bytes) else key
            if ":" in parts:
                endpoint = parts.split(":")[-1]
                count = await redis.zcard(key)
                if endpoint not in stats["endpoints"]:
                    stats["endpoints"][endpoint] = {"keys": 0, "total_requests": 0}
                stats["endpoints"][endpoint]["keys"] += 1
                stats["endpoints"][endpoint]["total_requests"] += count
        
        return stats
        
    except Exception as e:
        logger.error("Failed to get rate limit stats", error=str(e))
        return {"error": str(e)}

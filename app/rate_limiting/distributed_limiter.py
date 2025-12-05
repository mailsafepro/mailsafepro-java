"""
Distributed Rate Limiter using Redis and Lua scripts.
"""

from redis.asyncio import Redis
from typing import Tuple, Optional
import time
from app.logger import logger

# Lua script for Sliding Window Rate Limiting
# Keys: [key]
# Args: [window_size, limit, current_timestamp]
# Returns: {allowed (0/1), remaining_requests}
LUA_RATE_LIMIT_SCRIPT = """
local key = KEYS[1]
local window = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

-- Remove old entries (older than now - window)
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)

-- Count current entries
local count = redis.call('ZCARD', key)

if count < limit then
    -- Add new request
    redis.call('ZADD', key, now, now)
    redis.call('EXPIRE', key, window)
    return {1, limit - (count + 1)} -- Allowed, remaining
else
    return {0, 0} -- Denied, 0 remaining
end
"""

class DistributedRateLimiter:
    """
    Distributed Rate Limiter using Redis Sorted Sets (Sliding Window).
    """
    
    def __init__(self, redis: Redis):
        self.redis = redis
        self._script = None

    async def check_limit(self, key: str, limit: int, window: int) -> Tuple[bool, int]:
        """
        Check if request is within limit using Sliding Window.
        
        Args:
            key: Rate limit key (e.g., "rate:user:123")
            limit: Max requests allowed
            window: Time window in seconds
        
        Returns:
            (allowed: bool, remaining: int)
        """
        if not self._script:
            self._script = self.redis.register_script(LUA_RATE_LIMIT_SCRIPT)
        
        now = time.time()
        try:
            # Execute Lua script
            # keys=[key], args=[window, limit, now]
            result = await self._script(keys=[key], args=[window, limit, now])
            
            allowed = bool(result[0])
            remaining = int(result[1])
            
            return allowed, remaining
            
        except Exception as e:
            logger.error(f"Rate limiting error for {key}: {e}")
            # Fail open strategy: allow request if Redis fails
            return True, 1

    async def check_burst_limit(self, key: str, burst_limit: int) -> bool:
        """
        Check burst limit (1 second window).
        
        Args:
            key: Rate limit key
            burst_limit: Max requests per second
            
        Returns:
            allowed: bool
        """
        # Use a 1-second window for burst control
        allowed, _ = await self.check_limit(f"{key}:burst", burst_limit, 1)
        return allowed

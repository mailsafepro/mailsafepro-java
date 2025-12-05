"""
Redis Pipeline Utilities for Phase 7 Optimization.

Provides helper functions for batching Redis operations to reduce network overhead.
"""

from typing import Dict, Any, List, Optional
from redis.asyncio import Redis
from app.json_utils import dumps as json_dumps
from app.logger import logger

async def batch_cache_set(
    redis: Redis,
    items: Dict[str, Any],
    ttl: int = 3600,
    key_prefix: str = "cache"
) -> bool:
    """
    Batch set multiple cache items using Redis pipeline (2-3x faster than individual sets).
    
    Args:
        redis: Redis client
        items: Dict of {key: value} to cache
        ttl: Time to live in seconds
        key_prefix: Prefix for cache keys
    
    Returns:
        True if successful, False otherwise
    """
    if not items:
        return True
    
    try:
        async with redis.pipeline(transaction=False) as pipe:
            for key, value in items.items():
                full_key = f"{key_prefix}:{key}" if key_prefix else key
                serialized = json_dumps(value) if not isinstance(value, str) else value
                pipe.setex(full_key, ttl, serialized)
            await pipe.execute()
        logger.debug(f"Batch cached {len(items)} items with pipeline")
        return True
    except Exception as e:
        logger.error(f"Batch cache set failed: {e}")
        return False

async def batch_cache_get(
    redis: Redis,
    keys: List[str],
    key_prefix: str = "cache"
) -> Dict[str, Optional[str]]:
    """
    Batch get multiple cache items using Redis pipeline (2-3x faster than individual gets).
    
    Args:
        redis: Redis client
        keys: List of keys to retrieve
        key_prefix: Prefix for cache keys
    
    Returns:
        Dict of {key: value} (value is None if not found)
    """
    if not keys:
        return {}
    
    try:
        async with redis.pipeline(transaction=False) as pipe:
            full_keys = [f"{key_prefix}:{key}" if key_prefix else key for key in keys]
            for full_key in full_keys:
                pipe.get(full_key)
            results = await pipe.execute()
        
        # Map results back to original keys
        return {
            key: result.decode('utf-8') if isinstance(result, bytes) else result
            for key, result in zip(keys, results)
        }
    except Exception as e:
        logger.error(f"Batch cache get failed: {e}")
        return {key: None for key in keys}

async def batch_incr(
    redis: Redis,
    keys: List[str],
    amounts: Optional[List[int]] = None
) -> Dict[str, int]:
    """
    Batch increment multiple counters using Redis pipeline.
    
    Args:
        redis: Redis client
        keys: List of keys to increment
        amounts: Optional list of amounts to increment (default: 1 for each)
    
    Returns:
        Dict of {key: new_value}
    """
    if not keys:
        return {}
    
    if amounts is None:
        amounts = [1] * len(keys)
    
    try:
        async with redis.pipeline(transaction=False) as pipe:
            for key, amount in zip(keys, amounts):
                if amount == 1:
                    pipe.incr(key)
                else:
                    pipe.incrby(key, amount)
            results = await pipe.execute()
        
        return {key: result for key, result in zip(keys, results)}
    except Exception as e:
        logger.error(f"Batch incr failed: {e}")
        return {}

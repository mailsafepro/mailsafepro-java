"""
Unified Cache Layer

Provides a single, consistent API for caching across the application.
Handles serialization, sanitization, and type safety to prevent
common caching errors and injection vulnerabilities.
"""

import json
from typing import Optional, Any, Union, Type, TypeVar, Dict, List
from redis.asyncio import Redis

from app.logger import logger
from app.config import settings
from app.security.sanitization import build_safe_cache_key

# Type variable for generic return types
T = TypeVar("T")

class UnifiedCache:
    """
    Centralized cache manager.
    
    Replaces fragmented caching functions (async_cache_get, async_cache_set, etc.)
    with a unified, type-safe API.
    
    Features:
    - Automatic key sanitization
    - JSON serialization/deserialization
    - Type checking/conversion
    - Centralized error handling
    """
    
    _redis: Optional[Redis] = None
    
    @classmethod
    def initialize(cls, redis_client: Redis) -> None:
        """Initialize the cache with a Redis client."""
        cls._redis = redis_client
        logger.info("UnifiedCache initialized")
        
    @classmethod
    def get_redis(cls) -> Optional[Redis]:
        """Get the underlying Redis client."""
        return cls._redis
    
    @classmethod
    def build_key(cls, *parts: str) -> str:
        """
        Build a sanitized cache key from parts.
        
        Example:
            >>> UnifiedCache.build_key("user", "123", "profile")
            "user:123:profile"
        """
        # Filter out None or empty parts and normalize to lowercase
        valid_parts = [str(p).lower() for p in parts if p]
        
        if not valid_parts:
            raise ValueError("Cannot build cache key from empty parts")
            
        # Use existing sanitization logic if available, or simple join
        # We use build_safe_cache_key which handles sanitization
        if len(valid_parts) == 1:
            return valid_parts[0]
            
        prefix = valid_parts[0]
        suffix = ":".join(valid_parts[1:])
        return build_safe_cache_key(prefix, suffix)

    @classmethod
    async def get(
        cls, 
        key: str, 
        return_type: Optional[Type[T]] = None
    ) -> Optional[Union[T, Any]]:
        """
        Get a value from cache.
        
        Args:
            key: Cache key
            return_type: Optional type to cast/validate the result
            
        Returns:
            Cached value or None if not found or error
        """
        if cls._redis is None:
            return None
            
        try:
            raw = await cls._redis.get(key)
            if raw is None:
                return None
                
            # Decode bytes to string
            s = raw.decode("utf-8", errors="ignore") if isinstance(raw, (bytes, bytearray)) else str(raw)
            
            # Try to parse JSON
            try:
                data = json.loads(s)
            except json.JSONDecodeError:
                data = s
                
            # Convert to requested type if provided
            if return_type:
                if return_type == str:
                    return str(data)
                elif return_type == int:
                    return int(data)
                elif return_type == bool:
                    return bool(data)
                elif return_type == dict and isinstance(data, dict):
                    return data
                elif hasattr(return_type, "from_dict") and isinstance(data, dict):
                    # Support classes with from_dict method (like dataclasses/pydantic)
                    return return_type.from_dict(data)
                elif hasattr(return_type, "__init__") and isinstance(data, dict):
                    # Try unpacking dict into constructor (Pydantic models)
                    try:
                        return return_type(**data)
                    except Exception:
                        pass
                        
            return data
            
        except Exception as e:
            logger.debug(f"Cache GET error for {key}: {e}")
            return None

    @classmethod
    async def set(
        cls, 
        key: str, 
        value: Any, 
        ttl: int = 3600
    ) -> bool:
        """
        Set a value in cache.
        
        Args:
            key: Cache key
            value: Value to cache (will be JSON serialized)
            ttl: Time to live in seconds
            
        Returns:
            True if successful, False otherwise
        """
        if cls._redis is None:
            return False
            
        try:
            # Prepare value for serialization
            if hasattr(value, "to_dict") and callable(getattr(value, "to_dict")):
                storable = value.to_dict()
            elif hasattr(value, "dict") and callable(getattr(value, "dict")):
                # Pydantic v1
                storable = value.dict()
            elif hasattr(value, "model_dump") and callable(getattr(value, "model_dump")):
                # Pydantic v2
                storable = value.model_dump()
            else:
                storable = value
            # Serialize if needed
            if isinstance(storable, (dict, list, tuple)):
                json_val = json.dumps(storable)
            else:
                json_val = str(storable)
                
            kwargs = {}
            if ttl:
                kwargs["ex"] = ttl
                
            await cls._redis.set(key, json_val, **kwargs)
            return True
            
        except Exception as e:
            logger.error(f"Cache SET error for {key}: {e}")
            return False

    @classmethod
    async def delete(cls, key: str) -> bool:
        """Delete a value from cache."""
        if cls._redis is None:
            return False
            
        try:
            await cls._redis.delete(key)
            return True
        except Exception as e:
            logger.error(f"Cache DELETE error for {key}: {e}")
            return False

    @classmethod
    async def clear(cls, prefix: str = None) -> int:
        """
        Clear all keys matching a prefix.
        
        Args:
            prefix: Key prefix to clear (e.g., "mx:"). If None, clears all keys.
            
        Returns:
            Number of keys deleted
        """
        if cls._redis is None:
            return 0
            
        try:
            cursor = 0
            count = 0
            match_pattern = f"{prefix}*" if prefix else "*"
            
            while True:
                cursor, keys = await cls._redis.scan(cursor=cursor, match=match_pattern, count=100)
                if keys:
                    await cls._redis.delete(*keys)
                    count += len(keys)
                
                if cursor == 0:
                    break
                    
            return count
        except Exception as e:
            logger.error(f"Cache CLEAR error for {prefix}: {e}")
            return 0

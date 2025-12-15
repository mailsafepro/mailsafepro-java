"""
Redis Client Singleton

Provides a global Redis client instance for the application.
Uses lazy initialization to support both sync and async contexts.
"""

import os
from typing import Optional
from redis.asyncio import Redis
from app.logger import logger


class RedisClient:
    """
    Singleton Redis client with lazy initialization.
    """
    _instance: Optional[Redis] = None
    
    @classmethod
    def get_instance(cls) -> Redis:
        """
        Get or create the Redis client instance.
        
        Returns:
            Redis client instance
        """
        if cls._instance is None:
            redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
            
            try:
                cls._instance = Redis.from_url(
                    redis_url,
                    encoding="utf-8",
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                    retry_on_timeout=True,
                    health_check_interval=30
                )
                logger.info(f"Redis client initialized | URL: {redis_url}")
            except Exception as e:
                logger.error(f"Failed to initialize Redis client: {e}")
                raise
        
        return cls._instance
    
    @classmethod
    async def close(cls) -> None:
        """
        Close the Redis connection.
        """
        if cls._instance is not None:
            await cls._instance.close()
            cls._instance = None
            logger.info("Redis client closed")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SINGLETON GLOBAL
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

REDIS_CLIENT = RedisClient.get_instance()

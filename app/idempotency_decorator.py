"""
Idempotency decorator for FastAPI endpoints.

Provides a clean way to add idempotency to existing endpoints without modifying their signatures.
"""

from functools import wraps
from typing import Callable
from fastapi import Request, Response, Header
from fastapi.responses import JSONResponse
from app.idempotency import (
    get_idempotent_response,
    store_idempotent_response,
    compute_request_hash,
    is_valid_idempotency_key
)
from app.logger import logger

def with_idempotency(func: Callable):
    """
    Decorator to add idempotency support to POST endpoints.
    
    Usage:
        @router.post("/validate")
        @with_idempotency
        async def validate_email(...):
            ...
    
    Automatically handles Idempotency-Key header and caches responses.
    """
    
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # Extract request from kwargs
        request: Request = kwargs.get("request") or next((arg for arg in args if isinstance(arg, Request)), None)
        
        # Extract idempotency key from header (if provided)
        idempotency_key = request.headers.get("Idempotency-Key") or request.headers.get("idempotency-key")
        
        # Get Redis from kwargs
        redis = kwargs.get("redis")
        
        # If no idempotency key or no Redis, proceed normally
        if not idempotency_key or not redis:
            return await func(*args, **kwargs)
        
        # Validate key format
        if not is_valid_idempotency_key(idempotency_key):
            return JSONResponse(
                status_code=400,
                content={
                    "type": "invalid_idempotency_key",
                    "title": "Invalid Idempotency Key",
                    "status": 400,
                    "detail": "Idempotency-Key must be alphanumeric, 1-255 chars (UUID recommended)"
                }
            )
        
        # Compute request hash
        request_body = await request.body()
        request_hash = compute_request_hash(request_body)
        
        # Check for cached response
        try:
            cached = await get_idempotent_response(redis, idempotency_key, request_hash)
            if cached:
                response = JSONResponse(
                    status_code=cached["status_code"],
                    content=cached["body"]
                )
                if cached.get("replayed"):
                    response.headers["X-Idempotent-Replay"] = "true"
                    logger.info(f"Idempotent replay for key: {idempotency_key}")
                return response
        except Exception as e:
            logger.error(f"Idempotency check failed: {e}")
            # Continue with request if idempotency check fails
        
        # Execute original function
        result = await func(*args, **kwargs)
        
        # Store successful responses for future idempotency
        if isinstance(result, (JSONResponse, Response)):
            try:
                if 200 <= result.status_code < 300:
                    # Extract body from response
                    if hasattr(result, 'body'):
                        import json
                        body_content = json.loads(result.body.decode() if isinstance(result.body, bytes) else result.body)
                    else:
                        body_content = {}
                    
                    await store_idempotent_response(
                        redis,
                        idempotency_key,
                        request_hash,
                        result.status_code,
                        body_content
                    )
            except Exception as e:
                logger.error(f"Failed to store idempotent response: {e}")
        
        return result
    
    return wrapper

"""
Request logging middleware for developer debugging.

Logs all API requests to Redis for retrieval via /logs/requests endpoint.
"""

import time
import uuid
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from app.json_utils import dumps as json_dumps
from app.logger import logger

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware to log API requests for debugging.
    
    Logs include:
    - Request ID
    - Method, endpoint, query params
    - Status code, duration
    - User ID (if authenticated)
    - IP address
    
    Logs are stored in Redis sorted sets (score = timestamp).
    Retention: 30 days, max 1000 entries per user.
    """
    
    async def dispatch(self, request: Request, call_next):
        # Generate request ID if not present
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        
        # Track start time
        start_time = time.time()
        
        # Process request
        response = await call_next(request)
        
        # Calculate duration
        duration_ms = int((time.time() - start_time) * 1000)
        
        # Add request ID to response headers
        response.headers["X-Request-ID"] = request_id
        
        # Extract user ID from request state (set by auth middleware)
        user_id = getattr(request.state, "user_id", None)
        
        # Only log for authenticated users and non-GET requests (or important GET endpoints)
        should_log = user_id and (
            request.method in ["POST", "PUT", "DELETE", "PATCH"] or
            request.url.path.startswith("/validate") or
            request.url.path.startswith("/logs")
        )
        
        if should_log:
            try:
                redis = request.app.state.redis
                
                # Build log entry
                log_data = {
                    "request_id": request_id,
                    "method": request.method,
                    "endpoint": request.url.path,
                    "query_params": dict(request.query_params) if request.query_params else {},
                    "status_code": response.status_code,
                    "duration_ms": duration_ms,
                    "ip": request.client.host if request.client else "unknown",
                    "user_agent": request.headers.get("User-Agent", "")[:100],  # Truncate
                }
                
                # Store in Redis sorted set
                log_key = f"user:{user_id}:request_logs"
                timestamp = time.time()
                
                await redis.zadd(
                    log_key,
                    {json_dumps(log_data): timestamp}
                )
                
                # Keep only last 1000 entries (trim oldest)
                await redis.zremrangebyrank(log_key, 0, -1001)
                
                # Set TTL (30 days)
                await redis.expire(log_key, 2592000)
                
                logger.debug(
                    f"Logged request: {request.method} {request.url.path} "
                    f"→ {response.status_code} ({duration_ms}ms)"
                )
                
            except Exception as e:
                # Don't fail request if logging fails
                logger.error(f"Request logging failed: {e}")
        
        return response

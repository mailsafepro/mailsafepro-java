"""
Payload Size Limit Middleware

Enforces request body size limits to prevent:
- Memory exhaustion attacks
- DoS via large payloads
- Bandwidth abuse

Limits are enforced per-endpoint for granular control.
"""

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Dict
from app.logger import logger

class PayloadSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Enforce request payload size limits per endpoint.
    
    Returns 413 Payload Too Large if limit exceeded.
    """
    
    # Size limits in bytes
    LIMITS: Dict[str, int] = {
        # Validation endpoints
        "/validate/email": 10 * 1024,              # 10 KB (single email)
        "/email": 10 * 1024,                       # 10 KB (single email)
        "/validate/batch": 10 * 1024 * 1024,       # 10 MB (batch validation)
        "/batch": 10 * 1024 * 1024,                # 10 MB (batch validation)
        
        # Auth endpoints
        "/auth/register": 5 * 1024,                # 5 KB
        "/auth/login": 5 * 1024,                   # 5 KB
        
        # Billing endpoints
        "/billing/upgrade": 10 * 1024,             # 10 KB
        
        # Webhook endpoints
        "/webhooks": 50 * 1024,                    # 50 KB
        
        # Default for all other endpoints
        "default": 1 * 1024 * 1024                 # 1 MB
    }
    
    async def dispatch(self, request: Request, call_next):
        """Check payload size before processing request."""
        
        # Only check POST/PUT/PATCH methods
        if request.method not in ["POST", "PUT", "PATCH"]:
            return await call_next(request)
        
        # Get content-length header
        content_length = request.headers.get("content-length")
        
        if not content_length:
            # No content-length header - let it proceed
            # (FastAPI will handle if body is actually too large)
            return await call_next(request)
        
        try:
            content_length = int(content_length)
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={
                    "type": "invalid_content_length",
                    "title": "Invalid Content-Length Header",
                    "status": 400,
                    "detail": "Content-Length must be a valid integer"
                }
            )
        
        # Determine size limit for this endpoint
        limit = self._get_limit_for_path(request.url.path)
        
        if content_length > limit:
            logger.warning(
                f"Payload too large rejected",
                path=request.url.path,
                size=content_length,
                limit=limit,
                security_event=True
            )
            
            return JSONResponse(
                status_code=413,
                content={
                    "type": "payload_too_large",
                    "title": "Request Payload Too Large",
                    "status": 413,
                    "detail": f"Request body exceeds maximum size of {self._format_bytes(limit)}",
                    "max_size_bytes": limit,
                    "max_size_human": self._format_bytes(limit),
                    "received_bytes": content_length
                }
            )
        
        return await call_next(request)
    
    def _get_limit_for_path(self, path: str) -> int:
        """Get size limit for specific path."""
        # Check exact match first
        if path in self.LIMITS:
            return self.LIMITS[path]
        
        # Check prefix match
        for limit_path, limit_size in self.LIMITS.items():
            if limit_path != "default" and path.startswith(limit_path):
                return limit_size
        
        # Return default
        return self.LIMITS["default"]
    
    @staticmethod
    def _format_bytes(bytes_value: int) -> str:
        """Format bytes as human-readable string."""
        if bytes_value < 1024:
            return f"{bytes_value} bytes"
        elif bytes_value < 1024 * 1024:
            return f"{bytes_value / 1024:.1f} KB"
        else:
            return f"{bytes_value / (1024 * 1024):.1f} MB"

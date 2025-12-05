"""
Health Check Logic
"""

from fastapi import HTTPException, Request
from app.logger import logger
import time
import socket
import asyncio

async def check_liveness():
    """
    Basic liveness check.
    Returns 200 OK if the application process is running.
    """
    return {
        "status": "alive",
        "timestamp": time.time(),
        "service": "mailsafepro-api"
    }

async def check_readiness(request: Request):
    """
    Deep readiness check.
    Verifies critical dependencies (Redis, DNS) are accessible.
    Returns 503 if critical dependencies are down.
    """
    status = {
        "status": "ready",
        "timestamp": time.time(),
        "checks": {
            "redis": "unknown",
            "dns": "unknown"
        }
    }
    
    is_ready = True
    
    # 1. Check Redis (Critical)
    try:
        if hasattr(request.app.state, "redis"):
            # Ping Redis
            if await request.app.state.redis.ping():
                status["checks"]["redis"] = "ok"
            else:
                status["checks"]["redis"] = "failed: ping returned false"
                is_ready = False
        else:
            status["checks"]["redis"] = "failed: not initialized"
            is_ready = False
            
    except Exception as e:
        status["checks"]["redis"] = f"failed: {str(e)}"
        is_ready = False
        logger.error(f"Readiness check failed: Redis - {e}")

    # 2. Check DNS (Critical for validation)
    try:
        # Simple non-blocking DNS resolution check
        # Resolve google.com as a connectivity test
        loop = asyncio.get_event_loop()
        await loop.getaddrinfo('google.com', 80)
        status["checks"]["dns"] = "ok"
    except Exception as e:
        status["checks"]["dns"] = f"failed: {str(e)}"
        # DNS might be flaky, but if it fails completely, we can't validate emails
        # Marking as not ready might be too aggressive if it's just a blip,
        # but for a readiness probe, we want to ensure we can work.
        # Let's log it but maybe not fail readiness unless strict mode?
        # For now, we'll consider it critical.
        is_ready = False
        logger.error(f"Readiness check failed: DNS - {e}")

    if not is_ready:
        status["status"] = "not_ready"
        raise HTTPException(status_code=503, detail=status)

    return status

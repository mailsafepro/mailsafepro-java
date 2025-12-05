"""
Healthcheck Routes
"""

from fastapi import APIRouter, Request, Depends
from app.health.checks import check_liveness, check_readiness

router = APIRouter(tags=["Health"])

@router.get("/health/live")
async def liveness_probe():
    """
    Liveness probe: Is the application running?
    K8s action: Restart pod if fails.
    """
    return await check_liveness()

@router.get("/health/ready")
async def readiness_probe(request: Request):
    """
    Readiness probe: Can the application serve traffic?
    Checks dependencies: Redis, DNS.
    K8s action: Remove from load balancer if fails.
    """
    return await check_readiness(request)

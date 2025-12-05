"""
Admin and monitoring routes for cache warming and system statistics.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from typing import Dict

from app.auth import get_current_client, TokenData
from app.cache_warming import get_warming_stats
from app.logger import logger

router = APIRouter(prefix="/admin", tags=["Admin & Monitoring"])


@router.get("/cache-warming/stats", summary="Get cache warming statistics")
async def get_cache_warming_stats(
    current_client: TokenData = Depends(get_current_client)
) -> Dict:
    """
    Get statistics about cache warming performance and coverage.
    
    Requires authentication. Returns information about:
    - Total domains warmed
    - Warming failure rate
    - Configured tiers and domain counts
    - Last warming run timestamp
    
    **Response:**
    ```json
    {
        "total_warmed": 150,
        "total_failures": 3,
        "cache_hits_saved": 25000,
        "last_run": "2025-11-22T18:30:00",
        "running": true,
        "config": {
            "enabled": true,
            "tier_1_domains": 10,
            "tier_2_domains": 18,
            "tier_3_domains": 25,
            "tier_4_domains": 20,
            "total_domains": 73
        }
    }
    ```
    """
    try:
        stats = get_warming_stats()
        return stats
    except Exception as e:
        logger.error(f"Failed to get cache warming stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve cache warming statistics"
        )


@router.post("/cache-warming/trigger", summary="Manually trigger cache warming")
async def trigger_cache_warming(
    current_client: TokenData = Depends(get_current_client)
) -> Dict:
    """
    Manually trigger cache warming for all tiers.
    
    Requires authentication. Useful for:
    - Forcing immediate cache refresh
    - Testing cache warming configuration
    - Recovering from warming failures
    
    **Response:**
    ```json
    {
        "status": "triggered",
        "message": "Cache warming started in background"
    }
    ```
    """
    try:
        from app.cache_warming import get_cache_warmer
        import asyncio
        
        warmer = get_cache_warmer()
        
        # Trigger warming in background (don't block response)
        asyncio.create_task(warmer.warm_all_tiers(force=True))
        
        return {
            "status": "triggered",
            "message": "Cache warming started in background"
        }
    except Exception as e:
        logger.error(f"Failed to trigger cache warming: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to trigger cache warming"
        )

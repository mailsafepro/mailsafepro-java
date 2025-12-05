"""
Request Logs API for developer dashboard.

Provides endpoints to retrieve and filter API request logs for debugging.
"""

from fastapi import APIRouter, Depends, Query, HTTPException, Request
from typing import List, Optional
from datetime import datetime, timedelta
from redis.asyncio import Redis
from app.auth import get_current_client, TokenData
from app.logger import logger
from app.json_utils import loads as json_loads

router = APIRouter(prefix="/logs", tags=["Developer Tools"])

@router.get("/requests")
async def get_request_logs(
    request: Request,
    limit: int = Query(default=100, le=500, description="Max results to return"),
    status_code: Optional[int] = Query(default=None, description="Filter by HTTP status code"),
    endpoint: Optional[str] = Query(default=None, description="Filter by endpoint path"),
    method: Optional[str] = Query(default=None, description="Filter by HTTP method (GET, POST, etc)"),
    since: Optional[datetime] = Query(default=None, description="Filter by timestamp (ISO 8601)"),
    current: TokenData = Depends(get_current_client)
):
    """Get request logs for authenticated user."""
    
    redis = request.app.state.redis
    
    try:
        log_key = f"user:{current.sub}:request_logs"
        since_timestamp = since.timestamp() if since else 0
        now_timestamp = datetime.utcnow().timestamp()
        
        logs_raw = await redis.zrangebyscore(
            log_key,
            min=since_timestamp,
            max=now_timestamp,
            start=0,
            num=limit * 2,
            withscores=True
        )
        
        if not logs_raw:
            return {
                "count": 0,
                "logs": [],
                "filters": {"status_code": status_code, "endpoint": endpoint, "method": method},
                "retention_days": 30
            }
        
        results = []
        for log_data, timestamp in logs_raw:
            try:
                log = json_loads(log_data)
                if status_code and log.get("status_code") != status_code:
                    continue
                if endpoint and not log.get("endpoint", "").startswith(endpoint):
                    continue
                if method and log.get("method") != method.upper():
                    continue
                
                log["timestamp"] = datetime.fromtimestamp(timestamp).isoformat()
                results.append(log)
                
                if len(results) >= limit:
                    break
            except Exception:
                continue
        
        return {
            "count": len(results),
            "logs": results,
            "filters": {"status_code": status_code, "endpoint": endpoint, "method": method},
            "retention_days": 30
        }
    except Exception as e:
        logger.error(f"Failed to retrieve request logs: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve request logs")

@router.delete("/requests")
async def clear_request_logs(
    request: Request,
    current: TokenData = Depends(get_current_client)
):
    """Clear all request logs for current user."""
    redis = request.app.state.redis
    
    try:
        log_key = f"user:{current.sub}:request_logs"
        deleted_count = await redis.delete(log_key)
        logger.info(f"Cleared request logs for user {current.sub}")
        return {"deleted": deleted_count > 0, "message": "Request logs cleared successfully"}
    except Exception as e:
        logger.error(f"Failed to clear request logs: {e}")
        raise HTTPException(status_code=500, detail="Failed to clear request logs")

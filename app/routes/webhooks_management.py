"""
Webhook Management API for developer dashboard.

Provides endpoints to configure, test, and monitor webhooks.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, Query
from pydantic import BaseModel, HttpUrl
from typing import List, Optional
from datetime import datetime
import uuid
import hashlib
import secrets
from app.auth import get_current_client, TokenData
from app.logger import logger
from app.json_utils import dumps as json_dumps, loads as json_loads

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])

class WebhookCreate(BaseModel):
    url: HttpUrl
    events: List[str] = ["validation.completed", "batch.completed"]
    secret: Optional[str] = None
    description: Optional[str] = None

class WebhookUpdate(BaseModel):
    url: Optional[HttpUrl] = None
    events: Optional[List[str]] = None
    status: Optional[str] = None  # 'active' or 'paused'
    description: Optional[str] = None

@router.post("/")
async def create_webhook(
    request: Request,
    webhook_data: WebhookCreate,
    current: TokenData = Depends(get_current_client)
):
    """
    Create a new webhook endpoint.
    
    Events available:
    - validation.completed: Single email validation finished
    - batch.completed: Batch validation finished
    - usage.limit_reached: API usage limit reached (80%)
    """
    redis = request.app.state.redis
    
    webhook_id = str(uuid.uuid4())
    secret = webhook_data.secret or secrets.token_urlsafe(32)
    
    webhook = {
        "id": webhook_id,
        "user_id": current.sub,
        "url": str(webhook_data.url),
        "events": webhook_data.events,
        "secret": secret,
        "status": "active",
        "description": webhook_data.description,
        "created_at": datetime.utcnow().isoformat(),
        "deliveries": {
            "total": 0,
            "successful": 0,
            "failed": 0
        }
    }
    
    try:
        # Store webhook config
        await redis.set(
            f"webhook:{webhook_id}",
            json_dumps(webhook)
        )
        
        # Add to user's webhook list
        await redis.sadd(f"user:{current.sub}:webhooks", webhook_id)
        
        logger.info(f"Created webhook {webhook_id} for user {current.sub}")
        
        return {
            **webhook,
            "secret": f"{secret[:8]}..." # Don't return full secret
        }
    except Exception as e:
        logger.error(f"Failed to create webhook: {e}")
        raise HTTPException(status_code=500, detail="Failed to create webhook")

@router.get("/")
async def list_webhooks(
    request: Request,
    current: TokenData = Depends(get_current_client)
):
    """List all webhooks for authenticated user."""
    redis = request.app.state.redis
    
    try:
        webhook_ids = await redis.smembers(f"user:{current.sub}:webhooks")
        
        webhooks = []
        for webhook_id in webhook_ids:
            if isinstance(webhook_id, bytes):
                webhook_id = webhook_id.decode('utf-8')
            
            webhook_data = await redis.get(f"webhook:{webhook_id}")
            if webhook_data:
                webhook = json_loads(webhook_data)
                # Mask secret
                webhook["secret"] = f"{webhook['secret'][:8]}..."
                webhooks.append(webhook)
        
        return {"webhooks": webhooks, "count": len(webhooks)}
    except Exception as e:
        logger.error(f"Failed to list webhooks: {e}")
        raise HTTPException(status_code=500, detail="Failed to list webhooks")

@router.get("/{webhook_id}")
async def get_webhook(
    request: Request,
    webhook_id: str,
    current: TokenData = Depends(get_current_client)
):
    """Get webhook details."""
    redis = request.app.state.redis
    
    try:
        webhook_data = await redis.get(f"webhook:{webhook_id}")
        if not webhook_data:
            raise HTTPException(status_code=404, detail="Webhook not found")
        
        webhook = json_loads(webhook_data)
        
        # Verify ownership
        if webhook["user_id"] != current.sub:
            raise HTTPException(status_code=403, detail="Not authorized")
        
        webhook["secret"] = f"{webhook['secret'][:8]}..."
        return webhook
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get webhook: {e}")
        raise HTTPException(status_code=500, detail="Failed to get webhook")

@router.patch("/{webhook_id}")
async def update_webhook(
    request: Request,
    webhook_id: str,
    update_data: WebhookUpdate,
    current: TokenData = Depends(get_current_client)
):
    """Update webhook configuration."""
    redis = request.app.state.redis
    
    try:
        webhook_data = await redis.get(f"webhook:{webhook_id}")
        if not webhook_data:
            raise HTTPException(status_code=404, detail="Webhook not found")
        
        webhook = json_loads(webhook_data)
        
        if webhook["user_id"] != current.sub:
            raise HTTPException(status_code=403, detail="Not authorized")
        
        # Update fields
        if update_data.url:
            webhook["url"] = str(update_data.url)
        if update_data.events:
            webhook["events"] = update_data.events
        if update_data.status:
            webhook["status"] = update_data.status
        if update_data.description is not None:
            webhook["description"] = update_data.description
        
        webhook["updated_at"] = datetime.utcnow().isoformat()
        
        await redis.set(f"webhook:{webhook_id}", json_dumps(webhook))
        
        logger.info(f"Updated webhook {webhook_id}")
        
        webhook["secret"] = f"{webhook['secret'][:8]}..."
        return webhook
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update webhook: {e}")
        raise HTTPException(status_code=500, detail="Failed to update webhook")

@router.delete("/{webhook_id}")
async def delete_webhook(
    request: Request,
    webhook_id: str,
    current: TokenData = Depends(get_current_client)
):
    """Delete webhook."""
    redis = request.app.state.redis
    
    try:
        webhook_data = await redis.get(f"webhook:{webhook_id}")
        if not webhook_data:
            raise HTTPException(status_code=404, detail="Webhook not found")
        
        webhook = json_loads(webhook_data)
        
        if webhook["user_id"] != current.sub:
            raise HTTPException(status_code=403, detail="Not authorized")
        
        # Delete webhook and remove from user's list
        await redis.delete(f"webhook:{webhook_id}")
        await redis.srem(f"user:{current.sub}:webhooks", webhook_id)
        
        logger.info(f"Deleted webhook {webhook_id}")
        
        return {"deleted": True, "webhook_id": webhook_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete webhook: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete webhook")

@router.post("/{webhook_id}/test")
async def test_webhook(
    request: Request,
    webhook_id: str,
    current: TokenData = Depends(get_current_client)
):
    """Send test event to webhook."""
    redis = request.app.state.redis
    
    try:
        webhook_data = await redis.get(f"webhook:{webhook_id}")
        if not webhook_data:
            raise HTTPException(status_code=404, detail="Webhook not found")
        
        webhook = json_loads(webhook_data)
        
        if webhook["user_id"] != current.sub:
            raise HTTPException(status_code=403, detail="Not authorized")
        
        test_payload = {
            "event": "test.webhook",
            "data": {
                "message": "This is a test webhook delivery",
                "webhook_id": webhook_id
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Send webhook (async)
        from app.jobs.webhooks import send_webhook
        try:
            await send_webhook(webhook['url'], test_payload, webhook['secret'])
            logger.info(f"Test webhook sent to {webhook_id}")
            return {"status": "test_sent", "message": "Test webhook delivered"}
        except Exception as e:
            logger.error(f"Test webhook failed: {e}")
            return {"status": "test_failed", "error": str(e)}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to test webhook: {e}")
        raise HTTPException(status_code=500, detail="Failed to test webhook")

@router.get("/{webhook_id}/deliveries")
async def get_deliveries(
    request: Request,
    webhook_id: str,
    limit: int = Query(default=100, le=500),
    current: TokenData = Depends(get_current_client)
):
    """Get delivery history for webhook."""
    redis = request.app.state.redis
    
    try:
        webhook_data = await redis.get(f"webhook:{webhook_id}")
        if not webhook_data:
            raise HTTPException(status_code=404, detail="Webhook not found")
        
        webhook = json_loads(webhook_data)
        
        if webhook["user_id"] != current.sub:
            raise HTTPException(status_code=403, detail="Not authorized")
        
        # Get deliveries from Redis sorted set
        deliveries_raw = await redis.zrevrange(
            f"webhook:{webhook_id}:deliveries",
            0,
            limit - 1,
            withscores=True
        )
        
        deliveries = []
        for delivery_data, timestamp in deliveries_raw:
            delivery = json_loads(delivery_data)
            delivery['timestamp'] = datetime.fromtimestamp(timestamp).isoformat()
            deliveries.append(delivery)
        
        return {"deliveries": deliveries, "count": len(deliveries)}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get deliveries: {e}")
        raise HTTPException(status_code=500, detail="Failed to get deliveries")

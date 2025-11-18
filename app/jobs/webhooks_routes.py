# app/jobs/webhooks_routes.py
from __future__ import annotations
import hashlib, os, secrets, json, time
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Security, status
from fastapi.security import SecurityScopes
from pydantic import BaseModel, AnyHttpUrl
from app.auth import get_redis, validate_api_key_or_token, TokenData

router = APIRouter(prefix="/v1/webhooks", tags=["Webhooks"])

GRACE_SECONDS = int(os.getenv("WEBHOOK_ROTATION_GRACE_SEC", "86400"))

class RegisterEndpoint(BaseModel):
    callback_url: AnyHttpUrl

def _ep_id(callback_url: str) -> str:
    return hashlib.sha256(callback_url.encode("utf-8")).hexdigest()

@router.post("/endpoints/register")
async def register_endpoint(
    body: RegisterEndpoint,
    current: TokenData = Security(validate_api_key_or_token, scopes=["webhook:manage"]),
    redis=Depends(get_redis),
):
    eid = _ep_id(str(body.callback_url))
    k_active = f"webhook:{current.sub}:{eid}:secret_active"
    existing = await redis.get(k_active)
    if existing:
        raise HTTPException(status_code=409, detail="Endpoint already registered")
    secret = secrets.token_urlsafe(48)
    await redis.set(k_active, secret)
    return {"endpoint_id": eid, "secret": secret}

class RotateSecret(BaseModel):
    endpoint_id: str

@router.post("/endpoints/rotate")
async def rotate_secret(
    body: RotateSecret,
    current: TokenData = Security(validate_api_key_or_token, scopes=["webhook:manage"]),
    redis=Depends(get_redis),
):
    k_active = f"webhook:{current.sub}:{body.endpoint_id}:secret_active"
    k_prev = f"webhook:{current.sub}:{body.endpoint_id}:secret_prev"
    active = await redis.get(k_active)
    if not active:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    new_secret = secrets.token_urlsafe(48)
    await redis.set(k_prev, active, ex=GRACE_SECONDS)
    await redis.set(k_active, new_secret)
    return {"endpoint_id": body.endpoint_id, "new_secret": new_secret, "grace_seconds": GRACE_SECONDS}

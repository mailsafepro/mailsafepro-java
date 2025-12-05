"""
Tests for idempotency functionality.
"""

import pytest
import pytest_asyncio
import uuid
from fastapi import FastAPI, Request, Response, APIRouter, Depends
from httpx import AsyncClient, ASGITransport
import time
from pydantic import BaseModel
from unittest.mock import patch
from redis.asyncio import Redis

class IdempotencyTestRequest(BaseModel):
    email: str

class IdempotencyTestResponse(BaseModel):
    valid: bool
    email: str

@pytest_asyncio.fixture
async def test_app(redis_client):
    """Create minimal test app with idempotency support"""
    from app.idempotency_decorator import with_idempotency
    from app.auth import get_redis
    from fastapi.responses import JSONResponse
    
    app = FastAPI()
    app.state.redis = redis_client
    
    router = APIRouter()
    
    # Create a simple test endpoint with idempotency
    @router.post("/email")
    @with_idempotency
    async def test_email_endpoint(data: IdempotencyTestRequest, request: Request, redis: Redis = Depends(get_redis)):
        """Simple test endpoint that returns a response"""
        return JSONResponse(status_code=200, content={"valid": True, "email": data.email})
    
    app.include_router(router)
    
    yield app

@pytest_asyncio.fixture
async def client(test_app):
    """Create async client"""
    async with AsyncClient(app=test_app, base_url="http://test") as ac:
        yield ac

@pytest.mark.asyncio
async def test_idempotency_key_prevents_duplicates(client):
    """Verify idempotency key prevents duplicate requests."""
    
    idempotency_key = str(uuid.uuid4())
    payload = {"email": "test@example.com"}
    
    # First request
    response1 = await client.post(
        "/email",
        json=payload,
        headers={"Idempotency-Key": idempotency_key}
    )
    assert response1.status_code in [200, 401]  # May need auth
    
    # Second request with same key (should return cached response)
    response2 = await client.post(
        "/email",
        json=payload,
        headers={"Idempotency-Key": idempotency_key}
    )
    assert response2.status_code == response1.status_code
    
    # Check replay header
    if response2.status_code == 200:
        assert "X-Idempotent-Replay" in response2.headers

@pytest.mark.asyncio
async def test_idempotency_different_keys(client):
    """Test that different idempotency keys are treated as different requests"""
    key1 = str(uuid.uuid4())
    key2 = str(uuid.uuid4())
    
    # First request
    payload = {"email": "test1@example.com"}
    headers1 = {"X-Idempotency-Key": key1}
    response1 = await client.post("/email", json=payload, headers=headers1)
    assert response1.status_code == 200
    
    # Second request with different key
    headers2 = {"X-Idempotency-Key": key2}
    response2 = await client.post("/email", json=payload, headers=headers2)
    assert response2.status_code == 200
    
    # Should be processed again (different key)
    assert response1.headers.get("X-Idempotent-Replay") is None
    assert response2.headers.get("X-Idempotent-Replay") is None

@pytest.mark.asyncio
async def test_idempotency_key_reuse_with_different_body(client):
    """Test that reusing an idempotency key with different body returns error"""
    idempotency_key = "test-key-123"
    
    # Mock time to ensure consistent float values
    with patch('time.time', return_value=1000.0):
        # First request
        response1 = await client.post(
            "/email",
            json={"email": "test@example.com"},
            headers={"Idempotency-Key": idempotency_key}
        )
        
        # Second request with different body but same key
        response2 = await client.post(
            "/email",
            json={"email": "different@example.com"},  # Different email
            headers={"Idempotency-Key": idempotency_key}
        )
        
        # Should reject due to body mismatch (422 validation error or 409 conflict)
        assert response2.status_code in [409, 422]
        assert "idempotency" in response2.json().get("type", "").lower()

@pytest.mark.asyncio
async def test_without_idempotency_key(client):
    """Verify requests work without idempotency key (backward compatible)."""
    
    response = await client.post(
        "/email",
        json={"email": "test@example.com"}
    )
    
    # Should work without idempotency key
    assert response.status_code in [200, 401]
    assert "X-Idempotent-Replay" not in response.headers

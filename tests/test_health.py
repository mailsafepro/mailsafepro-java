"""
Tests for Health Checks
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from fastapi import HTTPException, Request
from app.health.checks import check_liveness, check_readiness

@pytest.mark.asyncio
async def test_liveness():
    """Test liveness probe returns 200 OK."""
    result = await check_liveness()
    assert result["status"] == "alive"
    assert "timestamp" in result

@pytest.mark.asyncio
async def test_readiness_success():
    """Test readiness probe success."""
    # Mock Request and Redis
    request = MagicMock(spec=Request)
    request.app.state.redis.ping = AsyncMock(return_value=True)
    
    # Mock DNS check - patch asyncio.get_event_loop
    import asyncio
    from unittest.mock import patch
    
    loop_mock = MagicMock()
    loop_mock.getaddrinfo = AsyncMock(return_value=[(None, None, None, None, ('8.8.8.8', 53))])
    
    with patch.object(asyncio, "get_event_loop", return_value=loop_mock):
        result = await check_readiness(request)
        assert result["status"] == "ready"
        assert result["checks"]["redis"] == "ok"
        assert result["checks"]["dns"] == "ok"

@pytest.mark.asyncio
async def test_readiness_redis_failure():
    """Test readiness probe fails when Redis is down."""
    request = MagicMock(spec=Request)
    request.app.state.redis.ping = AsyncMock(return_value=False)
    
    with pytest.raises(HTTPException) as exc:
        await check_readiness(request)
    
    assert exc.value.status_code == 503
    assert exc.value.detail["status"] == "not_ready"
    assert "failed" in exc.value.detail["checks"]["redis"]

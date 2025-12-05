"""
Tests for Advanced Rate Limiting
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from app.rate_limiting.distributed_limiter import DistributedRateLimiter
from app.rate_limiting.tiers import get_user_tier, UserTier, TIER_CONFIGS

@pytest.mark.asyncio
async def test_distributed_limiter_lua_script():
    """Test that Lua script logic works via mock."""
    redis_mock = MagicMock() # redis client itself can be MagicMock for sync methods
    # script object should be AsyncMock (callable -> awaitable)
    script_mock = AsyncMock(return_value=[1, 9])
    redis_mock.register_script.return_value = script_mock
    
    limiter = DistributedRateLimiter(redis_mock)
    allowed, remaining = await limiter.check_limit("test_key", 10, 60)
    
    assert allowed is True
    assert remaining == 9
    redis_mock.register_script.assert_called_once()

@pytest.mark.asyncio
async def test_distributed_limiter_denied():
    """Test rate limit exceeded."""
    redis_mock = MagicMock()
    script_mock = AsyncMock(return_value=[0, 0])
    redis_mock.register_script.return_value = script_mock
    
    limiter = DistributedRateLimiter(redis_mock)
    allowed, remaining = await limiter.check_limit("test_key", 10, 60)
    
    assert allowed is False
    assert remaining == 0

@pytest.mark.asyncio
async def test_burst_limit():
    """Test burst limit check."""
    redis_mock = MagicMock()
    script_mock = AsyncMock(return_value=[1, 4])
    redis_mock.register_script.return_value = script_mock
    
    limiter = DistributedRateLimiter(redis_mock)
    allowed = await limiter.check_burst_limit("test_key", 5)
    
    assert allowed is True

def test_get_user_tier():
    """Test tier resolution."""
    assert get_user_tier("msp_live_123") == UserTier.PRO
    assert get_user_tier("msp_ent_123") == UserTier.ENTERPRISE
    assert get_user_tier("msp_test_123") == UserTier.PRO
    assert get_user_tier("invalid_key") == UserTier.FREE
    assert get_user_tier("") == UserTier.FREE
    assert get_user_tier(None) == UserTier.FREE

def test_tier_configs():
    """Verify tier configurations."""
    free = TIER_CONFIGS[UserTier.FREE]
    assert free.requests_per_minute == 10
    assert free.burst_allowance == 2
    
    pro = TIER_CONFIGS[UserTier.PRO]
    assert pro.requests_per_minute == 100
    assert pro.burst_allowance == 20

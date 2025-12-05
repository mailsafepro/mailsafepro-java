"""
Tests for abuse detection system.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from app.security.abuse_detection import AbuseDetector

@pytest.mark.asyncio
async def test_same_email_repeated_abuse():
    """Test detection of repeated email validations."""
    redis_mock = AsyncMock()
    redis_mock.incr.return_value = 25  # Above threshold of 20
    redis_mock.expire.return_value = True
    
    # Mock pipeline - hincrby/expire are sync (not awaited), execute is async
    pipeline_mock = MagicMock()
    pipeline_mock.hincrby = MagicMock(return_value=pipeline_mock)
    pipeline_mock.expire = MagicMock(return_value=pipeline_mock)
    pipeline_mock.execute = AsyncMock(return_value=[None, None])
    
    # Configure redis_mock.pipeline to return the mock directly
    redis_mock.pipeline = MagicMock(return_value=pipeline_mock)
    redis_mock.hgetall = AsyncMock(return_value={})
    
    result = await AbuseDetector.check_abuse(
        redis=redis_mock,
        user_id="user123",
        email="test@example.com",
        is_valid=True
    )
    
    assert result["is_abuse"] is True
    assert result["abuse_type"] == "same_email_repeated"
    assert result["severity"] == "medium"

@pytest.mark.asyncio
async def test_rapid_requests_abuse():
    """Test detection of rapid request spikes."""
    redis_mock = AsyncMock()
    redis_mock.incr.side_effect = [5, 200]  # First email count, then minute count
    redis_mock.expire.return_value = True
    
    # Mock pipeline
    pipeline_mock = MagicMock()
    pipeline_mock.hincrby = MagicMock(return_value=pipeline_mock)
    pipeline_mock.expire = MagicMock(return_value=pipeline_mock)
    pipeline_mock.execute = AsyncMock(return_value=[None, None])
    
    # Configure redis_mock.pipeline to return the mock directly
    redis_mock.pipeline = MagicMock(return_value=pipeline_mock)
    redis_mock.hgetall = AsyncMock(return_value={})
    
    result = await AbuseDetector.check_abuse(
        redis=redis_mock,
        user_id="user123",
        email="test@example.com",
        is_valid=True
    )
    
    assert result["is_abuse"] is True
    assert result["abuse_type"] == "rapid_requests"
    assert result["severity"] == "high"

@pytest.mark.asyncio
async def test_honeypot_trigger():
    """Test honeypot email detection."""
    redis_mock = AsyncMock()
    redis_mock.incr.side_effect = [1, 1]  # Low counts
    redis_mock.expire.return_value = True
    
    # Mock pipeline - pipeline() is synchronous in redis-py
    pipeline_mock = MagicMock()
    pipeline_mock.hincrby = MagicMock(return_value=pipeline_mock)
    pipeline_mock.expire = MagicMock(return_value=pipeline_mock)
    pipeline_mock.execute = AsyncMock(return_value=[None, None])
    
    # Configure redis_mock.pipeline to return the mock directly (not a coroutine)
    redis_mock.pipeline = MagicMock(return_value=pipeline_mock)
    redis_mock.hgetall = AsyncMock(return_value={})
    
    result = await AbuseDetector.check_abuse(
        redis=redis_mock,
        user_id="user123",
        email="test@mailsafepro-honeypot.com",  # Honeypot!
        is_valid=False
    )
    
    assert result["is_abuse"] is True
    assert result["abuse_type"] == "honeypot_trigger"
    assert result["should_block"] is True
    assert result["severity"] == "high"

@pytest.mark.asyncio
async def test_no_abuse_normal_usage():
    """Test normal usage is not flagged."""
    redis_mock = AsyncMock()
    redis_mock.incr.side_effect = [2, 10]  # Low counts
    redis_mock.expire.return_value = True
    redis_mock.hgetall = AsyncMock(return_value={b"total": b"10", b"invalid": b"2"})
    
    # Mock pipeline
    pipeline_mock = MagicMock()
    pipeline_mock.hincrby = MagicMock(return_value=pipeline_mock)
    pipeline_mock.expire = MagicMock(return_value=pipeline_mock)
    pipeline_mock.execute = AsyncMock(return_value=[None, None])
    
    # Configure redis_mock.pipeline to return the mock directly
    redis_mock.pipeline = MagicMock(return_value=pipeline_mock)
    
    result = await AbuseDetector.check_abuse(
        redis=redis_mock,
        user_id="user123",
        email="normal@example.com",
        is_valid=True
    )
    
    assert result["is_abuse"] is False
    assert result["should_block"] is False

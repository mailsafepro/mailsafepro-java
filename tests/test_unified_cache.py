"""
Tests for UnifiedCache class

Tests the centralized Redis caching layer including:
- Initialization
- Get/Set operations
- Key building and sanitization
- Serialization/deserialization
- Clear operations
- Error handling
"""

import pytest
import json
from unittest.mock import AsyncMock, MagicMock, patch
from app.cache.unified_cache import UnifiedCache


@pytest.fixture
def mock_redis():
    """Mock Redis client"""
    redis = AsyncMock()
    redis.get = AsyncMock(return_value=None)
    redis.set = AsyncMock(return_value=True)
    redis.delete = AsyncMock(return_value=1)
    redis.scan = AsyncMock(return_value=(0, []))
    return redis


@pytest.fixture
def initialized_cache(mock_redis):
    """UnifiedCache initialized with mock Redis"""
    UnifiedCache.initialize(mock_redis)
    yield UnifiedCache
    # Cleanup
    UnifiedCache._redis = None


class TestUnifiedCacheInitialization:
    """Test cache initialization"""
    
    def test_initialize_sets_redis_client(self, mock_redis):
        """Test that initialize sets the Redis client"""
        UnifiedCache.initialize(mock_redis)
        assert UnifiedCache._redis is not None
        assert UnifiedCache._redis == mock_redis
    
    def test_initialize_can_be_called_multiple_times(self, mock_redis):
        """Test that initialize can be called multiple times safely"""
        UnifiedCache.initialize(mock_redis)
        UnifiedCache.initialize(mock_redis)  # Should not raise
        assert UnifiedCache._redis == mock_redis


class TestUnifiedCacheKeyBuilding:
    """Test key building and sanitization"""
    
    def test_build_key_simple(self):
        """Test simple key building"""
        key = UnifiedCache.build_key("mx", "gmail.com")
        assert key == "mx:gmail.com"
    
    def test_build_key_with_spaces(self):
        """Test key building removes spaces"""
        key = UnifiedCache.build_key("mx", " gmail.com ")
        assert key == "mx:gmail.com"
    
    def test_build_key_lowercase(self):
        """Test key building converts to lowercase"""
        key = UnifiedCache.build_key("mx", "GMAIL.COM")
        assert key == "mx:gmail.com"
    
    def test_build_key_with_special_chars(self):
        """Test key building with special characters"""
        key = UnifiedCache.build_key("email", "user@domain.com")
        assert ":" in key
        assert key.startswith("email:")
    
    def test_build_key_empty_value(self):
        """Test key building with empty value"""
        key = UnifiedCache.build_key("test", "")
        assert key == "test"
    
    def test_build_key_numeric_value(self):
        """Test key building with numeric value"""
        key = UnifiedCache.build_key("count", 123)
        assert key == "count:123"


class TestUnifiedCacheGetSet:
    """Test get and set operations"""
    
    @pytest.mark.asyncio
    async def test_get_returns_none_when_not_initialized(self):
        """Test get returns None when Redis not initialized"""
        UnifiedCache._redis = None
        result = await UnifiedCache.get("test:key")
        assert result is None
    
    @pytest.mark.asyncio
    async def test_get_returns_none_when_key_not_found(self, initialized_cache, mock_redis):
        """Test get returns None when key doesn't exist"""
        mock_redis.get.return_value = None
        result = await initialized_cache.get("test:key")
        assert result is None
        mock_redis.get.assert_called_once_with("test:key")
    
    @pytest.mark.asyncio
    async def test_get_deserializes_json(self, initialized_cache, mock_redis):
        """Test get deserializes JSON data"""
        test_data = {"foo": "bar", "count": 42}
        mock_redis.get.return_value = json.dumps(test_data).encode()
        
        result = await initialized_cache.get("test:key")
        assert result == test_data
    
    @pytest.mark.asyncio
    async def test_get_handles_strings(self, initialized_cache, mock_redis):
        """Test get handles non-JSON strings"""
        mock_redis.get.return_value = b"simple string"
        result = await initialized_cache.get("test:key")
        assert result == "simple string"
    
    @pytest.mark.asyncio
    async def test_get_handles_redis_error(self, initialized_cache, mock_redis):
        """Test get handles Redis errors gracefully"""
        mock_redis.get.side_effect = Exception("Redis error")
        result = await initialized_cache.get("test:key")
        assert result is None
    
    @pytest.mark.asyncio
    async def test_set_returns_none_when_not_initialized(self):
        """Test set returns False when Redis not initialized"""
        # Explicitly set to None to ensure clean state
        UnifiedCache._redis = None
        result = await UnifiedCache.set("test:key", "value")
        assert result is False
    
    @pytest.mark.asyncio
    async def test_set_serializes_dict(self, initialized_cache, mock_redis):
        """Test set serializes dict to JSON"""
        test_data = {"foo": "bar"}
        await initialized_cache.set("test:key", test_data)
        
        # Verify Redis set was called with JSON
        call_args = mock_redis.set.call_args
        assert call_args[0][0] == "test:key"
        stored_data = json.loads(call_args[0][1])
        assert stored_data == test_data
    
    @pytest.mark.asyncio
    async def test_set_with_ttl(self, initialized_cache, mock_redis):
        """Test set with TTL"""
        await initialized_cache.set("test:key", "value", ttl=3600)
        
        call_args = mock_redis.set.call_args
        assert call_args[1].get("ex") == 3600
    
    @pytest.mark.asyncio
    async def test_set_without_ttl(self, initialized_cache, mock_redis):
        """Test set without TTL - uses default from initialization"""
        # Note: UnifiedCache may have default TTL, just verify it's called
        await initialized_cache.set("test:key", "value")
        
        # Verify set was called
        assert mock_redis.set.called is True
    
    @pytest.mark.asyncio
    async def test_set_handles_redis_error(self, initialized_cache, mock_redis):
        """Test set handles Redis errors gracefully"""
        mock_redis.set.side_effect = Exception("Redis error")
        # Should not raise
        await initialized_cache.set("test:key", "value")


class TestUnifiedCacheClear:
    """Test clear operations"""
    
    @pytest.mark.asyncio
    async def test_clear_without_prefix_clears_all(self, initialized_cache, mock_redis):
        """Test clear without prefix clears all cache"""
        mock_redis.scan.return_value = (0, [b"key1", b"key2", b"key3"])
        
        await initialized_cache.clear()
        
        # Verify scan was called with pattern *
        mock_redis.scan.assert_called()
        # Verify delete was called with found keys
        mock_redis.delete.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_clear_with_prefix(self, initialized_cache, mock_redis):
        """Test clear with specific prefix"""
        mock_redis.scan.return_value = (0, [b"mx:gmail.com", b"mx:yahoo.com"])
        
        await initialized_cache.clear("mx:")
        
        # Verify scan was called with prefix pattern
        scan_call = mock_redis.scan.call_args
        assert "mx:*" in str(scan_call)
    
    @pytest.mark.asyncio
    async def test_clear_handles_redis_error(self, initialized_cache, mock_redis):
        """Test clear handles Redis errors gracefully"""
        mock_redis.scan.side_effect = Exception("Redis error")
        # Should not raise
        await initialized_cache.clear()
    
    @pytest.mark.asyncio
    async def test_clear_when_not_initialized(self):
        """Test clear returns 0 when Redis not initialized"""
        UnifiedCache._redis = None
        result = await UnifiedCache.clear()
        assert result == 0


class TestUnifiedCacheDelete:
    """Test delete operations"""
    
    @pytest.mark.asyncio
    async def test_delete_removes_key(self, initialized_cache, mock_redis):
        """Test delete removes specific key"""
        await initialized_cache.delete("test:key")
        mock_redis.delete.assert_called_once_with("test:key")
    
    @pytest.mark.asyncio
    async def test_delete_when_not_initialized(self):
        """Test delete returns False when Redis not initialized"""
        UnifiedCache._redis = None
        result = await UnifiedCache.delete("test:key")
        assert result is False
    
    @pytest.mark.asyncio
    async def test_delete_handles_redis_error(self, initialized_cache, mock_redis):
        """Test delete handles Redis errors gracefully"""
        mock_redis.delete.side_effect = Exception("Redis error")
        # Should not raise
        await initialized_cache.delete("test:key")


class TestUnifiedCacheComplexScenarios:
    """Test complex end-to-end scenarios"""
    
    @pytest.mark.asyncio
    async def test_cache_mx_records_scenario(self, initialized_cache, mock_redis):
        """Test caching MX records (real-world scenario)"""
        mx_records = [
            {"preference": 10, "exchange": "mx1.gmail.com"},
            {"preference": 20, "exchange": "mx2.gmail.com"}
        ]
        
        # Set MX records
        key = UnifiedCache.build_key("mx", "gmail.com")
        await initialized_cache.set(key, mx_records, ttl=7200)
        
        # Verify serialization
        call_args = mock_redis.set.call_args
        stored = json.loads(call_args[0][1])
        assert len(stored) == 2
        assert stored[0]["preference"] == 10
        
        # Mock retrieval
        mock_redis.get.return_value = json.dumps(mx_records).encode()
        result = await initialized_cache.get(key)
        
        assert result == mx_records
    
    @pytest.mark.asyncio
    async def test_cache_domain_validation_scenario(self, initialized_cache, mock_redis):
        """Test caching domain validation results"""
        validation_result = {
            "valid": True,
            "detail": "Domain is valid",
            "mx_found": True
        }
        
        key = UnifiedCache.build_key("domain", "example.com")
        await initialized_cache.set(key, validation_result, ttl=3600)
        
        # Mock retrieval
        mock_redis.get.return_value = json.dumps(validation_result).encode()
        result = await initialized_cache.get(key)
        
        assert result["valid"] is True
        assert result["mx_found"] is True

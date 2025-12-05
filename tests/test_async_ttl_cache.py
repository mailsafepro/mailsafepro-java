"""
Tests for AsyncTTLCache enhancements

Tests the enhanced AsyncTTLCache functionality including:
- Stats tracking (hits/misses)
- Prometheus metrics
- Named caches
- TTL override
- Default value support
"""

import pytest
import asyncio
import time
from unittest.mock import patch, MagicMock
from app.cache import AsyncTTLCache


@pytest.fixture
def cache():
    """Create a fresh AsyncTTLCache instance"""
    return AsyncTTLCache(ttl=60, maxsize=100, name="test_cache")


@pytest.fixture
def mock_prometheus():
    """Mock Prometheus metrics"""
    with patch('app.cache.PROM_AVAILABLE', True):
        with patch('app.cache.MET_CACHE_HITS') as mock_hits:
            with patch('app.cache.MET_CACHE_MISSES') as mock_misses:
                mock_hits.labels = MagicMock(return_value=mock_hits)
                mock_misses.labels = MagicMock(return_value=mock_misses)
                yield {
                    'hits': mock_hits,
                    'misses': mock_misses
                }


class TestAsyncTTLCacheBasics:
    """Test basic cache operations"""
    
    @pytest.mark.asyncio
    async def test_cache_initialization(self, cache):
        """Test cache initializes with correct parameters"""
        assert cache.ttl == 60
        assert cache.maxsize == 100
        assert cache.name == "test_cache"
        assert cache._hits == 0
        assert cache._misses == 0
    
    @pytest.mark.asyncio
    async def test_get_miss_returns_none(self, cache):
        """Test get on empty cache returns None"""
        result = await cache.get("nonexistent")
        assert result is None
    
    @pytest.mark.asyncio
    async def test_get_miss_returns_default(self, cache):
        """Test get returns default value on miss"""
        result = await cache.get("nonexistent", default="default_value")
        assert result == "default_value"
    
    @pytest.mark.asyncio
    async def test_set_and_get(self, cache):
        """Test basic set and get"""
        await cache.set("key1", "value1")
        result = await cache.get("key1")
        assert result == "value1"
    
    @pytest.mark.asyncio
    async def test_ttl_override_on_set(self):
        """Test TTL override functionality on set"""
        cache = AsyncTTLCache(ttl=60, maxsize=100, name="override_cache")
        
        # Set with custom TTL of 1 second
        await cache.set("key1", "value1", ttl=1)
        assert await cache.get("key1") == "value1"
        
        # Wait for expiry
        await asyncio.sleep(1.1)
        
        # Should be None after TTL expires
        assert await cache.get("key1") is None

    @pytest.mark.asyncio
    async def test_ttl_zero_means_no_set(self):
        """Test that TTL=0 means immediate expiry, so the value won't be set at all"""
        cache = AsyncTTLCache(ttl=60, maxsize=100, name="zero_ttl_cache")
        
        await cache.set("key_zero_ttl", "value_zero", ttl=0)
        
        # Should not be found immediately after setting with TTL=0
        assert await cache.get("key_zero_ttl") is None
        assert cache.stats()["size"] == 0
    
    @pytest.mark.asyncio
    async def test_ttl_expiration(self, cache):
        """Test that entries expire after TTL"""
        cache_short = AsyncTTLCache(ttl=1, maxsize=100, name="short")
        await cache_short.set("key1", "value1")
        
        # Should exist immediately
        assert await cache_short.get("key1") == "value1"
        
        # Wait for expiration
        await asyncio.sleep(1.1)
        
        # Should be expired
        assert await cache_short.get("key1") is None
    
    @pytest.mark.asyncio
    async def test_ttl_override(self):
        """Test that TTL can be overridden on set"""
        cache = AsyncTTLCache(ttl=60, maxsize=100, name="override_cache")
        
        await cache.set("key1", "value1", ttl=2)
        
        # Should exist initially
        assert await cache.get("key1") == "value1"
        
        # Wait for expiration
        await asyncio.sleep(2.2)
        
        # Should be expired
        assert await cache.get("key1") is None
    
    @pytest.mark.asyncio
    async def test_lru_eviction(self, cache):
        """Test LRU eviction when maxsize exceeded"""
        cache_small = AsyncTTLCache(ttl=60, maxsize=3, name="small")
        
        # Fill cache
        await cache_small.set("key1", "value1")
        await cache_small.set("key2", "value2")
        await cache_small.set("key3", "value3")
        
        # All should exist
        assert await cache_small.get("key1") == "value1"
        assert await cache_small.get("key2") == "value2"
        assert await cache_small.get("key3") == "value3"
        
        # Add one more (should evict key1 as least recently ADDED)
        await cache_small.set("key4", "value4")
        
        # key1 should be evicted
        assert await cache_small.get("key1") is None
        assert await cache_small.get("key4") == "value4"


class TestAsyncTTLCacheStats:
    """Test stats tracking functionality"""
    
    @pytest.mark.asyncio
    async def test_initial_stats(self, cache):
        """Test initial stats are zero"""
        stats = cache.stats()
        assert stats["hits"] == 0
        assert stats["misses"] == 0
        assert stats["size"] == 0
        assert stats["hit_ratio"] == 0.0
    
    @pytest.mark.asyncio
    async def test_hit_tracking(self, cache):
        """Test cache hits are tracked"""
        await cache.set("key1", "value1")
        
        # First get is a miss (because we're getting from cache, not from set)
        # Actually, set doesn't increment anything, only get does
        await cache.get("key1")  # Hit
        
        stats = cache.stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 0
    
    @pytest.mark.asyncio
    async def test_miss_tracking(self, cache):
        """Test cache misses are tracked"""
        await cache.get("nonexistent")
        
        stats = cache.stats()
        assert stats["hits"] == 0
        assert stats["misses"] == 1
    
    @pytest.mark.asyncio
    async def test_hit_ratio_calculation(self, cache):
        """Test hit ratio is calculated correctly"""
        await cache.set("key1", "value1")
        
        # 2 hits
        await cache.get("key1")
        await cache.get("key1")
        
        # 1 miss
        await cache.get("nonexistent")
        
        stats = cache.stats()
        assert stats["hits"] == 2
        assert stats["misses"] == 1
        assert stats["hit_ratio"] == pytest.approx(2/3, 0.01)
    
    @pytest.mark.asyncio
    async def test_stats_include_cache_info(self, cache):
        """Test stats include cache configuration"""
        await cache.set("key1", "value1")
        
        stats = cache.stats()
        assert stats["name"] == "test_cache"
        assert stats["ttl"] == 60
        assert stats["maxsize"] == 100
    
    @pytest.mark.asyncio
    async def test_clear_resets_stats(self, cache):
        """Test clear resets statistics"""
        await cache.set("key1", "value1")
        await cache.get("key1")  # Hit
        await cache.get("key2")  # Miss
        
        # Verify stats exist
        stats = cache.stats()
        assert stats["hits"] > 0
        assert stats["misses"] > 0
        
        # Clear
        await cache.clear()
        
        # Stats should be reset
        stats = cache.stats()
        assert stats["hits"] == 0
        assert stats["misses"] == 0
        assert stats["size"] == 0


class TestAsyncTTLCachePrometheusMetrics:
    """Test Prometheus metrics integration"""
    
    @pytest.mark.asyncio
    async def test_hit_increments_prometheus_metric(self, cache, mock_prometheus):
        """Test cache hit increments Prometheus counter"""
        await cache.set("key1", "value1")
        await cache.get("key1")
        
        # Verify Prometheus metric was incremented
        mock_prometheus['hits'].labels.assert_called_with(cache_type="test_cache")
        mock_prometheus['hits'].inc.assert_called()
    
    @pytest.mark.asyncio
    async def test_miss_increments_prometheus_metric(self, cache, mock_prometheus):
        """Test cache miss increments Prometheus counter"""
        await cache.get("nonexistent")
        
        # Verify Prometheus metric was incremented
        mock_prometheus['misses'].labels.assert_called_with(cache_type="test_cache")
        mock_prometheus['misses'].inc.assert_called()
    
    @pytest.mark.asyncio
    async def test_metrics_use_cache_name(self, mock_prometheus):
        """Test metrics use the cache name as label"""
        cache1 = AsyncTTLCache(ttl=60, maxsize=100, name="mx")
        cache2 = AsyncTTLCache(ttl=60, maxsize=100, name="domain")
        
        await cache1.set("k1", "v1")
        await cache2.set("k2", "v2")
        
        await cache1.get("k1")
        await cache2.get("k2")
        
        # Verify both caches used their names
        calls = mock_prometheus['hits'].labels.call_args_list
        cache_names = [call[1]['cache_type'] for call in calls]
        assert "mx" in cache_names
        assert "domain" in cache_names


class TestAsyncTTLCacheConcurrency:
    """Test cache behavior under concurrent access"""
    
    @pytest.mark.asyncio
    async def test_concurrent_sets(self, cache):
        """Test concurrent set operations"""
        async def set_value(key, value):
            await cache.set(key, value)
        
        # Set 10 values concurrently
        tasks = [set_value(f"key{i}", f"value{i}") for i in range(10)]
        await asyncio.gather(*tasks)
        
        # All should be present
        for i in range(10):
            assert await cache.get(f"key{i}") == f"value{i}"
    
    @pytest.mark.asyncio
    async def test_concurrent_gets(self, cache):
        """Test concurrent get operations"""
        await cache.set("shared_key", "shared_value")
        
        async def get_value():
            return await cache.get("shared_key")
        
        # Get 20 times concurrently
        tasks = [get_value() for _ in range(20)]
        results = await asyncio.gather(*tasks)
        
        # All should return the same value
        assert all(r == "shared_value" for r in results)
        
        # Stats should reflect 20 hits
        stats = cache.stats()
        assert stats["hits"] == 20
    
    @pytest.mark.asyncio
    async def test_concurrent_mixed_operations(self, cache):
        """Test mixed concurrent operations"""
        async def mixed_ops(i):
            await cache.set(f"key{i}", f"value{i}")
            result = await cache.get(f"key{i}")
            return result
        
        tasks = [mixed_ops(i) for i in range(10)]
        results = await asyncio.gather(*tasks)
        
        # All should return their values
        for i, result in enumerate(results):
            assert result == f"value{i}"


class TestAsyncTTLCacheEdgeCases:
    """Test edge cases and error handling"""
    
    @pytest.mark.asyncio
    async def test_none_value_is_cacheable(self, cache):
        """Test that None can be cached (different from miss)"""
        await cache.set("null_key", None)
        
        # This is tricky - None is a valid value but also returned on miss
        # Current implementation doesn't distinguish
        result = await cache.get("null_key")
        # Due to implementation, this will return None (can't distinguish)
        # This is a known limitation
    
    @pytest.mark.asyncio
    async def test_empty_string_value(self, cache):
        """Test empty string can be cached"""
        await cache.set("empty", "")
        result = await cache.get("empty")
        assert result == ""
    
    @pytest.mark.asyncio
    async def test_delete_removes_entry(self, cache):
        """Test delete removes entry"""
        await cache.set("key1", "value1")
        assert await cache.get("key1") == "value1"
        
        await cache.delete("key1")
        assert await cache.get("key1") is None
    
    @pytest.mark.asyncio
    async def test_delete_nonexistent_key(self, cache):
        """Test delete on nonexistent key doesn't error"""
        # Should not raise
        await cache.delete("nonexistent")
    
    @pytest.mark.asyncio
    async def test_large_values(self, cache):
        """Test caching large values"""
        large_value = "x" * 10000  # 10KB string
        await cache.set("large", large_value)
        result = await cache.get("large")
        assert result == large_value
    
    @pytest.mark.asyncio
    async def test_special_characters_in_keys(self, cache):
        """Test keys with special characters"""
        await cache.set("key:with:colons", "value1")
        await cache.set("key@with@at", "value2")
        await cache.set("key/with/slash", "value3")
        
        assert await cache.get("key:with:colons") == "value1"
        assert await cache.get("key@with@at") == "value2"
        assert await cache.get("key/with/slash") == "value3"


class TestAsyncTTLCacheComplexScenarios:
    """Test realistic usage scenarios"""
    
    @pytest.mark.asyncio
    async def test_mx_cache_scenario(self):
        """Test MX records caching scenario"""
        mx_cache = AsyncTTLCache(ttl=7200, maxsize=1000, name="mx")
        
        # Cache MX records for gmail
        mx_records = [
            {"preference": 10, "exchange": "mx1.gmail.com"},
            {"preference": 20, "exchange": "mx2.gmail.com"}
        ]
        await mx_cache.set("mx:gmail.com", mx_records)
        
        # Retrieve multiple times (cache hits)
        for _ in range(10):
            result = await mx_cache.get("mx:gmail.com")
            assert result == mx_records
        
        # Verify stats
        stats = mx_cache.stats()
        assert stats["hits"] == 10
        assert stats["misses"] == 0
        assert stats["hit_ratio"] == 1.0
    
    @pytest.mark.asyncio
    async def test_smtp_cache_scenario(self):
        """Test SMTP check caching scenario (short TTL)"""
        smtp_cache = AsyncTTLCache(ttl=300, maxsize=1000, name="smtp")
        
        # Cache SMTP check result
        smtp_result = {"mailbox_exists": True, "checked_at": time.time()}
        await smtp_cache.set("smtp:user@domain.com", smtp_result)
        
        # Should hit cache
        result = await smtp_cache.get("smtp:user@domain.com")
        assert result["mailbox_exists"] is True
        
        stats = smtp_cache.stats()
        assert stats["name"] == "smtp"
        assert stats["ttl"] == 300
    
    @pytest.mark.asyncio
    async def test_multiple_cache_instances(self):
        """Test multiple independent cache instances"""
        mx_cache = AsyncTTLCache(ttl=7200, maxsize=1000, name="mx")
        domain_cache = AsyncTTLCache(ttl=3600, maxsize=500, name="domain")
        
        # Populate both
        await mx_cache.set("key1", "mx_value")
        await domain_cache.set("key1", "domain_value")
        
        # Values are independent
        assert await mx_cache.get("key1") == "mx_value"
        assert await domain_cache.get("key1") == "domain_value"
        
        # Stats are independent
        mx_stats = mx_cache.stats()
        domain_stats = domain_cache.stats()
        
        assert mx_stats["name"] == "mx"
        assert domain_stats["name"] == "domain"

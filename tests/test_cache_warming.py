import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime, timedelta
from app.cache_warming import CacheWarmer, WarmingConfig, get_cache_warmer, start_cache_warming, stop_cache_warming
from app.validation import MXRecord

# Mock data - Use MXRecord objects
MOCK_MX_RECORDS = [
    MXRecord(preference=10, exchange="mx1.example.com"),
    MXRecord(preference=20, exchange="mx2.example.com")
]
MOCK_TXT_RECORDS = ["v=spf1 include:_spf.example.com ~all"]

@pytest.fixture
def mock_dependencies():
    """Mock external dependencies"""
    with patch("app.cache_warming.get_mx_records", new_callable=AsyncMock) as mock_mx, \
         patch("app.cache_warming.dns_resolver.query_txt", new_callable=AsyncMock) as mock_txt, \
         patch("app.cache_warming.async_cache_set", new_callable=AsyncMock) as mock_cache_set, \
         patch("app.cache_warming.settings") as mock_settings:
        
        mock_mx.return_value = MOCK_MX_RECORDS
        mock_txt.return_value = MOCK_TXT_RECORDS
        
        yield {
            "mx": mock_mx,
            "txt": mock_txt,
            "cache": mock_cache_set,
            "settings": mock_settings
        }

@pytest.fixture
def warmer(mock_dependencies):
    """Create a CacheWarmer instance with test config"""
    config = WarmingConfig(
        tier_1_interval=1,
        tier_2_interval=1,
        tier_3_interval=1,
        tier_4_interval=1,
        tier_1_ttl=60,
        tier_2_ttl=60,
        tier_3_ttl=60,
        tier_4_ttl=60,
        max_concurrent_lookups=5,
        batch_size=2,
        enabled=True
    )
    return CacheWarmer(config)

class TestCacheWarmer:
    
    @pytest.mark.asyncio
    async def test_initialization(self):
        """Test initialization with default and custom config"""
        warmer = CacheWarmer()
        assert warmer.config.enabled is True
        assert warmer._running is False
        
        config = WarmingConfig(enabled=False)
        warmer_custom = CacheWarmer(config)
        assert warmer_custom.config.enabled is False

    @pytest.mark.asyncio
    async def test_warm_domain_success(self, warmer, mock_dependencies):
        """Test successful domain warming"""
        domain = "example.com"
        ttl = 300
        
        result = await warmer._warm_domain(domain, ttl)
        
        assert result is True
        mock_dependencies["mx"].assert_called_with(domain, max_records=5)
        mock_dependencies["txt"].assert_called_with(domain)
        # Check that serialized MX records were cached (dicts, not MXRecord objects)
        expected_mx_dicts = [
            {"preference": 10, "exchange": "mx1.example.com"},
            {"preference": 20, "exchange": "mx2.example.com"}
        ]
        mock_dependencies["cache"].assert_any_call(f"mx:{domain}", expected_mx_dicts, ttl=ttl)
        mock_dependencies["cache"].assert_any_call(f"txt:{domain}", MOCK_TXT_RECORDS, ttl=ttl)
        assert warmer.stats["total_warmed"] == 1

    @pytest.mark.asyncio
    async def test_warm_domain_no_mx(self, warmer, mock_dependencies):
        """Test warming domain with no MX records"""
        mock_dependencies["mx"].return_value = []
        
        result = await warmer._warm_domain("invalid.com", 300)
        
        assert result is False
        assert "invalid.com" in warmer._failures
        assert warmer.stats["total_failures"] == 1

    @pytest.mark.asyncio
    async def test_warm_domain_exception(self, warmer, mock_dependencies):
        """Test warming domain handling exceptions"""
        mock_dependencies["mx"].side_effect = Exception("DNS Error")
        
        result = await warmer._warm_domain("error.com", 300)
        
        assert result is False
        assert "error.com" in warmer._failures

    @pytest.mark.asyncio
    async def test_should_skip_domain(self, warmer):
        """Test failure tracking and skipping logic"""
        domain = "fail.com"
        
        # Record failures
        for _ in range(warmer.config.max_failures_before_skip):
            warmer._record_failure(domain)
            
        assert warmer._should_skip_domain(domain) is True
        
        # Test reset after time (mock datetime?)
        # Easier to test logic: if failures are old, they are cleaned
        # But _should_skip_domain uses datetime.utcnow()
        # We can patch datetime if needed, or just rely on logic
        
    @pytest.mark.asyncio
    async def test_warm_tier(self, warmer, mock_dependencies):
        """Test warming a tier of domains"""
        domains = ["d1.com", "d2.com", "d3.com"]
        
        results = await warmer._warm_tier(1, domains, 60, force=True)
        
        assert len(results) == 3
        assert all(results.values())
        assert warmer.stats["total_warmed"] == 3
        assert mock_dependencies["mx"].call_count == 3

    @pytest.mark.asyncio
    async def test_warm_tier_interval_check(self, warmer):
        """Test that warming respects intervals"""
        warmer._last_warming[1] = datetime.utcnow()
        
        # Should skip because interval hasn't passed
        results = await warmer._warm_tier(1, ["d1.com"], 60, force=False)
        assert results == {}
        
        # Should run if forced
        results_forced = await warmer._warm_tier(1, ["d1.com"], 60, force=True)
        assert len(results_forced) == 1

    @pytest.mark.asyncio
    async def test_warm_all_tiers(self, warmer, mock_dependencies):
        """Test warming all tiers"""
        # Mock _warm_tier to avoid actual execution and verify calls
        with patch.object(warmer, '_warm_tier', new_callable=AsyncMock) as mock_warm_tier:
            await warmer.warm_all_tiers(force=True)
            
            assert mock_warm_tier.call_count == 4  # 4 tiers
            assert warmer.stats["last_run"] is not None

    @pytest.mark.asyncio
    async def test_background_warming_start_stop(self, warmer):
        """Test starting and stopping background task"""
        # Mock warm_all_tiers to avoid actual work
        warmer.warm_all_tiers = AsyncMock()
        
        await warmer.start_background_warming()
        assert warmer._running is True
        assert warmer._task is not None
        
        # Wait a bit to let the loop run once
        await asyncio.sleep(0.1)
        
        await warmer.stop()
        assert warmer._running is False
        assert warmer._task.cancelled() or warmer._task.done()

    @pytest.mark.asyncio
    async def test_global_functions(self):
        """Test global helper functions"""
        # Reset global instance
        import app.cache_warming
        app.cache_warming._cache_warmer = None
        
        warmer = get_cache_warmer()
        assert isinstance(warmer, CacheWarmer)
        
        # Test start/stop wrappers
        with patch.object(warmer, 'start_background_warming', new_callable=AsyncMock) as mock_start, \
             patch.object(warmer, 'stop', new_callable=AsyncMock) as mock_stop:
            
            await start_cache_warming()
            mock_start.assert_called_once()
            
            await stop_cache_warming()
            mock_stop.assert_called_once()

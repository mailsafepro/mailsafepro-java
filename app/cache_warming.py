"""
Cache Warming Module for MailSafePro

Pre-caches MX records and DNS data for popular email domains to achieve
sub-100ms response times for common validations.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Set
from dataclasses import dataclass

from app.logger import logger
from app.validation import get_mx_records, async_cache_set, dns_resolver
from app.config import settings
from app.cache import UnifiedCache  # For standardized key building

# =============================================================================
# TOP EMAIL DOMAINS - Actualizado con datos de 2024
# =============================================================================

# Tier 1: Mega providers (>100M usuarios cada uno)
TIER_1_DOMAINS = [
    "gmail.com", "googlemail.com",  # Google - 1.8B usuarios
    "outlook.com", "hotmail.com", "live.com",  # Microsoft - 400M
    "yahoo.com", "ymail.com", "yahoomail.com",  # Yahoo - 225M
    "icloud.com", "me.com", "mac.com",  # Apple - 850M
]

# Tier 2: Large providers (10M-100M usuarios)
TIER_2_DOMAINS = [
    "aol.com",  # Verizon - 25M
    "mail.ru", "yandex.ru", "yandex.com",  # Russia - 120M combined
    "qq.com", "163.com", "126.com",  # China - 900M combined
    "protonmail.com", "proton.me",  # ProtonMail - 70M
    "zoho.com", "zohomail.com",  # Zoho - 80M
    "gmx.com", "gmx.net",  # GMX - 47M
    "web.de", "t-online.de",  # Germany - 35M
    "naver.com", "hanmail.net",  # Korea - 31M
    "daum.net",  # Korea - 10M
]

# Tier 3: Business & Regional (1M-10M usuarios)
TIER_3_DOMAINS = [
    "fastmail.com", "fastmail.fm",
    "tutanota.com", "tuta.io",
    "mailbox.org",
    "seznam.cz",  # Czech - 6M
    "orange.fr", "wanadoo.fr",  # France - 10M
    "libero.it", "virgilio.it",  # Italy - 8M
    "optonline.net", "verizon.net",  # US ISPs
    "bellsouth.net", "att.net",  # US ISPs
    "comcast.net", "sbcglobal.net",  # US ISPs
    "cox.net", "charter.net",  # US ISPs
    "rediffmail.com",  # India - 5M
    "inbox.com", "email.com",
]

# Tier 4: Enterprise providers (Microsoft, Google Workspace dominios personalizados ya están en outlook/gmail)
TIER_4_DOMAINS = [
    "btinternet.com",  # UK - 4M
    "sky.com", "talktalk.net",  # UK
    "o2.co.uk", "ntlworld.com",  # UK
    "live.co.uk", "live.fr", "live.de",  # Microsoft regional
    "gmx.de", "gmx.at", "gmx.ch",  # GMX regional
    "freenet.de", "arcor.de",  # Germany
    "laposte.net", "sfr.fr",  # France
    "tiscali.it", "tiscali.co.uk",  # Italy/UK
]

# =============================================================================
# CACHE WARMING CONFIGURATION
# =============================================================================

@dataclass
class WarmingConfig:
    """Configuration for cache warming behavior."""
    
    # Warming intervals per tier (in seconds)
    tier_1_interval: int = 300  # 5 minutes - refresh frequently
    tier_2_interval: int = 900  # 15 minutes
    tier_3_interval: int = 1800  # 30 minutes
    tier_4_interval: int = 3600  # 1 hour
    
    # TTL per tier (how long cache stays valid)
    tier_1_ttl: int = 7200  # 2 hours
    tier_2_ttl: int = 10800  # 3 hours
    tier_3_ttl: int = 21600  # 6 hours
    tier_4_ttl: int = 43200  # 12 hours
    
    # Concurrency limits
    max_concurrent_lookups: int = 50
    batch_size: int = 10
    
    # Failures
    max_failures_before_skip: int = 3
    failure_reset_hours: int = 24
    
    # Enable/disable
    enabled: bool = True
    
    @classmethod
    def from_settings(cls) -> "WarmingConfig":
        """Load configuration from settings."""
        cache_warming = getattr(settings, "cache_warming", {})
        return cls(
            tier_1_interval=cache_warming.get("tier_1_interval", 300),
            tier_2_interval=cache_warming.get("tier_2_interval", 900),
            tier_3_interval=cache_warming.get("tier_3_interval", 1800),
            tier_4_interval=cache_warming.get("tier_4_interval", 3600),
            tier_1_ttl=cache_warming.get("tier_1_ttl", 7200),
            tier_2_ttl=cache_warming.get("tier_2_ttl", 10800),
            tier_3_ttl=cache_warming.get("tier_3_ttl", 21600),
            tier_4_ttl=cache_warming.get("tier_4_ttl", 43200),
            max_concurrent_lookups=cache_warming.get("max_concurrent_lookups", 50),
            batch_size=cache_warming.get("batch_size", 10),
            enabled=cache_warming.get("enabled", True),
        )


# =============================================================================
# CACHE WARMER
# =============================================================================

class CacheWarmer:
    """Proactive cache warming for popular email domains."""
    
    def __init__(self, config: Optional[WarmingConfig] = None):
        self.config = config or WarmingConfig.from_settings()
        self._running = False
        self._task: Optional[asyncio.Task] = None
        
        # Track failures per domain to avoid wasting resources
        self._failures: Dict[str, List[datetime]] = {}
        
        # Track last warming time per tier
        self._last_warming: Dict[int, datetime] = {}
        
        # Statistics
        self.stats = {
            "total_warmed": 0,
            "total_failures": 0,
            "cache_hits_saved": 0,  # Estimated based on tier 1 frequency
            "last_run": None,
        }
    
    def _should_skip_domain(self, domain: str) -> bool:
        """Check if domain has too many recent failures."""
        if domain not in self._failures:
            return False
        
        cutoff = datetime.utcnow() - timedelta(hours=self.config.failure_reset_hours)
        recent_failures = [f for f in self._failures[domain] if f > cutoff]
        self._failures[domain] = recent_failures  # Clean old ones
        
        return len(recent_failures) >= self.config.max_failures_before_skip
    
    def _record_failure(self, domain: str) -> None:
        """Record a failed warming attempt."""
        if domain not in self._failures:
            self._failures[domain] = []
        self._failures[domain].append(datetime.utcnow())
        self.stats["total_failures"] += 1
    
    async def _warm_domain(self, domain: str, ttl: int) -> bool:
        """Warm cache for a single domain."""
        try:
            if self._should_skip_domain(domain):
                logger.bind(request_id="cache-warmer").debug(f"Skipping domain {domain} due to repeated failures")
                return False
            
            logger.bind(request_id="cache-warmer").debug(f"Warming cache for domain: {domain}")
            
            # Fetch MX records
            mx_records = await get_mx_records(domain, max_records=5)
            
            if not mx_records:
                logger.bind(request_id="cache-warmer").warning(f"No MX records found for {domain}")
                self._record_failure(domain)
                return false
            
            # Cache MX records with tier-specific TTL
            # Convert MXRecord objects to dicts to avoid serialization errors
            mx_records_serializable = [
                {"preference": mx.preference, "exchange": str(mx.exchange)} 
                for mx in mx_records
            ]
            cache_key = UnifiedCache.build_key("mx", domain)
            await async_cache_set(cache_key, mx_records_serializable, ttl=ttl)
            
            # Also warm TXT records for SPF (common check)
            try:
                spf_records = await dns_resolver.query_txt(f"{domain}")
                if spf_records:
                    txt_cache_key = UnifiedCache.build_key("txt", domain)
                    await async_cache_set(txt_cache_key, spf_records, ttl=ttl)
            except Exception as e:
                logger.bind(request_id="cache-warmer").debug(f"SPF warming failed for {domain}: {e}")
            
            self.stats["total_warmed"] += 1
            logger.bind(request_id="cache-warmer").info(f"✅ Warmed cache for {domain} (TTL: {ttl}s)")
            return True
            
        except Exception as e:
            logger.bind(request_id="cache-warmer").error(f"Failed to warm cache for {domain}: {e}")
            self._record_failure(domain)
            return false
    
    async def _warm_tier(
        self,
        tier: int,
        domains: List[str],
        ttl: int,
        force: bool = False
    ) -> Dict[str, bool]:
        """Warm cache for all domains in a tier."""
        
        # Check if we need to warm this tier
        if not force:
            last_run = self._last_warming.get(tier)
            if last_run:
                interval_map = {
                    1: self.config.tier_1_interval,
                    2: self.config.tier_2_interval,
                    3: self.config.tier_3_interval,
                    4: self.config.tier_4_interval,
                }
                interval = interval_map.get(tier, 3600)
                if (datetime.utcnow() - last_run).total_seconds() < interval:
                    logger.debug(f"Tier {tier} not due for warming yet")
                    return {}
        
        logger.info(f"🔥 Warming Tier {tier}: {len(domains)} domains (TTL: {ttl}s)")
        
        # Process in batches with concurrency control
        semaphore = asyncio.Semaphore(self.config.max_concurrent_lookups)
        
        async def _warm_with_semaphore(domain: str) -> tuple[str, bool]:
            async with semaphore:
                result = await self._warm_domain(domain, ttl)
                return (domain, result)
        
        # Create tasks for all domains
        tasks = [_warm_with_semaphore(domain) for domain in domains]
        
        # Execute with batching to avoid overwhelming DNS
        results = {}
        for i in range(0, len(tasks), self.config.batch_size):
            batch = tasks[i:i + self.config.batch_size]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, Exception):
                    logger.error(f"Task failed: {result}")
                    continue
                domain, success = result
                results[domain] = success
            
            # Small delay between batches to avoid rate limits
            if i + self.config.batch_size < len(tasks):
                await asyncio.sleep(0.1)
        
        self._last_warming[tier] = datetime.utcnow()
        
        success_count = sum(1 for v in results.values() if v)
        logger.bind(request_id="cache-warmer").info(f"✅ Tier {tier} warming complete: {success_count}/{len(domains)} successful")
        
        return results
    
    async def warm_all_tiers(self, force: bool = False) -> None:
        """Warm cache for all tiers."""
        start_time = datetime.utcnow()
        logger.bind(request_id="cache-warmer").info("🚀 Starting cache warming for all tiers")
        
        # Warm in parallel by tier (each tier has its own semaphore)
        await asyncio.gather(
            self._warm_tier(1, TIER_1_DOMAINS, self.config.tier_1_ttl, force),
            self._warm_tier(2, TIER_2_DOMAINS, self.config.tier_2_ttl, force),
            self._warm_tier(3, TIER_3_DOMAINS, self.config.tier_3_ttl, force),
            self._warm_tier(4, TIER_4_DOMAINS, self.config.tier_4_ttl, force),
        )
        
        duration = (datetime.utcnow() - start_time).total_seconds()
        self.stats["last_run"] = start_time.isoformat()
        
        logger.bind(request_id="cache-warmer").info(f"✅ Cache warming completed in {duration:.1f}s")
        logger.bind(request_id="cache-warmer").info(f"📊 Stats: Total warmed: {self.stats['total_warmed']} | Failures: {self.stats['total_failures']}")
    
    async def start_background_warming(self) -> None:
        """Start background task that periodically warms cache."""
        if self._running:
            logger.bind(request_id="cache-warmer").warning("Cache warmer already running")
            return
        
        if not self.config.enabled:
            logger.bind(request_id="cache-warmer").info("Cache warming disabled in configuration")
            return
        
        self._running = True
        logger.bind(request_id="cache-warmer").info("🔥 Starting background cache warming")
        
        async def _warming_loop():
            # Initial warm on startup
            try:
                await self.warm_all_tiers(force=True)
            except Exception as e:
                logger.bind(request_id="cache-warmer").error(f"Initial cache warming failed: {e}")
            
            # Continuous warming loop
            while self._running:
                try:
                    await asyncio.sleep(60)  # Check every minute
                    await self.warm_all_tiers(force=False)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.bind(request_id="cache-warmer").error(f"Cache warming loop error: {e}")
                    await asyncio.sleep(300)  # Wait 5min on error
        
        self._task = asyncio.create_task(_warming_loop())
        logger.bind(request_id="cache-warmer").info("✅ Background cache warming started")
    
    async def stop(self) -> None:
        """Stop background warming."""
        if not self._running:
            return
        
        logger.bind(request_id="cache-warmer").info("Stopping background cache warming")
        self._running = False
        
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        
        logger.bind(request_id="cache-warmer").info("✅ Background cache warming stopped")
    
    def get_stats(self) -> Dict:
        """Get warming statistics."""
        return {
            **self.stats,
            "running": self._running,
            "config": {
                "enabled": self.config.enabled,
                "tier_1_domains": len(TIER_1_DOMAINS),
                "tier_2_domains": len(TIER_2_DOMAINS),
                "tier_3_domains": len(TIER_3_DOMAINS),
                "tier_4_domains": len(TIER_4_DOMAINS),
                "total_domains": (
                    len(TIER_1_DOMAINS) + len(TIER_2_DOMAINS) +
                    len(TIER_3_DOMAINS) + len(TIER_4_DOMAINS)
                ),
            }
        }


# =============================================================================
# GLOBAL INSTANCE
# =============================================================================

# Singleton instance
_cache_warmer: Optional[CacheWarmer] = None

def get_cache_warmer() -> CacheWarmer:
    """Get or create the global cache warmer instance."""
    global _cache_warmer
    if _cache_warmer is None:
        _cache_warmer = CacheWarmer()
    return _cache_warmer


async def start_cache_warming() -> None:
    """Start background cache warming (call from app startup)."""
    warmer = get_cache_warmer()
    await warmer.start_background_warming()


async def stop_cache_warming() -> None:
    """Stop background cache warming (call from app shutdown)."""
    global _cache_warmer
    if _cache_warmer:
        await _cache_warmer.stop()


def get_warming_stats() -> Dict:
    """Get cache warming statistics."""
    warmer = get_cache_warmer()
    return warmer.get_stats()

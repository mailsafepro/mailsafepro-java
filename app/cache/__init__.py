# app/cache/__init__.py

import time
import asyncio
import os
from typing import Any, Optional, Dict
from collections import OrderedDict
from .unified_cache import UnifiedCache

# Optional Prometheus metrics
try:
    from prometheus_client import Counter
    PROM_AVAILABLE = True if os.getenv("DISABLE_PROMETHEUS") != "1" else False
except Exception:
    PROM_AVAILABLE = False

if PROM_AVAILABLE:
    MET_CACHE_HITS = Counter("cache_hits_total", "Total cache hits", ["cache_type"])
    MET_CACHE_MISSES = Counter("cache_misses_total", "Total cache misses", ["cache_type"])
else:
    class DummyCounter:
        def inc(self): pass
    MET_CACHE_HITS = DummyCounter()
    MET_CACHE_MISSES = DummyCounter()


class AsyncTTLCache:
    """Caché asíncrona con TTL y tamaño máximo, usando política LRU con estadísticas."""

    def __init__(self, ttl: int = 300, maxsize: int = 1024, name: str = "default"):
        self.ttl = ttl
        self.maxsize = maxsize
        self.name = name
        self._cache: OrderedDict[str, tuple[Any, float, int]] = OrderedDict()
        self._lock = asyncio.Lock()
        self._hits = 0
        self._misses = 0

    async def get(self, key: str, default: Any = None) -> Optional[Any]:
        """
        Devuelve el valor si está en caché y no ha expirado.
        """
        async with self._lock:
            if key in self._cache:
                # Unpack value, timestamp, and ttl (handling legacy format if needed)
                entry = self._cache[key]
                if len(entry) == 3:
                    value, timestamp, entry_ttl = entry
                else:
                    value, timestamp = entry
                    entry_ttl = self.ttl

                if time.time() - timestamp < entry_ttl:
                    self._cache.move_to_end(key)
                    self._hits += 1
                    if PROM_AVAILABLE:
                        MET_CACHE_HITS.labels(cache_type=self.name).inc()
                    return value
                # Expirado
                del self._cache[key]
            
            self._misses += 1
            if PROM_AVAILABLE:
                MET_CACHE_MISSES.labels(cache_type=self.name).inc()
            return default

    async def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """
        Inserta valor en caché. Aplica política LRU si se supera maxsize.
        """
        async with self._lock:
            expiry_ttl = ttl if ttl is not None else self.ttl
            # If TTL is 0, do not cache (immediate expiry)
            if expiry_ttl == 0:
                return

            self._cache[key] = (value, time.time(), expiry_ttl)
            self._cache.move_to_end(key)
            while len(self._cache) > self.maxsize:
                self._cache.popitem(last=False)

    async def delete(self, key: str):
        """Elimina una clave específica."""
        async with self._lock:
            self._cache.pop(key, None)

    async def clear(self):
        """Limpia toda la caché."""
        async with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0

    def stats(self) -> Dict[str, Any]:
        """Retorna estadísticas de la caché."""
        total = self._hits + self._misses
        return {
            "name": self.name,
            "size": len(self._cache),
            "maxsize": self.maxsize,
            "ttl": self.ttl,
            "hits": self._hits,
            "misses": self._misses,
            "hit_ratio": (self._hits / total) if total > 0 else 0.0,
        }

__all__ = ["AsyncTTLCache", "UnifiedCache"]


# app/cache.py

import time
import asyncio
from typing import Any, Optional
from collections import OrderedDict

class AsyncTTLCache:
    """Caché asíncrona con TTL y tamaño máximo, usando política LRU."""

    def __init__(self, ttl: int = 300, maxsize: int = 1024):
        self.ttl = ttl
        self.maxsize = maxsize
        self._cache: OrderedDict[str, tuple[Any, float]] = OrderedDict()
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        """
        Devuelve el valor si está en caché y no ha expirado.
        """
        async with self._lock:
            if key in self._cache:
                value, timestamp = self._cache[key]
                if time.time() - timestamp < self.ttl:
                    self._cache.move_to_end(key)
                    return value
                # Expirado
                del self._cache[key]
            return None

    async def set(self, key: str, value: Any):
        """
        Inserta valor en caché. Aplica política LRU si se supera maxsize.
        """
        async with self._lock:
            self._cache[key] = (value, time.time())
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

# Caching Strategy - MailSafePro

**Última actualización**: 2025-11-30  
**Mantenedor**: Engineering Team

---

## 📋 Tabla de Contenidos

1. [Arquitectura General](#arquitectura-general)
2. [Implementaciones de Caché](#implementaciones-de-caché)
3. [Cuándo Usar Qué Caché](#cuándo-usar-qué-caché)
4. [Convenciones de Keys](#convenciones-de-keys)
5. [TTL Guidelines](#ttl-guidelines)
6. [Monitoreo y Debugging](#monitoreo-y-debugging)
7. [Mejores Prácticas](#mejores-prácticas)

---

## 🏗️ Arquitectura General

MailSafePro utiliza una **arquitectura de caché en capas (L1 + L2)**:

```
┌─────────────────────────────────────────────────────┐
│                  Application Layer                   │
└──────────────────┬──────────────────────────────────┘
                   │
     ┌─────────────┴─────────────┐
     │                           │
┌────▼─────┐              ┌─────▼─────┐
│ L1 Cache │              │ L2 Cache  │
│ (Memory) │◄─────────────│  (Redis)  │
│ Fallback │   On Fail    │ Primary   │
└──────────┘              └───────────┘
AsyncTTLCache             UnifiedCache
```

### Ventajas del Layered Caching

- **Performance**: L1 (in-memory) es extremadamente rápido (~µs)
- **Resilience**: Si Redis falla, L1 sigue funcionando
- **Distribution**: L2 (Redis) permite compartir cache entre instancias
- **Flexibility**: TTLs diferentes por layer según necesidad

---

## 🔧 Implementaciones de Caché

### 1. UnifiedCache (L2 - Redis)

**Ubicación**: `app/cache/unified_cache.py`  
**Tipo**: Class-level, Redis-backed  
**Scope**: Distribuido entre todas las instancias

**Características**:
- Serialización/deserialización JSON automática
- Sanitización de keys
- Type-safe API
- TTL configurable

**Uso**:
```python
from app.cache import UnifiedCache

# Inicializar (automático en startup)
UnifiedCache.initialize(redis_client)

# Get
value = await UnifiedCache.get(key)

# Set
await UnifiedCache.set(key, value, ttl=3600)

# Build key (recomendado)
cache_key = UnifiedCache.build_key("mx", "gmail.com")
# Resultado: "mx:gmail.com"

# Clear
await UnifiedCache.clear("mx:")  # Por prefijo
await UnifiedCache.clear()        # Todo
```

**Cuándo usar**: 
- ✅ Datos compartidos entre instancias
- ✅ TTLs largos (>5 minutos)
- ✅ Datos que necesitan persistencia breve

---

### 2. AsyncTTLCache (L1 - In-Memory)

**Ubicación**: `app/cache/__init__.py`  
**Tipo**: Instance-based, in-memory  
**Scope**: Local a cada proceso/instancia

**Características**:
- LRU eviction policy
- TTL por entry
- Async-safe (asyncio.Lock)
- Stats tracking (hits/misses)
- Prometheus metrics

**Uso**:
```python
from app.cache import AsyncTTLCache

# Crear instancia
mx_cache = AsyncTTLCache(
    ttl=3600,           # Default TTL en segundos
    maxsize=1000,       # Max entries (LRU)
    name="mx"          # Para metrics
)

# Get
value = await mx_cache.get(key, default=None)

# Set
await mx_cache.set(key, value, ttl=7200)  # TTL override

# Stats
stats = mx_cache.stats()
# {'name': 'mx', 'size': 42, 'hits': 150, 'misses': 23, 'hit_ratio': 0.867}

# Clear
await mx_cache.clear()
```

**Cuándo usar**:
- ✅ Datos específicos de proceso
- ✅ Lookups ultra-rápidos (<1ms)
- ✅ Fallback cuando Redis no disponible

---

### 3. ResponseCacheASGI (HTTP Middleware)

**Ubicación**: `app/asgi_middleware.py`  
**Tipo**: Middleware-level, Redis-backed  
**Scope**: HTTP responses completas

**Características**:
- Cachea responses HTTP completas (headers + body)
- Automático basado en paths configurados
- GET requests únicamente

**Configuración**:
```python
CACHEABLE_PATHS = {
    "/validate/disposable-domains": 3600,  # 1 hour
    "/validate/provider-stats": 300,       # 5 minutes
    "/health": 10,                         # 10 seconds
    "/metrics/stats": 60,                  # 1 minute
}
```

**Cuándo usar**:
- ✅ Endpoints idempotentes (GET)
- ✅ Responses costosas de generar
- ✅ Datos que no cambian frecuentemente

---

### 4. CacheWarmer (Pre-population)

**Ubicación**: `app/cache_warming.py`  
**Tipo**: Background service  
**Scope**: Proactive caching

**Características**:
- Pre-cachea MX records de dominios populares
- 4 tiers basados en popularidad
- TTLs diferenciados por tier
- Failure tracking

**Tiers**:
```python
Tier 1: Mega providers (gmail, outlook, yahoo)
  - Interval: 5 minutos
  - TTL: 2 horas
  
Tier 2: Large providers (protonmail, zoho, gmx)
  - Interval: 15 minutos
  - TTL: 3 horas
  
Tier 3: Business & Regional
  - Interval: 30 minutos
  - TTL: 6 horas
  
Tier 4: Enterprise providers
  - Interval: 1 hora
  - TTL: 12 horas
```

**Cuándo usar**:
- ✅ Reducir latencia en cold starts
- ✅ Datos predecibles y frecuentes
- ✅ Lookups DNS que son lentos

---

## 🎯 Cuándo Usar Qué Caché

| Caso de Uso | Caché Recomendado | Razón |
|-------------|-------------------|-------|
| **MX Records** | L2 (Redis) + L1 fallback | Compartir entre instancias |
| **Domain validation** | L2 (Redis) + L1 fallback | Resultados consistentes |
| **SMTP checks** | L2 (Redis) + L1 fallback | TTL corto, compartido |
| **Rate limiting** | L1 (AsyncTTLCache) | Ultra-rápido, específico del proceso |
| **Plan configs** | L1 (AsyncTTLCache) | Raramente cambia, lectura frecuente |
| **HTTP responses** | ResponseCacheASGI | Endpoints públicos costosos |
| **Provider stats** | ResponseCacheASGI | Agregaciones lentas |
| **Session data** | Redis directo | Persistencia requerida |

---

## 🔑 Convenciones de Keys

### Formato Estándar

**SIEMPRE usar `UnifiedCache.build_key()`**:

```python
# ✅ CORRECTO
cache_key = UnifiedCache.build_key("mx", "gmail.com")
cache_key = UnifiedCache.build_key("domain", "example.com")
cache_key = UnifiedCache.build_key("smtp", "user@domain.com")

# ❌ INCORRECTO
cache_key = f"mx:{domain}"  # No sanitizado
cache_key = "mx-" + domain   # Formato inconsistente
```

### Prefijos Estándar

| Prefijo | Propósito | Ejemplo | TTL Típico |
|---------|-----------|---------|------------|
| `mx:` | MX records | `mx:gmail.com` | 2-12h |
| `domain:` | Domain validation results | `domain:example.com` | 1h |
| `smtp:` | SMTP check results | `smtp:user@domain.com` | 5min |
| `txt:` | TXT records (SPF) | `txt:domain.com` | 1h |
| `dkim:` | DKIM info | `dkim:domain.com` | 1h |
| `mx_ip:` | MX IP addresses | `mx_ip:gmail-smtp-in.l.google.com` | 12h |
| `asn:` | ASN info | `asn:172.217.14.109` | 24h |
| `hibp:` | HIBP breach data | `hibp:user@domain.com` | 24h |
| `catch_all:` | Catch-all detection | `catch_all:domain.com` | 24h |
| `http_cache:` | HTTP response cache | `http_cache:/health:...` | Varies |

### Sanitización Automática

`UnifiedCache.build_key()` automáticamente:
- Convierte a lowercase
- Remueve espacios
- Escapa caracteres especiales
- Trunca a longitud máxima

---

## ⏱️ TTL Guidelines

### Principios de TTL

1. **Más corto es más seguro** - Datos obsoletos son peor que cache misses
2. **Basado en frecuencia de cambio** - TTL debe reflejar volatilidad
3. **Considerar costo de regeneración** - Datos costosos = TTL más largo

### TTLs Recomendados por Tipo

| Tipo de Dato | TTL Recomendado | Justificación |
|--------------|-----------------|---------------|
| **MX Records** | 2-12 horas | Cambian raramente, DNS es lento |
| **Domain validation** | 1 hora | Resultados estables |
| **SMTP checks** | 5 minutos | Pueden cambiar, no muy costoso |
| **DNS TXT (SPF/DKIM)** | 1 hora | Actualizado infrecuentemente |
| **IP → ASN mapping** | 24 horas | Muy estable |
| **HIBP data** | 24 horas | Solo se agregan breaches nuevos |
| **Catch-all detection** | 24 horas | Configuración estable |
| **Rate limit counters** | 60 segundos | Debe reflejar ventanas precisas |
| **Plan configs** | 60 segundos | Puede cambiar en admin |
| **Provider stats** | 5 minutos | Agregaciones costosas |

### TTL por Tier (Cache Warming)

```python
Tier 1 (gmail, outlook): 2 horas   # Refresh cada 5 min
Tier 2 (protonmail):     3 horas   # Refresh cada 15 min
Tier 3 (regional):       6 horas   # Refresh cada 30 min
Tier 4 (enterprise):     12 horas  # Refresh cada 1 hora
```

---

## 📊 Monitoreo y Debugging

### Prometheus Metrics

```python
# Cache hits/misses por tipo
cache_hits_total{cache_type="mx"}
cache_misses_total{cache_type="mx"}

# Calcular hit ratio
sum(rate(cache_hits_total[5m])) / 
(sum(rate(cache_hits_total[5m])) + sum(rate(cache_misses_total[5m])))
```

### Cache Stats Endpoint

```bash
GET /metrics/cache-stats
```

Response:
```json
{
  "mx_cache": {
    "name": "mx",
    "size": 1523,
    "hits": 45234,
    "misses": 8765,
    "hit_ratio": 0.838
  },
  "redis_enabled": true,
  "cache_warming": {
    "total_warmed": 89,
    "total_failures": 2,
    "last_run": "2025-11-30T18:00:00Z"
  }
}
```

### Debugging Cache Issues

#### Ver keys en Redis
```bash
# Listar keys por patrón
redis-cli --scan --pattern "mx:*" | head -20

# Ver un key específico
redis-cli GET "mx:gmail.com"

# Ver TTL restante
redis-cli TTL "mx:gmail.com"
```

#### Ver stats en logs
```python
# Desde código
logger.info(f"MX Cache stats: {mx_cache.stats()}")
```

#### Limpiar cache
```python
# Limpiar prefijo específico
await async_cache_clear("mx:")

# Limpiar todo
await async_cache_clear()
```

---

## 🎓 Mejores Prácticas

### 1. Serialización

✅ **HACER**:
```python
# Convertir objetos a dicts antes de cachear
mx_records_serializable = [
    {"preference": mx.preference, "exchange": str(mx.exchange)} 
    for mx in mx_records
]
await cache.set(key, mx_records_serializable)
```

❌ **NO HACER**:
```python
# Cachear objetos directamente
await cache.set(key, mx_records)  # MXRecord not JSON serializable!
```

### 2. Key Building

✅ **HACER**:
```python
cache_key = UnifiedCache.build_key("mx", domain)
```

❌ **NO HACER**:
```python
cache_key = f"mx:{domain}"  # No sanitizado
```

### 3. Error Handling

```python
# Siempre tener fallback
try:
    cached = await UnifiedCache.get(key)
    if cached:
        return cached
except RedisError as e:
    logger.warning(f"Redis error: {e}")
    # Continuar sin cache

# L1 fallback
return await mx_cache.get(key)
```

### 4. TTL por Contexto

```python
# TTL dinámico basado en contexto
if is_premium_user:
    ttl = 3600  # Premium: cache 1h
else:
    ttl = 300   # Free: cache 5min

await cache.set(key, value, ttl=ttl)
```

### 5. Cache Invalidation

```python
# Invalidar cuando datos cambian
async def update_mx_records(domain: str, new_records):
    # Update source
    await db.update_mx_records(domain, new_records)
    
    # Invalidate cache
    cache_key = UnifiedCache.build_key("mx", domain)
    await UnifiedCache.delete(cache_key)
```

### 6. Warmed Cache en Startup

```python
# main.py startup
@app.on_event("startup")
async def startup():
    await start_cache_warming()  # Pre-populate caches
```

### 7. Monitorear Hit Ratios

Target hit ratios:
- **MX cache**: >85% (con warming)
- **Domain cache**: >70%  
- **SMTP cache**: >50% (más volátil)

Si hit ratio <target, ajustar TTL o warming strategy.

---

## 🔄 Evolución del Sistema

### Historia de Cambios

**2025-11-30**: Phase 11 - Consolidación y Optimización
- Consolidado TTLCache → AsyncTTLCache
- Estandarizado cache key building (6 ubicaciones)
- Añadido stats/metrics a AsyncTTLCache
- Fixed MXRecord serialization

**2025-11-28**: Phase 9 - Circuit Breaker & Unified Cache
- Implementado UnifiedCache para Redis
- Implementado layered caching (L1 + L2)
- Migrado validation.py y providers.py

**2024**: Initial Implementation
- AsyncTTLCache para in-memory caching
- Cache warming para MX records populares

---

## 📚 Referencias

- [cache/__init__.py](file:///Users/pablo/Desktop/toni/app/cache/__init__.py) - AsyncTTLCache
- [cache/unified_cache.py](file:///Users/pablo/Desktop/toni/app/cache/unified_cache.py) - UnifiedCache
- [cache_warming.py](file:///Users/pablo/Desktop/toni/app/cache_warming.py) - CacheWarmer
- [asgi_middleware.py](file:///Users/pablo/Desktop/toni/app/asgi_middleware.py) - ResponseCacheASGI
- [Redis Best Practices](https://redis.io/docs/manual/patterns/)
- [TTL Guidelines](https://aws.amazon.com/caching/best-practices/)

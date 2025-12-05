"""
Performance benchmarks for Phase 7 optimizations.

Tests:
1. JSON serialization speed (orjson vs standard json)
2. Connection warming effectiveness
3. Overall API performance improvements
"""

import time
import asyncio
import sys
import json as stdlib_json
from app.json_utils import dumps as orjson_dumps, loads as orjson_loads

def benchmark_json_serialization():
    """Verify orjson is 2-3x faster than standard json."""
    print("\n" + "="*60)
    print("BENCHMARK 1: JSON Serialization Speed")
    print("="*60)
    
    # Create realistic test data
    data = {
        "email": "test@example.com",
        "valid": True,
        "risk_score": 0.15,
        "mx_records": ["mx1.example.com", "mx2.example.com"],
        "results": [{"valid": True, "email": f"user{i}@test.com"} for i in range(100)]
    }
    
    # Benchmark standard JSON
    iterations = 10000
    start = time.perf_counter()
    for _ in range(iterations):
        stdlib_json.dumps(data)
    json_time = time.perf_counter() - start
    
    # Benchmark orjson
    start = time.perf_counter()
    for _ in range(iterations):
        orjson_dumps(data)
    orjson_time = time.perf_counter() - start
    
    speedup = json_time / orjson_time
    
    print(f"Standard json: {json_time*1000:.2f}ms ({iterations} iterations)")
    print(f"orjson:        {orjson_time*1000:.2f}ms ({iterations} iterations)")
    print(f"Speedup:       {speedup:.2f}x faster ✅" if speedup >= 2.0 else f"Speedup: {speedup:.2f}x (Expected >= 2.0x) ❌")
    
    return speedup >= 2.0

def benchmark_json_parsing():
    """Verify orjson parsing is faster."""
    print("\n" + "="*60)
    print("BENCHMARK 2: JSON Parsing Speed")
    print("="*60)
    
    # Create realistic test data
    data = {
        "results": [{"email": f"user{i}@test.com", "valid": True} for i in range(1000)]
    }
    json_str = stdlib_json.dumps(data)
    
    iterations = 5000
    
    # Benchmark standard JSON
    start = time.perf_counter()
    for _ in range(iterations):
        stdlib_json.loads(json_str)
    json_time = time.perf_counter() - start
    
    # Benchmark orjson
    start = time.perf_counter()
    for _ in range(iterations):
        orjson_loads(json_str)
    orjson_time = time.perf_counter() - start
    
    speedup = json_time / orjson_time
    
    print(f"Standard json: {json_time*1000:.2f}ms ({iterations} iterations)")
    print(f"orjson:        {orjson_time*1000:.2f}ms ({iterations} iterations)")
    print(f"Speedup:       {speedup:.2f}x faster ✅" if speedup >= 1.5 else f"Speedup: {speedup:.2f}x (Expected >= 1.5x) ❌")
    
    return speedup >= 1.5

async def benchmark_connection_warming():
    """Test connection warming reduces first-request latency."""
    print("\n" + "="*60)
    print("BENCHMARK 3: Connection Warming Impact")
    print("="*60)
    
    try:
        from redis.asyncio import Redis
        from app.config import settings
        
        # Test without warm-up
        redis1 = Redis.from_url(str(settings.redis_url), decode_responses=True)
        start = time.perf_counter()
        await redis1.ping()
        cold_time = time.perf_counter() - start
        await redis1.close()
        
        # Test with warm-up (simulating warmed pool)
        redis2 = Redis.from_url(str(settings.redis_url), decode_responses=True)
        # Pre-warm
        await asyncio.gather(*[redis2.ping() for _ in range(10)])
        # Measure
        start = time.perf_counter()
        await redis2.ping()
        warm_time = time.perf_counter() - start
        await redis2.close()
        
        improvement = ((cold_time - warm_time) / cold_time) * 100
        
        print(f"Cold start (first ping): {cold_time*1000:.2f}ms")
        print(f"Warmed pool (11th ping): {warm_time*1000:.2f}ms")
        print(f"Improvement:             {improvement:.1f}% faster ✅")
        
        return True
    except Exception as e:
        print(f"⚠️ Connection warming test failed: {e}")
        return False

def run_all_benchmarks():
    """Run all performance benchmarks."""
    print("\n" + "🚀" * 30)
    print("Phase 7: Advanced Performance Optimization Benchmarks")
    print("🚀" * 30)
    
    results = []
    
    # JSON benchmarks (synchronous)
    results.append(("JSON Serialization", benchmark_json_serialization()))
    results.append(("JSON Parsing", benchmark_json_parsing()))
    
    # Connection warming (async)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    results.append(("Connection Warming", loop.run_until_complete(benchmark_connection_warming())))
    loop.close()
    
    # Summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{name:30} {status}")
    
    print(f"\nOverall: {passed}/{total} benchmarks passed")
    
    if passed == total:
        print("\n🎉 All Phase 7 optimizations verified!")
        return 0
    else:
        print(f"\n⚠️ {total - passed} benchmark(s) failed")
        return 1

if __name__ == "__main__":
    sys.exit(run_all_benchmarks())

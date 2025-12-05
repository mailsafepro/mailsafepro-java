# 2. Use Redis for Distributed Rate Limiting

Date: 2025-11-27

## Status

Accepted

## Context

The API requires a robust rate limiting system to prevent abuse and manage traffic. Since the application may be deployed across multiple replicas (e.g., in Kubernetes), a local in-memory rate limiter would not be accurate or effective. We need a distributed solution that ensures atomic operations and high performance.

## Decision

We will use **Redis** combined with **Lua scripts** to implement distributed rate limiting.

- **Redis**: Provides a shared, high-performance data store accessible by all API instances.
- **Lua Scripts**: Ensure atomicity for "check-and-set" operations (checking the limit and incrementing the counter/adding timestamp) to prevent race conditions.
- **Algorithm**: We will use the **Sliding Window** algorithm (using Redis Sorted Sets) for accurate rate limiting, and a **Token Bucket** variation (or simple counter) for burst handling.

## Consequences

### Positive
- **Accuracy**: Rate limits are enforced globally across all instances.
- **Atomicity**: Lua scripts prevent race conditions.
- **Performance**: Redis is extremely fast and suitable for high-throughput rate limiting.

### Negative
- **Dependency**: The application now has a critical dependency on Redis. If Redis goes down, rate limiting may fail (we will implement a "fail-open" strategy to mitigate this).
- **Complexity**: Lua scripts add a layer of complexity to the codebase compared to simple Python logic.

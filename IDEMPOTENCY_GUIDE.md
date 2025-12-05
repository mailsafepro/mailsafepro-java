# Phase 8: Idempotency Keys — Quick Integration Guide

## Overview
Idempotency feature is now available via decorator. Simply add `@with_idempotency` to any POST endpoint.

## Usage

### 1. Import the decorator
```python
from app.idempotency_decorator import with_idempotency
```

### 2. Add to endpoints
```python
@router.post("/validate")
@with_idempotency  # ← Add this line
async def validate_email(
    request: Request,
    redis: Redis = Depends(get_redis),
    ...
):
    # Your existing code - no changes needed!
    pass
```

### 3. Client Usage
```bash
# Without idempotency (normal request)
curl -X POST https://api.mailsafepro.com/validate \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com"}'

# With idempotency (prevents duplicates)
curl -X POST https://api.mailsafepro.com/validate \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: 550e8400-e29b-41d4-a716-446655440000" \
  -d '{"email": "test@example.com"}'

# Retry with same key → Returns cached response
curl -X POST https://api.mailsafepro.com/validate \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: 550e8400-e29b-41d4-a716-446655440000" \
  -d '{"email": "test@example.com"}'
# Response headers: X-Idempotent-Replay: true
```

## Features
- ✅ 24-hour replay window
- ✅ Request body validation (prevents key reuse with different body)
- ✅ Automatic caching of successful responses (2xx)
- ✅ RFC-compliant implementation
- ✅ Zero code changes to existing endpoints
- ✅ Backward compatible (works without header)

## Recommended Endpoints
Add `@with_idempotency` to:
- `/validate` or `/email` (single validation)
- `/validate/batch` (batch validation)
- Any POST endpoint that creates/modifies data

## Testing
```python
# tests/test_idempotency.py already created with tests
pytest tests/test_idempotency.py -v
```

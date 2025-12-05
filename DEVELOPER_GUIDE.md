# MailSafePro API - Developer Documentation

> **Professional Email Validation API** - Enterprise-grade infrastructure with sub-100ms response times

[![CI/CD](https://img.shields.io/badge/CI%2FCD-Automated-success)](.)
[![Coverage](https://img.shields.io/badge/Coverage-85%25-brightgreen)](.)
[![Uptime](https://img.shields.io/badge/Uptime-99.9%25-blue)](.)
[![Response Time](https://img.shields.io/badge/Response%20Time-%3C100ms-green)](.)

---

## Table of Contents

- [Quick Start](#quick-start)
- [Authentication](#authentication)
- [API Reference](#api-reference)
- [Rate Limits](#rate-limits)
- [Webhooks](#webhooks)
- [SDKs & Libraries](#sdks--libraries)
- [Error Handling](#error-handling)
- [Testing](#testing)
- [Deployment](#deployment)
- [Performance](#performance)

---

## Quick Start

### 1. Get Your API Key

```bash
curl -X POST https://api.mailsafepro.com/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "your@email.com",
    "password": "SecurePassword123!",
    "plan": "FREE"
  }'
```

### 2. Validate an Email

```bash
curl -X POST https://api.mailsafepro.com/v1/validate-email \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'
```

### 3. Get Results

```json
{
  "valid": true,
  "email": "user@example.com",
  "domain": "example.com",
  "mx_host": "mx.example.com",
  "smtp_verified": true,
  "disposable": false,
  "free_provider": false,
  "risk_score": 5,
  "response_time_ms": 87
}
```

---

## Authentication

### JWT Tokens (Recommended)

```python
import requests

# Login to get token
response = requests.post(
    "https://api.mailsafepro.com/auth/login",
    data={"username": "your@email.com", "password": "your_password"}
)
token = response.json()["access_token"]

# Use token in requests
headers = {"Authorization": f"Bearer {token}"}
result = requests.post(
    "https://api.mailsafepro.com/v1/validate-email",
    headers=headers,
    json={"email": "test@example.com"}
)
```

### API Keys

```python
# Alternative: Use API key directly
headers = {"X-API-Key": "your_api_key_here"}
result = requests.post(
    "https://api.mailsafepro.com/v1/validate-email",
    headers=headers,
    json={"email": "test@example.com"}
)
```

---

## API Reference

### Validate Single Email

**`POST /v1/validate-email`**

Validate a single email address with comprehensive checks.

#### Request

```json
{
  "email": "user@example.com",
  "check_smtp": true,  // Optional: verify via SMTP (slower)
  "timeout": 10        // Optional: timeout in seconds
}
```

#### Response

```json
{
  "valid": true,
  "email": "user@example.com",
  "domain": "example.com",
  "provider": "google",
  "mx_host": "gmail-smtp-in.l.google.com",
  "smtp_verified": true,
  "smtp_response": "250 OK",
  "disposable": false,
  "free_provider": true,
  "role_based": false,
  "risk_score": 10,
  "details": {
    "syntax_valid": true,
    "domain_exists": true,
    "mx_records_found": true,
    "spf_record": "v=spf1 include:_spf.google.com ~all"
  },
  "metadata": {
    "cache_hit": true,
    "response_time_ms": 87,
    "timestamp": "2025-01-15T10:30:00Z"
  }
}
```

---

### Batch Validation

**`POST /v1/validate-batch`**

Validate multiple emails in one request (PREMIUM & ENTERPRISE only).

#### Request

```json
{
  "emails": [
    "user1@example.com",
    "user2@example.com",
    "user3@example.com"
  ],
  "check_smtp": false,
  "parallel": true
}
```

#### Response

```json
{
  "total": 3,
  "valid_count": 2,
  "invalid_count": 1,
  "results": [
    {"email": "user1@example.com", "valid": true, "risk_score": 5},
    {"email": "user2@example.com", "valid": true, "risk_score": 8},
    {"email": "user3@example.com", "valid": false, "error": "Domain not found"}
  ],
  "processing_time_ms": 234
}
```

---

### Create Batch Job

**`POST /v1/jobs`**

Create an asynchronous batch validation job for large lists (PREMIUM & ENTERPRISE).

#### Request

```json
{
  "emails": ["email1@test.com", "email2@test.com", ...],  // Max 10,000
  "webhook_url": "https://yourdomain.com/webhook",  // Optional
  "metadata": {
    "campaign_id": "summer-2025",
    "source": "signup-form"
  }
}
```

#### Response

```json
{
  "job_id": "job_abc123",
  "status": "queued",
  "total_emails": 10000,
  "estimated_completion_seconds": 120,
  "webhook_url": "https://yourdomain.com/webhook"
}
```

---

## Rate Limits

Rate limits vary by plan tier:

| Plan | Requests/Min | Requests/Day | Burst |
|------|--------------|--------------|-------|
| **FREE** | 100 | 10,000 | 150 |
| **PREMIUM** | 1,000 | 100,000 | 1,500 |
| **ENTERPRISE** | 10,000 | 1,000,000+ | Custom |

### Rate Limit Headers

Every response includes rate limit information:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 987
X-RateLimit-Reset: 1642521600
Retry-After: 45
```

### Handling Rate Limits

```python
import time

def validate_with_retry(email, max_retries=3):
    for attempt in range(max_retries):
        response = requests.post(url, json={"email": email})
        
        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", 60))
            print(f"Rate limited. Waiting {retry_after}s...")
            time.sleep(retry_after)
            continue
        
        return response.json()
    
    raise Exception("Max retries exceeded")
```

---

## Webhooks

Configure webhooks to receive notifications for batch job completion.

### Event Types

- `job.completed` - Batch job finished successfully
- `job.failed` - Batch job failed
- `plan.upgraded` - User upgraded plan
- `quota.exceeded` - Monthly quota reached

### Webhook Payload

```json
{
  "event": "job.completed",
  "job_id": "job_abc123",
  "status": "completed",
  "results_url": "https://api.mailsafepro.com/v1/jobs/job_abc123/results",
  "summary": {
    "total": 10000,
    "valid": 8543,
    "invalid": 1457
  },
  "timestamp": "2025-01-15T10:45:00Z"
}
```

### Webhook Verification

```python
import hmac
import hashlib

def verify_webhook(payload, signature, secret):
    expected = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(signature, expected)
```

---

## SDKs & Libraries

### Official SDKs

- **Python**: `pip install mailsafepro`
- **Node.js**: `npm install @mailsafepro/sdk`
- **PHP**: `composer require mailsafepro/php-sdk`
- **Go**: `go get github.com/mailsafepro/go-sdk`

### Python Example

```python
from mailsafepro import MailSafePro

client = MailSafePro(api_key="your_api_key")

# Single validation
result = client.validate("user@example.com")
print(f"Valid: {result.valid}, Risk: {result.risk_score}")

# Batch validation
results = client.validate_batch([
    "user1@example.com",
    "user2@example.com"
])
```

---

## Error Handling

### Error Response Format

```json
{
  "error": {
    "type": "validation_error",
    "message": "Invalid email format",
    "code": "INVALID_EMAIL_FORMAT",
    "details": {
      "email": "not-an-email",
      "issue": "Missing @ symbol"
    }
  }
}
```

### Common Error Codes

| Code | HTTP | Description | Action |
|------|------|-------------|--------|
| `INVALID_EMAIL_FORMAT` | 422 | Email format invalid | Fix email format |
| `DOMAIN_NOT_FOUND` | 404 | Domain doesn't exist | Verify domain |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests | Wait and retry |
| `UNAUTHORIZED` | 401 | Invalid/missing auth | Check API key |
| `QUOTA_EXCEEDED` | 403 | Monthly quota reached | Upgrade plan |
| `INTERNAL_ERROR` | 500 | Server error | Retry later |

### Retry Strategy

```python
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10)
)
def validate_email(email):
    response = requests.post(url, json={"email": email})
    response.raise_for_status()
    return response.json()
```

---

## Testing

### Test Mode

Use test API keys for development:

```python
# Test API key (prefix: test_)
client = MailSafePro(api_key="test_abc123...")

# Always returns predictable results
result = client.validate("test@example.com")
# {valid: true, risk_score: 5, disposable: false}
```

###Test Email Addresses

| Email | Result |
|-------|--------|
| `valid@example.com` | Always valid |
| `invalid@example.com` | Always invalid |
| `disposable@example.com` | Marked as disposable |
| `risky@example.com` | High risk score |

---

## Deployment

### Docker

```bash
docker pull mailsafepro/api:latest
docker run -p 8000:8000 \
  -e REDIS_URL=redis://localhost:6379 \
  -e JWT_SECRET_KEY=your_secret \
  mailsafepro/api:latest
```

### Kubernetes

```bash
kubectl apply -f k8s/deployment.yaml
kubectl get pods -n mailsafepro
```

### Health Checks

- **Liveness**: `GET /health/live`
- **Readiness**: `GET /health/ready`
- **Detailed**: `GET /health/detailed`

---

## Performance

### Response Times

| Tier | Avg Response | 95th Percentile | Cache Hit |
|------|--------------|-----------------|-----------|
| **Tier 1** (Gmail, Outlook) | 45ms | 87ms | 95% |
| **Tier 2** (Yahoo, ProtonMail) | 120ms | 245ms | 75% |
| **Tier 3** (Others) | 350ms | 890ms | 45% |

### Optimization Tips

1. ✅ **Enable caching**: Reuse results for 24h
2. ✅ **Batch requests**: Use batch API for multiple emails
3. ✅ **Disable SMTP**: Skip for faster results (domain-only validation)
4. ✅ **Use webhooks**: For large batch jobs

---

## Support

- 📧 Email: support@mailsafepro.com
- 💬 Discord: [discord.gg/mailsafepro](https://discord.gg/mailsafepro)
- 📚 Docs: [docs.mailsafepro.com](https://docs.mailsafepro.com)
- 🐛 Issues: [github.com/mailsafepro/api/issues](https://github.com/mailsafepro/api/issues)

---

## Changelog

See [CHANGELOG.md](./CHANGELOG.md) for version history.

## License

Proprietary. See LICENSE file for details.

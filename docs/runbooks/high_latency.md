# Runbook: High API Latency

## Trigger
Alert: `HighLatency`
Severity: **Warning**
Threshold: p99 > 1.0s for 5 minutes

## Impact
Slow user experience. Potential timeouts in client applications.

## Diagnosis Steps

1. **Identify Slow Endpoints**
   - Check metrics to see which endpoint is slow.
   ```promql
   topk(5, sum(rate(http_request_duration_seconds_sum[5m])) by (path) / sum(rate(http_request_duration_seconds_count[5m])) by (path))
   ```

2. **Check Resource Usage**
   - **CPU**: Is the pod throttled?
   - **Memory**: Is there high GC activity or swapping?

3. **Check Dependencies**
   - **Redis**: Is Redis slow? Check `redis_command_duration_seconds`.
   - **DNS/SMTP**: Are external checks timing out?

## Mitigation Steps

1. **Scale Up**
   - Increase number of replicas to distribute load.
   ```bash
   kubectl scale deployment mailsafepro-api --replicas=5
   ```

2. **Clear Cache**
   - If specific cache keys are causing issues (e.g., hot keys), consider clearing them.
   - *Warning*: This might cause a spike in backend load.

3. **Enable Aggressive Rate Limiting**
   - If under attack, lower rate limits for suspicious IPs.

## Escalation
If latency persists > 2s or affects > 10% of users, escalate to **On-Call Engineer**.

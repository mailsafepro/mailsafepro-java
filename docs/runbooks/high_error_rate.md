# Runbook: High API Error Rate

## Trigger
Alert: `HighErrorRate`
Severity: **Critical**
Threshold: > 1% 5xx errors for 2 minutes

## Impact
Users are experiencing failed requests. API reliability is compromised.

## Diagnosis Steps

1. **Check Logs**
   - Access logs via Kibana/Grafana/CLI.
   - Filter for `status=500`.
   - Look for stack traces or error messages.
   ```bash
   # If using local logs
   grep " 500 " app.log | tail -n 20
   ```

2. **Check Dependencies**
   - **Redis**: Is it up? Check `RedisDown` alert.
   - **Database**: Is the DB accessible?
   - **External APIs**: Are DNS/SMTP checks failing?

3. **Check Recent Deployments**
   - Was code deployed recently?
   - Check git history or deployment logs.

## Mitigation Steps

1. **Rollback**
   - If a recent deployment caused the issue, rollback immediately.
   ```bash
   kubectl rollout undo deployment/mailsafepro-api
   ```

2. **Enable Circuit Breakers**
   - If a specific dependency (e.g., SMTP) is failing, ensure circuit breakers are open.
   - Force open if necessary (via admin panel if available).

3. **Scale Up**
   - If CPU/Memory is saturated (check `HighCpuUsage` alert), scale up pods.
   ```bash
   kubectl scale deployment mailsafepro-api --replicas=5
   ```

## Escalation
If unable to resolve within 15 minutes, escalate to:
- **On-Call Engineer**: [Phone Number]
- **Tech Lead**: [Name]

#!/usr/bin/env bash
set -euo pipefail

wait_ready() { local url="$1"; local tries=60; for i in $(seq 1 $tries); do curl -fsS "$url" >/dev/null && return 0 || sleep 2; done; echo "Timeout $url"; exit 1; }

wait_ready http://localhost:9090/-/ready
wait_ready http://localhost:3000/api/health

# Registro con email válido (evitar .local)
REG_JSON="$(curl -fsS -X POST http://127.0.0.1:8000/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"ci@testexample.com","password":"TestPassw0rd!","plan":"PREMIUM"}' || true)"

# Si el usuario ya existe, intenta login para obtener token y api_key si tu API lo devuelve; si no, reintenta un segundo email
if ! printf '%s' "$REG_JSON" | jq -e '.api_key' >/dev/null 2>&1; then
  # Intento 2: otro email válido
  REG_JSON="$(curl -fsS -X POST http://127.0.0.1:8000/auth/register \
    -H 'Content-Type: application/json' \
    -d '{"email":"ci2@testexample.com","password":"TestPassw0rd!","plan":"PREMIUM"}')"
fi

API_KEY="$(printf '%s' "$REG_JSON" | jq -r '.api_key')"
[ -n "$API_KEY" ] || { echo "Register failed or missing api_key: $REG_JSON"; exit 1; }

# Genera carga: 50 jobs * 3 emails = 150 validaciones
for i in $(seq 1 50); do
  curl -fsS -X POST http://127.0.0.1:8000/v1/jobs \
    -H 'Content-Type: application/json' \
    -H "X-API-Key: $API_KEY" \
    -d '{"source":"list","emails":["a@ex.com","b@ex.com","c@ex.com"],"sandbox":true,"plan":"FREE"}' >/dev/null
done

sleep 10

# Consultas clave: throughput, p99 y ratio unknown
Q1='sum(rate(email_validation_business_validations_total[5m]))'
Q2='histogram_quantile(0.99, sum by (le) (rate(email_validation_business_validation_duration_seconds_bucket[5m])))'
Q3='(sum(rate(email_validation_business_validations_total{result="unknown"}[10m])) OR on() vector(0)) / clamp_min((sum(rate(email_validation_business_validations_total[10m])) OR on() vector(0)), 1e-9)'

for q in "$Q1" "$Q2" "$Q3"; do
  v=$(curl -fsS -G 'http://localhost:9090/api/v1/query' --data-urlencode "query=$q" | jq -r '.data.result[0].value[1] // empty')
  [ -n "$v" ] || { echo "Empty PromQL: $q"; exit 1; }
done

# Alerta sintética para verificar pipeline de alertas
curl -fsS -X POST 'http://localhost:9093/api/v2/alerts' -H 'Content-Type: application/json' -d '[
  {"labels":{"alertname":"SyntheticE2E","service":"email-api","severity":"info"},
   "annotations":{"summary":"obs e2e"},
   "startsAt":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}]' >/dev/null

echo "obs e2e OK"

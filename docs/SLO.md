# SLOs Email API

- SLI latencia p99 de validación: p99 ≤ 5 s (objetivo mensual 99.9%). Panel: Validation p99 (s).
- SLI ratio unknown: ≤ 0.1% (objetivo mensual 99.9%). Panel: Ratio unknown (10m).
- Presupuesto de error mensual: 0.1%.
- Burn rate:
  - Rápido (5m): alert warning si avg_over_time(slo:validation_latency_p99_gt5s:bool[5m]) > 0.02 por 5m.
  - Lento (1h): alert critical si avg_over_time(slo:validation_latency_p99_gt5s:bool[1h]) > 0.01 por 30m.
- Runbook: verificar backlog, latencias por instancia, panel Workers y “Alertas activas”.

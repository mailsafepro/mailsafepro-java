# AUDIT – MailSafePro Email Validation API

## Resumen ejecutivo
- Estado: **Early-stage avanzado**, con controles de seguridad/observabilidad presentes (rate limiting global, JWT/API Keys estrictos, métricas Prometheus, middlewares ASGI), pero con riesgos pendientes.  
- Se detectan **secretos reales en el repositorio** (`.env`, `.env.bak`), lo que expone Stripe y SMTP.  
- Prioridad principal: retirar/rotar secretos y evitar carga de `.env` en producción.

## Hallazgos por áreas

### 1) Seguridad – Secretos expuestos en el repo (**Critical**)
- **Evidencia**: Stripe y credenciales SMTP en texto plano @/.env#15-33, @/.env.bak#6-23.  
- **Riesgo**: uso fraudulento de pagos y envío de spam; compromiso total.  
- **Reproducción**: `sed -n '1,40p' .env` muestra `STRIPE_SECRET_KEY`, `SMTP_PASSWORD`.  
- **Test propuesto (pytest)**: `audit-tests/test_secrets_guard.py` (comprueba que en prod no se cargue `.env`).  
- **Corrección** (mínimo viable): no cargar `.env` en producción.  
  ```diff
  # app/main.py
  - load_dotenv()
  + if os.getenv("ENVIRONMENT", "").lower() != "production":
  +     load_dotenv()
  ```
  Acciones obligatorias: rotar todas las claves vistas, borrar `.env`/`.env.bak` del repo e historial, usar secret manager.
- **Verificación**: `ENVIRONMENT=production pytest -q audit-tests/test_secrets_guard.py::test_dotenv_not_loaded_in_production`.

## Comandos de verificación recomendados
1) Seguridad estática: `bandit -q -r app -o bandit_report_latest.json`  
2) Dependencias: `pip-audit -r requirements.txt`  
3) Tests focalizados: `pytest -q audit-tests/test_secrets_guard.py`

## Roadmap priorizado
| Acción | Impacto en riesgo | Criterio mínimo de aceptación |
| --- | --- | --- |
| Rotar/retirar secretos y bloquear carga de `.env` en prod | High | Claves rotadas, `.env`/`.env.bak` fuera del repo/historial, arranque en prod falla si intenta leer `.env`, test `test_secrets_guard` pasa |

## Archivos/patches a entregar
- `audit-patches/001-avoid-loading-dotenv-in-prod.patch`
- Tests propuestos en `audit-tests/` (ver sección de hallazgos).

## Riesgos residuales
- Dependencia de Redis para rate limiting/cuotas: definir `redis_required=True` en prod o fail-closed.  
- Superficie de latencia/DoS en SMTP/DNS externos: monitorizar métricas y ajustar timeouts/backoff.  
- Historial git con secretos: debe purgarse incluso tras borrar archivos.

"""
metrics.py — versión corregida y endurecida

Objetivos:
- Nombres de métricas sin doble prefijo; usar namespace/subsystem del cliente Prometheus.
- Endpoint /metrics compatible con multiproceso (Gunicorn) usando CollectorRegistry por request.
- Control de cardinalidad: evitar user_id como etiqueta; usar plan/segmento agregados.
- Histogramas con buckets coherentes para latencia y tamaños; sincrónicos con Instrumentator.
- Sin acceso a response.body para tamaño; usar Content-Length cuando esté presente.
"""

from __future__ import annotations

import time
import logging
import os
from contextlib import asynccontextmanager
from functools import wraps
from typing import Dict, Any, Optional, Callable, Tuple

from fastapi import FastAPI, Response, Depends, Request
from fastapi.responses import Response as StarletteResponse
from prometheus_client import (
    Counter,
    Histogram,
    Gauge,
    generate_latest,
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    REGISTRY,
)
from prometheus_fastapi_instrumentator import Instrumentator, metrics

from app.auth import validate_api_key
from app.config import get_settings

# Configuración
settings = get_settings()
logger = logging.getLogger(__name__)

# Espacios de nombres (se aplican como parámetros, no en los nombres)
METRIC_NAMESPACE = "email_validation"
METRIC_SUBSYSTEM_API = "api"
METRIC_SUBSYSTEM_BUSINESS = "business"
METRIC_SUBSYSTEM_SMTP = "smtp"
METRIC_SUBSYSTEM_CACHE = "cache"
METRIC_SUBSYSTEM_SYSTEM = "system"
METRIC_SUBSYSTEM_WEBHOOKS = "webhooks"

# Buckets de histogramas
LATENCY_BUCKETS = (0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 10.0)
VALIDATION_BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5)
SIZE_BUCKETS = (100, 1000, 10_000, 50_000, 100_000, 500_000, 1_000_000, 5_000_000)

# Utilidad para obtener registry adecuado (multiproceso o no)
def get_export_registry() -> CollectorRegistry:
    """
    Devuelve un CollectorRegistry apropiado para exportación de métricas.
    - Si PROMETHEUS_MULTIPROC_DIR está definido: crear un registry por request y acoplar MultiProcessCollector.
    - Si no: usar REGISTRY global.
    """
    try:
        from prometheus_client import multiprocess  # import local para evitar coste si no se usa
    except Exception:
        multiprocess = None  # type: ignore

    if multiprocess and os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
        return registry
    # Fallback: single-process registry global
    return REGISTRY  # type: ignore[return-value]


class MetricsManager:
    """Gestor centralizado de métricas."""

    def __init__(self) -> None:
        # Nota: las métricas se registran en el registry por defecto del cliente
        # El endpoint de exportación decidirá qué registry exponer.
        self._initialize_metrics()

    def _initialize_metrics(self) -> None:
        """Define todas las métricas con etiquetas y documentación adecuadas."""
        # HTTP
        self.requests_total = Counter(
            "http_requests_total",
            "Total number of HTTP requests",
            ["method", "endpoint", "status_code", "client_plan"],
            namespace=METRIC_NAMESPACE,
            subsystem=METRIC_SUBSYSTEM_API,
        )
        self.request_duration = Histogram(
            "http_request_duration_seconds",
            "HTTP request duration in seconds",
            ["method", "endpoint", "status_code"],
            buckets=LATENCY_BUCKETS,
            namespace=METRIC_NAMESPACE,
            subsystem=METRIC_SUBSYSTEM_API,
        )
        self.request_size_bytes = Histogram(
            "http_request_size_bytes",
            "HTTP request size in bytes",
            ["method", "endpoint"],
            buckets=SIZE_BUCKETS,
            namespace=METRIC_NAMESPACE,
            subsystem=METRIC_SUBSYSTEM_API,
        )
        self.response_size_bytes = Histogram(
            "http_response_size_bytes",
            "HTTP response size in bytes",
            ["method", "endpoint", "status_code"],
            buckets=SIZE_BUCKETS,
            namespace=METRIC_NAMESPACE,
            subsystem=METRIC_SUBSYSTEM_API,
        )

        # Negocio
        self.validations_total = Counter(
            "validations_total",
            "Total email validation requests",
            ["validation_type", "result", "client_plan"],
            namespace=METRIC_NAMESPACE,
            subsystem=METRIC_SUBSYSTEM_BUSINESS,
        )
        self.validation_duration = Histogram(
            "validation_duration_seconds",
            "Email validation processing time",
            ["validation_type", "result"],
            buckets=VALIDATION_BUCKETS,
            namespace=METRIC_NAMESPACE,
            subsystem=METRIC_SUBSYSTEM_BUSINESS,
        )

        # SMTP
        self.smtp_checks_total = Counter(
            "smtp_checks_total",
            "Total SMTP verification attempts",
            ["status", "mx_host_group"],
            namespace=METRIC_NAMESPACE,
            subsystem=METRIC_SUBSYSTEM_SMTP,
        )
        self.smtp_check_duration = Histogram(
            "smtp_check_duration_seconds",
            "SMTP verification duration",
            ["status"],
            buckets=LATENCY_BUCKETS,
            namespace=METRIC_NAMESPACE,
            subsystem=METRIC_SUBSYSTEM_SMTP,
        )

        # Cache
        self.cache_operations_total = Counter(
            "cache_operations_total",
            "Total cache operations",
            ["operation", "cache_type", "result"],
            namespace=METRIC_NAMESPACE,
            subsystem=METRIC_SUBSYSTEM_CACHE,
        )
        self.cache_hit_ratio = Gauge(
            "cache_hit_ratio",
            "Cache hit ratio",
            ["cache_type"],
            namespace=METRIC_NAMESPACE,
            subsystem=METRIC_SUBSYSTEM_CACHE,
        )

        # Sistema
        self.active_connections = Gauge(
            "active_connections",
            "Number of active connections",
            ["service"],
            namespace=METRIC_NAMESPACE,
            subsystem=METRIC_SUBSYSTEM_SYSTEM,
        )
        self.error_total = Counter(
            "errors_total",
            "Total errors by type",
            ["error_type", "severity", "component"],
            namespace=METRIC_NAMESPACE,
            subsystem=METRIC_SUBSYSTEM_SYSTEM,
        )

        # Concurrencia de validaciones (sin user_id para evitar alta cardinalidad)
        self.concurrent_validations = Gauge(
            "concurrent_validations",
            "Number of concurrent validation processes",
            ["plan"],
            namespace=METRIC_NAMESPACE,
            subsystem=METRIC_SUBSYSTEM_BUSINESS,
        )

        # Uso de cuota (evitar user_id; usar plan o segmento de cliente)
        self.quota_usage = Gauge(
            "quota_usage_ratio",
            "Current quota usage ratio (0..1)",
            ["plan"],
            namespace=METRIC_NAMESPACE,
            subsystem=METRIC_SUBSYSTEM_BUSINESS,
        )

        # Jobs
        self.jobs_events_total = Counter(
            "jobs_events_total",
            "Total job events",
            ["event", "plan"],
            namespace=METRIC_NAMESPACE,
            subsystem=METRIC_SUBSYSTEM_BUSINESS,
        )
        self.job_duration_seconds = Histogram(
            "job_duration_seconds",
            "Job end-to-end processing time",
            ["plan"],
            buckets=LATENCY_BUCKETS,
            namespace=METRIC_NAMESPACE,
            subsystem=METRIC_SUBSYSTEM_BUSINESS,
        )
        self.job_queue_depth = Gauge(
            "job_queue_depth",
            "Current jobs queue depth",
            ["queue"],
            namespace=METRIC_NAMESPACE,
            subsystem=METRIC_SUBSYSTEM_BUSINESS,
        )

        # Webhooks
        self.webhook_deliveries_total = Counter(
            "webhook_deliveries_total",
            "Total webhook delivery attempts labeled by status class",
            ["status_class"],
            namespace=METRIC_NAMESPACE,
            subsystem=METRIC_SUBSYSTEM_WEBHOOKS,
        )
        self.webhook_delivery_duration = Histogram(
            "webhook_delivery_duration_seconds",
            "Webhook delivery duration in seconds",
            ["status_class"],
            buckets=LATENCY_BUCKETS,
            namespace=METRIC_NAMESPACE,
            subsystem=METRIC_SUBSYSTEM_WEBHOOKS,
        )
        self.webhook_retries_total = Counter(
            "webhook_retries_total",
            "Total webhook retries by reason",
            ["reason"],
            namespace=METRIC_NAMESPACE,
            subsystem=METRIC_SUBSYSTEM_WEBHOOKS,
        )


class MetricLabelNormalizer:
    """Normaliza y sanitiza etiquetas para Prometheus (evitando alta cardinalidad)."""

    HIGH_CARDINALITY_FIELDS = {"user_id", "email", "ip_address", "trace_id", "session_id"}
    FIELD_GROUPS = {
        "mx_host": lambda host: ".".join(host.split(".")[-2:]) if "." in host else "unknown",
        "error_type": lambda error: error.split(":")[0] if ":" in error else error,
        "endpoint": lambda ep: ep.split("/")[1] if "/" in ep and ep != "/" else ep or "root",
        "status_code": lambda sc: sc[0] + "xx" if sc.isdigit() and len(sc) == 3 else sc,
    }

    @classmethod
    def normalize_label(cls, label_name: str, value: Any) -> str:
        if value is None:
            return "unknown"
        normalized = str(value).strip().lower()
        if label_name in cls.FIELD_GROUPS:
            try:
                normalized = cls.FIELD_GROUPS[label_name](normalized)
            except Exception:
                normalized = "unknown"
        normalized = (
            normalized.replace(" ", "_")
            .replace("-", "_")
            .replace(".", "_")
            .replace(":", "_")
            .replace("/", "_")
            .replace("\\", "_")
            .replace("@", "_at_")
        )
        normalized = "_".join(filter(None, normalized.split("_")))[:64]
        return normalized or "unknown"

    @classmethod
    def should_include_label(cls, label_name: str, value: Any) -> bool:
        if label_name in cls.HIGH_CARDINALITY_FIELDS:
            logger.warning("High cardinality label '%s' detected - dropping", label_name)
            return False
        return value is not None


class SafeMetricsRecorder:
    """Registro seguro de métricas con validación de etiquetas y manejo de errores."""

    def __init__(self, metrics_manager: MetricsManager) -> None:
        self.metrics = metrics_manager
        self.normalizer = MetricLabelNormalizer()

    def record_http_request(
        self,
        method: str,
        endpoint: str,
        status_code: int,
        client_plan: str,
        duration: float,
        request_size: int = 0,
        response_size: int = 0,
    ) -> None:
        try:
            labels = {
                "method": self.normalizer.normalize_label("method", method),
                "endpoint": self.normalizer.normalize_label("endpoint", endpoint),
                "status_code": str(status_code),
                "client_plan": self.normalizer.normalize_label("client_plan", client_plan),
            }
            # Conteo
            self._safe_increment(self.metrics.requests_total, labels)
            # Duración
            self._safe_observe(
                self.metrics.request_duration,
                duration,
                {"method": labels["method"], "endpoint": labels["endpoint"], "status_code": labels["status_code"]},
            )
            # Tamaños
            if request_size > 0:
                self._safe_observe(
                    self.metrics.request_size_bytes,
                    float(request_size),
                    {"method": labels["method"], "endpoint": labels["endpoint"]},
                )
            if response_size > 0:
                self._safe_observe(
                    self.metrics.response_size_bytes,
                    float(response_size),
                    {"method": labels["method"], "endpoint": labels["endpoint"], "status_code": labels["status_code"]},
                )
        except Exception as e:
            logger.warning("Failed to record HTTP metrics: %s", e)

    def record_validation(self, validation_type: str, result: str, client_plan: str, duration: float) -> None:
        try:
            labels = {
                "validation_type": self.normalizer.normalize_label("validation_type", validation_type),
                "result": self.normalizer.normalize_label("result", result),
                "client_plan": self.normalizer.normalize_label("client_plan", client_plan),
            }
            self._safe_increment(self.metrics.validations_total, labels)
            self._safe_observe(
                self.metrics.validation_duration,
                duration,
                {"validation_type": labels["validation_type"], "result": labels["result"]},
            )
        except Exception as e:
            logger.warning("Failed to record validation metrics: %s", e)

    def record_smtp_check(self, status: str, mx_host: str, duration: float) -> None:
        try:
            mx_host_group = self.normalizer.normalize_label("mx_host", mx_host)
            self._safe_increment(
                self.metrics.smtp_checks_total,
                {"status": self.normalizer.normalize_label("status", status), "mx_host_group": mx_host_group},
            )
            self._safe_observe(
                self.metrics.smtp_check_duration,
                duration,
                {"status": self.normalizer.normalize_label("status", status)},
            )
        except Exception as e:
            logger.warning("Failed to record SMTP metrics: %s", e)

    def record_cache_operation(self, operation: str, cache_type: str, result: str) -> None:
        try:
            self._safe_increment(
                self.metrics.cache_operations_total,
                {
                    "operation": self.normalizer.normalize_label("operation", operation),
                    "cache_type": self.normalizer.normalize_label("cache_type", cache_type),
                    "result": self.normalizer.normalize_label("result", result),
                },
            )
        except Exception as e:
            logger.warning("Failed to record cache metrics: %s", e)

    def record_error(self, error_type: str, severity: str, component: str) -> None:
        try:
            self._safe_increment(
                self.metrics.error_total,
                {
                    "error_type": self.normalizer.normalize_label("error_type", error_type),
                    "severity": self.normalizer.normalize_label("severity", severity),
                    "component": self.normalizer.normalize_label("component", component),
                },
            )
        except Exception as e:
            logger.warning("Failed to record error metrics: %s", e)

    def _safe_increment(self, counter: Counter, labels: Dict[str, str]) -> None:
        try:
            label_names = getattr(counter, "_labelnames", [])
            filtered = {name: labels.get(name, "unknown") for name in label_names}
            counter.labels(**filtered).inc()
        except Exception as e:
            logger.warning("Failed to increment counter %s: %s", getattr(counter, "_name", "unknown"), e)

    def _safe_observe(self, histogram: Histogram, value: float, labels: Dict[str, str]) -> None:
        try:
            label_names = getattr(histogram, "_labelnames", [])
            filtered = {name: labels.get(name, "unknown") for name in label_names}
            histogram.labels(**filtered).observe(value)
        except Exception as e:
            logger.warning("Failed to observe histogram %s: %s", getattr(histogram, "_name", "unknown"), e)

    def record_job_event(self, plan: str, event: str) -> None:
        try:
            plan_norm = self.normalizer.normalize_label("client_plan", plan)
            event_norm = self.normalizer.normalize_label("event", event)
            self.metrics.jobs_events_total.labels(event=event_norm, plan=plan_norm).inc()
        except Exception as e:
            logger.warning("Failed to record job event: %s", e)

    def observe_job_duration(self, plan: str, seconds: float) -> None:
        try:
            plan_norm = self.normalizer.normalize_label("client_plan", plan)
            self.metrics.job_duration_seconds.labels(plan=plan_norm).observe(float(seconds))
        except Exception as e:
            logger.warning("Failed to observe job duration: %s", e)

    def set_job_queue_depth(self, queue: str, depth: int) -> None:
        try:
            q = self.normalizer.normalize_label("queue", queue)
            self.metrics.job_queue_depth.labels(queue=q).set(int(max(0, depth)))
        except Exception as e:
            logger.warning("Failed to set job queue depth: %s", e)

    def record_webhook_delivery(self, status_code: int, duration: float) -> None:
        try:
            # agrupa por clase 2xx/4xx/5xx
            sc = str(int(status_code))
            status_class = f"{sc[0]}xx" if len(sc) == 3 and sc.isdigit() else "other"
            self.metrics.webhook_deliveries_total.labels(status_class=status_class).inc()
            self.metrics.webhook_delivery_duration.labels(status_class=status_class).observe(float(duration))
        except Exception as e:
            logger.warning("Failed to record webhook delivery: %s", e)

    def record_webhook_retry(self, reason: str) -> None:
        try:
            r = self.normalizer.normalize_label("reason", reason)
            self.metrics.webhook_retries_total.labels(reason=r).inc()
        except Exception as e:
            logger.warning("Failed to record webhook retry: %s", e)


# ---- exporta utilidades de montaje ----
def mount_metrics_endpoint(app: FastAPI) -> None:
    @app.get("/metrics", include_in_schema=False)
    async def metrics_endpoint(request: Request):  # scraping sin auth
        try:
            registry = get_export_registry()
            data = generate_latest(registry)
            return Response(
                content=data,
                media_type=CONTENT_TYPE_LATEST,
                headers={
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                    "Pragma": "no-cache",
                    "Expires": "0",
                },
            )
        except Exception as e:
            logger.error("Metrics generation failed: %s", e)
            return Response(content=b"", status_code=500, media_type=CONTENT_TYPE_LATEST)


def instrument_app(app: FastAPI) -> None:
    instrumentator = Instrumentator(
        should_group_status_codes=False,
        should_ignore_untemplated=True,
        should_respect_env_var=True,
        should_instrument_requests_inprogress=True,
        excluded_handlers=["/metrics", "/health", "/healthz", "/docs", "/redoc", "/favicon.ico"],
        inprogress_name="http_requests_inprogress",
        inprogress_labels=True,
    )

    # Compatibilidad: si tu versión da error con metric_namespace/metric_subsystem, elimina esos kwargs
    # Métricas estándar con buckets y namespace/subsystem
    instrumentator.add(
        metrics.request_size(
            should_include_handler=True,
            should_include_method=True,
            should_include_status=True,
            metric_namespace=METRIC_NAMESPACE,
            metric_subsystem=METRIC_SUBSYSTEM_API,
        )
    ).add(
        metrics.response_size(
            should_include_handler=True,
            should_include_method=True,
            should_include_status=True,
            metric_namespace=METRIC_NAMESPACE,
            metric_subsystem=METRIC_SUBSYSTEM_API,
        )
    ).add(
        metrics.latency(
            should_include_handler=True,
            should_include_method=True,
            should_include_status=True,
            metric_namespace=METRIC_NAMESPACE,
            metric_subsystem=METRIC_SUBSYSTEM_API,
        )
    ).add(
        metrics.requests(
            should_include_handler=True,
            should_include_method=True,
            should_include_status=True,
            metric_namespace=METRIC_NAMESPACE,
            metric_subsystem=METRIC_SUBSYSTEM_API,
        )
    )

    # Agregar histogramas personalizados con buckets específicos
    @instrumentator.instrument
    def custom_histograms(response: Response):
        # Esta función se ejecutará después de cada request y puedes agregar métricas personalizadas aquí
        # Pero los buckets ya están definidos en las métricas que creamos manualmente en MetricsManager
        pass
    

    # Importante: no expongas aquí si montarás tu propio endpoint /metrics
    instrumentator.instrument(app)
    logger.info("Application instrumentation completed")


def mount_metrics_endpoint(app: FastAPI) -> None:
    @app.get("/metrics", include_in_schema=False)
    async def metrics_endpoint(request: Request):  # <- quita Depends(validate_api_key) si quieres scraping sin auth
        try:
            registry = get_export_registry()
            data = generate_latest(registry)
            return Response(
                content=data,
                media_type=CONTENT_TYPE_LATEST,
                headers={
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                    "Pragma": "no-cache",
                    "Expires": "0",
                },
            )
        except Exception as e:
            logger.error("Metrics generation failed: %s", e)
            return Response(content=b"", status_code=500, media_type=CONTENT_TYPE_LATEST)


async def metrics_middleware(request: Request, call_next: Callable[..., Any]):
    start_time = time.time()

    try:
        request_size = int(request.headers.get("content-length", "0")) if request.headers.get("content-length") else 0
    except Exception:
        request_size = 0

    # Procesa la petición; si falla, registra 500 y repropaga
    try:
        response = await call_next(request)
    except Exception:
        duration = time.time() - start_time
        metrics_recorder.record_http_request(
            method=request.method,
            endpoint=request.url.path,
            status_code=500,
            client_plan=getattr(request.state, "client_plan", "unknown"),
            duration=duration,
            request_size=request_size,
            response_size=0,
        )
        metrics_recorder.record_error("http_request", "error", "http_server")
        raise

    duration = time.time() - start_time

    try:
        response_size = int(response.headers.get("content-length", "0")) if response.headers.get("content-length") else 0
    except Exception:
        response_size = 0

    metrics_recorder.record_http_request(
        method=request.method,
        endpoint=request.url.path,
        status_code=response.status_code,
        client_plan=getattr(request.state, "client_plan", "unknown"),
        duration=duration,
        request_size=request_size,
        response_size=response_size,
    )

    return response

def track_validation_metrics(validation_type: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator para medir duración y resultado de validaciones."""
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            start_time = time.time()
            client_plan = kwargs.get("client_plan", "unknown")
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time
                metrics_recorder.record_validation(validation_type, "success", client_plan, duration)
                return result
            except Exception:
                duration = time.time() - start_time
                metrics_recorder.record_validation(validation_type, "error", client_plan, duration)
                metrics_recorder.record_error(validation_type, "error", "validation")
                raise
        return wrapper
    return decorator


class PerformanceMonitor:
    """Utilidades simples de monitorización de rendimiento."""

    @staticmethod
    @asynccontextmanager
    async def measure_operation(operation_name: str, labels: Optional[Dict[str, str]] = None):
        start = time.time()
        try:
            yield
        finally:
            duration = time.time() - start
            logger.debug("Operation %s took %.3fs", operation_name, duration)

    @staticmethod
    def set_concurrent_validations(plan: str, count: int) -> None:
        """Ajusta el número de validaciones concurrentes actuales por plan."""
        try:
            plan_norm = MetricLabelNormalizer.normalize_label("client_plan", plan)
            metrics_manager.concurrent_validations.labels(plan=plan_norm).set(count)
        except Exception as e:
            logger.warning("Failed to set concurrent validations: %s", e)

    @staticmethod
    def update_quota_usage(plan: str, usage_ratio: float) -> None:
        """Actualiza la ratio de uso de cuota (0..1) por plan."""
        try:
            plan_norm = MetricLabelNormalizer.normalize_label("client_plan", plan)
            metrics_manager.quota_usage.labels(plan=plan_norm).set(float(max(0.0, min(1.0, usage_ratio))))
        except Exception as e:
            logger.warning("Failed to update quota usage: %s", e)

metrics_manager = MetricsManager()
metrics_recorder = SafeMetricsRecorder(metrics_manager)

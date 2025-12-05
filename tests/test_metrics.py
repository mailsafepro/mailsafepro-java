"""
Tests para metrics.py - Alcanzar 100% coverage
"""
import pytest
import time
import os
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from prometheus_client import CollectorRegistry, generate_latest, REGISTRY

from app.metrics import (
    MetricsManager,
    MetricLabelNormalizer,
    SafeMetricsRecorder,
    get_export_registry,
    mount_metrics_endpoint,
    instrument_app,
    metrics_middleware,
    track_validation_metrics,
    PerformanceMonitor,
    metrics_manager,
    metrics_recorder,
    METRIC_NAMESPACE,
    METRIC_SUBSYSTEM_API,
    LATENCY_BUCKETS,
    SIZE_BUCKETS
)

class TestMetricsManager:
    def test_metrics_manager_initialization(self):
        # Usamos inyección de dependencias en lugar de parchear REGISTRY
        clean_registry = CollectorRegistry()
        
        # Reiniciamos el singleton para este test
        MetricsManager._instance = None
        # Aquí es donde ocurría el error, ahora funcionará gracias al fix en __new__
        manager = MetricsManager(registry=clean_registry)
        
        assert manager.requests_total is not None
        assert manager.request_duration is not None
        assert manager.request_size_bytes is not None
        assert manager.response_size_bytes is not None
        assert manager.validations_total is not None
        assert manager.validation_duration is not None
        assert manager.smtp_checks_total is not None
        assert manager.smtp_check_duration is not None
        assert manager.cache_operations_total is not None
        assert manager.cache_hit_ratio is not None
        assert manager.active_connections is not None
        assert manager.error_total is not None
        assert manager.concurrent_validations is not None
        assert manager.quota_usage is not None
        assert manager.jobs_events_total is not None
        assert manager.job_duration_seconds is not None
        assert manager.job_queue_depth is not None
        assert manager.webhook_deliveries_total is not None
        assert manager.webhook_delivery_duration is not None
        assert manager.webhook_retries_total is not None


class TestMetricLabelNormalizer:
    """Tests para MetricLabelNormalizer"""

    def test_normalize_label_basic(self):
        normalizer = MetricLabelNormalizer()
        assert normalizer.normalize_label("method", "GET") == "get"
        assert normalizer.normalize_label("endpoint", "/api/v1/validate") == "api"
        assert normalizer.normalize_label("status_code", "200") == "2xx"
        assert normalizer.normalize_label("status_code", "404") == "4xx"
        assert normalizer.normalize_label("status_code", "500") == "5xx"

    def test_normalize_label_with_special_chars(self):
        normalizer = MetricLabelNormalizer()
        assert normalizer.normalize_label("test", "hello world") == "hello_world"
        assert normalizer.normalize_label("test", "hello-world") == "hello_world"
        assert normalizer.normalize_label("test", "hello.world") == "hello_world"
        assert normalizer.normalize_label("test", "hello:world") == "hello_world"
        assert normalizer.normalize_label("test", "hello/world") == "hello_world"
        assert normalizer.normalize_label("test", "hello@world") == "hello_at_world"

    def test_normalize_label_mx_host(self):
        normalizer = MetricLabelNormalizer()
        assert normalizer.normalize_label("mx_host", "mail.google.com") == "google_com"
        assert normalizer.normalize_label("mx_host", "mx.example.com") == "example_com"
        assert normalizer.normalize_label("mx_host", "unknown") == "unknown"

    def test_normalize_label_error_type(self):
        normalizer = MetricLabelNormalizer()
        assert normalizer.normalize_label("error_type", "validation:email") == "validation"
        assert normalizer.normalize_label("error_type", "smtp:timeout") == "smtp"
        assert normalizer.normalize_label("error_type", "simple_error") == "simple_error"

    def test_normalize_label_none_value(self):
        normalizer = MetricLabelNormalizer()
        assert normalizer.normalize_label("test", None) == "unknown"

    def test_normalize_label_truncation(self):
        normalizer = MetricLabelNormalizer()
        long_string = "a" * 100
        result = normalizer.normalize_label("test", long_string)
        assert len(result) <= 64

    def test_should_include_label(self):
        normalizer = MetricLabelNormalizer()
        assert normalizer.should_include_label("user_id", "123") is False
        assert normalizer.should_include_label("email", "test@example.com") is False
        assert normalizer.should_include_label("ip_address", "192.168.1.1") is False
        assert normalizer.should_include_label("method", "GET") is True
        assert normalizer.should_include_label("endpoint", "/api") is True
        assert normalizer.should_include_label("method", None) is False


class TestSafeMetricsRecorder:
    @pytest.fixture
    def recorder(self):
        # Crear un registry aislado para este test
        clean_registry = CollectorRegistry()
        
        # Resetear Singleton e inyectar el registry limpio
        MetricsManager._instance = None
        manager = MetricsManager(registry=clean_registry)
        
        return SafeMetricsRecorder(manager)

    def test_record_http_request_success(self, recorder):
        with patch.object(recorder.metrics.requests_total, 'labels') as mock_labels:
            mock_counter = Mock()
            mock_labels.return_value = mock_counter
            
            recorder.record_http_request(
                method="POST",
                endpoint="/api/v1/validate",
                status_code=200,
                client_plan="PREMIUM",
                duration=0.15,
                request_size=1024,
                response_size=2048
            )
            
            assert mock_labels.called
            mock_counter.inc.assert_called_once()

    def test_record_http_request_failure(self, recorder):
        with patch.object(recorder.metrics.requests_total, 'labels', side_effect=Exception("Test error")):
            recorder.record_http_request(
                method="GET",
                endpoint="/test",
                status_code=200,
                client_plan="FREE",
                duration=0.1
            )

    def test_record_validation(self, recorder):
        with patch.object(recorder.metrics.validations_total, 'labels') as mock_labels:
            mock_counter = Mock()
            mock_labels.return_value = mock_counter
            
            recorder.record_validation(
                validation_type="smtp",
                result="success",
                client_plan="ENTERPRISE",
                duration=0.05
            )
            
            assert mock_labels.called
            mock_counter.inc.assert_called_once()

    def test_record_smtp_check(self, recorder):
        with patch.object(recorder.metrics.smtp_checks_total, 'labels') as mock_counter_labels:
            with patch.object(recorder.metrics.smtp_check_duration, 'labels') as mock_histogram_labels:
                mock_counter = Mock()
                mock_histogram = Mock()
                mock_counter_labels.return_value = mock_counter
                mock_histogram_labels.return_value = mock_histogram
                
                recorder.record_smtp_check(
                    status="success",
                    mx_host="mail.example.com",
                    duration=0.25
                )
                
                assert mock_counter_labels.called
                assert mock_histogram_labels.called
                mock_counter.inc.assert_called_once()
                mock_histogram.observe.assert_called_once_with(0.25)

    def test_record_cache_operation(self, recorder):
        with patch.object(recorder.metrics.cache_operations_total, 'labels') as mock_labels:
            mock_counter = Mock()
            mock_labels.return_value = mock_counter
            
            recorder.record_cache_operation(
                operation="get",
                cache_type="redis",
                result="hit"
            )
            
            assert mock_labels.called
            mock_counter.inc.assert_called_once()

    def test_record_error(self, recorder):
        with patch.object(recorder.metrics.error_total, 'labels') as mock_labels:
            mock_counter = Mock()
            mock_labels.return_value = mock_counter
            
            recorder.record_error(
                error_type="validation_error",
                severity="error",
                component="api"
            )
            
            assert mock_labels.called
            mock_counter.inc.assert_called_once()

    def test_record_job_event(self, recorder):
        with patch.object(recorder.metrics.jobs_events_total, 'labels') as mock_labels:
            mock_counter = Mock()
            mock_labels.return_value = mock_counter
            
            recorder.record_job_event("PREMIUM", "queued")
            assert mock_labels.called
            mock_counter.inc.assert_called_once()

    def test_observe_job_duration(self, recorder):
        with patch.object(recorder.metrics.job_duration_seconds, 'labels') as mock_labels:
            mock_histogram = Mock()
            mock_labels.return_value = mock_histogram
            
            recorder.observe_job_duration("FREE", 10.5)
            assert mock_labels.called
            mock_histogram.observe.assert_called_once_with(10.5)

    def test_set_job_queue_depth(self, recorder):
        with patch.object(recorder.metrics.job_queue_depth, 'labels') as mock_labels:
            mock_gauge = Mock()
            mock_labels.return_value = mock_gauge
            
            recorder.set_job_queue_depth("validation_queue", 5)
            assert mock_labels.called
            mock_gauge.set.assert_called_once_with(5)

    def test_record_webhook_delivery(self, recorder):
        with patch.object(recorder.metrics.webhook_deliveries_total, 'labels') as mock_counter_labels:
            with patch.object(recorder.metrics.webhook_delivery_duration, 'labels') as mock_histogram_labels:
                mock_counter = Mock()
                mock_histogram = Mock()
                mock_counter_labels.return_value = mock_counter
                mock_histogram_labels.return_value = mock_histogram
                
                recorder.record_webhook_delivery(200, 1.5)
                assert mock_counter_labels.called
                assert mock_histogram_labels.called
                mock_counter.inc.assert_called_once()
                mock_histogram.observe.assert_called_once_with(1.5)

    def test_record_webhook_retry(self, recorder):
        with patch.object(recorder.metrics.webhook_retries_total, 'labels') as mock_labels:
            mock_counter = Mock()
            mock_labels.return_value = mock_counter
            
            recorder.record_webhook_retry("timeout")
            assert mock_labels.called
            mock_counter.inc.assert_called_once()


class TestMetricsFunctions:
    def test_get_export_registry_single_process(self):
        with patch.dict(os.environ, {}, clear=True):
            registry = get_export_registry()
            assert registry is not None

    def test_get_export_registry_multiprocess(self):
        with patch.dict(os.environ, {'PROMETHEUS_MULTIPROC_DIR': '/tmp/metrics'}):
            with patch('prometheus_client.multiprocess') as mock_multiprocess:
                registry = get_export_registry()
                assert registry is not None
                mock_multiprocess.MultiProcessCollector.assert_called_once()

    @pytest.mark.asyncio
    async def test_metrics_middleware_success(self):
        mock_request = Mock()
        mock_request.method = "GET"
        mock_request.url.path = "/test"
        mock_request.headers = {"content-length": "100"}
        mock_request.state.client_plan = "PREMIUM"
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"content-length": "200"}

        async def call_next(request):
            return mock_response

        with patch.object(metrics_recorder, 'record_http_request') as mock_record:
            response = await metrics_middleware(mock_request, call_next)
            assert response == mock_response
            mock_record.assert_called_once()

    @pytest.mark.asyncio
    async def test_metrics_middleware_exception(self):
        mock_request = Mock()
        mock_request.method = "POST"
        mock_request.url.path = "/api"
        mock_request.headers = {}
        mock_request.state.client_plan = "FREE"

        async def call_next(request):
            raise Exception("Test error")

        with patch.object(metrics_recorder, 'record_http_request') as mock_record:
            with patch.object(metrics_recorder, 'record_error') as mock_error:
                with pytest.raises(Exception):
                    await metrics_middleware(mock_request, call_next)
                mock_error.assert_called_once()
                mock_record.assert_called_once()

    def test_track_validation_metrics_decorator_success(self):
        @track_validation_metrics("smtp_check")
        async def mock_validation(*args, **kwargs):
            return "success"

        with patch.object(metrics_recorder, 'record_validation') as mock_record:
            import asyncio
            result = asyncio.run(mock_validation(client_plan="FREE"))
            assert result == "success"
            
            mock_record.assert_called_once()
            call_args = mock_record.call_args[0]
            assert call_args[0] == "smtp_check"
            assert call_args[1] == "success"
            assert call_args[2] == "FREE"

    def test_track_validation_metrics_decorator_error(self):
        @track_validation_metrics("smtp_check")
        async def mock_validation(*args, **kwargs):
            raise ValueError("Validation failed")

        with patch.object(metrics_recorder, 'record_validation') as mock_record:
            with patch.object(metrics_recorder, 'record_error') as mock_error:
                import asyncio
                with pytest.raises(ValueError):
                    asyncio.run(mock_validation(client_plan="PREMIUM"))
                
                mock_record.assert_called_once()
                mock_error.assert_called_once()


class TestPerformanceMonitor:
    @pytest.mark.asyncio
    async def test_measure_operation_success(self):
        with patch('time.time', side_effect=[0.0, 1.5]):
            async with PerformanceMonitor.measure_operation("test_operation"):
                pass

    def test_set_concurrent_validations(self):
        with patch.object(metrics_manager.concurrent_validations, 'labels') as mock_labels:
            mock_gauge = Mock()
            mock_labels.return_value = mock_gauge
            PerformanceMonitor.set_concurrent_validations("ENTERPRISE", 10)
            mock_labels.assert_called_once_with(plan="enterprise")
            mock_gauge.set.assert_called_once_with(10)

    def test_update_quota_usage(self):
        with patch.object(metrics_manager.quota_usage, 'labels') as mock_labels:
            mock_gauge = Mock()
            mock_labels.return_value = mock_gauge
            PerformanceMonitor.update_quota_usage("PREMIUM", 0.75)
            mock_labels.assert_called_once_with(plan="premium")
            mock_gauge.set.assert_called_once_with(0.75)

    def test_update_quota_usage_clamping(self):
        with patch.object(metrics_manager.quota_usage, 'labels') as mock_labels:
            mock_gauge = Mock()
            mock_labels.return_value = mock_gauge
            PerformanceMonitor.update_quota_usage("FREE", 1.5)
            mock_gauge.set.assert_called_with(1.0)
            PerformanceMonitor.update_quota_usage("FREE", -0.5)
            mock_gauge.set.assert_called_with(0.0)


class TestMetricsEndpoint:
    def test_mount_metrics_endpoint(self):
        app = FastAPI()
        mount_metrics_endpoint(app)
        routes = {route.path: route for route in app.routes}
        assert "/metrics" in routes
        assert routes["/metrics"].include_in_schema is False

    def test_metrics_endpoint_success(self):
        app = FastAPI()
        mount_metrics_endpoint(app)
        client = TestClient(app)
        
        with patch('app.metrics.get_export_registry') as mock_registry:
            with patch('app.metrics.generate_latest', return_value=b"test_metrics_data"):
                response = client.get("/metrics")
                assert response.status_code == 200
                assert b"test_metrics_data" in response.content

    def test_metrics_endpoint_failure(self):
        app = FastAPI()
        mount_metrics_endpoint(app)
        client = TestClient(app)
        
        with patch('app.metrics.get_export_registry', side_effect=Exception("Registry error")):
            response = client.get("/metrics")
            assert response.status_code == 500


class TestInstrumentApp:
    def test_instrument_app(self):
        app = FastAPI()
        with patch('app.metrics.Instrumentator') as MockInstrumentator:
            mock_instance = Mock()
            # Configurar para soportar encadenamiento .add().add()
            mock_instance.add.return_value = mock_instance
            MockInstrumentator.return_value = mock_instance
            
            instrument_app(app)
            
            assert mock_instance.instrument.call_count >= 1
            assert mock_instance.add.call_count >= 4


class TestModuleLevelObjects:
    def test_module_constants(self):
        assert METRIC_NAMESPACE == "email_validation"
        assert METRIC_SUBSYSTEM_API == "api"
        assert len(LATENCY_BUCKETS) > 0
        assert len(SIZE_BUCKETS) > 0

    def test_global_instances(self):
        assert metrics_manager is not None
        assert metrics_recorder is not None
        assert isinstance(metrics_manager, MetricsManager)
        assert isinstance(metrics_recorder, SafeMetricsRecorder)

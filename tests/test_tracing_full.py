"""
Comprehensive tests for app/tracing.py - Achieving 100% Coverage

Tests cover:
- TracingConfig initialization from environment
- Tracer setup and shutdown
- Exporter configuration (Console, Jaeger, OTLP)
- Span utilities and helpers
- Business-specific tracing helpers
- Correlation ID management
- Sampling strategies
"""

import pytest
import os
from unittest.mock import MagicMock, patch, call
from contextlib import contextmanager


# =============================================================================
# TEST TRACING CONFIGURATION
# =============================================================================

class TestTracingConfig:
    """Test TracingConfig class."""
    
    def test_default_configuration(self):
        """Test TracingConfig with default values."""
        from app.tracing import TracingConfig
        
        with patch.dict(os.environ, {}, clear=True):
            config = TracingConfig()
            
            assert config.enabled == True
            assert config.service_name == "mailsafepro-api"
            assert config.service_version == "2.1.0"
            assert config.environment == "development"
            assert config.exporter_type == "console"
            assert config.sample_rate == 1.0
            assert config.instrument_redis == True
            assert config.instrument_http == True
    
    def test_custom_configuration(self):
        """Test TracingConfig with custom environment variables."""
        from app.tracing import TracingConfig
        
        env_vars = {
            "TRACING_ENABLED": "false",
            "SERVICE_NAME": "custom-service",
            "SERVICE_VERSION": "3.0.0",
            "ENVIRONMENT": "production",
            "TRACING_EXPORTER": "jaeger",
            "JAEGER_AGENT_HOST": "jaeger-host",
            "JAEGER_AGENT_PORT": "6832",
            "OTLP_ENDPOINT": "http://otlp:4317",
            "TRACING_SAMPLE_RATE": "0.5",
            "TRACING_INSTRUMENT_REDIS": "false",
            "TRACING_INSTRUMENT_HTTP": "false",
        }
        
        with patch.dict(os.environ, env_vars, clear=True):
            config = TracingConfig()
            
            assert config.enabled == False
            assert config.service_name == "custom-service"
            assert config.service_version == "3.0.0"
            assert config.environment == "production"
            assert config.exporter_type == "jaeger"
            assert config.jaeger_agent_host == "jaeger-host"
            assert config.jaeger_agent_port == 6832
            assert config.otlp_endpoint == "http://otlp:4317"
            assert config.sample_rate == 0.5
            assert config.instrument_redis == False
            assert config.instrument_http == False


# =============================================================================
# TEST TRACER SETUP
# =============================================================================

class TestTracerSetup:
    """Test tracer initialization and configuration."""
    
    def test_setup_tracing_disabled(self):
        """Test setup_tracing when disabled."""
        from app.tracing import setup_tracing
        
        with patch.dict(os.environ, {"TRACING_ENABLED": "false"}):
            with patch('app.tracing.logger') as mock_logger:
                setup_tracing()
                
                mock_logger.info.assert_called_with("Distributed tracing is disabled")
    
    def test_setup_console_exporter(self):
        """Test setup with console exporter."""
        from app.tracing import setup_tracing
        
        with patch.dict(os.environ, {"TRACING_EXPORTER": "console"}):
            with patch('app.tracing.TracerProvider') as mock_provider, \
                 patch('app.tracing.Resource') as mock_resource, \
                 patch('app.tracing.trace') as mock_trace, \
                 patch('app.tracing.ConsoleSpanExporter') as mock_console, \
                 patch('app.tracing.BatchSpanProcessor') as mock_processor, \
                 patch('app.tracing.logger'):
                
                setup_tracing()
                
                # Verify TracerProvider was created
                mock_provider.assert_called_once()
                # Verify console exporter was created
                mock_console.assert_called()
    
    def test_setup_with_fastapi_app(self):
        """Test setup with FastAPI app instrumentation."""
        from app.tracing import setup_tracing
        
        mock_app = MagicMock()
        
        with patch.dict(os.environ, {"TRACING_EXPORTER": "console"}):
            with patch('app.tracing.TracerProvider'), \
                 patch('app.tracing.Resource'), \
                 patch('app.tracing.trace'), \
                 patch('app.tracing.ConsoleSpanExporter'), \
                 patch('app.tracing.BatchSpanProcessor'), \
                 patch('app.tracing.FastAPIInstrumentor') as mock_instrumentor, \
                 patch('app.tracing.logger') as mock_logger:
                
                setup_tracing(app=mock_app)
                
                # Verify FastAPI instrumentation
                mock_instrumentor.instrument_app.assert_called_once_with(mock_app)
                assert any("FastAPI instrumented" in str(c) for c in mock_logger.success.call_args_list)
    
    def test_setup_instrument_redis(self):
        """Test Redis instrumentation."""
        from app.tracing import setup_tracing
        
        with patch.dict(os.environ, {"TRACING_INSTRUMENT_REDIS": "true"}):
            with patch('app.tracing.TracerProvider'), \
                 patch('app.tracing.Resource'), \
                 patch('app.tracing.trace'), \
                 patch('app.tracing.ConsoleSpanExporter'), \
                 patch('app.tracing.BatchSpanProcessor'), \
                 patch('app.tracing.RedisInstrumentor') as mock_redis_inst, \
                 patch('app.tracing.logger') as mock_logger:
                
                setup_tracing()
                
                # Verify Redis instrumentation
                mock_redis_inst.return_value.instrument.assert_called_once()
                assert any("Redis instrumented" in str(c) for c in mock_logger.success.call_args_list)
    
    def test_setup_instrument_http(self):
        """Test HTTP client instrumentation."""
        from app.tracing import setup_tracing
        
        with patch.dict(os.environ, {"TRACING_INSTRUMENT_HTTP": "true"}):
            with patch('app.tracing.TracerProvider'), \
                 patch('app.tracing.Resource'), \
                 patch('app.tracing.trace'), \
                 patch('app.tracing.ConsoleSpanExporter'), \
                 patch('app.tracing.BatchSpanProcessor'), \
                 patch('app.tracing.AioHttpClientInstrumentor') as mock_http_inst, \
                 patch('app.tracing.logger') as mock_logger:
                
                setup_tracing()
                
                # Verify HTTP instrumentation
                mock_http_inst.return_value.instrument.assert_called_once()
                assert any("HTTP client instrumented" in str(c) for c in mock_logger.success.call_args_list)
    
    def test_instrumentation_failures(self):
        """Test handling of instrumentation failures."""
        from app.tracing import setup_tracing
        
        mock_app = MagicMock()
        
        with patch.dict(os.environ, {}):
            with patch('app.tracing.TracerProvider'), \
                 patch('app.tracing.Resource'), \
                 patch('app.tracing.trace'), \
                 patch('app.tracing.ConsoleSpanExporter'), \
                 patch('app.tracing.BatchSpanProcessor'), \
                 patch('app.tracing.FastAPIInstrumentor') as mock_fastapi, \
                 patch('app.tracing.RedisInstrumentor') as mock_redis, \
                 patch('app.tracing.AioHttpClientInstrumentor') as mock_http, \
                 patch('app.tracing.logger') as mock_logger:
                
                # Make instrumentations fail
                mock_fastapi.instrument_app.side_effect = Exception("FastAPI error")
                mock_redis.return_value.instrument.side_effect = Exception("Redis error")
                mock_http.return_value.instrument.side_effect = Exception("HTTP error")
                
                setup_tracing(app=mock_app)
                
                # Verify errors were logged
                assert any("Failed to instrument FastAPI" in str(c) for c in mock_logger.error.call_args_list)
                assert any("Failed to instrument Redis" in str(c) for c in mock_logger.error.call_args_list)
                assert any("Failed to instrument HTTP" in str(c) for c in mock_logger.error.call_args_list)
    
    def test_shutdown_tracing(self):
        """Test shutdown_tracing function."""
        from app.tracing import shutdown_tracing
        import app.tracing as tracing_module
        
        mock_provider = MagicMock()
        tracing_module._tracer_provider = mock_provider
        
        with patch('app.tracing.logger') as mock_logger:
            shutdown_tracing()
            
            mock_provider.shutdown.assert_called_once()
            mock_logger.info.assert_called_with("✅ Tracing shut down cleanly")
    
    def test_shutdown_tracing_with_error(self):
        """Test shutdown_tracing with exception."""
        from app.tracing import shutdown_tracing
        import app.tracing as tracing_module
        
        mock_provider = MagicMock()
        mock_provider.shutdown.side_effect = Exception("Shutdown error")
        tracing_module._tracer_provider = mock_provider
        
        with patch('app.tracing.logger') as mock_logger:
            shutdown_tracing()
            
            assert any("Error shutting down tracing" in str(c) for c in mock_logger.error.call_args_list)
    
    def test_shutdown_tracing_no_provider(self):
        """Test shutdown_tracing when no provider exists."""
        from app.tracing import shutdown_tracing
        import app.tracing as tracing_module
        
        tracing_module._tracer_provider = None
        
        # Should not raise any exception
        shutdown_tracing()


# =============================================================================
# TEST EXPORTERS
# =============================================================================

class TestExporters:
    """Test exporter creation."""
    
    def test_create_console_exporter(self):
        """Test console exporter creation."""
        from app.tracing import _create_exporter, TracingConfig
        
        with patch.dict(os.environ, {"TRACING_EXPORTER": "console"}):
            config = TracingConfig()
            
            with patch('app.tracing.ConsoleSpanExporter') as mock_console:
                mock_console.return_value = "console_exporter"
                exporter = _create_exporter(config)
                
                assert exporter == "console_exporter"
    
    def test_create_jaeger_exporter_available(self):
        """Test Jaeger exporter when available."""
        from app.tracing import _create_exporter, TracingConfig
        import app.tracing as tracing_module
        
        # Mock Jaeger as available
        original_available = tracing_module.JAEGER_AVAILABLE
        tracing_module.JAEGER_AVAILABLE = True
        
        try:
            with patch.dict(os.environ, {
                "TRACING_EXPORTER": "jaeger",
                "JAEGER_AGENT_HOST": "localhost",
                "JAEGER_AGENT_PORT": "6831"
            }):
                config = TracingConfig()
                
                # Mock the JaegerExporter class at the module level
                mock_jaeger_class = MagicMock()
                mock_jaeger_class.return_value = "jaeger_exporter"
                tracing_module.JaegerExporter = mock_jaeger_class
                
                exporter = _create_exporter(config)
                
                mock_jaeger_class.assert_called_with(
                    agent_host_name="localhost",
                    agent_port=6831
                )
                assert exporter == "jaeger_exporter"
        finally:
            tracing_module.JAEGER_AVAILABLE = original_available
    
    def test_create_jaeger_exporter_unavailable(self):
        """Test Jaeger exporter when not available."""
        from app.tracing import _create_exporter, TracingConfig
        import app.tracing as tracing_module
        
        # Mock Jaeger as unavailable
        tracing_module.JAEGER_AVAILABLE = False
        
        with patch.dict(os.environ, {"TRACING_EXPORTER": "jaeger"}):
            config = TracingConfig()
            
            with patch('app.tracing.logger') as mock_logger:
                exporter = _create_exporter(config)
                
                assert exporter is None
                assert any("Jaeger exporter not available" in str(c) for c in mock_logger.warning.call_args_list)
    
    def test_create_otlp_exporter_available(self):
        """Test OTLP exporter when available."""
        from app.tracing import _create_exporter, TracingConfig
        import app.tracing as tracing_module
        
        # Mock OTLP as available
        original_available = tracing_module.OTLP_AVAILABLE
        tracing_module.OTLP_AVAILABLE = True
        
        try:
            with patch.dict(os.environ, {
                "TRACING_EXPORTER": "otlp",
                "OTLP_ENDPOINT": "http://localhost:4317"
            }):
                config = TracingConfig()
                
                # Mock the OTLPSpanExporter class at the module level
                mock_otlp_class = MagicMock()
                mock_otlp_class.return_value = "otlp_exporter"
                tracing_module.OTLPSpanExporter = mock_otlp_class
                
                exporter = _create_exporter(config)
                
                mock_otlp_class.assert_called_with(
                    endpoint="http://localhost:4317",
                    insecure=True
                )
                assert exporter == "otlp_exporter"
        finally:
            tracing_module.OTLP_AVAILABLE = original_available
    
    def test_create_otlp_exporter_unavailable(self):
        """Test OTLP exporter when not available."""
        from app.tracing import _create_exporter, TracingConfig
        import app.tracing as tracing_module
        
        # Mock OTLP as unavailable
        tracing_module.OTLP_AVAILABLE = False
        
        with patch.dict(os.environ, {"TRACING_EXPORTER": "otlp"}):
            config = TracingConfig()
            
            with patch('app.tracing.logger') as mock_logger:
                exporter = _create_exporter(config)
                
                assert exporter is None
                assert any("OTLP exporter not available" in str(c) for c in mock_logger.warning.call_args_list)
    
    def test_create_unknown_exporter(self):
        """Test unknown exporter type."""
        from app.tracing import _create_exporter, TracingConfig
        
        with patch.dict(os.environ, {"TRACING_EXPORTER": "unknown"}):
            config = TracingConfig()
            
            with patch('app.tracing.logger') as mock_logger:
                exporter = _create_exporter(config)
                
                assert exporter is None
                assert any("Unknown exporter type" in str(c) for c in mock_logger.warning.call_args_list)


# =============================================================================
# TEST SPAN UTILITIES
# =============================================================================

class TestSpanUtilities:
    """Test span utility functions."""
    
    def test_get_tracer_with_tracer(self):
        """Test get_tracer when tracer exists."""
        from app.tracing import get_tracer
        import app.tracing as tracing_module
        
        mock_tracer = MagicMock()
        tracing_module._tracer = mock_tracer
        
        result = get_tracer()
        
        assert result == mock_tracer
    
    def test_get_tracer_no_tracer(self):
        """Test get_tracer fallback when no tracer."""
        from app.tracing import get_tracer
        import app.tracing as tracing_module
        
        tracing_module._tracer = None
        
        with patch('app.tracing.trace') as mock_trace:
            mock_trace.get_tracer.return_value = "fallback_tracer"
            result = get_tracer()
            
            mock_trace.get_tracer.assert_called_once()
    
    def test_trace_span_success(self):
        """Test trace_span context manager success."""
        from app.tracing import trace_span
        
        with patch('app.tracing.get_tracer') as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_span = MagicMock()
            mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span
            mock_tracer.start_as_current_span.return_value.__exit__.return_value = False
            mock_get_tracer.return_value = mock_tracer
            
            with trace_span("test_operation", {"key": "value"}):
                pass
            
            mock_span.set_attribute.assert_called_with("key", "value")
    
    def test_trace_span_with_error(self):
        """Test trace_span handles exceptions."""
        from app.tracing import trace_span
        
        with patch('app.tracing.get_tracer') as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_span = MagicMock()
            mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span
            mock_tracer.start_as_current_span.return_value.__exit__.return_value = False
            mock_get_tracer.return_value = mock_tracer
            
            with pytest.raises(ValueError):
                with trace_span("test_operation"):
                    raise ValueError("Test error")
            
            # Verify span error handling
            assert mock_span.set_status.called
            assert mock_span.record_exception.called
    
    def test_add_span_attributes(self):
        """Test add_span_attributes function."""
        from app.tracing import add_span_attributes
        
        with patch('app.tracing.trace') as mock_trace:
            mock_span = MagicMock()
            mock_span.is_recording.return_value = True
            mock_trace.get_current_span.return_value = mock_span
            
            add_span_attributes(key1="value1", key2=123, key3=True)
            
            assert mock_span.set_attribute.call_count == 3
    
    def test_add_span_attributes_no_span(self):
        """Test add_span_attributes with no active span."""
        from app.tracing import add_span_attributes
        
        with patch('app.tracing.trace') as mock_trace:
            mock_trace.get_current_span.return_value = None
            
            # Should not raise exception
            add_span_attributes(key="value")
    
    def test_add_span_event(self):
        """Test add_span_event function."""
        from app.tracing import add_span_event
        
        with patch('app.tracing.trace') as mock_trace:
            mock_span = MagicMock()
            mock_span.is_recording.return_value = True
            mock_trace.get_current_span.return_value = mock_span
            
            add_span_event("test_event", {"detail": "info"})
            
            mock_span.add_event.assert_called_once_with("test_event", {"detail": "info"})
    
    def test_get_trace_context(self):
        """Test get_trace_context function."""
        from app.tracing import get_trace_context
        
        with patch('app.tracing.TraceContextTextMapPropagator') as mock_propagator:
            mock_instance = MagicMock()
            mock_propagator.return_value = mock_instance
            
            result = get_trace_context()
            
            mock_instance.inject.assert_called_once()
            assert isinstance(result, dict)
    
    def test_set_span_error(self):
        """Test set_span_error function."""
        from app.tracing import set_span_error
        
        with patch('app.tracing.trace') as mock_trace:
            mock_span = MagicMock()
            mock_span.is_recording.return_value = True
            mock_trace.get_current_span.return_value = mock_span
            
            error = ValueError("Test error")
            set_span_error(error, "Custom message")
            
            mock_span.set_status.assert_called_once()
            mock_span.record_exception.assert_called_once_with(error)


# =============================================================================
# TEST BUSINESS TRACING HELPERS
# =============================================================================

class TestBusinessTracingHelpers:
    """Test business-specific tracing helpers."""
    
    def test_trace_validation(self):
        """Test trace_validation helper."""
        from app.tracing import trace_validation
        
        with patch('app.tracing.trace_span') as mock_trace_span:
            result = trace_validation("test@example.com", "PREMIUM")
            
            # Verify it returns a context manager
            mock_trace_span.assert_called_once()
            call_args = mock_trace_span.call_args
            assert call_args[0][0] == "email.validation"
            assert "example.com" in str(call_args[1]["attributes"])
            assert "PREMIUM" in str(call_args[1]["attributes"])
    
    def test_trace_smtp_check(self):
        """Test trace_smtp_check helper."""
        from app.tracing import trace_smtp_check
        
        with patch('app.tracing.trace_span') as mock_trace_span:
            result = trace_smtp_check("mx.example.com", "test@example.com")
            
            mock_trace_span.assert_called_once()
            call_args = mock_trace_span.call_args
            assert call_args[0][0] == "smtp.verification"
    
    def test_trace_dns_lookup(self):
        """Test trace_dns_lookup helper."""
        from app.tracing import trace_dns_lookup
        
        with patch('app.tracing.trace_span') as mock_trace_span:
            result = trace_dns_lookup("example.com", "MX")
            
            mock_trace_span.assert_called_once()
            call_args = mock_trace_span.call_args
            assert call_args[0][0] == "dns.lookup"
    
    def test_trace_cache_operation(self):
        """Test trace_cache_operation helper."""
        from app.tracing import trace_cache_operation
        
        with patch('app.tracing.trace_span') as mock_trace_span:
            result = trace_cache_operation("get", "user:123")
            
            mock_trace_span.assert_called_once()
            call_args = mock_trace_span.call_args
            assert call_args[0][0] == "cache.get"
    
    def test_trace_batch_job(self):
        """Test trace_batch_job helper."""
        from app.tracing import trace_batch_job
        
        with patch('app.tracing.trace_span') as mock_trace_span:
            result = trace_batch_job("job-123", 1000)
            
            mock_trace_span.assert_called_once()
            call_args = mock_trace_span.call_args
            assert call_args[0][0] == "batch.job.process"


# =============================================================================
# TEST CORRELATION ID
# =============================================================================

class TestCorrelationID:
    """Test correlation ID utilities."""
    
    def test_get_correlation_id(self):
        """Test get_correlation_id with active span."""
        from app.tracing import get_correlation_id
        
        with patch('app.tracing.trace') as mock_trace:
            mock_span = MagicMock()
            mock_span.is_recording.return_value = True
            mock_context = MagicMock()
            mock_context.trace_id = 123456789012345678901234567890123456
            mock_span.get_span_context.return_value = mock_context
            mock_trace.get_current_span.return_value = mock_span
            
            result = get_correlation_id()
            
            assert result is not None
            assert isinstance(result, str)
            assert len(result) == 32  # Hex format
    
    def test_get_correlation_id_no_span(self):
        """Test get_correlation_id with no active span."""
        from app.tracing import get_correlation_id
        
        with patch('app.tracing.trace') as mock_trace:
            mock_trace.get_current_span.return_value = None
            
            result = get_correlation_id()
            
            assert result is None
    
    def test_inject_correlation_id(self):
        """Test inject_correlation_id function."""
        from app.tracing import inject_correlation_id
        
        with patch('app.tracing.get_trace_context') as mock_get_context:
            mock_get_context.return_value = {"traceparent": "abc123"}
            
            headers = {"existing": "header"}
            result = inject_correlation_id(headers)
            
            assert result["existing"] == "header"
            assert result["traceparent"] == "abc123"


# =============================================================================
# TEST SAMPLING STRATEGIES
# =============================================================================

class TestSamplingStrategies:
    """Test sampling strategy logic."""
    
    def test_should_sample_no_config(self):
        """Test sampling with no config."""
        from app.tracing import should_sample_trace
        import app.tracing as tracing_module
        
        tracing_module._config = None
        
        result = should_sample_trace()
        
        assert result == False
    
    def test_should_sample_development(self):
        """Test sampling in development always returns True."""
        from app.tracing import should_sample_trace, TracingConfig
        import app.tracing as tracing_module
        
        with patch.dict(os.environ, {"ENVIRONMENT": "development"}):
            tracing_module._config = TracingConfig()
            
            result = should_sample_trace()
            
            assert result == True
    
    def test_should_sample_enterprise(self):
        """Test sampling for ENTERPRISE plan."""
        from app.tracing import should_sample_trace, TracingConfig
        import app.tracing as tracing_module
        
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            tracing_module._config = TracingConfig()
            
            result = should_sample_trace(plan="ENTERPRISE")
            
            assert result == True
    
    def test_should_sample_premium(self):
        """Test sampling for PREMIUM plan."""
        from app.tracing import should_sample_trace, TracingConfig
        import app.tracing as tracing_module
        
        with patch.dict(os.environ, {
            "ENVIRONMENT": "production",
            "TRACING_SAMPLE_RATE": "0.6"
        }):
            tracing_module._config = TracingConfig()
            
            result = should_sample_trace(plan="PREMIUM")
            
            assert result == True  # 0.6 >= 0.5
    
    def test_should_sample_premium_below_threshold(self):
        """Test sampling for PREMIUM with low sample rate."""
        from app.tracing import should_sample_trace, TracingConfig
        import app.tracing as tracing_module
        
        with patch.dict(os.environ, {
            "ENVIRONMENT": "production",
            "TRACING_SAMPLE_RATE": "0.3"
        }):
            tracing_module._config = TracingConfig()
            
            result = should_sample_trace(plan="PREMIUM")
            
            assert result == False  # 0.3 < 0.5
    
    def test_should_sample_free(self):
        """Test sampling for FREE plan."""
        from app.tracing import should_sample_trace, TracingConfig
        import app.tracing as tracing_module
        
        with patch.dict(os.environ, {
            "ENVIRONMENT": "production",
            "TRACING_SAMPLE_RATE": "0.2"
        }):
            tracing_module._config = TracingConfig()
            
            result = should_sample_trace(plan="FREE")
            
            assert result == True  # 0.2 >= 0.1
    
    def test_should_sample_free_below_threshold(self):
        """Test sampling for FREE with very low sample rate."""
        from app.tracing import should_sample_trace, TracingConfig
        import app.tracing as tracing_module
        
        with patch.dict(os.environ, {
            "ENVIRONMENT": "production",
            "TRACING_SAMPLE_RATE": "0.05"
        }):
            tracing_module._config = TracingConfig()
            
            result = should_sample_trace(plan="FREE")
            
            assert result == False  # 0.05 < 0.1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

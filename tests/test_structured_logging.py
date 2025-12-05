"""
Tests para structured_logging.py - 100% coverage
"""
import pytest
import logging
import os
import sys
import re
from unittest.mock import Mock, patch, MagicMock, call
from datetime import datetime
import structlog

# Importamos los componentes a testear
from app.structured_logging import (
    StructuredLoggingConfig,
    add_timestamp,
    add_log_level,
    add_logger_name,
    add_correlation_id,
    redact_sensitive_data,
    drop_debug_in_production,
    setup_structured_logging,
    get_logger,
    LogContext,
    log_validation_attempt,
    log_validation_result,
    log_cache_hit,
    log_cache_miss,
    log_smtp_check,
    log_batch_job_created,
    log_batch_job_completed,
    log_api_key_created,
    log_api_key_rotation,
    log_rate_limit_exceeded,
    log_authentication_failure,
    log_webhook_sent,
    log_error_with_context,
    PerformanceLogger
)

# =============================================================================
# CONFIGURATION TESTS
# =============================================================================

class TestStructuredLoggingConfig:
    def test_default_config(self):
        with patch.dict(os.environ, {}, clear=True):
            config = StructuredLoggingConfig()
            assert config.enabled is True
            assert config.log_level == "INFO"
            assert config.json_format is True
            assert config.include_caller is True

    def test_custom_config(self):
        env_vars = {
            "STRUCTURED_LOGGING_ENABLED": "false",
            "LOG_LEVEL": "DEBUG",
            "LOG_JSON_FORMAT": "false",
            "LOG_INCLUDE_CALLER": "false"
        }
        with patch.dict(os.environ, env_vars):
            config = StructuredLoggingConfig()
            assert config.enabled is False
            assert config.log_level == "DEBUG"
            assert config.json_format is False
            assert config.include_caller is False

    def test_redact_patterns_exist(self):
        config = StructuredLoggingConfig()
        assert len(config.redact_patterns) > 0
        # Verify patterns are compiled regex objects
        for pattern, replacement in config.redact_patterns:
            assert isinstance(pattern, type(re.compile("")))
            assert isinstance(replacement, str)

# =============================================================================
# PROCESSOR TESTS
# =============================================================================

def test_add_timestamp():
    event_dict = {"event": "test"}
    result = add_timestamp(None, None, event_dict)
    assert "timestamp" in result
    assert result["timestamp"].endswith("Z")

def test_add_log_level():
    event_dict = {"event": "test"}
    result = add_log_level(None, "info", event_dict)
    assert result["level"] == "INFO"

def test_add_logger_name():
    # Case 1: With _record
    record = Mock()
    record.name = "test_logger"
    event_dict = {"_record": record}
    result = add_logger_name(None, None, event_dict)
    assert result["logger"] == "test_logger"

    # Case 2: Without _record
    event_dict = {}
    result = add_logger_name(None, None, event_dict)
    assert "logger" not in result

def test_add_correlation_id_success():
    event_dict = {}
    mock_tracing = Mock()
    mock_tracing.get_correlation_id.return_value = "test-trace-id-123"
    
    # Aseguramos que 'app' existe como módulo para evitar AttributeError
    if 'app' not in sys.modules:
        sys.modules['app'] = Mock()
    
    # Mockeamos app.tracing en sys.modules
    with patch.dict(sys.modules, {'app.tracing': mock_tracing}):
        result = add_correlation_id(None, None, event_dict)
        assert result.get("correlation_id") == "test-trace-id-123"

def test_add_correlation_id_none():
    event_dict = {}
    mock_tracing = Mock()
    mock_tracing.get_correlation_id.return_value = None
    
    if 'app' not in sys.modules:
        sys.modules['app'] = Mock()

    with patch.dict(sys.modules, {'app.tracing': mock_tracing}):
        result = add_correlation_id(None, None, event_dict)
        assert "correlation_id" not in result

def test_redact_sensitive_data():
    # Test data with various sensitive fields
    event_dict = {
        "event": 'User login attempt. Context: "password": "secret123"', 
        "api_key": '"sk_live_123abc"',
        "nested": '{"token": "jwt.token.here"}',
        "safe_field": "safe_value",
        "non_string": 123
    }
    
    result = redact_sensitive_data(None, None, event_dict)
    
    # Check redactions
    assert 'password": "[REDACTED]"' in result["event"]
    assert 'sk_live_[REDACTED]' in result["api_key"] or '[REDACTED]' in result["api_key"]
    assert 'token": "[REDACTED]"' in result["nested"]
    assert result["safe_field"] == "safe_value"
    assert result["non_string"] == 123

def test_drop_debug_in_production():
    event_dict = {"event": "debug info"}
    
    # Case 1: Production + Debug -> Drop
    with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
        with pytest.raises(structlog.DropEvent):
            drop_debug_in_production(None, "debug", event_dict)

    # Case 2: Production + Info -> Keep
    with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
        result = drop_debug_in_production(None, "info", event_dict)
        assert result == event_dict

    # Case 3: Development + Debug -> Keep
    with patch.dict(os.environ, {"ENVIRONMENT": "development"}):
        result = drop_debug_in_production(None, "debug", event_dict)
        assert result == event_dict

# =============================================================================
# SETUP TESTS
# =============================================================================

def test_setup_structured_logging_disabled():
    with patch.dict(os.environ, {"STRUCTURED_LOGGING_ENABLED": "false"}):
        with patch('logging.basicConfig') as mock_basic_config:
            with patch('logging.info') as mock_info:
                setup_structured_logging()
                mock_basic_config.assert_not_called()
                mock_info.assert_called_with("Structured logging is disabled, using standard logging")

def test_setup_structured_logging_json():
    with patch.dict(os.environ, {
        "STRUCTURED_LOGGING_ENABLED": "true",
        "LOG_JSON_FORMAT": "true",
        "LOG_LEVEL": "INFO"
    }):
        with patch('logging.basicConfig') as mock_basic_config:
            with patch('structlog.configure') as mock_configure:
                setup_structured_logging()
                
                # Verify configuration
                mock_basic_config.assert_called_once()
                mock_configure.assert_called_once()
                
                # Inspect processors to verify JSONRenderer is added
                call_args = mock_configure.call_args[1]
                processors = call_args['processors']
                assert any(isinstance(p, structlog.processors.JSONRenderer) for p in processors)

def test_setup_structured_logging_console():
    with patch.dict(os.environ, {
        "STRUCTURED_LOGGING_ENABLED": "true",
        "LOG_JSON_FORMAT": "false"
    }):
        with patch('logging.basicConfig') as mock_basic_config:
            with patch('structlog.configure') as mock_configure:
                setup_structured_logging()
                
                # Inspect processors to verify ConsoleRenderer is added
                call_args = mock_configure.call_args[1]
                processors = call_args['processors']
                # ConsoleRenderer might be wrapped or checked by class name depending on version
                # Here we just check it's not JSONRenderer for sure
                assert not any(isinstance(p, structlog.processors.JSONRenderer) for p in processors)

# =============================================================================
# LOGGER FACTORY TESTS
# =============================================================================

def test_get_logger():
    # structlog.get_logger returns a FilteringBoundLogger or similar proxy
    logger = get_logger("test_logger")
    # Check it has standard logging methods
    assert hasattr(logger, "info")
    assert hasattr(logger, "error")
    assert hasattr(logger, "debug")

# =============================================================================
# CONTEXTUAL LOGGING TESTS
# =============================================================================

def test_log_context():
    with patch('structlog.contextvars.bind_contextvars') as mock_bind:
        with patch('structlog.contextvars.unbind_contextvars') as mock_unbind:
            
            # Test enter
            context_data = {"user_id": "123", "req_id": "abc"}
            with LogContext(**context_data):
                mock_bind.assert_called_with(**context_data)
            
            # Test exit
            mock_unbind.assert_called_with("user_id", "req_id")

# =============================================================================
# HELPER TESTS
# =============================================================================

@pytest.fixture
def mock_logger():
    return MagicMock()

def test_log_validation_attempt(mock_logger):
    log_validation_attempt(mock_logger, "test@example.com", "premium", True)
    mock_logger.info.assert_called_with(
        "validation_attempt",
        email_domain="example.com",
        user_plan="premium",
        smtp_enabled=True,
        validation_type="single"
    )
    
    # Test unknown domain
    log_validation_attempt(mock_logger, "invalid_email", "free")
    args = mock_logger.info.call_args[1]
    assert args["email_domain"] == "unknown"

def test_log_validation_result(mock_logger):
    log_validation_result(mock_logger, "test@example.com", True, 10, 150.5)
    mock_logger.info.assert_called_with(
        "validation_complete",
        email_domain="example.com",
        valid=True,
        risk_score=10,
        duration_ms=150.5,
        outcome="valid"
    )

    log_validation_result(mock_logger, "test@example.com", False, 90, 100.0)
    args = mock_logger.info.call_args[1]
    assert args["outcome"] == "invalid"

def test_log_cache_hit(mock_logger):
    log_cache_hit(mock_logger, "long_key_" * 10, "redis")
    mock_logger.debug.assert_called()
    args = mock_logger.debug.call_args[1]
    assert len(args["cache_key"]) <= 50
    assert args["cache_type"] == "redis"

def test_log_cache_miss(mock_logger):
    log_cache_miss(mock_logger, "key", "memory")
    mock_logger.debug.assert_called_with(
        "cache_miss",
        cache_key="key",
        cache_type="memory"
    )

def test_log_smtp_check(mock_logger):
    log_smtp_check(mock_logger, "mx.google.com", "user@gmail.com", True, 200.0, 250)
    mock_logger.info.assert_called_with(
        "smtp_verification",
        mx_host="mx.google.com",
        email_domain="gmail.com",
        success=True,
        duration_ms=200.0,
        smtp_response_code=250
    )

def test_log_batch_job_created(mock_logger):
    log_batch_job_created(mock_logger, "job_123", 1000, "user_1", "pro")
    mock_logger.info.assert_called_with(
        "batch_job_created",
        job_id="job_123",
        email_count=1000,
        user_id="user_1",
        user_plan="pro",
        job_type="email_validation"
    )

def test_log_batch_job_completed(mock_logger):
    # Case 1: Normal duration
    log_batch_job_completed(mock_logger, "job_123", 100, 90, 2.0)
    args = mock_logger.info.call_args[1]
    assert args["emails_per_second"] == 50.0
    assert args["invalid_count"] == 10

    # Case 2: Zero duration
    log_batch_job_completed(mock_logger, "job_123", 100, 90, 0.0)
    args = mock_logger.info.call_args[1]
    assert args["emails_per_second"] == 0

def test_log_api_key_created(mock_logger):
    log_api_key_created(mock_logger, "u1", "test_key", "free")
    mock_logger.info.assert_called_with(
        "api_key_created",
        user_id="u1",
        key_name="test_key",
        user_plan="free",
        event_type="security_audit"
    )

def test_log_api_key_rotation(mock_logger):
    log_api_key_rotation(mock_logger, "u1", "old_long_key_12345", "new_long_key_67890")
    args = mock_logger.info.call_args[1]
    assert args["old_key_id"] == "old_long" # First 8 chars
    assert args["new_key_id"] == "new_long"

def test_log_rate_limit_exceeded(mock_logger):
    log_rate_limit_exceeded(mock_logger, "u1", "/api/validate", 100, 60)
    mock_logger.warning.assert_called_with(
        "rate_limit_exceeded",
        user_id="u1",
        endpoint="/api/validate",
        limit=100,
        window_seconds=60,
        event_type="security_event"
    )

def test_log_authentication_failure(mock_logger):
    log_authentication_failure(mock_logger, "u@e.com", "bad_pass", "1.1.1.1")
    mock_logger.warning.assert_called_with(
        "authentication_failed",
        email="u@e.com",
        reason="bad_pass",
        ip_address="1.1.1.1",
        event_type="security_audit"
    )

def test_log_webhook_sent(mock_logger):
    url = "https://webhook.site/very-long-url-that-should-be-truncated-for-security-logs"
    log_webhook_sent(mock_logger, url, "validation_completed", True, 200, 50)
    args = mock_logger.info.call_args[1]
    assert len(args["webhook_url"]) <= 50
    assert args["success"] is True

# =============================================================================
# ERROR LOGGING TESTS
# =============================================================================

def test_log_error_with_context(mock_logger):
    error = ValueError("Invalid input")
    context = {"request_id": "123"}
    
    # Default severity (error)
    log_error_with_context(mock_logger, error, context)
    mock_logger.error.assert_called_with(
        "error_occurred",
        error_type="ValueError",
        error_message="Invalid input",
        request_id="123"
    )

    # Custom severity (warning)
    log_error_with_context(mock_logger, error, context, severity="warning")
    mock_logger.warning.assert_called()

# =============================================================================
# PERFORMANCE LOGGING TESTS
# =============================================================================

def test_performance_logger_success(mock_logger):
    with patch('app.structured_logging.datetime') as mock_datetime:
        # Mock time passage
        start_time = datetime(2023, 1, 1, 12, 0, 0)
        end_time = datetime(2023, 1, 1, 12, 0, 1) # 1 second later
        mock_datetime.utcnow.side_effect = [start_time, end_time]
        
        with PerformanceLogger(mock_logger, "db_query", table="users"):
            pass # Operation successful
            
        # Check start log
        mock_logger.debug.assert_called_with("db_query_started", table="users")
        
        # Check end log
        mock_logger.info.assert_called_with(
            "db_query_completed",
            duration_ms=1000.0,
            table="users"
        )

def test_performance_logger_failure(mock_logger):
    with patch('app.structured_logging.datetime') as mock_datetime:
        start_time = datetime(2023, 1, 1, 12, 0, 0)
        end_time = datetime(2023, 1, 1, 12, 0, 1)
        mock_datetime.utcnow.side_effect = [start_time, end_time]
        
        try:
            with PerformanceLogger(mock_logger, "db_query", table="users"):
                raise ValueError("Connection failed")
        except ValueError:
            pass
            
        # Check failure log
        mock_logger.error.assert_called_with(
            "db_query_failed",
            duration_ms=1000.0,
            error_type="ValueError",
            error_message="Connection failed",
            table="users"
        )

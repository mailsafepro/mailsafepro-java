"""
Structured Logging Module

Enterprise-grade structured logging with:
- JSON output for log aggregation (ELK, Loki, CloudWatch)
- Correlation ID propagation from tracing
- Contextual logging with bound loggers
- Performance-optimized with log sampling
- Sensitive data redaction
"""

from __future__ import annotations

import logging
import sys
import os
from typing import Any, Dict, Optional
from datetime import datetime
import re

import structlog
from structlog.contextvars import merge_contextvars
from pythonjsonlogger import jsonlogger

# =============================================================================
# CONFIGURATION
# =============================================================================

class StructuredLoggingConfig:
    """Configuration for structured logging."""
    
    def __init__(self):
        self.enabled = os.getenv("STRUCTURED_LOGGING_ENABLED", "true").lower() == "true"
        self.log_level = os.getenv("LOG_LEVEL", "INFO").upper()
        self.json_format = os.getenv("LOG_JSON_FORMAT", "true").lower() == "true"
        self.include_caller = os.getenv("LOG_INCLUDE_CALLER", "true").lower() == "true"
        
        # Sensitive data patterns to redact
        self.redact_patterns = [
            (re.compile(r'"password"\s*:\s*"[^"]*"'), '"password": "[REDACTED]"'),
            (re.compile(r'"api_key"\s*:\s*"[^"]*"'), '"api_key": "[REDACTED]"'),
            (re.compile(r'"secret"\s*:\s*"[^"]*"'), '"secret": "[REDACTED]"'),
            (re.compile(r'"token"\s*:\s*"[^"]*"'), '"token": "[REDACTED]"'),
            (re.compile(r'sk_live_[a-zA-Z0-9]+'), 'sk_live_[REDACTED]'),
            (re.compile(r'pk_live_[a-zA-Z0-9]+'), 'pk_live_[REDACTED]'),
        ]


# =============================================================================
# PROCESSORS
# =============================================================================

def add_timestamp(logger: Any, method_name: str, event_dict: Dict) -> Dict:
    """Add ISO8601 timestamp to log events."""
    event_dict["timestamp"] = datetime.utcnow().isoformat() + "Z"
    return event_dict


def add_log_level(logger: Any, method_name: str, event_dict: Dict) -> Dict:
    """Add log level to event dict."""
    event_dict["level"] = method_name.upper()
    return event_dict


def add_logger_name(logger: Any, method_name: str, event_dict: Dict) -> Dict:
    """Add logger name to event dict."""
    record = event_dict.get("_record")
    if record:
        event_dict["logger"] = record.name
    return event_dict


def add_correlation_id(logger: Any, method_name: str, event_dict: Dict) -> Dict:
    """Add correlation ID from tracing context if available."""
    try:
        from app.tracing import get_correlation_id
        correlation_id = get_correlation_id()
        if correlation_id:
            event_dict["correlation_id"] = correlation_id
    except Exception:
        pass
    
    return event_dict


def redact_sensitive_data(logger: Any, method_name: str, event_dict: Dict) -> Dict:
    """Redact sensitive data from logs."""
    config = StructuredLoggingConfig()
    
    # Redact from event message
    event = event_dict.get("event", "")
    if isinstance(event, str):
        for pattern, replacement in config.redact_patterns:
            event = pattern.sub(replacement, event)
        event_dict["event"] = event
    
    # Redact from other string fields
    for key, value in event_dict.items():
        if isinstance(value, str):
            for pattern, replacement in config.redact_patterns:
                value = pattern.sub(replacement, value)
            event_dict[key] = value
    
    return event_dict


def drop_debug_in_production(logger: Any, method_name: str, event_dict: Dict) -> Dict:
    """Drop DEBUG logs in production for performance."""
    if os.getenv("ENVIRONMENT") == "production" and method_name == "debug":
        raise structlog.DropEvent
    return event_dict


# =============================================================================
# SETUP
# =============================================================================

def setup_structured_logging() -> None:
    """Initialize structured logging with JSON output."""
    config = StructuredLoggingConfig()
    
    if not config.enabled:
        logging.info("Structured logging is disabled, using standard logging")
        return
    
    # Configure stdlib logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, config.log_level),
    )
    
    # Build processor chain
    processors = [
        # Contextvars must come first
        merge_contextvars,
        # Add custom fields
        add_timestamp,
        add_log_level,
        add_logger_name,
        add_correlation_id,
        # Security
        redact_sensitive_data,
        # Performance
        drop_debug_in_production,
        # Stack info and exception formatting
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        # Rendering
        structlog.processors.UnicodeDecoder(),
    ]
    
    if config.json_format:
        # JSON output for production
        processors.append(structlog.processors.JSONRenderer())
    else:
        # Pretty console output for development
        processors.append(structlog.dev.ConsoleRenderer(colors=True))
    
    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, config.log_level)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    logging.info(
        f"✅ Structured logging initialized "
        f"(level={config.log_level}, json={config.json_format})"
    )


# =============================================================================
# LOGGER FACTORY
# =============================================================================

def get_logger(name: str = __name__) -> structlog.BoundLogger:
    """
    Get a structured logger instance.
    
    Usage:
        logger = get_logger(__name__)
        logger.info("user_logged_in", user_id=user_id, plan=plan)
    """
    return structlog.get_logger(name)


# =============================================================================
# CONTEXTUAL LOGGING
# =============================================================================

class LogContext:
    """
    Context manager for adding contextual information to all logs within scope.
    
    Usage:
        with LogContext(user_id=user_id, request_id=request_id):
            logger.info("processing_request")  # Includes user_id and request_id
    """
    
    def __init__(self, **kwargs):
        self.context = kwargs
        self.clear_token = None
    
    def __enter__(self):
        self.clear_token = structlog.contextvars.bind_contextvars(**self.context)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.clear_token:
            structlog.contextvars.unbind_contextvars(*self.context.keys())


# =============================================================================
# BUSINESS-SPECIFIC LOGGING HELPERS
# =============================================================================

def log_validation_attempt(
    logger: structlog.BoundLogger,
    email: str,
    plan: str,
    check_smtp: bool = False
):
    """Log email validation attempt with business context."""
    domain = email.split("@")[1] if "@" in email else "unknown"
    
    logger.info(
        "validation_attempt",
        email_domain=domain,
        user_plan=plan,
        smtp_enabled=check_smtp,
        validation_type="single"
    )


def log_validation_result(
    logger: structlog.BoundLogger,
    email: str,
    valid: bool,
    risk_score: int,
    duration_ms: float
):
    """Log validation result with metrics."""
    domain = email.split("@")[1] if "@" in email else "unknown"
    
    logger.info(
        "validation_complete",
        email_domain=domain,
        valid=valid,
        risk_score=risk_score,
        duration_ms=round(duration_ms, 2),
        outcome="valid" if valid else "invalid"
    )


def log_cache_hit(
    logger: structlog.BoundLogger,
    cache_key: str,
    cache_type: str = "redis"
):
    """Log cache hit for performance monitoring."""
    logger.debug(
        "cache_hit",
        cache_key=cache_key[:50],  # Truncate for readability
        cache_type=cache_type
    )


def log_cache_miss(
    logger: structlog.BoundLogger,
    cache_key: str,
    cache_type: str = "redis"
):
    """Log cache miss for monitoring."""
    logger.debug(
        "cache_miss",
        cache_key=cache_key[:50],
        cache_type=cache_type
    )


def log_smtp_check(
    logger: structlog.BoundLogger,
    mx_host: str,
    email: str,
    success: bool,
    duration_ms: float,
    response_code: Optional[int] = None
):
    """Log SMTP verification attempt."""
    logger.info(
        "smtp_verification",
        mx_host=mx_host,
        email_domain=email.split("@")[1] if "@" in email else "unknown",
        success=success,
        duration_ms=round(duration_ms, 2),
        smtp_response_code=response_code
    )


def log_batch_job_created(
    logger: structlog.BoundLogger,
    job_id: str,
    email_count: int,
    user_id: str,
    plan: str
):
    """Log batch job creation."""
    logger.info(
        "batch_job_created",
        job_id=job_id,
        email_count=email_count,
        user_id=user_id,
        user_plan=plan,
        job_type="email_validation"
    )


def log_batch_job_completed(
    logger: structlog.BoundLogger,
    job_id: str,
    email_count: int,
    valid_count: int,
    duration_seconds: float
):
    """Log batch job completion."""
    logger.info(
        "batch_job_completed",
        job_id=job_id,
        email_count=email_count,
        valid_count=valid_count,
        invalid_count=email_count - valid_count,
        duration_seconds=round(duration_seconds, 2),
        emails_per_second=round(email_count / duration_seconds, 2) if duration_seconds > 0 else 0
    )


def log_api_key_created(
    logger: structlog.BoundLogger,
    user_id: str,
    key_name: str,
    plan: str
):
    """Log API key creation (security audit)."""
    logger.info(
        "api_key_created",
        user_id=user_id,
        key_name=key_name,
        user_plan=plan,
        event_type="security_audit"
    )


def log_api_key_rotation(
    logger: structlog.BoundLogger,
    user_id: str,
    old_key_id: str,
    new_key_id: str
):
    """Log API key rotation (security audit)."""
    logger.info(
        "api_key_rotated",
        user_id=user_id,
        old_key_id=old_key_id[:8],  # Only log prefix for security
        new_key_id=new_key_id[:8],
        event_type="security_audit"
    )


def log_rate_limit_exceeded(
    logger: structlog.BoundLogger,
    user_id: str,
    endpoint: str,
    limit: int,
    window_seconds: int
):
    """Log rate limit exceeded event."""
    logger.warning(
        "rate_limit_exceeded",
        user_id=user_id,
        endpoint=endpoint,
        limit=limit,
        window_seconds=window_seconds,
        event_type="security_event"
    )


def log_authentication_failure(
    logger: structlog.BoundLogger,
    email: str,
    reason: str,
    ip_address: str
):
    """Log failed authentication attempt (security audit)."""
    logger.warning(
        "authentication_failed",
        email=email,
        reason=reason,
        ip_address=ip_address,
        event_type="security_audit"
    )


def log_webhook_sent(
    logger: structlog.BoundLogger,
    webhook_url: str,
    event_type: str,
    success: bool,
    response_code: Optional[int] = None,
    duration_ms: float = 0
):
    """Log webhook delivery attempt."""
    logger.info(
        "webhook_sent",
        webhook_url=webhook_url[:50],  # Truncate for security
        event_type=event_type,
        success=success,
        http_status=response_code,
        duration_ms=round(duration_ms, 2)
    )


# =============================================================================
# ERROR LOGGING WITH STRUCTURED DATA
# =============================================================================

def log_error_with_context(
    logger: structlog.BoundLogger,
    error: Exception,
    context: Dict[str, Any],
    severity: str = "error"
):
    """
    Log an error with rich contextual information.
    
    Args:
        logger: Structured logger instance
        error: Exception that occurred
        context: Dict with contextual information (user_id, request_id, etc.)
        severity: Log severity (error, critical)
    """
    log_func = getattr(logger, severity, logger.error)
    
    log_func(
        "error_occurred",
        error_type=type(error).__name__,
        error_message=str(error),
        **context
    )


# =============================================================================
# PERFORMANCE LOGGING
# =============================================================================

class PerformanceLogger:
    """
    Context manager for logging operation performance.
    
    Usage:
        with PerformanceLogger(logger, "database_query", user_id=user_id):
            result = await db.query(...)
    """
    
    def __init__(
        self,
        logger: structlog.BoundLogger,
        operation: str,
        **context
    ):
        self.logger = logger
        self.operation = operation
        self.context = context
        self.start_time = None
    
    def __enter__(self):
        self.start_time = datetime.utcnow()
        self.logger.debug(f"{self.operation}_started", **self.context)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = (datetime.utcnow() - self.start_time).total_seconds() * 1000
        
        if exc_type:
            self.logger.error(
                f"{self.operation}_failed",
                duration_ms=round(duration, 2),
                error_type=exc_type.__name__,
                error_message=str(exc_val),
                **self.context
            )
        else:
            self.logger.info(
                f"{self.operation}_completed",
                duration_ms=round(duration, 2),
                **self.context
            )

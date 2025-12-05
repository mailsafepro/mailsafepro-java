"""
Enhanced Error Handling and Categorization

Provides intelligent error categorization, retry strategies, and user-friendly
error responses for production-grade error handling.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional, Dict, Any, Callable
from dataclasses import dataclass
import asyncio

from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
    after_log
)
import logging

# =============================================================================
# ERROR CATEGORIES
# =============================================================================

class ErrorCategory(str, Enum):
    """Categorized error types for better handling and monitoring."""
    
    # Client Errors (4xx) - User's fault
    VALIDATION_ERROR = "validation_error"  # Invalid input
    AUTHENTICATION_ERROR = "authentication_error"  # Invalid credentials
    AUTHORIZATION_ERROR = "authorization_error"  # Insufficient permissions
    RATE_LIMIT_ERROR = "rate_limit_error"  # Too many requests
    QUOTA_EXCEEDED = "quota_exceeded"  # Plan limit reached
    NOT_FOUND = "not_found"  # Resource not found
    
    # Server Errors (5xx) - Our fault
    INTERNAL_ERROR = "internal_error"  # Unexpected server error
    DATABASE_ERROR = "database_error"  # Redis/DB issues
    EXTERNAL_SERVICE_ERROR = "external_service_error"  # Third-party API failed
    TIMEOUT_ERROR = "timeout_error"  # Operation timed out
    CIRCUIT_BREAKER_OPEN = "circuit_breaker_open"  # Service degraded
    
    # Domain-specific Errors
    DNS_ERROR = "dns_error"  # DNS lookup failed
    SMTP_ERROR = "smtp_error"  # SMTP verification failed
    NETWORK_ERROR = "network_error"  # Network connectivity issues


class ErrorSeverity(str, Enum):
    """Error severity levels for alerting and monitoring."""
    
    LOW = "low"  # Expected errors, no action needed
    MEDIUM = "medium"  # Unusual but manageable
    HIGH = "high"  # Requires attention
    CRITICAL = "critical"  # Immediate action required


# =============================================================================
# ERROR MODELS
# =============================================================================

@dataclass
class CategorizedError:
    """Enhanced error with category, severity, and retry information."""
    
    category: ErrorCategory
    severity: ErrorSeverity
    message: str
    details: Optional[Dict[str, Any]] = None
    is_retryable: bool = False
    suggested_action: Optional[str] = None
    http_status: int = 500
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "error": {
                "category": self.category.value,
                "severity": self.severity.value,
                "message": self.message,
                "details": self.details or {},
                "retryable": self.is_retryable,
                "suggested_action": self.suggested_action,
            }
        }


# =============================================================================
# ERROR CATEGORIZER
# =============================================================================

class ErrorCategorizer:
    """Intelligently categorize exceptions into business domains."""
    
    @staticmethod
    def categorize(exception: Exception) -> CategorizedError:
        """
        Categorize an exception into a CategorizedError.
        
        Args:
            exception: The exception to categorize
            
        Returns:
            CategorizedError with category, severity, and retry strategy
        """
        error_name = type(exception).__name__
        error_msg = str(exception).lower()
        
        # DNS Errors
        if any(x in error_name.lower() for x in ["dns", "nxdomain", "resolution"]):
            return CategorizedError(
                category=ErrorCategory.DNS_ERROR,
                severity=ErrorSeverity.LOW,
                message="DNS lookup failed. Domain may not exist or DNS server is unavailable.",
                details={"error_type": error_name, "original_message": str(exception)},
                is_retryable=True,
                suggested_action="Verify domain exists and try again in a few seconds.",
                http_status=503
            )
        
        # SMTP Errors
        if any(x in error_name.lower() for x in ["smtp", "smtplib"]):
            return CategorizedError(
                category=ErrorCategory.SMTP_ERROR,
                severity=ErrorSeverity.MEDIUM,
                message="SMTP verification failed. Mailbox may not exist or server is temporarily unavailable.",
                details={"error_type": error_name, "original_message": str(exception)},
                is_retryable=True,
                suggested_action="This is expected for some providers that block SMTP checks. Domain validation is still reliable.",
                http_status=503
            )
        
        # Timeout Errors
        if any(x in error_name.lower() for x in ["timeout", "asyncio.timeout"]):
            return CategorizedError(
                category=ErrorCategory.TIMEOUT_ERROR,
                severity=ErrorSeverity.HIGH,
                message="Operation timed out. Service may be experiencing high load.",
                details={"error_type": error_name},
                is_retryable=True,
                suggested_action="Try again with a larger timeout or retry later.",
                http_status=504
            )
        
        # Network Errors
        if any(x in error_msg for x in ["connection", "network", "unreachable", "refused"]):
            return CategorizedError(
                category=ErrorCategory.NETWORK_ERROR,
                severity=ErrorSeverity.HIGH,
                message="Network connectivity issue. Unable to reach external service.",
                details={"error_type": error_name, "original_message": str(exception)},
                is_retryable=True,
                suggested_action="Check network connectivity and firewall settings.",
                http_status=503
            )
        
        # Redis/Database Errors
        if any(x in error_name.lower() for x in ["redis", "connection", "database"]):
            return CategorizedError(
                category=ErrorCategory.DATABASE_ERROR,
                severity=ErrorSeverity.CRITICAL,
                message="Database connection error. Service degraded.",
                details={"error_type": error_name},
                is_retryable=True,
                suggested_action="System administrators have been notified. Please try again shortly.",
                http_status=503
            )
        
        # Rate Limiting
        if any(x in error_msg for x in ["rate limit", "too many requests", "quota"]):
            return CategorizedError(
                category=ErrorCategory.RATE_LIMIT_ERROR,
                severity=ErrorSeverity.LOW,
                message="Rate limit exceeded. Please slow down requests.",
                details={"error_type": error_name},
                is_retryable=False,
                suggested_action="Wait for the rate limit window to reset or upgrade your plan.",
                http_status=429
            )
        
        # Validation Errors
        if any(x in error_name.lower() for x in ["validation", "valueerror", "typeerror"]):
            return CategorizedError(
                category=ErrorCategory.VALIDATION_ERROR,
                severity=ErrorSeverity.LOW,
                message="Invalid input data. Please check your request.",
                details={"error_type": error_name, "original_message": str(exception)},
                is_retryable=False,
                suggested_action="Review API documentation and correct your request parameters.",
                http_status=400
            )
        
        # Authentication Errors
        if any(x in error_msg for x in ["unauthorized", "authentication", "invalid credentials"]):
            return CategorizedError(
                category=ErrorCategory.AUTHENTICATION_ERROR,
                severity=ErrorSeverity.MEDIUM,
                message="Authentication failed. Invalid or expired credentials.",
                details={"error_type": error_name},
                is_retryable=False,
                suggested_action="Verify your API key or JWT token is valid and not expired.",
                http_status=401
            )
        
        # Authorization Errors
        if any(x in error_msg for x in ["forbidden", "permission", "access denied"]):
            return CategorizedError(
                category=ErrorCategory.AUTHORIZATION_ERROR,
                severity=ErrorSeverity.MEDIUM,
                message="Insufficient permissions for this operation.",
                details={"error_type": error_name},
                is_retryable=False,
                suggested_action="Upgrade your plan or contact support for access to this feature.",
                http_status=403
            )
        
        # Default: Internal Error
        return CategorizedError(
            category=ErrorCategory.INTERNAL_ERROR,
            severity=ErrorSeverity.HIGH,
            message="An unexpected error occurred. Our team has been notified.",
            details={
                "error_type": error_name,
                "original_message": str(exception)[:200]  # Truncate for security
            },
            is_retryable=True,
            suggested_action="If this persists, please contact support with the error details.",
            http_status=500
        )


# =============================================================================
# RETRY STRATEGIES
# =============================================================================

class RetryStrategy:
    """Configurable retry strategies for different error categories."""
    
    # DNS lookups: Fast retry with short backoff
    DNS_RETRY = retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.5, min=0.5, max=2),
        retry=retry_if_exception_type((OSError, asyncio.TimeoutError)),
        before_sleep=before_sleep_log(logging.getLogger(__name__), logging.DEBUG),
        reraise=True
    )
    
    # SMTP verification: Slower retry with longer backoff
    SMTP_RETRY = retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=1, min=1, max=5),
        retry=retry_if_exception_type((ConnectionError, asyncio.TimeoutError)),
        before_sleep=before_sleep_log(logging.getLogger(__name__), logging.DEBUG),
        reraise=True
    )
    
    # External API calls: Moderate retry
    EXTERNAL_API_RETRY = retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type((ConnectionError, asyncio.TimeoutError)),
        before_sleep=before_sleep_log(logging.getLogger(__name__), logging.INFO),
        reraise=True
    )
    
    # Database operations: Aggressive retry
    DATABASE_RETRY = retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=0.5, min=0.5, max=3),
        retry=retry_if_exception_type((ConnectionError, OSError)),
        before_sleep=before_sleep_log(logging.getLogger(__name__), logging.WARNING),
        reraise=True
    )


def with_retry(strategy: str = "default"):
    """
    Decorator to apply retry strategy to functions.
    
    Usage:
        @with_retry("dns")
        async def lookup_dns(domain):
            ...
    """
    strategies = {
        "dns": RetryStrategy.DNS_RETRY,
        "smtp": RetryStrategy.SMTP_RETRY,
        "api": RetryStrategy.EXTERNAL_API_RETRY,
        "database": RetryStrategy.DATABASE_RETRY,
    }
    
    return strategies.get(strategy, RetryStrategy.EXTERNAL_API_RETRY)


# =============================================================================
# ERROR HANDLER DECORATOR
# =============================================================================

def handle_errors(
    categorize: bool = True,
    log_errors: bool = True,
    fallback_value: Any = None
):
    """
    Decorator for automatic error handling with categorization.
    
    Args:
        categorize: Whether to categorize errors
        log_errors: Whether to log errors
        fallback_value: Value to return on error (instead of raising)
    
    Usage:
        @handle_errors(categorize=True, log_errors=True)
        async def my_function():
            ...
    """
    def decorator(func: Callable):
        async def async_wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                if log_errors:
                    from app.structured_logging import get_logger
                    logger = get_logger(__name__)
                    logger.error(
                        "function_error",
                        function=func.__name__,
                        error_type=type(e).__name__,
                        error_message=str(e)
                    )
                
                if categorize:
                    categorized = ErrorCategorizer.categorize(e)
                    if fallback_value is not None:
                        return fallback_value
                    raise categorized
                else:
                    if fallback_value is not None:
                        return fallback_value
                    raise
        
        def sync_wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if log_errors:
                    from app.structured_logging import get_logger
                    logger = get_logger(__name__)
                    logger.error(
                        "function_error",
                        function=func.__name__,
                        error_type=type(e).__name__,
                        error_message=str(e)
                    )
                
                if categorize:
                    categorized = ErrorCategorizer.categorize(e)
                    if fallback_value is not None:
                        return fallback_value
                    raise categorized
                else:
                    if fallback_value is not None:
                        return fallback_value
                    raise
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


# =============================================================================
# ERROR METRICS
# =============================================================================

class ErrorMetrics:
    """Track error rates and patterns for monitoring."""
    
    error_counts: Dict[str, int] = {}
    
    @classmethod
    def record_error(cls, category: ErrorCategory, severity: ErrorSeverity):
        """Record an error occurrence for metrics."""
        key = f"{category.value}:{severity.value}"
        cls.error_counts[key] = cls.error_counts.get(key, 0) + 1
    
    @classmethod
    def get_stats(cls) -> Dict[str, Any]:
        """Get error statistics."""
        return {
            "error_counts": cls.error_counts,
            "total_errors": sum(cls.error_counts.values()),
        }
    
    @classmethod
    def reset(cls):
        """Reset error counters."""
        cls.error_counts = {}

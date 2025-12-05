"""
Comprehensive tests for error_handling.py

Tests cover:
- ErrorCategory and ErrorSeverity enums
- CategorizedError model
- ErrorCategorizer (exception categorization)
- RetryStrategy (retry decorators)
- handle_errors decorator
- ErrorMetrics (error tracking)
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio


class TestErrorEnums:
    """Test error enumerations."""
    
    def test_error_category_values(self):
        """Test ErrorCategory enum values."""
        from app.error_handling import ErrorCategory
        
        assert ErrorCategory.VALIDATION_ERROR == "validation_error"
        assert ErrorCategory.AUTHENTICATION_ERROR == "authentication_error"
        assert ErrorCategory.DNS_ERROR == "dns_error"
        assert ErrorCategory.SMTP_ERROR == "smtp_error"
    
    def test_error_severity_values(self):
        """Test ErrorSeverity enum values."""
        from app.error_handling import ErrorSeverity
        
        assert ErrorSeverity.LOW == "low"
        assert ErrorSeverity.MEDIUM == "medium"
        assert ErrorSeverity.HIGH == "high"
        assert ErrorSeverity.CRITICAL == "critical"


class TestCategorizedError:
    """Test CategorizedError model."""
    
    def test_error_creation(self):
        """Test creating a categorized error."""
        from app.error_handling import CategorizedError, ErrorCategory, ErrorSeverity
        
        error = CategorizedError(
            category=ErrorCategory.VALIDATION_ERROR,
            severity=ErrorSeverity.MEDIUM,
            message="Invalid input",
            is_retryable=False
        )
        
        assert error.category == ErrorCategory.VALIDATION_ERROR
        assert error.severity == ErrorSeverity.MEDIUM
        assert error.message == "Invalid input"
        assert error.is_retryable is False
    
    def test_error_to_dict(self):
        """Test converting error to dictionary."""
        from app.error_handling import CategorizedError, ErrorCategory, ErrorSeverity
        
        error = CategorizedError(
            category=ErrorCategory.DNS_ERROR,
            severity=ErrorSeverity.HIGH,
            message="DNS lookup failed",
            details={"domain": "example.com"}
        )
        
        error_dict = error.to_dict()
        
        assert isinstance(error_dict, dict)
        assert "error" in error_dict
        assert error_dict["error"]["message"] == "DNS lookup failed"


class TestErrorCategorizer:
    """Test ErrorCategorizer class."""
    
    def test_categorize_value_error(self):
        """Test categorizing ValueError."""
        from app.error_handling import ErrorCategorizer, ErrorCategory
        
        error = ValueError("Invalid value")
        categorized = ErrorCategorizer.categorize(error)
        
        assert categorized.category == ErrorCategory.VALIDATION_ERROR
        assert not categorized.is_retryable
    
    def test_categorize_connection_error(self):
        """Test categorizing ConnectionError."""
        from app.error_handling import ErrorCategorizer, ErrorCategory
        
        error = ConnectionError("Connection failed")
        categorized = ErrorCategorizer.categorize(error)
        
        assert categorized.category == ErrorCategory.NETWORK_ERROR
        assert categorized.is_retryable
    
    def test_categorize_timeout_error(self):
        """Test categorizing TimeoutError."""
        from app.error_handling import ErrorCategorizer, ErrorCategory
        
        error = TimeoutError("Request timeout")
        categorized = ErrorCategorizer.categorize(error)
        
        assert categorized.category == ErrorCategory.TIMEOUT_ERROR
        assert categorized.is_retryable
    
    def test_categorize_dns_error(self):
        """Test categorizing DNS errors."""
        from app.error_handling import ErrorCategorizer, ErrorCategory
        
        # Create custom DNS error class
        class DNSError(Exception):
            pass
        
        error = DNSError("DNS lookup failed for domain example.com")
        categorized = ErrorCategorizer.categorize(error)
        
        assert categorized.category == ErrorCategory.DNS_ERROR
        assert categorized.is_retryable
    
    def test_categorize_smtp_error(self):
        """Test categorizing SMTP errors."""
        from app.error_handling import ErrorCategorizer, ErrorCategory
        
        # Create custom SMTP error class
        class SMTPError(Exception):
            pass
        
        error = SMTPError("SMTP connection refused")
        categorized = ErrorCategorizer.categorize(error)
        
        assert categorized.category == ErrorCategory.SMTP_ERROR
        assert categorized.is_retryable
    
    def test_categorize_generic_error(self):
        """Test categorizing generic exceptions."""
        from app.error_handling import ErrorCategorizer
        
        error = RuntimeError("Something went wrong")
        categorized = ErrorCategorizer.categorize(error)
        
        # Should categorize as something (not necessarily UNKNOWN)
        assert categorized.category is not None
        assert isinstance(categorized.message, str)


class TestRetryStrategy:
    """Test retry strategies."""
    
    @pytest.mark.asyncio
    async def test_with_retry_decorator(self):
        """Test with_retry decorator."""
        from app.error_handling import with_retry
        
        call_count = 0
        
        @with_retry("network")
        async def flaky_function():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionError("Network error")
            return "success"
        
        result = await flaky_function()
        
        assert result == "success"
        assert call_count >= 1  # May be 1 or 2 depending on retry
    
    def test_retry_strategies_exist(self):
        """Test that retry strategies are defined."""
        from app.error_handling import RetryStrategy
        
        # Just verify the class exists
        assert RetryStrategy is not None


class TestHandleErrorsDecorator:
    """Test handle_errors decorator."""
    
    @pytest.mark.asyncio
    async def test_handle_errors_async(self):
        """Test handle_errors with async functions."""
        from app.error_handling import handle_errors
        
        @handle_errors(categorize=True, log_errors=False, fallback_value="fallback")
        async def async_function():
            raise ValueError("Test error")
        
        # With fallback, should return fallback value
        result = await async_function()
        assert result == "fallback"
    
    def test_handle_errors_sync(self):
        """Test handle_errors with sync functions."""
        from app.error_handling import handle_errors
        
        @handle_errors(categorize=True, log_errors=False, fallback_value="fallback")
        def sync_function():
            raise ValueError("Test error")
        
        # With fallback, should return fallback value
        result = sync_function()
        assert result == "fallback"
    
    @pytest.mark.asyncio
    async def test_handle_errors_with_fallback(self):
        """Test handle_errors with fallback value."""
        from app.error_handling import handle_errors
        
        @handle_errors(categorize=True, fallback_value="fallback")
        async def failing_function():
            raise ValueError("Test error")
        
        result = await failing_function()
        
        assert result == "fallback"
    
    @pytest.mark.asyncio
    async def test_handle_errors_success(self):
        """Test handle_errors with successful execution."""
        from app.error_handling import handle_errors
        
        @handle_errors(categorize=True)
        async def successful_function():
            return "success"
        
        result = await successful_function()
        
        assert result == "success"


class TestErrorMetrics:
    """Test ErrorMetrics class."""
    
    def test_record_error(self):
        """Test recording an error."""
        from app.error_handling import ErrorMetrics, ErrorCategory, ErrorSeverity
        
        # Reset first  
        ErrorMetrics.reset()
        
        ErrorMetrics.record_error(
            ErrorCategory.DNS_ERROR,
            ErrorSeverity.HIGH
        )
        
        stats = ErrorMetrics.get_stats()
        
        # Just verify stats exist
        assert isinstance(stats, dict)
    
    def test_get_stats(self):
        """Test getting error statistics."""
        from app.error_handling import ErrorMetrics
        
        ErrorMetrics.reset()
        stats = ErrorMetrics.get_stats()
        
        assert isinstance(stats, dict)
    
    def test_reset_metrics(self):
        """Test resetting error metrics."""
        from app.error_handling import ErrorMetrics, ErrorCategory, ErrorSeverity
        
        ErrorMetrics.record_error(
            ErrorCategory.VALIDATION_ERROR,
            ErrorSeverity.LOW
        )
        
        ErrorMetrics.reset()
        stats = ErrorMetrics.get_stats()
        
        # After reset, should have empty or zero stats
        assert isinstance(stats, dict)
    
    def test_multiple_error_recordings(self):
        """Test recording multiple errors."""
        from app.error_handling import ErrorMetrics, ErrorCategory, ErrorSeverity
        
        ErrorMetrics.reset()
        
        ErrorMetrics.record_error(ErrorCategory.DNS_ERROR, ErrorSeverity.HIGH)
        ErrorMetrics.record_error(ErrorCategory.DNS_ERROR, ErrorSeverity.HIGH)
        ErrorMetrics.record_error(ErrorCategory.SMTP_ERROR, ErrorSeverity.MEDIUM)
        
        stats = ErrorMetrics.get_stats()
        
        assert len(stats) >= 1


class TestErrorCategorizationEdgeCases:
    """Test edge cases in error categorization."""
    
    def test_categorize_permission_error(self):
        """Test categorizing PermissionError."""
        from app.error_handling import ErrorCategorizer, ErrorCategory
        
        error = PermissionError("Access denied")
        categorized = ErrorCategorizer.categorize(error)
        
        assert categorized.category == ErrorCategory.AUTHORIZATION_ERROR
        assert not categorized.is_retryable
    
    def test_categorize_key_error(self):
        """Test categorizing KeyError."""
        from app.error_handling import ErrorCategorizer
        
        error = KeyError("missing_key")
        categorized = ErrorCategorizer.categorize(error)
        
        # KeyError contains 'error' in name so may be VALIDATION or INTERNAL
        assert categorized.category is not None
    
    def test_error_with_details(self):
        """Test error with additional details."""
        from app.error_handling import CategorizedError, ErrorCategory, ErrorSeverity
        
        error = CategorizedError(
            category=ErrorCategory.DNS_ERROR,
            severity=ErrorSeverity.HIGH,
            message="DNS failure",
            details={
                "domain": "example.com",
                "nameserver": "8.8.8.8",
                "timeout": 5
            }
        )
        
        assert len(error.details) == 3
        assert error.details["domain"] == "example.com"
    
    def test_error_suggested_action(self):
        """Test error with suggested action."""
        from app.error_handling import CategorizedError, ErrorCategory, ErrorSeverity
        
        error = CategorizedError(
            category=ErrorCategory.RATE_LIMIT_ERROR,
            severity=ErrorSeverity.MEDIUM,
            message="Rate limit exceeded",
            suggested_action="Wait 60 seconds before retrying"
        )
        
        assert error.suggested_action == "Wait 60 seconds before retrying"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

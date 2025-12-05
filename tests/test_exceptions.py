"""
Tests para exceptions.py - Alcanzar 100% coverage
"""

import pytest
import json
from unittest.mock import Mock, patch
from fastapi import Request, status
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError

from app.exceptions import (
    APIException,
    ValidationException,
    AuthenticationException,
    AuthorizationException,
    RateLimitException,
    ServiceUnavailableException,
    ProblemDetail,
    api_exception_handler,
    validation_exception_handler,
    general_exception_handler,
    register_exception_handlers,
    _extract_plan_from_jwt,
    _record_error_metrics,
    _format_validation_errors
)


class TestAPIException:
    """Tests para APIException y subclases"""
    
    def test_api_exception_basic(self):
        exc = APIException(
            error_type="test_error",
            title="Test Error",
            detail="Test error detail",
            status_code=400
        )
        
        assert exc.error_type == "test_error"
        assert exc.title == "Test Error"
        assert exc.detail == "Test error detail"
        assert exc.status_code == 400
        assert str(exc) == "Test error detail"
    
    def test_api_exception_with_extensions(self):
        exc = APIException(
            detail="Test with extensions",
            extensions={"extra_field": "extra_value"}
        )
        
        assert exc.extensions["extra_field"] == "extra_value"
    
    def test_api_exception_to_problem_detail(self):
        exc = APIException(
            error_type="test_error",
            title="Test Error", 
            detail="Test detail",
            status_code=400
        )
        
        problem = exc.to_problem_detail(
            instance="/test",
            trace_id="test-trace-123",
            timestamp="2023-01-01T00:00:00Z"
        )
        
        assert problem.type == "test_error"
        assert problem.title == "Test Error"
        assert problem.status == 400
        assert problem.detail == "Test detail"
        assert problem.instance == "/test"
        assert problem.trace_id == "test-trace-123"
        assert problem.timestamp == "2023-01-01T00:00:00Z"
    
    def test_validation_exception(self):
        exc = ValidationException("Validation failed", errors=[{"field": "test", "error": "invalid"}])
        
        assert exc.error_type == "validation_error"
        assert exc.status_code == 422
        assert "errors" in exc.extensions
    
    def test_authentication_exception(self):
        exc = AuthenticationException("Auth failed")
        
        assert exc.error_type == "authentication_error"
        assert exc.status_code == 401
        assert "WWW-Authenticate" in exc.headers
    
    def test_authorization_exception(self):
        exc = AuthorizationException("Not allowed")
        
        assert exc.error_type == "authorization_error"
        assert exc.status_code == 403
    
    def test_rate_limit_exception(self):
        exc = RateLimitException("Too many requests", retry_after=60)
        
        assert exc.error_type == "rate_limit_exceeded"
        assert exc.status_code == 429
        assert exc.headers["Retry-After"] == "60"
    
    def test_service_unavailable_exception(self):
        exc = ServiceUnavailableException("Service down", service="redis")
        
        assert exc.error_type == "service_unavailable"
        assert exc.status_code == 503
        assert exc.extensions["service"] == "redis"


class TestProblemDetail:
    """Tests para el modelo ProblemDetail"""
    
    def test_problem_detail_basic(self):
        problem = ProblemDetail(
            type="test_type",
            title="Test Title",
            status=400,
            detail="Test detail",
            instance="/test"
        )
        
        assert problem.type == "test_type"
        assert problem.title == "Test Title"
        assert problem.status == 400
        assert problem.detail == "Test detail"
        assert problem.instance == "/test"
    
    def test_problem_detail_with_extensions(self):
        problem = ProblemDetail(
            type="test_type",
            title="Test Title",
            status=400,
            detail="Test detail",
            instance="/test",
            errors=[{"field": "email", "error": "invalid"}],
            client_plan="PREMIUM"
        )
        
        assert problem.errors[0]["field"] == "email"
        assert problem.client_plan == "PREMIUM"
    
    def test_problem_detail_dump_excludes_none(self):
        problem = ProblemDetail(
            type="test_type",
            title="Test Title", 
            status=400,
            detail="Test detail",
            instance="/test",
            trace_id=None,
            timestamp=None
        )
        
        data = problem.model_dump(exclude_none=True)
        assert "trace_id" not in data
        assert "timestamp" not in data


class TestExceptionHandlers:
    """Tests para los manejadores de excepciones"""
    
    @pytest.fixture
    def mock_request(self):
        request = Mock(spec=Request)
        request.url.path = "/test"
        request.headers = {}
        request.state.correlation_id = "test-correlation-123"
        return request
    
    @pytest.fixture
    def mock_metrics_recorder(self):
        with patch("app.exceptions.metrics_recorder") as mock:
            yield mock
    
    @pytest.mark.asyncio
    async def test_api_exception_handler(self, mock_request, mock_metrics_recorder):
        exc = APIException(
            error_type="test_error",
            title="Test Error",
            detail="Test error detail", 
            status_code=400,
            headers={"X-Test": "test"}
        )
        
        response = await api_exception_handler(mock_request, exc)
        
        assert response.status_code == 400
        content = json.loads(response.body)
        assert content["type"] == "test_error"
        assert content["detail"] == "Test error detail"
        assert response.headers["X-Test"] == "test"
    
    @pytest.mark.asyncio
    async def test_api_exception_handler_with_jwt_plan(self, mock_request, mock_metrics_recorder):
        # Mock JWT token with plan
        mock_request.headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwbGFuIjoiUFJFTUlVTSJ9.fake_signature"}
        
        exc = APIException(detail="Test error")
        
        response = await api_exception_handler(mock_request, exc)
        content = json.loads(response.body)
        
        assert content["client_plan"] == "PREMIUM"
    
    @pytest.mark.asyncio 
    async def test_validation_exception_handler(self, mock_request, mock_metrics_recorder):
        # Mock validation errors
        validation_errors = [
            {
                "loc": ("body", "email"),
                "msg": "Invalid email",
                "type": "value_error",
                "input": "invalid-email"
            }
        ]
        exc = RequestValidationError(validation_errors)
        
        response = await validation_exception_handler(mock_request, exc)
        
        assert response.status_code == 422
        content = json.loads(response.body)
        assert content["type"] == "validation_error"
        assert len(content["errors"]) == 1
        assert content["errors"][0]["field"] == "body.email"
    
    @pytest.mark.asyncio
    async def test_validation_exception_handler_with_jwt_plan(self, mock_request, mock_metrics_recorder):
        # Mock JWT token with plan
        mock_request.headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwbGFuIjoiRU5URVJQUklTRSJ9.fake_signature"}
        
        validation_errors = [{"loc": ("body", "test"), "msg": "error", "type": "error"}]
        exc = RequestValidationError(validation_errors)
        
        response = await validation_exception_handler(mock_request, exc)
        content = json.loads(response.body)
        
        assert content["client_plan"] == "ENTERPRISE"
    
    @pytest.mark.asyncio
    async def test_general_exception_handler_production(self, mock_request, mock_metrics_recorder):
        with patch("app.exceptions.settings") as mock_settings:
            mock_settings.environment = "PRODUCTION"
            
            exc = Exception("Unexpected error")
            
            response = await general_exception_handler(mock_request, exc)
            
            assert response.status_code == 500
            content = json.loads(response.body)
            assert "contact support" in content["detail"].lower()
    
    @pytest.mark.asyncio
    async def test_general_exception_handler_development(self, mock_request, mock_metrics_recorder):
        with patch("app.exceptions.settings") as mock_settings:
            mock_settings.environment = "DEVELOPMENT"
            
            exc = ValueError("Test value error")
            
            response = await general_exception_handler(mock_request, exc)
            
            assert response.status_code == 500
            content = json.loads(response.body)
            assert "ValueError" in content["detail"]


class TestHelperFunctions:
    """Tests para funciones auxiliares"""
    
    def test_extract_plan_from_jwt(self):
        request = Mock(spec=Request)
        
        # Test with valid JWT containing plan
        request.headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwbGFuIjoiUFJFTUlVTSJ9.fake_signature"}
        
        plan = _extract_plan_from_jwt(request)
        assert plan == "PREMIUM"
    
    def test_extract_plan_from_jwt_no_bearer(self):
        request = Mock(spec=Request)
        request.headers = {"Authorization": "Basic dGVzdDp0ZXN0"}
        
        plan = _extract_plan_from_jwt(request)
        assert plan == "UNKNOWN"
    
    def test_extract_plan_from_jwt_no_header(self):
        request = Mock(spec=Request)
        request.headers = {}
        
        plan = _extract_plan_from_jwt(request)
        assert plan == "UNKNOWN"
    
    def test_extract_plan_from_jwt_invalid_token(self):
        request = Mock(spec=Request)
        request.headers = {"Authorization": "Bearer invalid-token"}
        
        plan = _extract_plan_from_jwt(request)
        assert plan == "UNKNOWN"
    
    def test_extract_plan_from_jwt_no_plan(self):
        request = Mock(spec=Request)
        request.headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.fake_signature"}
        
        plan = _extract_plan_from_jwt(request)
        assert plan == "UNKNOWN"
    
    def test_record_error_metrics_success(self):
        with patch("app.exceptions.metrics_recorder") as mock_recorder:
            _record_error_metrics("test_error", 500, "test_component")
            
            mock_recorder.record_error.assert_called_once()
    
    def test_record_error_metrics_failure(self):
        with patch("app.exceptions.metrics_recorder.record_error", side_effect=Exception("Metrics error")):
            # Should not raise exception
            _record_error_metrics("test_error", 500, "test_component")
    
    def test_format_validation_errors(self):
        raw_errors = [
            {
                "loc": ("body", "email"),
                "msg": "Invalid email format",
                "type": "value_error",
                "input": "invalid-email"
            },
            {
                "loc": ("body", "password"),
                "msg": "Password too short", 
                "type": "value_error",
                "input": "123"
            }
        ]
        
        formatted = _format_validation_errors(raw_errors)
        
        assert len(formatted) == 2
        assert formatted[0]["field"] == "body.email"
        assert formatted[0]["message"] == "Invalid email format"
        assert formatted[0]["type"] == "value_error"
        assert formatted[0]["input"] == "invalid-email"
        
        assert formatted[1]["field"] == "body.password"
        assert formatted[1]["message"] == "Password too short"
    
    def test_format_validation_errors_missing_fields(self):
        raw_errors = [
            {
                "loc": ("body",),
                "msg": "Some error"
            }
        ]
        
        formatted = _format_validation_errors(raw_errors)
        
        assert formatted[0]["field"] == "body"
        assert formatted[0]["message"] == "Some error"
        assert formatted[0]["type"] == "unknown"


class TestRegistration:
    """Tests para registro de handlers"""
    
    def test_register_exception_handlers(self):
        mock_app = Mock()
        
        register_exception_handlers(mock_app)
        
        # Verify all handlers are registered
        assert mock_app.add_exception_handler.call_count == 3
        
        # Get the calls and verify they're for the correct exception types
        calls = mock_app.add_exception_handler.call_args_list
        
        exception_types = [call[0][0] for call in calls]
        assert APIException in exception_types
        assert RequestValidationError in exception_types  
        assert Exception in exception_types
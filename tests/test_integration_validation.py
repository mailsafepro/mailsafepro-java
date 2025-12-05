import pytest
import pytest_asyncio
import json
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi import FastAPI, UploadFile
from httpx import AsyncClient, ASGITransport

from app.routes.validation_routes import router as validation_router
from app.auth import validate_api_key_or_token, get_redis
from app.models import TokenData

# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def mock_user_token():
    return TokenData(
        sub="user123",
        exp=1735689600,
        jti="test-jti-1234567890123456",
        iss="test-issuer",
        aud="test-audience",
        iat=1704067200,
        email="user@example.com",
        plan="PREMIUM",
        scopes=["validate:single", "validate:batch", "batch:upload"],
        type="access"
    )

@pytest.fixture
def app(redis_client, mock_user_token):
    """FastAPI app with validation routes and mocked auth"""
    app = FastAPI()
    app.include_router(validation_router)
    
    # Mock auth to always return valid user
    app.dependency_overrides[validate_api_key_or_token] = lambda: mock_user_token
    app.dependency_overrides[get_redis] = lambda: redis_client
    
    return app

@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

# =============================================================================
# TESTS
# =============================================================================

class TestValidationEndpoints:
    
    @pytest.mark.asyncio
    async def test_validate_email_endpoint_valid(self, client, app):
        """Test /email with valid email"""
        
        # Mock internal validation logic - patch the INSTANCE
        with patch("app.routes.validation_routes.validation_engine") as mock_engine:
            # Mock perform_comprehensive_validation to return a JSONResponse
            from fastapi.responses import JSONResponse
            from unittest.mock import AsyncMock
            
            mock_engine.perform_comprehensive_validation = AsyncMock(return_value=JSONResponse(
                content={
                    "valid": True,
                    "email": "test@example.com",
                    "detail": "Email format and domain are valid",
                    "risk_score": 0.1,
                    "quality_score": 0.9,
                    "provider_analysis": {"provider": "google"},
                    "smtp_validation": {"checked": True, "mailbox_exists": True},
                    "client_plan": "PREMIUM"
                }
            ))
            
            payload = {"email": "test@example.com", "check_smtp": True}
            response = await client.post("/email", json=payload)
            
            assert response.status_code == 200
            data = response.json()
            assert data["valid"] is True
            assert data["email"] == "test@example.com"

    @pytest.mark.asyncio
    async def test_validate_email_endpoint_invalid_format(self, client, app):
        """Test /email with invalid email format"""
        
        # Mock engine to handle invalid format or let the endpoint handle it
        # The endpoint checks format before calling engine
        
        payload = {"email": "invalid-email"}
        response = await client.post("/email", json=payload)
        
        # Expecting 400 Bad Request or 422 Unprocessable Entity
        # Expecting 400 Bad Request or 422 Unprocessable Entity
        assert response.status_code in [400, 422]
        data = response.json()
        if response.status_code == 422:
            # Pydantic validation error
            assert isinstance(data["detail"], list)
            assert any("email" in str(e["loc"]) for e in data["detail"])
        else:
            assert data["detail"] == "Invalid email format"

    @pytest.mark.asyncio
    async def test_batch_validate_endpoint(self, client, app):
        """Test /batch endpoint"""
        
        payload = {
            "emails": ["test1@example.com", "test2@example.com"],
            "check_smtp": False
        }
        
        with patch("app.routes.validation_routes.validation_engine") as mock_engine:
            # Mock perform_comprehensive_validation for batch calls
            from fastapi.responses import JSONResponse
            from unittest.mock import AsyncMock
            
            async def side_effect(*args, **kwargs):
                email = kwargs.get("email")
                return JSONResponse(content={"email": email, "valid": True})
                
            mock_engine.perform_comprehensive_validation = AsyncMock(side_effect=side_effect)
            
            response = await client.post("/batch", json=payload)
            
            assert response.status_code == 200
            data = response.json()
            assert data["count"] == 2
            assert len(data["results"]) == 2

    @pytest.mark.asyncio
    async def test_file_upload_endpoint(self, client, app):
        """Test /batch/upload endpoint"""
        
        # Mock FileValidationService INSTANCE
        with patch("app.routes.validation_routes.file_validation_service") as mock_service:
            from unittest.mock import AsyncMock
            mock_service.process_uploaded_file = AsyncMock(return_value=["test1@example.com", "test2@example.com"])
            mock_service.generate_csv_report.return_value = "email,valid\ntest1@example.com,true"
            mock_service._calculate_risk_distribution.return_value = {"low": 2}
            mock_service._calculate_provider_breakdown.return_value = {"google": 2}
            
            # Mock Engine INSTANCE for batch processing
            with patch("app.routes.validation_routes.validation_engine") as mock_engine:
                from fastapi.responses import JSONResponse
                async def side_effect(*args, **kwargs):
                    email = kwargs.get("email")
                    return JSONResponse(content={"email": email, "valid": True})
                mock_engine.perform_comprehensive_validation = AsyncMock(side_effect=side_effect)
                
                files = {'file': ('test.csv', b'email\ntest1@example.com\ntest2@example.com', 'text/csv')}
                
                response = await client.post("/batch/upload", files=files)
                
                if response.status_code != 200:
                    print(f"Error response: {response.json()}")

                assert response.status_code == 200
                data = response.json()
                assert data["emails_found"] == 2

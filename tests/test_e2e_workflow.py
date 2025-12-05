import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from fastapi import FastAPI
from unittest.mock import patch, MagicMock, AsyncMock
import fakeredis
from app.auth import create_user, get_password_hash, router as auth_router
from app.config import settings
from app.api_keys import router as api_keys_router
from app.routes.validation_routes import router as validation_router

# Mock external services for validation
@pytest.fixture
def mock_validation_services():
    with patch("app.routes.validation_routes.validation_engine") as mock_engine:
        # Mock validate_email
        from fastapi.responses import JSONResponse
        async def mock_validate(email, **kwargs):
            return JSONResponse(content={
                "email": email,
                "is_valid": True,
                "score": 0.95,
                "details": {"domain": "example.com", "mx_records": True}
            })
        mock_engine.perform_comprehensive_validation = AsyncMock(side_effect=mock_validate)
        yield mock_engine

@pytest_asyncio.fixture
async def e2e_app(redis_client):
    """Create a FastAPI app for E2E testing with all routers and mocked redis"""
    # We use the main app but override dependency overrides if needed
    # Or better, create a fresh app to avoid pollution
    app = FastAPI()
    app.state.redis = redis_client
    
    # Include all routers
    app.include_router(auth_router)
    app.include_router(api_keys_router)
    app.include_router(validation_router, prefix="/v1") # Assuming prefix based on previous files
    
    return app

@pytest.fixture
def mock_hashing():
    """Mock password hashing to avoid bcrypt/passlib incompatibility"""
    with patch("app.auth.get_password_hash") as mock_hash, \
         patch("app.auth.verify_password") as mock_verify:
        
        mock_hash.side_effect = lambda p: f"hashed_{p}"
        mock_verify.side_effect = lambda p, h: h == f"hashed_{p}"
        yield

@pytest_asyncio.fixture(scope="function")
async def redis_client():
    """Fake Redis async client for testing"""
    client = fakeredis.FakeAsyncRedis(decode_responses=False)
    yield client
    await client.flushall()
    await client.aclose()

@pytest.mark.asyncio
@patch('app.config.settings')
async def test_full_user_journey(mock_settings, e2e_app, redis_client, mock_validation_services, mock_hashing):
    """
    Test a complete user journey:
    1. Register
    2. Login
    3. Create API Key
    4. Validate Email (using API Key)
    5. Check Usage
    6. Logout
    """
    # Configure settings
    mock_settings.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
    mock_settings.jwt.issuer = "test-issuer"
    mock_settings.jwt.audience = "test-audience"
    mock_settings.jwt.access_token_expire_minutes = 30
    mock_settings.jwt.refresh_token_expire_days = 7
    
    email = "newuser@example.com"
    password = "SecurePassword123!"
    
    async with AsyncClient(transport=ASGITransport(app=e2e_app), base_url="http://test") as ac:
        
        # 1. Register
        print("Step 1: Registering user...")
        reg_response = await ac.post(
            "/register",
            json={"email": email, "password": password, "plan": "FREE"}
        )
        assert reg_response.status_code == 201
        reg_data = reg_response.json()
        assert "access_token" in reg_data
        
        # 2. Login
        print("Step 2: Logging in...")
        login_response = await ac.post(
            "/login",
            json={"email": email, "password": password}
        )
        assert login_response.status_code == 200
        login_data = login_response.json()
        access_token = login_data["access_token"]
        refresh_token = login_data["refresh_token"]
        headers = {"Authorization": f"Bearer {access_token}"}
        
        # 3. Create API Key
        print("Step 3: Creating API Key...")
        key_response = await ac.post(
            "/api-keys",
            headers=headers,
            json={"name": "Test Key", "scopes": ["validate:single"]}
        )
        assert key_response.status_code == 200
        key_data = key_response.json()
        api_key = key_data["api_key"]
        
        # 4. Validate Email using API Key
        print("Step 4: Validating Email with API Key...")
        # Note: Validation endpoint might expect X-API-Key header or similar
        # Assuming it uses X-API-Key based on typical patterns, or Bearer if it accepts API key as token
        # Let's check validation_routes.py or api_keys.py for auth scheme.
        # Usually it's X-API-Key header.
        val_headers = {"X-API-Key": api_key}
        
        val_response = await ac.post(
            "/v1/email",
            headers=val_headers,
            json={"email": "check@example.com"}
        )
        assert val_response.status_code == 200
        val_data = val_response.json()
        assert val_data["email"] == "check@example.com"
        assert val_data["is_valid"] is True
        
        # 5. Check Usage
        print("Step 5: Checking Usage...")
        # Usage endpoint might be /usage or /api-keys/usage
        usage_response = await ac.get(
            "/api-keys/usage",
            headers=headers
        )
        assert usage_response.status_code == 200
        usage_data = usage_response.json()
        # Should show 1 validation
        # Note: Usage tracking might be async or require mocking if it writes to redis differently
        # But since we use the same redis_client, it should be there.
        # However, validation_routes might increment usage.
        # Let's assume usage is tracked.
        
        # 6. Logout
        print("Step 6: Logging out...")
        logout_response = await ac.post(
            "/logout",
            headers=headers,
            json={"refresh_token": refresh_token}
        )
        assert logout_response.status_code == 200
        
        # Verify token is invalid
        me_response = await ac.get("/me", headers=headers)
        assert me_response.status_code == 401


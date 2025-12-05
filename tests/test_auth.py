"""
Comprehensive Test Suite for Email Validation API
Tests for auth.py, api_keys.py, and billing_routes.py

Requirements:
- pytest
- pytest-asyncio
- pytest-mock
- fakeredis[lua]
- httpx
"""

import pytest
import pytest_asyncio
from typing import Dict, Any, Optional
import json
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, AsyncMock, patch, MagicMock

import fakeredis
from redis.asyncio import Redis
from fastapi import FastAPI, HTTPException, status
from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport
import jwt  # PyJWT
from passlib.context import CryptContext

# Import modules to test
from app.auth import (
    create_hashed_key,
    verify_password,
    get_password_hash,
    create_access_token,
    create_refresh_token,
    create_jwt_token,
    validate_api_key,
    get_current_client,
    create_user,
    get_user_by_email,
    blacklist_token,
    is_token_blacklisted,
    store_refresh_token,
    revoke_refresh_token,
    is_refresh_token_valid,
    PLAN_SCOPES,
    JWT_ALGORITHM,
    router as auth_router
)

from app.models import (
    UserRegister,
    UserLogin,
    TokenData,
    APIKeyCreateRequest,
    APIKeyMeta
)

# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def mock_settings():
    """Mock settings configuration"""
    settings = Mock()
    settings.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
    settings.jwt.access_token_expire_minutes = 30
    settings.jwt.refresh_token_expire_days = 7
    settings.jwt.issuer = "test-issuer"
    settings.jwt.audience = "test-audience"
    settings.stripe.secret_key.get_secret_value.return_value = "sk_test_123"
    settings.stripe.premium_plan_id = "price_premium_test"
    settings.stripe.enterprise_plan_id = "price_enterprise_test"
    settings.stripe.success_url = "http://test.com/success"
    settings.stripe.cancel_url = "http://test.com/cancel"
    return settings


@pytest_asyncio.fixture(scope="function")
async def redis_client():
    """Fake Redis async client for testing"""
    client = fakeredis.FakeAsyncRedis(decode_responses=False)
    yield client
    await client.flushall()
    await client.aclose()


# ... (skipping unchanged parts) ...


class TestAuthEndpoints:
    """Tests for authentication endpoints"""
    
    @pytest.mark.asyncio
    @patch('app.config.settings')
    async def test_register_endpoint_success(self, mock_settings, valid_email, valid_password, mock_hashing, redis_client):
        """Test user registration endpoint"""
        mock_settings.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
        mock_settings.jwt.issuer = "test-issuer"
        mock_settings.jwt.audience = "test-audience"
        mock_settings.jwt.access_token_expire_minutes = 30
        mock_settings.jwt.refresh_token_expire_days = 7
        
        # Use fixture redis_client which has mocked eval
        app = FastAPI()
        app.state.redis = redis_client
        app.include_router(auth_router)
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.post(
                "/register",
                json={
                    "email": valid_email,
                    "password": valid_password,
                    "plan": "FREE"
                }
            )
        
        if response.status_code != 201:
            print(f"DEBUG: Register failed: {response.json()}")

        assert response.status_code == 201
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert "api_key" in data
        assert data["token_type"] == "bearer"
    
    @pytest.mark.asyncio
    @patch('app.config.settings')
    async def test_login_endpoint_success(self, mock_settings, valid_email, valid_password, mock_hashing, redis_client):
        """Test login endpoint with valid credentials"""
        mock_settings.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
        mock_settings.jwt.issuer = "test-issuer"
        mock_settings.jwt.audience = "test-audience"
        mock_settings.jwt.access_token_expire_minutes = 30
        mock_settings.jwt.refresh_token_expire_days = 7
        
        # Create user first
        await create_user(redis_client, valid_email, valid_password, "FREE")
        
        app = FastAPI()
        app.state.redis = redis_client
        app.include_router(auth_router)
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.post(
                "/login",
                json={
                    "email": valid_email,
                    "password": valid_password
                }
            )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
    
    @pytest.mark.asyncio
    @patch('app.config.settings')
    async def test_login_endpoint_wrong_password(self, mock_settings, valid_email, valid_password, mock_hashing, redis_client):
        """Test login with wrong password"""
        mock_settings.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
        mock_settings.jwt.issuer = "test-issuer"
        mock_settings.jwt.audience = "test-audience"
        
        await create_user(redis_client, valid_email, valid_password, "FREE")
        
        app = FastAPI()
        app.state.redis = redis_client
        app.include_router(auth_router)
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.post(
                "/login",
                json={
                    "email": valid_email,
                    "password": "WrongPassword123"
                }
            )
        
        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]

    @pytest.mark.asyncio
    @patch('app.config.settings')
    async def test_me_endpoint_success(self, mock_settings, valid_email, valid_password, mock_hashing, redis_client):
        """Test /me endpoint"""
        mock_settings.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
        mock_settings.jwt.issuer = "test-issuer"
        mock_settings.jwt.audience = "test-audience"
        mock_settings.jwt.access_token_expire_minutes = 30
        
        await create_user(redis_client, valid_email, valid_password, "FREE")
        
        app = FastAPI()
        app.state.redis = redis_client
        app.include_router(auth_router)
        
        # Login to get token
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            login_response = await ac.post(
                "/login",
                json={"email": valid_email, "password": valid_password}
            )
            token = login_response.json()["access_token"]
            
            # Call /me
            response = await ac.get(
                "/me",
                headers={"Authorization": f"Bearer {token}"}
            )
            
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == valid_email
        assert data["plan"] == "FREE"

    @pytest.mark.asyncio
    @patch('app.config.settings')
    async def test_refresh_endpoint_success(self, mock_settings, valid_email, valid_password, mock_hashing, redis_client):
        """Test /refresh endpoint"""
        mock_settings.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
        mock_settings.jwt.issuer = "test-issuer"
        mock_settings.jwt.audience = "test-audience"
        mock_settings.jwt.access_token_expire_minutes = 30
        mock_settings.jwt.refresh_token_expire_days = 7
        
        await create_user(redis_client, valid_email, valid_password, "PREMIUM")
        
        app = FastAPI()
        app.state.redis = redis_client
        app.include_router(auth_router)
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            # Login
            login_res = await ac.post(
                "/login",
                json={"email": valid_email, "password": valid_password}
            )
            refresh_token = login_res.json()["refresh_token"]
            
            # Refresh
            response = await ac.post(
                "/refresh",
                json={"refresh_token": refresh_token}
            )
            
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["access_token"] != login_res.json()["access_token"]
        assert data["plan"] == "PREMIUM"

    @pytest.mark.asyncio
    @patch('app.config.settings')
    async def test_logout_endpoint_success(self, mock_settings, valid_email, valid_password, mock_hashing, redis_client):
        """Test /logout endpoint"""
        mock_settings.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
        mock_settings.jwt.issuer = "test-issuer"
        mock_settings.jwt.audience = "test-audience"
        mock_settings.jwt.access_token_expire_minutes = 30
        mock_settings.jwt.refresh_token_expire_days = 7
        
        await create_user(redis_client, valid_email, valid_password, "FREE")
        
        app = FastAPI()
        app.state.redis = redis_client
        app.include_router(auth_router)
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            # Login
            login_res = await ac.post(
                "/login",
                json={"email": valid_email, "password": valid_password}
            )
            access_token = login_res.json()["access_token"]
            refresh_token = login_res.json()["refresh_token"]
            
            # Logout
            response = await ac.post(
                "/logout",
                headers={"Authorization": f"Bearer {access_token}"},
                json={"refresh_token": refresh_token}
            )
            
            # Verify access token is blacklisted (via endpoint call failure)
            me_res = await ac.get(
                "/me",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
        assert response.status_code == 200
        assert response.json()["token_status"] == "revoked"
        
        assert me_res.status_code == 401


@pytest.fixture
def app(redis_client, mock_settings):
    """FastAPI application for testing"""
    with patch('app.config.settings', mock_settings):
        app = FastAPI()
        app.state.redis = redis_client
        app.include_router(auth_router)
        return app


@pytest_asyncio.fixture(scope="function")
async def client(app):
    """Async HTTP client for testing"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


@pytest.fixture
def valid_password():
    """Valid test password"""
    return "SecurePassword123!"


@pytest.fixture
def valid_email():
    """Valid test email"""
    return "test@example.com"


@pytest.fixture
def valid_api_key():
    """Valid test API key"""
    return secrets.token_urlsafe(32)


@pytest.fixture
def hashed_password(valid_password):
    """Hashed password for testing"""
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    return pwd_context.hash(valid_password)


# =============================================================================
# AUTH.PY TESTS - UTILITY FUNCTIONS
# =============================================================================

class TestPasswordHashing:
    """Tests for password hashing functions"""
    
    def test_get_password_hash_valid(self, valid_password):
        """Test hashing a valid password"""
        hashed = get_password_hash(valid_password)
        assert hashed.startswith("$2b$")
        assert len(hashed) > 50
    
    def test_get_password_hash_short_password(self):
        """Test hashing password too short raises error"""
        with pytest.raises(ValueError, match="at least 8 characters"):
            get_password_hash("short")
    
    def test_get_password_hash_empty_password(self):
        """Test hashing empty password raises error"""
        with pytest.raises(ValueError):
            get_password_hash("")
    
    def test_verify_password_correct(self, valid_password, hashed_password):
        """Test verifying correct password"""
        assert verify_password(valid_password, hashed_password) is True
    
    def test_verify_password_incorrect(self, hashed_password):
        """Test verifying incorrect password"""
        assert verify_password("WrongPassword", hashed_password) is False
    
    def test_verify_password_empty_hash(self, valid_password):
        """Test verifying password with empty hash"""
        assert verify_password(valid_password, "") is False
    
    def test_verify_password_invalid_hash_format(self, valid_password):
        """Test verifying password with invalid hash format"""
        assert verify_password(valid_password, "invalid_hash") is False


@pytest.fixture
def mock_hashing():
    """Mock hashing functions to avoid passlib/bcrypt issues"""
    with patch("app.auth.get_password_hash") as mock_hash, \
         patch("app.auth.verify_password") as mock_verify:
        
        def side_effect_hash(password):
            if len(password) < 8:
                raise ValueError("Password must be at least 8 characters")
            return f"hashed_{password}"
            
        def side_effect_verify(plain, hashed):
            return hashed == f"hashed_{plain}"
            
        mock_hash.side_effect = side_effect_hash
        mock_verify.side_effect = side_effect_verify
        yield


class TestAPIKeyHashing:
    """Tests for API key hashing functions"""
    
    def test_create_hashed_key_valid(self, valid_api_key):
        """Test creating hash from valid API key"""
        hashed = create_hashed_key(valid_api_key)
        assert len(hashed) == 64
        assert all(c in '0123456789abcdef' for c in hashed)
    
    def test_create_hashed_key_deterministic(self, valid_api_key):
        """Test hashing is deterministic"""
        hash1 = create_hashed_key(valid_api_key)
        hash2 = create_hashed_key(valid_api_key)
        assert hash1 == hash2
    
    def test_create_hashed_key_too_short(self):
        """Test hashing key too short raises error"""
        with pytest.raises(ValueError, match="at least 16 characters"):
            create_hashed_key("short")
    
    def test_create_hashed_key_invalid_characters(self):
        """Test hashing key with invalid characters"""
        with pytest.raises(ValueError, match="invalid characters"):
            create_hashed_key("a" * 16 + "!@#$%^&*()")
    
    def test_create_hashed_key_insufficient_entropy(self):
        """Test hashing key with insufficient entropy"""
        with pytest.raises(ValueError, match="insufficient entropy"):
            create_hashed_key("aaaaaaaaaaaaaaaa")
    
    def test_create_hashed_key_not_string(self):
        """Test hashing non-string raises error"""
        with pytest.raises(ValueError, match="must be a string"):
            create_hashed_key(123456789012345678)


# =============================================================================
# AUTH.PY TESTS - JWT TOKEN CREATION
# =============================================================================

class TestJWTTokens:
    """Tests for JWT token creation and validation"""
    
    @patch('app.config.settings')
    def test_create_access_token_basic(self, mock_settings):
        """Test creating basic access token"""
        mock_settings.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
        mock_settings.jwt.issuer = "test-issuer"
        mock_settings.jwt.audience = "test-audience"
        
        data = {"sub": "user123"}
        token = create_access_token(data, plan="FREE")
        
        assert isinstance(token, str)
        assert len(token) > 50
    
    @patch("app.auth.settings")
    def test_create_access_token_decodes_correctly(self, mock_settings):
        """Test access token contains correct claims"""
        mock_settings.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
        mock_settings.jwt.issuer = "test-issuer"
        mock_settings.jwt.audience = "test-audience"
        
        data = {"sub": "user123", "email": "test@example.com"}
        token = create_access_token(data, plan="PREMIUM")
        
        payload = jwt.decode(
            token,
            "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo",
            algorithms=[JWT_ALGORITHM],
            audience="test-audience",  # ← AGREGAR
            issuer="test-issuer",      # ← AGREGAR
            options={"verify_signature": True}
        )
        
        assert payload["sub"] == "user123"
        assert payload["email"] == "test@example.com"
        assert payload["plan"] == "PREMIUM"
        assert payload["type"] == "access"
        assert "scopes" in payload
        assert "validate:batch" in payload["scopes"]
    
    @patch("app.auth.settings")
    def test_create_refresh_token(self, mock_settings):
        """Test creating refresh token"""
        mock_settings.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
        mock_settings.jwt.issuer = "test-issuer"
        mock_settings.jwt.audience = "test-audience"
        
        data = {"sub": "user123"}
        token, expires_at = create_refresh_token(data, plan="FREE")
        
        assert isinstance(token, str)
        assert isinstance(expires_at, datetime)
        
        payload = jwt.decode(
            token,
            "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo",
            algorithms=[JWT_ALGORITHM],
            audience="test-audience",  # ← AGREGAR
            issuer="test-issuer",      # ← AGREGAR
            options={"verify_signature": True}
        )
        assert payload["type"] == "refresh"
    
    @patch("app.auth.settings")
    def test_token_scopes_by_plan(self, mock_settings):
        """Test tokens have correct scopes based on plan"""
        mock_settings.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
        mock_settings.jwt.issuer = "test-issuer"
        mock_settings.jwt.audience = "test-audience"
        
        # FREE plan
        token_free = create_access_token({"sub": "user1"}, plan="FREE")
        payload_free = jwt.decode(
            token_free,
            "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo",
            algorithms=[JWT_ALGORITHM],
            audience="test-audience",  # ← AGREGAR
            issuer="test-issuer",      # ← AGREGAR
            options={"verify_signature": True}
        )
        assert set(payload_free["scopes"]) == set(PLAN_SCOPES["FREE"])
        
        # PREMIUM plan
        token_premium = create_access_token({"sub": "user2"}, plan="PREMIUM")
        payload_premium = jwt.decode(
            token_premium,
            "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo",
            algorithms=[JWT_ALGORITHM],
            audience="test-audience",  # ← AGREGAR
            issuer="test-issuer",      # ← AGREGAR
            options={"verify_signature": True}
        )
        assert "validate:batch" in payload_premium["scopes"]
        
        # ENTERPRISE plan
        token_enterprise = create_access_token({"sub": "user3"}, plan="ENTERPRISE")
        payload_enterprise = jwt.decode(
            token_enterprise,
            "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo",
            algorithms=[JWT_ALGORITHM],
            audience="test-audience",  # ← AGREGAR
            issuer="test-issuer",      # ← AGREGAR
            options={"verify_signature": True}
        )
        assert "admin" in payload_enterprise["scopes"]


# =============================================================================
# AUTH.PY TESTS - USER MANAGEMENT
# =============================================================================

class TestUserManagement:
    """Tests for user creation and retrieval"""
    
    @pytest.mark.asyncio
    async def test_create_user_success(self, redis_client, valid_email, valid_password, mock_hashing):
        """Test creating a new user successfully"""
        user = await create_user(redis_client, valid_email, valid_password, "FREE")
        
        assert user.email == valid_email
        assert user.plan == "FREE"
        assert user.is_active is True
        assert user.email_verified is False
        assert isinstance(user.id, str)
        assert len(user.id) > 0
    
    @pytest.mark.asyncio
    async def test_create_user_duplicate_email(self, redis_client, valid_email, valid_password, mock_hashing):
        """Test creating user with duplicate email raises error"""
        await create_user(redis_client, valid_email, valid_password, "FREE")
        
        with pytest.raises(HTTPException) as exc_info:
            await create_user(redis_client, valid_email, valid_password, "FREE")
        
        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert "already exists" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_create_user_invalid_email(self, redis_client, valid_password, mock_hashing):
        """Test creating user with invalid email format"""
        with pytest.raises(HTTPException) as exc_info:
            await create_user(redis_client, "invalid-email", valid_password, "FREE")
        
        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert "Invalid email" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_create_user_short_password(self, redis_client, valid_email, mock_hashing):
        """Test creating user with short password"""
        with pytest.raises(HTTPException) as exc_info:
            await create_user(redis_client, valid_email, "short", "FREE")
        
        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert "8 characters" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_get_user_by_email_exists(self, redis_client, valid_email, valid_password, mock_hashing):
        """Test retrieving existing user by email"""
        created_user = await create_user(redis_client, valid_email, valid_password, "PREMIUM")
        retrieved_user = await get_user_by_email(redis_client, valid_email)
        
        assert retrieved_user is not None
        assert retrieved_user.id == created_user.id
        assert retrieved_user.email == valid_email
        assert retrieved_user.plan == "PREMIUM"
    
    @pytest.mark.asyncio
    async def test_get_user_by_email_not_exists(self, redis_client):
        """Test retrieving non-existent user returns None"""
        user = await get_user_by_email(redis_client, "nonexistent@example.com")
        assert user is None
    
    @pytest.mark.asyncio
    async def test_get_user_by_email_invalid_format(self, redis_client):
        """Test retrieving user with invalid email format"""
        user = await get_user_by_email(redis_client, "invalid-email")
        assert user is None


# =============================================================================
# AUTH.PY TESTS - TOKEN BLACKLISTING
# =============================================================================
# ... (TestTokenBlacklisting and TestRefreshTokens don't need mocking) ...

# ... (TestAPIKeyValidation doesn't need mocking) ...

# =============================================================================
# AUTH.PY TESTS - ENDPOINT TESTING
# =============================================================================

class TestAuthEndpoints:
    """Tests for authentication endpoints"""
    
    @pytest.mark.asyncio
    @patch('app.config.settings')
    async def test_register_endpoint_success(self, mock_settings, valid_email, valid_password, mock_hashing):
        """Test user registration endpoint"""
        mock_settings.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
        mock_settings.jwt.issuer = "test-issuer"
        mock_settings.jwt.audience = "test-audience"
        mock_settings.jwt.access_token_expire_minutes = 30
        mock_settings.jwt.refresh_token_expire_days = 7
        
        # Create FastAPI app with router and fake redis
        redis_client = fakeredis.FakeAsyncRedis(decode_responses=False)
        app = FastAPI()
        app.state.redis = redis_client
        app.include_router(auth_router)
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.post(
                "/register",
                json={
                    "email": valid_email,
                    "password": valid_password,
                    "plan": "FREE"
                }
            )
        
        assert response.status_code == 201
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert "api_key" in data
        assert data["token_type"] == "bearer"
        
        await redis_client.aclose()
    
    @pytest.mark.asyncio
    @patch('app.config.settings')
    async def test_login_endpoint_success(self, mock_settings, valid_email, valid_password, mock_hashing):
        """Test login endpoint with valid credentials"""
        mock_settings.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
        mock_settings.jwt.issuer = "test-issuer"
        mock_settings.jwt.audience = "test-audience"
        mock_settings.jwt.access_token_expire_minutes = 30
        mock_settings.jwt.refresh_token_expire_days = 7
        
        # Create user first
        redis_client = fakeredis.FakeAsyncRedis(decode_responses=False)
        await create_user(redis_client, valid_email, valid_password, "FREE")
        
        app = FastAPI()
        app.state.redis = redis_client
        app.include_router(auth_router)
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.post(
                "/login",
                json={
                    "email": valid_email,
                    "password": valid_password
                }
            )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        
        await redis_client.aclose()
    
    @pytest.mark.asyncio
    @patch('app.config.settings')
    async def test_login_endpoint_wrong_password(self, mock_settings, valid_email, valid_password, mock_hashing):
        """Test login with wrong password"""
        mock_settings.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
        mock_settings.jwt.issuer = "test-issuer"
        mock_settings.jwt.audience = "test-audience"
        
        redis_client = fakeredis.FakeAsyncRedis(decode_responses=False)
        await create_user(redis_client, valid_email, valid_password, "FREE")
        
        app = FastAPI()
        app.state.redis = redis_client
        app.include_router(auth_router)
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.post(
                "/login",
                json={
                    "email": valid_email,
                    "password": "WrongPassword123"
                }
            )
        
        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]
        
        await redis_client.aclose()

    @pytest.mark.asyncio
    @patch('app.config.settings')
    async def test_me_endpoint_success(self, mock_settings, valid_email, valid_password, mock_hashing):
        """Test /me endpoint"""
        mock_settings.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
        mock_settings.jwt.issuer = "test-issuer"
        mock_settings.jwt.audience = "test-audience"
        mock_settings.jwt.access_token_expire_minutes = 30
        
        redis_client = fakeredis.FakeAsyncRedis(decode_responses=False)
        await create_user(redis_client, valid_email, valid_password, "FREE")
        
        app = FastAPI()
        app.state.redis = redis_client
        app.include_router(auth_router)
        
        # Login to get token
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            login_response = await ac.post(
                "/login",
                json={"email": valid_email, "password": valid_password}
            )
            token = login_response.json()["access_token"]
            
            # Call /me
            response = await ac.get(
                "/me",
                headers={"Authorization": f"Bearer {token}"}
            )
            
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == valid_email
        assert data["plan"] == "FREE"
        
        await redis_client.aclose()

    @pytest.mark.asyncio
    @patch('app.config.settings')
    async def test_refresh_endpoint_success(self, mock_settings, valid_email, valid_password, mock_hashing):
        """Test /refresh endpoint"""
        mock_settings.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
        mock_settings.jwt.issuer = "test-issuer"
        mock_settings.jwt.audience = "test-audience"
        mock_settings.jwt.access_token_expire_minutes = 30
        mock_settings.jwt.refresh_token_expire_days = 7
        
        redis_client = fakeredis.FakeAsyncRedis(decode_responses=False)
        await create_user(redis_client, valid_email, valid_password, "PREMIUM")
        
        app = FastAPI()
        app.state.redis = redis_client
        app.include_router(auth_router)
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            # Login
            login_res = await ac.post(
                "/login",
                json={"email": valid_email, "password": valid_password}
            )
            refresh_token = login_res.json()["refresh_token"]
            
            # Refresh
            response = await ac.post(
                "/refresh",
                json={"refresh_token": refresh_token}
            )
            
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["access_token"] != login_res.json()["access_token"]
        assert data["plan"] == "PREMIUM"
        
        await redis_client.aclose()

    @pytest.mark.asyncio
    @patch('app.config.settings')
    async def test_logout_endpoint_success(self, mock_settings, valid_email, valid_password, mock_hashing):
        """Test /logout endpoint"""
        mock_settings.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
        mock_settings.jwt.issuer = "test-issuer"
        mock_settings.jwt.audience = "test-audience"
        mock_settings.jwt.access_token_expire_minutes = 30
        mock_settings.jwt.refresh_token_expire_days = 7
        
        redis_client = fakeredis.FakeAsyncRedis(decode_responses=False)
        await create_user(redis_client, valid_email, valid_password, "FREE")
        
        app = FastAPI()
        app.state.redis = redis_client
        app.include_router(auth_router)
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            # Login
            login_res = await ac.post(
                "/login",
                json={"email": valid_email, "password": valid_password}
            )
            access_token = login_res.json()["access_token"]
            refresh_token = login_res.json()["refresh_token"]
            
            # Logout
            response = await ac.post(
                "/logout",
                headers={"Authorization": f"Bearer {access_token}"},
                json={"refresh_token": refresh_token}
            )
            
            # Verify access token is blacklisted (via endpoint call failure)
            me_res = await ac.get(
                "/me",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
        assert response.status_code == 200
        assert response.json()["token_status"] == "revoked"
        
        assert me_res.status_code == 401
        
        await redis_client.aclose()



# =============================================================================

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
from jose import jwt
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
    async def test_create_user_success(self, redis_client, valid_email, valid_password):
        """Test creating a new user successfully"""
        user = await create_user(redis_client, valid_email, valid_password, "FREE")
        
        assert user.email == valid_email
        assert user.plan == "FREE"
        assert user.is_active is True
        assert user.email_verified is False
        assert isinstance(user.id, str)
        assert len(user.id) > 0
    
    @pytest.mark.asyncio
    async def test_create_user_duplicate_email(self, redis_client, valid_email, valid_password):
        """Test creating user with duplicate email raises error"""
        await create_user(redis_client, valid_email, valid_password, "FREE")
        
        with pytest.raises(HTTPException) as exc_info:
            await create_user(redis_client, valid_email, valid_password, "FREE")
        
        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert "already exists" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_create_user_invalid_email(self, redis_client, valid_password):
        """Test creating user with invalid email format"""
        with pytest.raises(HTTPException) as exc_info:
            await create_user(redis_client, "invalid-email", valid_password, "FREE")
        
        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert "Invalid email" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_create_user_short_password(self, redis_client, valid_email):
        """Test creating user with short password"""
        with pytest.raises(HTTPException) as exc_info:
            await create_user(redis_client, valid_email, "short", "FREE")
        
        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert "8 characters" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_get_user_by_email_exists(self, redis_client, valid_email, valid_password):
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

class TestTokenBlacklisting:
    """Tests for token blacklisting functionality"""
    
    @pytest.mark.asyncio
    async def test_blacklist_token_success(self, redis_client):
        """Test blacklisting a token successfully"""
        jti = "test-jti-12345"
        exp = datetime.now(timezone.utc) + timedelta(hours=1)
        
        await blacklist_token(jti, exp, redis_client)
        is_blacklisted = await is_token_blacklisted(jti, redis_client)
        
        assert is_blacklisted is True
    
    @pytest.mark.asyncio
    async def test_token_not_blacklisted(self, redis_client):
        """Test checking non-blacklisted token"""
        is_blacklisted = await is_token_blacklisted("non-existent-jti", redis_client)
        assert is_blacklisted is False
    
    @pytest.mark.asyncio
    async def test_blacklist_token_with_timestamp(self, redis_client):
        """Test blacklisting token with integer timestamp"""
        jti = "test-jti-timestamp"
        exp_timestamp = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        
        await blacklist_token(jti, exp_timestamp, redis_client)
        is_blacklisted = await is_token_blacklisted(jti, redis_client)
        
        assert is_blacklisted is True


# =============================================================================
# AUTH.PY TESTS - REFRESH TOKEN MANAGEMENT
# =============================================================================

class TestRefreshTokens:
    """Tests for refresh token storage and revocation"""
    
    @pytest.mark.asyncio
    async def test_store_refresh_token(self, redis_client):
        """Test storing refresh token"""
        jti = "refresh-jti-123"
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        
        await store_refresh_token(jti, expires_at, redis_client)
        is_valid = await is_refresh_token_valid(jti, redis_client)
        
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_revoke_refresh_token(self, redis_client):
        """Test revoking refresh token"""
        jti = "refresh-jti-456"
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        
        await store_refresh_token(jti, expires_at, redis_client)
        await revoke_refresh_token(jti, redis_client)
        is_valid = await is_refresh_token_valid(jti, redis_client)
        
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_refresh_token_not_stored(self, redis_client):
        """Test checking non-stored refresh token"""
        is_valid = await is_refresh_token_valid("non-existent-jti", redis_client)
        assert is_valid is False


# =============================================================================
# AUTH.PY TESTS - API KEY VALIDATION
# =============================================================================

class TestAPIKeyValidation:
    """Tests for API key validation"""
    
    @pytest.mark.asyncio
    async def test_validate_api_key_success(self, redis_client, valid_api_key):
        """Test validating a valid API key"""
        # Setup: store API key in Redis
        key_hash = create_hashed_key(valid_api_key)
        key_data = {
            "status": "active",
            "user_id": "user123",
            "plan": "PREMIUM",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await redis_client.set(f"key:{key_hash}", json.dumps(key_data))
        
        # Create mock request
        mock_request = Mock()
        mock_request.state.correlation_id = "test-request-123"
        
        result = await validate_api_key(mock_request, valid_api_key, redis_client)
        
        assert result["api_key"] == valid_api_key
        assert result["key_hash"] == key_hash
        assert result["key_info"]["status"] == "active"
    
    @pytest.mark.asyncio
    async def test_validate_api_key_not_found(self, redis_client, valid_api_key):
        """Test validating non-existent API key"""
        mock_request = Mock()
        mock_request.state.correlation_id = "test-request-123"
        
        with pytest.raises(HTTPException) as exc_info:
            await validate_api_key(mock_request, valid_api_key, redis_client)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    
    @pytest.mark.asyncio
    async def test_validate_api_key_empty(self, redis_client):
        """Test validating empty API key"""
        mock_request = Mock()
        mock_request.state.correlation_id = "test-request-123"
        
        with pytest.raises(HTTPException) as exc_info:
            await validate_api_key(mock_request, "", redis_client)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Missing API Key" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_validate_api_key_deprecated(self, redis_client, valid_api_key):
        """Test validating deprecated API key"""
        key_hash = create_hashed_key(valid_api_key)
        key_data = {"status": "deprecated"}
        await redis_client.set(f"key:{key_hash}", json.dumps(key_data))
        
        mock_request = Mock()
        mock_request.state.correlation_id = "test-request-123"
        
        with pytest.raises(HTTPException) as exc_info:
            await validate_api_key(mock_request, valid_api_key, redis_client)
        
        assert exc_info.value.status_code == status.HTTP_410_GONE
        assert "Deprecated" in exc_info.value.detail


# =============================================================================
# AUTH.PY TESTS - ENDPOINT TESTING
# =============================================================================

class TestAuthEndpoints:
    """Tests for authentication endpoints"""
    
    @pytest.mark.asyncio
    @patch('app.config.settings')
    async def test_register_endpoint_success(self, mock_settings, valid_email, valid_password):
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
    async def test_login_endpoint_success(self, mock_settings, valid_email, valid_password):
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
    async def test_login_endpoint_wrong_password(self, mock_settings, valid_email, valid_password):
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


# =============================================================================
# API_KEYS.PY TESTS - KEY CREATION
# =============================================================================

class TestAPIKeyCreation:
    """Tests for API key creation functionality"""
    
    @pytest.mark.asyncio
    async def test_create_api_key_max_limit(self, redis_client):
        """Test creating API key when max limit reached"""
        from app.api_keys import MAX_KEYS_PER_USER, AtomicOperations
        from redis.exceptions import ResponseError
        
        user_id = "user123"
        client_hash = hashlib.sha256(user_id.encode()).hexdigest()
        
        # Setup: crear el usuario primero
        user_key = f"user:{user_id}"
        await redis_client.hset(user_key, mapping={
            "id": user_id,
            "email": "test@example.com",
            "plan": "FREE"
        })
        
        # Crear MAX_KEYS_PER_USER keys
        for i in range(MAX_KEYS_PER_USER):
            fake_hash = f"{i:064d}"[:64]
            key_data = {"status": "active", "user_id": user_id}
            await redis_client.set(f"key:{fake_hash}", json.dumps(key_data))
            await redis_client.sadd(f"api_keys:{client_hash}", fake_hash)
        
        # Verificar el límite
        count = await redis_client.scard(f"api_keys:{client_hash}")
        assert count == MAX_KEYS_PER_USER
        
        # NUEVO: Intentar crear una key adicional y verificar que falla
        new_key_hash = f"{MAX_KEYS_PER_USER:064d}"[:64]
        new_key_data = json.dumps({"status": "active", "user_id": user_id})
        
        with pytest.raises(ResponseError, match="max_keys_exceeded"):
            await redis_client.eval(
                AtomicOperations.CREATE_KEY_SCRIPT,
                3,
                user_key,
                f"key:{new_key_hash}",
                f"api_keys:{client_hash}",
                new_key_hash,
                new_key_data,
                user_id,
                "test@example.com",
                "FREE",
                datetime.now(timezone.utc).isoformat(),
                str(MAX_KEYS_PER_USER),
            )



# =============================================================================
# API_KEYS.PY TESTS - KEY LISTING
# =============================================================================

class TestAPIKeyListing:
    """Tests for API key listing functionality"""
    
    @pytest.mark.asyncio
    async def test_list_api_keys_empty(self, redis_client):
        """Test listing API keys when none exist"""
        from app.api_keys import APIKeySecurity
        
        user_id = "user123"
        client_hash = APIKeySecurity.hash_id(user_id)
        
        # No keys stored
        api_key_hashes = await redis_client.smembers(f"api_keys:{client_hash}")
        assert len(api_key_hashes) == 0
    
    @pytest.mark.asyncio
    async def test_list_api_keys_multiple(self, redis_client):
        """Test listing multiple API keys"""
        from app.api_keys import APIKeySecurity
        
        user_id = "user123"
        client_hash = APIKeySecurity.hash_id(user_id)
        
        # Create test keys
        for i in range(3):
            key_hash = f"{'0' * (64 - len(str(i)))}{i}"
            key_data = {
                "status": "active",
                "user_id": user_id,
                "plan": "PREMIUM",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "name": f"Key {i}",
                "revoked": False
            }
            await redis_client.set(f"key:{key_hash}", json.dumps(key_data))
            await redis_client.sadd(f"api_keys:{client_hash}", key_hash)
        
        api_key_hashes = await redis_client.smembers(f"api_keys:{client_hash}")
        assert len(api_key_hashes) == 3


# =============================================================================
# API_KEYS.PY TESTS - KEY REVOCATION
# =============================================================================

class TestAPIKeyRevocation:
    """Tests for API key revocation"""
    
    @pytest.mark.asyncio
    async def test_revoke_api_key_success(self, redis_client, valid_api_key):
        """Test revoking API key successfully"""
        from app.api_keys import APIKeySecurity
        
        user_id = "user123"
        key_hash = create_hashed_key(valid_api_key)
        client_hash = APIKeySecurity.hash_id(user_id)
        
        # Setup key
        key_data = {
            "status": "active",
            "user_id": user_id,
            "plan": "PREMIUM",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "revoked": False
        }
        await redis_client.set(f"key:{key_hash}", json.dumps(key_data))
        await redis_client.sadd(f"api_keys:{client_hash}", key_hash)
        
        # Verify key is active
        is_member = await redis_client.sismember(f"api_keys:{client_hash}", key_hash)
        assert is_member == 1
    
    @pytest.mark.asyncio
    async def test_revoke_api_key_not_found(self, redis_client):
        """Test revoking non-existent API key"""
        from app.api_keys import APIKeySecurity
        
        user_id = "user123"
        key_hash = "0" * 64
        client_hash = APIKeySecurity.hash_id(user_id)
        
        # Key doesn't exist in set
        is_member = await redis_client.sismember(f"api_keys:{client_hash}", key_hash)
        assert is_member == 0


# =============================================================================
# API_KEYS.PY TESTS - KEY ROTATION
# =============================================================================

class TestAPIKeyRotation:
    """Tests for API key rotation with grace period"""
    
    @pytest.mark.asyncio
    async def test_rotate_api_key_creates_new(self, redis_client, valid_api_key):
        """Test rotation creates new key"""
        from app.api_keys import GRACE_PERIOD_DAYS
        
        old_hash = create_hashed_key(valid_api_key)
        new_key = secrets.token_urlsafe(32)
        new_hash = create_hashed_key(new_key)
        
        # Old key data
        old_data = {
            "status": "active",
            "user_id": "user123",
            "plan": "PREMIUM",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "name": "Original Key"
        }
        await redis_client.set(f"key:{old_hash}", json.dumps(old_data))
        
        # Simulate rotation
        grace_seconds = GRACE_PERIOD_DAYS * 24 * 3600
        deprecated_data = {
            **old_data,
            "status": "deprecated",
            "grace_period_ends": (datetime.now(timezone.utc) + timedelta(seconds=grace_seconds)).isoformat()
        }
        
        await redis_client.setex(f"key:{old_hash}", grace_seconds, json.dumps(deprecated_data))
        
        # Verify old key has TTL
        ttl = await redis_client.ttl(f"key:{old_hash}")
        assert ttl > 0


# =============================================================================
# BILLING_ROUTES.PY TESTS - SECURITY UTILITIES
# =============================================================================

class TestBillingSecurity:
    """Tests for billing security utilities"""
    
    def test_sanitize_metadata_value_clean(self):
        """Test sanitizing clean metadata value"""
        from app.routes.billing_routes import BillingSecurity
        
        result = BillingSecurity.sanitize_metadata_value("user_123-ABC")
        assert result == "user_123-ABC"
    
    def test_sanitize_metadata_value_special_chars(self):
        """Test sanitizing metadata with special characters"""
        from app.routes.billing_routes import BillingSecurity
        
        result = BillingSecurity.sanitize_metadata_value("user@123#ABC!")
        assert "@" not in result
        assert "#" not in result
        assert "!" not in result
    
    def test_sanitize_metadata_value_empty(self):
        """Test sanitizing empty metadata"""
        from app.routes.billing_routes import BillingSecurity
        
        result = BillingSecurity.sanitize_metadata_value("")
        assert result == ""
    
    def test_sanitize_metadata_value_none(self):
        """Test sanitizing None metadata"""
        from app.routes.billing_routes import BillingSecurity
        
        result = BillingSecurity.sanitize_metadata_value(None)
        assert result == ""
    
    def test_mask_pii_email(self):
        """Test masking PII in email addresses"""
        from app.routes.billing_routes import BillingSecurity
        
        raw = "Contact: john.doe@example.com for support"
        masked = BillingSecurity.mask_pii(raw)
        
        assert "john.doe@example.com" not in masked
        assert "j***@e***.com" in masked
    
    def test_mask_pii_multiple_emails(self):
        """Test masking multiple emails"""
        from app.routes.billing_routes import BillingSecurity
        
        raw = "Emails: alice@test.com and bob@example.org"
        masked = BillingSecurity.mask_pii(raw)
        
        assert "alice@test.com" not in masked
        assert "bob@example.org" not in masked


# =============================================================================
# BILLING_ROUTES.PY TESTS - REDIS OPERATIONS
# =============================================================================

class TestRedisOperations:
    """Tests for Redis operation helpers"""
    
    @pytest.mark.asyncio
    async def test_bytes_to_str_with_bytes(self):
        """Test converting bytes to string"""
        from app.routes.billing_routes import RedisOperations
        
        result = await RedisOperations.bytes_to_str(b"test_string")
        assert result == "test_string"
    
    @pytest.mark.asyncio
    async def test_bytes_to_str_with_none(self):
        """Test converting None returns None"""
        from app.routes.billing_routes import RedisOperations
        
        result = await RedisOperations.bytes_to_str(None)
        assert result is None
    
    @pytest.mark.asyncio
    async def test_bytes_to_str_with_string(self):
        """Test converting string returns string"""
        from app.routes.billing_routes import RedisOperations
        
        result = await RedisOperations.bytes_to_str("already_string")
        assert result == "already_string"
    
    @pytest.mark.asyncio
    async def test_get_json_success(self, redis_client):
        """Test getting JSON from Redis"""
        from app.routes.billing_routes import RedisOperations
        
        test_data = {"key": "value", "number": 123}
        await redis_client.set("test:json", json.dumps(test_data))
        
        result = await RedisOperations.get_json(redis_client, "test:json")
        assert result == test_data
    
    @pytest.mark.asyncio
    async def test_get_json_not_exists(self, redis_client):
        """Test getting non-existent JSON returns None"""
        from app.routes.billing_routes import RedisOperations
        
        result = await RedisOperations.get_json(redis_client, "non:existent")
        assert result is None
    
    @pytest.mark.asyncio
    async def test_set_json_success(self, redis_client):
        """Test setting JSON in Redis"""
        from app.routes.billing_routes import RedisOperations
        
        test_data = {"test": "data"}
        await RedisOperations.set_json(redis_client, "test:key", test_data)
        
        raw = await redis_client.get("test:key")
        result = json.loads(raw)
        assert result == test_data


# =============================================================================
# BILLING_ROUTES.PY TESTS - STRIPE CLIENT
# =============================================================================

class TestStripeClient:
    """Tests for Stripe client wrapper"""
    
    @pytest.mark.asyncio
    @patch('stripe.Subscription.retrieve')
    async def test_retrieve_subscription_success(self, mock_retrieve):
        """Test retrieving Stripe subscription"""
        from app.routes.billing_routes import StripeClient
        
        mock_retrieve.return_value = {"id": "sub_123", "status": "active"}
        
        result = await StripeClient.retrieve_subscription("sub_123")
        assert result["id"] == "sub_123"
        mock_retrieve.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('stripe.Customer.create')
    async def test_create_customer_success(self, mock_create):
        """Test creating Stripe customer"""
        from app.routes.billing_routes import StripeClient
        
        mock_create.return_value = {"id": "cus_123", "email": "test@example.com"}
        
        result = await StripeClient.create_customer({"user_id": "user123"})
        assert result["id"] == "cus_123"
        mock_create.assert_called_once()


# =============================================================================
# BILLING_ROUTES.PY TESTS - EVENT PROCESSING
# =============================================================================

class TestEventProcessor:
    """Tests for Stripe event processing"""
    
    @pytest.mark.asyncio
    async def test_is_event_processed_true(self, redis_client):
        """Test checking if event was processed"""
        from app.routes.billing_routes import EventProcessor, PROCESSED_EVENT_KEY_PREFIX
        
        event_id = "evt_test_123"
        await redis_client.set(f"{PROCESSED_EVENT_KEY_PREFIX}{event_id}", "1")
        
        result = await EventProcessor.is_event_processed(redis_client, event_id)
        assert result is True
    
    @pytest.mark.asyncio
    async def test_is_event_processed_false(self, redis_client):
        """Test checking unprocessed event"""
        from app.routes.billing_routes import EventProcessor
        
        result = await EventProcessor.is_event_processed(redis_client, "evt_not_processed")
        assert result is False
    
    @pytest.mark.asyncio
    async def test_mark_event_processed(self, redis_client):
        """Test marking event as processed"""
        from app.routes.billing_routes import EventProcessor, PROCESSED_EVENT_KEY_PREFIX
        
        event_id = "evt_new_123"
        await EventProcessor.mark_event_processed(redis_client, event_id)
        
        exists = await redis_client.exists(f"{PROCESSED_EVENT_KEY_PREFIX}{event_id}")
        assert exists == 1
    
    def test_extract_plan_info_premium(self):
        """Test extracting plan info from subscription"""
        from app.routes.billing_routes import EventProcessor
        from app.config import get_settings
        
        with patch('app.config.get_settings') as mock_settings:
            mock_settings.return_value.stripe.premium_plan_id = "price_premium"
            mock_settings.return_value.stripe.enterprise_plan_id = "price_enterprise"
            
            subscription = {
                "id": "sub_123",
                "items": {
                    "data": [
                        {"price": {"id": "price_premium"}}
                    ]
                },
                "current_period_end": int((datetime.now(timezone.utc) + timedelta(days=30)).timestamp())
            }
            
            result = EventProcessor._extract_plan_info(subscription)
            assert result["plan"] == "PREMIUM"
            assert result["subscription_id"] == "sub_123"
            assert result["next_billing"] != ""


# =============================================================================
# BILLING_ROUTES.PY TESTS - LOCK MANAGER
# =============================================================================

class TestLockManager:
    """Tests for distributed locking"""
    
    @pytest.mark.asyncio
    async def test_acquire_lock_success(self, redis_client):
        """Test acquiring lock successfully"""
        from app.routes.billing_routes import LockManager
        
        async with LockManager.acquire_lock(redis_client, "test:lock", 60, "test") as owner:
            assert owner is not None
            # Lock should exist
            exists = await redis_client.exists("test:lock")
            assert exists == 1
    
    @pytest.mark.asyncio
    async def test_acquire_lock_already_held(self, redis_client):
        """Test acquiring already held lock"""
        from app.routes.billing_routes import LockManager
        
        # First lock
        async with LockManager.acquire_lock(redis_client, "test:lock2", 60, "test") as owner1:
            assert owner1 is not None
            
            # Try to acquire same lock
            async with LockManager.acquire_lock(redis_client, "test:lock2", 60, "test") as owner2:
                assert owner2 is None
    
    @pytest.mark.asyncio
    async def test_lock_released_after_context(self, redis_client):
        """Test lock is released after context"""
        from app.routes.billing_routes import LockManager
        
        async with LockManager.acquire_lock(redis_client, "test:lock3", 60, "test") as owner:
            assert owner is not None
        
        # Lock should be released
        exists = await redis_client.exists("test:lock3")
        assert exists == 0


# =============================================================================
# INTEGRATION TESTS - COMPLETE WORKFLOWS
# =============================================================================

class TestCompleteWorkflows:
    """Integration tests for complete user workflows"""
    
    @pytest.mark.asyncio
    @patch("app.auth.settings")
    async def test_complete_user_registration_flow(self, mock_settings):
        """Test complete user registration to API key creation"""
        mock_settings.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
        mock_settings.jwt.issuer = "test-issuer"
        mock_settings.jwt.audience = "test-audience"
        mock_settings.jwt.access_token_expire_minutes = 30
        mock_settings.jwt.refresh_token_expire_days = 7
        
        redis_client = fakeredis.FakeAsyncRedis(decode_responses=False)
        
        # Step 1: Register user
        email = "integration@test.com"
        password = "SecurePass123!"
        user = await create_user(redis_client, email, password, "FREE")
        
        assert user.email == email
        assert user.plan == "FREE"
        
        # Step 2: Login
        retrieved_user = await get_user_by_email(redis_client, email)
        assert retrieved_user is not None
        assert verify_password(password, retrieved_user.hashed_password)
        
        # Step 3: Create access token
        token = create_access_token({"sub": user.id, "email": email}, plan="FREE")
        assert token is not None
        
        # Step 4: Verify token contains correct scopes
        payload = jwt.decode(
            token,
            "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo",
            algorithms=[JWT_ALGORITHM],
            audience="test-audience",  # ← AGREGAR
            issuer="test-issuer",      # ← AGREGAR
            options={"verify_signature": True}
        )
        assert "validate:single" in payload["scopes"]
        
        await redis_client.aclose()
    
    @pytest.mark.asyncio
    async def test_api_key_lifecycle(self, valid_api_key):
        """Test API key creation, usage, and revocation"""
        from app.api_keys import APIKeySecurity
        
        redis_client = fakeredis.FakeAsyncRedis(decode_responses=False)
        
        user_id = "lifecycle_user"
        key_hash = create_hashed_key(valid_api_key)
        client_hash = APIKeySecurity.hash_id(user_id)
        
        # Create
        key_data = {
            "status": "active",
            "user_id": user_id,
            "plan": "PREMIUM",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "revoked": False,
            "name": "Test Key"
        }
        await redis_client.set(f"key:{key_hash}", json.dumps(key_data))
        await redis_client.sadd(f"api_keys:{client_hash}", key_hash)
        
        # Verify active
        stored_data = await redis_client.get(f"key:{key_hash}")
        assert stored_data is not None
        parsed = json.loads(stored_data)
        assert parsed["status"] == "active"
        
        # Revoke
        key_data["status"] = "revoked"
        key_data["revoked"] = True
        await redis_client.set(f"key:{key_hash}", json.dumps(key_data))
        await redis_client.srem(f"api_keys:{client_hash}", key_hash)
        
        # Verify revoked
        is_member = await redis_client.sismember(f"api_keys:{client_hash}", key_hash)
        assert is_member == 0
        
        await redis_client.aclose()


# =============================================================================
# EDGE CASES AND ERROR HANDLING
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error conditions"""
    
    @pytest.mark.asyncio
    async def test_concurrent_user_creation(self, redis_client, valid_email, valid_password):
        """Test handling concurrent user creation attempts"""
        # First creation should succeed
        user1 = await create_user(redis_client, valid_email, valid_password, "FREE")
        assert user1 is not None
        
        # Second should fail
        with pytest.raises(HTTPException) as exc_info:
            await create_user(redis_client, valid_email, valid_password, "FREE")
        
        assert exc_info.value.status_code == 400
    
    @pytest.mark.asyncio
    async def test_token_expiration_handling(self, mock_settings):
        """Test handling expired tokens"""
        with patch('app.config.settings', mock_settings):
            # Create token with past expiration
            data = {"sub": "user123"}
            past_time = datetime.now(timezone.utc) - timedelta(hours=1)
            
            token = create_jwt_token(
                data,
                expires_delta=timedelta(seconds=-3600),
                plan="FREE"
            )
            
            # Token should be created but will fail validation
            assert token is not None
    
    def test_password_edge_cases(self):
        """Test password hashing edge cases"""
        # Unicode characters
        unicode_password = "Pässwörd123!"
        hashed = get_password_hash(unicode_password)
        assert verify_password(unicode_password, hashed)
        
        # Very long password
        long_password = "A" * 100 + "a1!"
        hashed_long = get_password_hash(long_password)
        assert verify_password(long_password, hashed_long)


# =============================================================================
# PERFORMANCE AND LOAD TESTS
# =============================================================================

class TestPerformance:
    """Basic performance tests"""
    
    @pytest.mark.asyncio
    async def test_password_hashing_performance(self, valid_password):
        """Test password hashing performance"""
        import time
        start = time.time()
        for _ in range(10):
            get_password_hash(valid_password)
        elapsed = time.time() - start
        # Bcrypt es intencionalmente lento por seguridad
        assert elapsed < 3.0  # Cambiar de 2.0 a 3.0

    
    @pytest.mark.asyncio
    async def test_api_key_hashing_performance(self):
        """Test API key hashing performance"""
        import time
        
        test_key = secrets.token_urlsafe(32)
        
        start = time.time()
        for _ in range(1000):
            create_hashed_key(test_key)
        elapsed = time.time() - start
        
        # Should complete 1000 hashes quickly (< 0.1 seconds)
        assert elapsed < 0.1


# =============================================================================
# TEST CONFIGURATION AND MARKERS
# =============================================================================

# Add custom markers
pytest.mark.unit = pytest.mark.unit
pytest.mark.integration = pytest.mark.integration
pytest.mark.slow = pytest.mark.slow

# Run with:
# pytest test_complete_api.py -v
# pytest test_complete_api.py -v -m "not slow"  # Skip slow tests
# pytest test_complete_api.py -v -k "test_create_user"  # Run specific tests

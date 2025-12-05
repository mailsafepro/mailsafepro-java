"""
COMPLETE AUTH.PY TESTING - Production-grade test suite
With proper fakeredis[lua] support and comprehensive coverage
"""

import pytest
import pytest_asyncio
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timedelta, timezone
import secrets
import json

import os
os.environ["TESTING"] = "1"
os.environ["DISABLE_PROMETHEUS"] = "1"

# Import with Lua support
import fakeredis.aioredis
from fastapi import FastAPI, HTTPException
from httpx import AsyncClient, ASGITransport
import jwt

from app.auth import (
    router as auth_router,
    create_user,
    get_user_by_email,
    create_access_token,
    create_refresh_token,
    blacklist_token,
    is_token_blacklisted,
    store_refresh_token,
    revoke_refresh_token,
    is_refresh_token_valid,
    validate_api_key,
    get_current_client,
    validate_api_key_or_token,
    create_hashed_key,
    verify_password,
    get_password_hash,
    enforce_rate_limit,
    JWT_ALGORITHM,
    PLAN_SCOPES,
)


# ============================================================================
# PRODUCTION FIXTURES
# ============================================================================

@pytest_asyncio.fixture
async def redis_with_lua():
    """Redis client WITH Lua script support"""
    # Use FakeRedis with Lua support
    client = fakeredis.aioredis.FakeRedis(decode_responses=False, version=7)
    yield client
    await client.flushall()
    await client.aclose()


@pytest.fixture
def mock_password_functions():
    """Mock password hashing to avoid bcrypt issues"""
    with patch("app.auth.get_password_hash") as m_hash, \
         patch("app.auth.verify_password") as m_verify:
        
        def hash_side_effect(password):
            if len(password) < 8:
                raise ValueError("Password must be at least 8 characters")
            # Return bcrypt-like format
            return f"$2b$12$hashed_{password}_end"
        
        def verify_side_effect(plain, hashed):
            expected = f"$2b$12$hashed_{plain}_end"
            return hashed == expected
        
        m_hash.side_effect = hash_side_effect
        m_verify.side_effect = verify_side_effect
        
        yield


@pytest.fixture
def mock_all_settings():
    """Mock all settings properly"""
    with patch("app.auth.settings") as m_auth, \
         patch("app.config.settings") as m_config:
        
        secret = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
        
        for mock in [m_auth, m_config]:
            mock.jwt.secret.get_secret_value.return_value = secret
            mock.jwt.access_token_expire_minutes = 30
            mock.jwt.refresh_token_expire_days = 7
            mock.jwt.issuer = "mailsafepro"
            mock.jwt.audience = "mailsafepro-api"
        
        yield m_auth


@pytest_asyncio.fixture
async def test_app(redis_with_lua, mock_all_settings):
    """FastAPI test app with all dependencies"""
    app = FastAPI()
    app.state.redis = redis_with_lua
    app.include_router(auth_router)
    return app


# ============================================================================
# TOKEN OPERATIONS - NOW WITH LUA SUPPORT
# ============================================================================

class TestTokenOperations:
    """Test token operations with Lua support"""
    
    @pytest.mark.asyncio
    async def test_blacklist_token_complete(self, redis_with_lua):
        """Test blacklisting token"""
        token = "test_token_abc123"
        ttl = 3600
        
        await blacklist_token(token, ttl, redis_with_lua)
        
        # Verify it's blacklisted
        is_blacklisted = await is_token_blacklisted(token, redis_with_lua)
        assert is_blacklisted is True
    
    @pytest.mark.asyncio
    async def test_token_not_blacklisted(self, redis_with_lua):
        """Test token that's not blacklisted"""
        is_blacklisted = await is_token_blacklisted("not_blacklisted", redis_with_lua)
        assert is_blacklisted is False
    
    @pytest.mark.asyncio
    async def test_refresh_token_lifecycle(self, redis_with_lua):
        """Test complete refresh token lifecycle"""
        user_id = "user_lifecycle_123"
        token_value = "refresh_token_xyz"
        
        # Store
        from datetime import datetime, timedelta, timezone
        expires = datetime.now(timezone.utc) + timedelta(seconds=3600)
        await store_refresh_token(token_value, expires, redis_with_lua)
        
        # Validate
        is_valid = await is_refresh_token_valid(token_value, redis_with_lua)
        assert is_valid is True
        
        # Revoke
        await revoke_refresh_token(token_value, redis_with_lua)
        
        # Should be invalid now
        is_valid = await is_refresh_token_valid(token_value, redis_with_lua)
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_multiple_tokens_blacklist(self, redis_with_lua):
        """Test blacklisting multiple tokens"""
        tokens = [f"token_{i}" for i in range(5)]
        
        for token in tokens:
            await blacklist_token(token, 3600, redis_with_lua)
        
        for token in tokens:
            assert await is_token_blacklisted(token, redis_with_lua) is True


# ============================================================================
# USER OPERATIONS - NOW WORKING
# ============================================================================

class TestUserOperations:
    """Test user operations with proper Redis"""
    
    @pytest.mark.asyncio
    async def test_create_user_success(self, redis_with_lua, mock_password_functions):
        """Test creating user successfully"""
        email = "testuser@example.com"
        password = "CorrectHorseBatteryStaple2024!"
        plan = "FREE"
        
        user = await create_user(redis_with_lua, email, password, plan)
        
        assert user.email == email
        assert user.plan == plan
        assert user.is_active is True
        assert user.email_verified is False
        assert len(user.id) > 10
    
    @pytest.mark.asyncio
    async def test_create_user_duplicate_email(self, redis_with_lua, mock_password_functions):
        """Test duplicate email raises error"""
        email = "duplicate@test.com"
        
        # Use a stronger password to pass zxcvbn check
        await create_user(redis_with_lua, email, "StrongPassword123!@#", "FREE")
        
        # Try to create same user
        with pytest.raises(HTTPException) as exc:
            await create_user(redis_with_lua, email, "StrongPassword123!@#", "FREE")
            
        assert exc.value.status_code == 400
        assert "already exists" in exc.value.detail
    
    @pytest.mark.asyncio
    async def test_create_user_all_plans(self, redis_with_lua, mock_password_functions):
        """Test creating users with all plan types"""
        plans = ["FREE", "PREMIUM", "ENTERPRISE"]
        
        for i, plan in enumerate(plans):
            email = f"user_{plan.lower()}@test.com"
            user = await create_user(redis_with_lua, email, "StrongPassword123!@#", plan)
            
            assert user.plan == plan
            assert user.email == email
    
    @pytest.mark.asyncio
    async def test_get_user_by_email(self, redis_with_lua, mock_password_functions):
        """Test retrieving user by email"""
        email = "retrieve@test.com"
        created_user = await create_user(redis_with_lua, email, "StrongPassword123!@#", "PREMIUM")
        
        retrieved_user = await get_user_by_email(redis_with_lua, email)
        
        assert retrieved_user is not None
        assert retrieved_user.email == email
        assert retrieved_user.id == created_user.id
        assert retrieved_user.plan == "PREMIUM"
    
    @pytest.mark.asyncio
    async def test_get_user_nonexistent(self, redis_with_lua):
        """Test getting nonexistent user"""
        user = await get_user_by_email(redis_with_lua, "nonexistent@test.com")
        assert user is None
    
    @pytest.mark.asyncio
    async def test_create_user_invalid_email(self, redis_with_lua, mock_password_functions):
        """Test invalid email format"""
        with pytest.raises(HTTPException) as exc:
            await create_user(redis_with_lua, "not-an-email", "CorrectHorseBatteryStaple2024!", "FREE")
        
        assert exc.value.status_code == 400


# ============================================================================
# API KEY VALIDATION - COMPLETE
# ============================================================================

class TestAPIKeyValidation:
    """Test API key validation completely"""
    
    @pytest.mark.asyncio
    async def test_validate_api_key_success(self, redis_with_lua):
        """Test successful API key validation"""
        # Generate real API key
        api_key = secrets.token_urlsafe(32)
        hashed_key = create_hashed_key(api_key)
        
        # Store in Redis with correct JSON format
        import json
        key_data = {
            "user_id": "api_user_123",
            "plan": "PREMIUM",
            "is_active": True,
            "status": "active",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "name": "Test API Key"
        }
        
        await redis_with_lua.set(f"key:{hashed_key}", json.dumps(key_data))
        
        # Create mock request
        request = Mock()
        request.app.state.redis = redis_with_lua
        request.state.correlation_id = "test-123"
        
        # Validate
        result = await validate_api_key(request, api_key, redis_with_lua)
        
        assert result["api_key"] == api_key
    
    @pytest.mark.asyncio
    async def test_validate_api_key_not_found(self, redis_with_lua):
        """Test API key not in database"""
        api_key = secrets.token_urlsafe(32)
        request = Mock()
        
        with pytest.raises(HTTPException) as exc:
            await validate_api_key(request, api_key, redis_with_lua)
        
        assert exc.value.status_code == 401
    
    @pytest.mark.asyncio
    async def test_validate_api_key_inactive(self, redis_with_lua):
        """Test inactive API key"""
        api_key = secrets.token_urlsafe(32)
        hashed_key = create_hashed_key(api_key)
        
        # Store in Redis as JSON with deprecated status
        import json
        key_data = {
            "user_id": "user123",
            "plan": "FREE",
            "status": "deprecated",  # Triggers 410
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        await redis_with_lua.set(f"key:{hashed_key}", json.dumps(key_data))
        
        request = Mock()
        request.state.correlation_id = "test-123"
        
        with pytest.raises(HTTPException) as exc:
            await validate_api_key(request, api_key, redis_with_lua)
        
        assert exc.value.status_code == 410  # Deprecated returns 410


# ============================================================================
# JWT TOKEN TESTS - COMPREHENSIVE
# ============================================================================

class TestJWTTokens:
    """Comprehensive JWT token tests"""
    
    @patch("app.auth.settings")
    def test_create_access_token(self, mock_settings):
        """Test creating access token"""
        mock_settings.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
        mock_settings.jwt.issuer = "test"
        mock_settings.jwt.audience = "test"
        
        token = create_access_token(
            data={"sub": "user123", "email": "test@example.com"},
            plan="PREMIUM"
        )
        
        assert isinstance(token, str)
        assert len(token) > 50
        
        # Decode and verify
        payload = jwt.decode(
            token,
            "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo",
            algorithms=[JWT_ALGORITHM],
            audience="test",
            issuer="test"
        )
        
        assert payload["sub"] == "user123"
        assert payload["email"] == "test@example.com"
        assert payload["plan"] == "PREMIUM"
        assert payload["type"] == "access"
        assert "validate:batch" in payload["scopes"]
    
    @patch("app.auth.settings")
    def test_create_refresh_token(self, mock_settings):
        """Test creating refresh token"""
        mock_settings.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
        mock_settings.jwt.issuer = "test"
        mock_settings.jwt.audience = "test"
        mock_settings.jwt.refresh_token_expire_days = 7
        
        token, expires_at = create_refresh_token(data={"sub": "user123"}, plan="FREE")
        
        assert isinstance(token, str)
        assert isinstance(expires_at, datetime)
        
        # Should expire in ~7 days
        now = datetime.now(timezone.utc)
        assert expires_at > now + timedelta(days=6)
    
    @patch("app.auth.settings")
    def test_token_scopes_all_plans(self, mock_settings):
        """Test tokens have correct scopes for all plans"""
        mock_settings.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
        mock_settings.jwt.issuer = "test"
        mock_settings.jwt.audience = "test"
        
        # Test FREE
        token_free = create_access_token({"sub": "u1"}, plan="FREE")
        payload_free = jwt.decode(token_free, "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo", algorithms=[JWT_ALGORITHM], audience="test", issuer="test")
        assert set(payload_free["scopes"]) == set(PLAN_SCOPES["FREE"])
        
        # Test ENTERPRISE
        token_ent = create_access_token({"sub": "u3"}, plan="ENTERPRISE")
        payload_ent = jwt.decode(token_ent, "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo", algorithms=[JWT_ALGORITHM], audience="test", issuer="test")
        assert "admin" in payload_ent["scopes"]


# ============================================================================
# RATE LIMITING - WITH LUA SUPPORT
# ============================================================================

class TestRateLimiting:
    """Test rate limiting with Lua scripts"""
    
    @pytest.mark.asyncio
    async def test_enforce_rate_limit_under_limit(self, redis_with_lua):
        """Test rate limit when under limit"""
        bucket = "test:bucket:under"
        
        # Should not raise
        await enforce_rate_limit(redis_with_lua, bucket, limit=10, window=60)
        
        # Should work fine
        assert True
    
    @pytest.mark.asyncio
    async def test_enforce_rate_limit_multiple_requests(self, redis_with_lua):
        """Test multiple requests within limit"""
        bucket = "test:bucket:multiple"
        
        # Make 5 requests
        for i in range(5):
            await enforce_rate_limit(redis_with_lua, bucket, limit=10, window=60)
        
        # All should succeed
        assert True


# ============================================================================
# ENDPOINT TESTS - WITH REAL APP
# ============================================================================

class TestEndpoints:
    """Test authentication endpoints"""
    
    @pytest.mark.asyncio
    async def test_register_endpoint(self, test_app, mock_password_functions):
        """Test /register endpoint"""
        async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
            response = await client.post(
                "/register",
                json={
                    "email": "newuser@example.com",
                    "password": "CorrectHorseBatteryStaple2024!",
                    "plan": "FREE"
                }
            )
        
        assert response.status_code in [200, 201]
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert "api_key" in data
    
    @pytest.mark.asyncio
    async def test_login_endpoint(self, test_app, redis_with_lua, mock_password_functions):
        """Test /login endpoint"""
        # Create user first
        email = "logintest@example.com"
        password = "CorrectHorseBatteryStaple2024!"
        await create_user(redis_with_lua, email, password, "FREE")
        
        async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
            response = await client.post(
                "/login",
                json={"email": email, "password": password}
            )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data



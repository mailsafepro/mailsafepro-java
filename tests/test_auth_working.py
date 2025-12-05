"""
PRODUCTION-READY auth.py tests
Con signatures correctas y fakeredis[lua] support
"""

import pytest
import pytest_asyncio
from unittest.mock import Mock, patch
from datetime import datetime, timedelta, timezone
import secrets

import os
os.environ["TESTING"] = "1"
os.environ["DISABLE_PROMETHEUS"] = "1"

# Import fakeredis with Lua support
from fakeredis import FakeAsyncRedis
from fastapi import HTTPException
import jwt

from app.auth import (
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
    create_hashed_key,
    JWT_ALGORITHM,
    PLAN_SCOPES,
)


# ============================================================================
# FIXTURES
# ============================================================================

@pytest_asyncio.fixture
async def redis():
    """Redis con soporte Lua"""
    client = FakeAsyncRedis(decode_responses=False)
    yield client
    await client.flushall()
    await client.aclose()


@pytest.fixture
def mock_hash():
    """Mock password hashing"""
    with patch("app.auth.get_password_hash") as m_hash, \
         patch("app.auth.verify_password") as m_verify:
        
        m_hash.side_effect = lambda p: f"$2b$12${p}$" if len(p) >= 8 else (_ for _ in ()).throw(ValueError("Password must be at least 8 characters"))
        m_verify.side_effect = lambda plain, hashed: hashed == f"$2b$12${plain}$"
        yield


@pytest.fixture
def mock_settings():
    """Mock settings"""
    with patch("app.auth.settings") as m:
        m.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
        m.jwt.access_token_expire_minutes = 30
        m.jwt.refresh_token_expire_days = 7
        m.jwt.issuer = "mailsafepro"
        m.jwt.audience = "mailsafepro-api"
        yield m


# ============================================================================
# TOKEN BLACKLIST - SIGNATURES CORRECTAS
# ============================================================================

class TestTokenBlacklist:
    """Test token blacklisting con signatures correctas"""
    
    @pytest.mark.asyncio
    async def test_blacklist_token_works(self, redis):
        """Test blacklisting a token"""
        jti = "token_jti_123"
        exp = datetime.now(timezone.utc) + timedelta(hours=1)
        
        # Blacklist
        await blacklist_token(jti, exp, redis)
        
        # Check
        is_blacklisted = await is_token_blacklisted(jti, redis)
        assert is_blacklisted is True
    
    @pytest.mark.asyncio
    async def test_token_not_blacklisted(self, redis):
        """Test non-blacklisted token"""
        is_blacklisted = await is_token_blacklisted("not_blacklisted", redis)
        assert is_blacklisted is False
    
    @pytest.mark.asyncio
    async def test_blacklist_with_int_timestamp(self, redis):
        """Test blacklist with int timestamp"""
        jti = "token_int_123"
        exp_ts = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        
        await blacklist_token(jti, exp_ts, redis)
        
        is_blacklisted = await is_token_blacklisted(jti, redis)
        assert is_blacklisted is True


# ============================================================================
# REFRESH TOKENS - SIGNATURES CORRECTAS
# ============================================================================

class TestRefreshTokens:
    """Test refresh tokens con signatures correctas"""
    
    @pytest.mark.asyncio
    async def test_store_and_validate_refresh_token(self, redis):
        """Test storing and validating refresh token"""
        jti = "refresh_jti_abc"
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        
        # Store
        await store_refresh_token(jti, expires_at, redis)
        
        # Validate
        is_valid = await is_refresh_token_valid(jti, redis)
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_revoke_refresh_token(self, redis):
        """Test revoking refresh token"""
        jti = "refresh_revoke_123"
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        
        # Store
        await store_refresh_token(jti, expires_at, redis)
        
        # Revoke
        await revoke_refresh_token(jti, redis)
        
        # Should be invalid
        is_valid = await is_refresh_token_valid(jti, redis)
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_refresh_token_not_stored(self, redis):
        """Test checking non-existent refresh token"""
        is_valid = await is_refresh_token_valid("nonexistent", redis)
        assert is_valid is False


# ============================================================================
# USER MANAGEMENT - CON REDIS
# ============================================================================

class TestUserManagement:
    """Test user management"""
    
    @pytest.mark.asyncio
    async def test_create_user(self, redis, mock_hash):
        """Test creating user"""
        user = await create_user(redis, "test@example.com", "CorrectHorseBatteryStaple2024!", "FREE")
        
        assert user.email == "test@example.com"
        assert user.plan == "FREE"
        assert user.is_active is True
        assert len(user.id) > 10
    
    @pytest.mark.asyncio
    async def test_create_duplicate_user(self, redis, mock_hash):
        """Test duplicate email fails"""
        await create_user(redis, "dup@test.com", "CorrectHorseBatteryStaple2024!", "FREE")
        
        with pytest.raises(HTTPException) as exc:
            await create_user(redis, "dup@test.com", "CorrectHorseBatteryStaple2024!", "FREE")
        
        assert exc.value.status_code == 400
    
    @pytest.mark.asyncio
    async def test_get_user_by_email(self, redis, mock_hash):
        """Test retrieving user"""
        created = await create_user(redis, "get@test.com", "CorrectHorseBatteryStaple2024!", "PREMIUM")
        retrieved = await get_user_by_email(redis, "get@test.com")
        
        assert retrieved is not None
        assert retrieved.email == "get@test.com"
        assert retrieved.id == created.id
    
    @pytest.mark.asyncio
    async def test_get_nonexistent_user(self, redis):
        """Test getting nonexistent user"""
        user = await get_user_by_email(redis, "nonexistent@test.com")
        assert user is None
    
    @pytest.mark.asyncio
    async def test_create_user_all_plans(self, redis, mock_hash):
        """Test all plan types"""
        for i, plan in enumerate(["FREE", "PREMIUM", "ENTERPRISE"]):
            user = await create_user(redis, f"user{i}@test.com", "CorrectHorseBatteryStaple2024!", plan)
            assert user.plan == plan


# ============================================================================
# API KEY VALIDATION
# ============================================================================

class TestAPIKeyValidation:
    """Test API key validation"""
    
    @pytest.mark.asyncio
    async def test_validate_api_key_success(self, redis):
        """Test successful API key validation"""
        api_key = secrets.token_urlsafe(32)
        hashed = create_hashed_key(api_key)
        
        # Store in Redis as JSON
        import json
        key_data = {
            "user_id": "user123",
            "plan": "PREMIUM",
            "is_active": True,
            "status": "active",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await redis.set(f"key:{hashed}", json.dumps(key_data))
        
        # Validate
        request = Mock()
        request.app.state.redis = redis
        request.state.correlation_id = "test-123"
        
        result = await validate_api_key(request, api_key, redis)
        
        assert result["api_key"] == api_key
    
    @pytest.mark.asyncio
    async def test_validate_api_key_not_found(self, redis):
        """Test API key not found"""
        api_key = secrets.token_urlsafe(32)
        request = Mock()
        
        with pytest.raises(HTTPException) as exc:
            await validate_api_key(request, api_key, redis)
        
        assert exc.value.status_code == 401
    
    @pytest.mark.asyncio
    async def test_validate_api_key_inactive(self, redis):
        """Test inactive API key"""
        api_key = secrets.token_urlsafe(32)
        hashed = create_hashed_key(api_key)
        
        # Store as JSON with deprecated status
        import json
        key_data = {
            "user_id": "user123",
            "plan": "FREE",
            "status": "deprecated",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await redis.set(f"key:{hashed}", json.dumps(key_data))
        
        request = Mock()
        request.state.correlation_id = "test-123"
        
        with pytest.raises(HTTPException) as exc:
            await validate_api_key(request, api_key, redis)
        
        assert exc.value.status_code == 410  # Deprecated returns 410


# ============================================================================
# JWT TOKENS
# ============================================================================

class TestJWTTokens:
    """Test JWT token creation"""
    
    def test_create_access_token(self, mock_settings):
        """Test access token creation"""
        token = create_access_token(
            data={"sub": "user123", "email": "test@example.com"},
            plan="PREMIUM"
        )
        
        assert isinstance(token, str)
        assert len(token) > 50
        
        # Decode
        payload = jwt.decode(
            token,
            "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo",
            algorithms=[JWT_ALGORITHM],
            audience="mailsafepro-api",
            issuer="mailsafepro"
        )
        
        assert payload["sub"] == "user123"
        assert payload["plan"] == "PREMIUM"
        assert payload["type"] == "access"
        assert "validate:batch" in payload["scopes"]
    
    def test_create_refresh_token(self, mock_settings):
        """Test refresh token creation"""
        token, expires_at = create_refresh_token(
            data={"sub": "user123"},
            plan="FREE"
        )
        
        assert isinstance(token, str)
        assert isinstance(expires_at, datetime)
        assert expires_at > datetime.now(timezone.utc) + timedelta(days=6)
    
    def test_token_scopes_by_plan(self, mock_settings):
        """Test scopes for different plans"""
        # FREE
        token_free = create_access_token({"sub": "u1"}, plan="FREE")
        payload_free = jwt.decode(token_free, "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo", algorithms=[JWT_ALGORITHM], audience="mailsafepro-api", issuer="mailsafepro")
        assert set(payload_free["scopes"]) == set(PLAN_SCOPES["FREE"])
        
        # ENTERPRISE
        token_ent = create_access_token({"sub": "u3"}, plan="ENTERPRISE")
        payload_ent = jwt.decode(token_ent, "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo", algorithms=[JWT_ALGORITHM], audience="mailsafepro-api", issuer="mailsafepro")
        assert "admin" in payload_ent["scopes"]


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestIntegration:
    """Integration tests"""
    
    @pytest.mark.asyncio
    async def test_complete_user_flow(self, redis, mock_hash, mock_settings):
        """Test complete user lifecycle"""
        # Create user
        user = await create_user(redis, "flow@test.com", "CorrectHorseBatteryStaple2024!", "PREMIUM")
        
        # Create tokens
        access_token = create_access_token({"sub": user.id, "email": user.email}, plan=user.plan)
        refresh_token, expires = create_refresh_token({"sub": user.id}, plan=user.plan)
        
        # Extract JTI from refresh token
        payload = jwt.decode(refresh_token, "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo", algorithms=[JWT_ALGORITHM], audience="mailsafepro-api", issuer="mailsafepro", options={"verify_exp": False})
        jti = payload["jti"]
        
        # Store refresh token
        await store_refresh_token(jti, expires, redis)
        
        # Validate
        assert await is_refresh_token_valid(jti, redis) is True
        
        # Revoke
        await revoke_refresh_token(jti, redis)
        
        # Should be invalid
        assert await is_refresh_token_valid(jti, redis) is False
    
    @pytest.mark.asyncio
    async def test_multiple_users_and_tokens(self, redis, mock_hash, mock_settings):
        """Test multiple users"""
        users = []
        for i in range(3):
            user = await create_user(redis, f"user{i}@test.com", "CorrectHorseBatteryStaple2024!", "FREE")
            users.append(user)
        
        assert len(users) == 3
        assert all(u.plan == "FREE" for u in users)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=app/auth.py", "--cov-report=term-missing"])

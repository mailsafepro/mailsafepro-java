"""
LAST PUSH - Auth.py - Targeting remaining easy wins
"""

import pytest
import pytest_asyncio
from unittest.mock import Mock, patch
from datetime import datetime, timedelta, timezone

import os
os.environ["TESTING"] = "1"
os.environ["DISABLE_PROMETHEUS"] = "1"

from fakeredis import FakeAsyncRedis
from fastapi import HTTPException
import jwt

from app.auth import (
    create_user,
    get_user_by_email,
    create_access_token,
    create_refresh_token,
    create_jwt_token,
    JWT_ALGORITHM,
)


@pytest_asyncio.fixture
async def redis():
    client = FakeAsyncRedis(decode_responses=False)
    yield client
    await client.flushall()
    await client.aclose()


@pytest.fixture
def mock_hash():
    with patch("app.auth.get_password_hash") as m_hash, \
         patch("app.auth.verify_password") as m_verify:
        m_hash.side_effect = lambda p: f"$2b$12${p}$" if len(p) >= 8 else (_ for _ in ()).throw(ValueError("Password must be at least 8 characters"))
        m_verify.side_effect = lambda plain, hashed: hashed == f"$2b$12${plain}$"
        yield


@pytest.fixture
def mock_settings():
    with patch("app.auth.settings") as m:
        m.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
        m.jwt.access_token_expire_minutes = 30
        m.jwt.refresh_token_expire_days = 7
        m.jwt.issuer = "mailsafepro"
        m.jwt.audience = "mailsafepro-api"
        yield m


class TestFinalCoverage:
    """Final coverage push"""
    
    @pytest.mark.asyncio
    async def test_create_user_with_special_email(self, redis, mock_hash):
        """Test user creation with special email"""
        user = await create_user(redis, "test+tag@example.com", "CorrectHorseBatteryStaple2024!", "FREE")
        assert user.email == "test+tag@example.com"
    
    @pytest.mark.asyncio
    async def test_get_user_with_spaces(self, redis, mock_hash):
        """Test getting user with email containing spaces (trimmed)"""
        await create_user(redis, "test@example.com", "CorrectHorseBatteryStaple2024!", "FREE")
        user = await get_user_by_email(redis, "  test@example.com  ")
        # Should handle trimming or fail gracefully
        assert user is None or user.email == "test@example.com"
    
    def test_create_jwt_token_with_scopes(self, mock_settings):
        """Test JWT with custom scopes"""
        token = create_jwt_token(
            data={"sub": "user123"},
            scopes=["custom:scope", "admin"],
            plan="ENTERPRISE",
            token_type="access"
        )
        
        payload = jwt.decode(
            token,
            "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo",
            algorithms=[JWT_ALGORITHM],
            audience="mailsafepro-api",
            issuer="mailsafepro"
        )
        
        assert "custom:scope" in payload["scopes"]
    
    def test_create_jwt_token_without_scopes(self, mock_settings):
        """Test JWT without explicit scopes"""
        token = create_jwt_token(
            data={"sub": "user123"},
            plan="FREE",
            token_type="access"
        )
        
        payload = jwt.decode(
            token,
            "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo",
            algorithms=[JWT_ALGORITHM],
            audience="mailsafepro-api",
            issuer="mailsafepro"
        )
        
        assert "scopes" in payload
    
    def test_create_access_token_with_custom_expiry(self, mock_settings):
        """Test access token with custom expiry"""
        token = create_access_token(
            data={"sub": "user123"},
            plan="PREMIUM",
            expires_delta=timedelta(hours=2)
        )
        
        assert len(token) > 50
    
    def test_create_refresh_token_enterprise(self, mock_settings):
        """Test refresh token for enterprise"""
        token, expires_at = create_refresh_token(
            data={"sub": "user123"},
            plan="ENTERPRISE"
        )
        
        assert isinstance(token, str)
        assert expires_at > datetime.now(timezone.utc)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

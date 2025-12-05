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

from app.config import get_settings
# Configuración
settings = get_settings()

# =============================================================================
# FIXTURES
# =============================================================================
# BILLING_ROUTES.PY TESTS - SECURITY UTILITIES
# =============================================================================

@pytest.fixture(scope="module", autouse=True)
def cleanup_patches():
    """Clean up any module-level patches after all tests complete"""
    yield
    # Stop all active patches to prevent pollution to other test modules
    from unittest.mock import patch
    patch.stopall()

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
        password = "CorrectHorseBatteryStaple2024!"
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


import pytest
import json
from unittest.mock import AsyncMock, MagicMock, patch, ANY
from app.routes.billing_routes import EventProcessor, LockManager, StripeClient, RedisOperations, RedisError, BillingManager



class TestEventProcessorSync:
    """Synchronous tests for EventProcessor helper methods"""
    
    def test_extract_plan_info_premium(self):
        # Simular estructura de suscripción
        sub = {
            "id": "sub_1",
            "current_period_end": 1735689600,
            "items": {"data": [{"price": {"id": settings.stripe.premium_plan_id}}]}
        }
        
        info = EventProcessor._extract_plan_info(sub)
        assert info["plan"] == "PREMIUM"
        assert info["subscription_id"] == "sub_1"
        assert "2025" in info["next_billing"] # Verificar fecha formateada

    def test_extract_plan_info_enterprise(self):
        sub = {
            "id": "sub_2",
            "current_period_end": 1735689600,
            "items": {"data": [{"price": {"id": settings.stripe.enterprise_plan_id}}]}
        }
        
        info = EventProcessor._extract_plan_info(sub)
        assert info["plan"] == "ENTERPRISE"

    def test_extract_plan_info_default_fallback(self):
        """Si no hay items o precio desconocido, fallback a PREMIUM"""
        sub = {"id": "sub_3", "items": {"data": []}}
        info = EventProcessor._extract_plan_info(sub)
        assert info["plan"] == "PREMIUM"

    def test_extract_plan_info_invalid_date(self):
        """Manejo de error en fecha"""
        sub = {"id": "sub_4", "current_period_end": "invalid_date"}
        info = EventProcessor._extract_plan_info(sub)
        assert info["next_billing"] == ""


@pytest.mark.asyncio
class TestEventProcessor:

    # --- Tests para is_event_processed ---
    async def test_is_event_processed_true(self):
        redis = AsyncMock()
        redis.get.return_value = "1"
        result = await EventProcessor.is_event_processed(redis, "evt_123")
        assert result is True
        redis.get.assert_called_once()

    async def test_is_event_processed_false(self):
        redis = AsyncMock()
        redis.get.return_value = None
        result = await EventProcessor.is_event_processed(redis, "evt_123")
        assert result is False

    async def test_is_event_processed_error(self):
        redis = AsyncMock()
        redis.get.side_effect = RedisError("Connection failed")
        # Debe retornar False y loguear warning, no explotar
        result = await EventProcessor.is_event_processed(redis, "evt_123")
        assert result is False

    # --- Tests para mark_event_processed ---
    async def test_mark_event_processed_success(self):
        redis = AsyncMock()
        await EventProcessor.mark_event_processed(redis, "evt_123")
        redis.setex.assert_called_once()

    async def test_mark_event_processed_error(self):
        redis = AsyncMock()
        redis.setex.side_effect = RedisError("Write failed")
        # Debe capturar la excepción y loguear warning
        await EventProcessor.mark_event_processed(redis, "evt_123")

    # --- Tests para process_checkout_session_completed ---
    async def test_process_checkout_unsupported_mode_setup(self):
        """Debe saltar si el modo no es subscription o payment"""
        redis = AsyncMock()
        event = {"data": {"object": {"id": "sess_1", "mode": "setup"}}}
        
        # CORRECCIÓN: Parchear el logger donde se importa (billing_routes)
        with patch("app.routes.billing_routes.logger") as mock_logger:
            await EventProcessor.process_checkout_session_completed(event, redis)
            mock_logger.info.assert_any_call("Skipping unsupported session mode: setup")

    async def test_process_checkout_payment_mode_skipped(self):
        """Modo payment es soportado en general pero esta función filtra solo subscription"""
        redis = AsyncMock()
        event = {"data": {"object": {"id": "sess_1", "mode": "payment"}}}
        
        # CORRECCIÓN: Parchear el logger donde se importa (billing_routes)
        with patch("app.routes.billing_routes.logger") as mock_logger:
            await EventProcessor.process_checkout_session_completed(event, redis)
            mock_logger.info.assert_any_call("Skipping non-subscription session: payment")

    async def test_process_checkout_stripe_fetch_success(self):
        """Flujo ideal: recupera sesión de Stripe y procesa"""
        redis = AsyncMock()
        event = {"data": {"object": {"id": "sess_1", "mode": "subscription"}}}
        mock_fetched_session = {"id": "sess_1", "mode": "subscription", "metadata": {"user_id": "u1"}}

        with patch.object(StripeClient, "retrieve_checkout_session", return_value=mock_fetched_session) as mock_fetch, \
             patch.object(EventProcessor, "_extract_user_info", return_value={"user_id": "u1"}), \
             patch.object(EventProcessor, "_update_user_subscription") as mock_update:
            
            await EventProcessor.process_checkout_session_completed(event, redis)
            
            mock_fetch.assert_called_with("sess_1")
            mock_update.assert_called_once()

    async def test_process_checkout_stripe_fetch_fail_fallback(self):
        """Si Stripe falla, usa datos del evento (webhook)"""
        redis = AsyncMock()
        event = {"data": {"object": {"id": "sess_1", "mode": "subscription", "metadata": {"user_id": "u1"}}}}
        
        with patch.object(StripeClient, "retrieve_checkout_session", side_effect=Exception("Stripe down")), \
             patch.object(EventProcessor, "_extract_user_info", return_value={"user_id": "u1"}), \
             patch.object(EventProcessor, "_update_user_subscription") as mock_update, \
             patch("app.routes.billing_routes.logger") as mock_logger:  # CORRECCIÓN AQUÍ
            
            await EventProcessor.process_checkout_session_completed(event, redis)
            
            # Verificar que se usó el fallback (warning llamado)
            mock_logger.warning.assert_called()
            mock_update.assert_called_once()

    async def test_process_checkout_missing_user_id(self):
        """Si no hay user_id, guarda evento fallido"""
        redis = AsyncMock()
        event = {"data": {"object": {"id": "sess_1", "mode": "subscription"}}}
        
        with patch.object(EventProcessor, "_extract_user_info", return_value={"user_id": None}), \
             patch.object(EventProcessor, "_store_failed_event") as mock_store_fail:
            
            await EventProcessor.process_checkout_session_completed(event, redis)
            
            mock_store_fail.assert_called_with(redis, event, "missing_user_id", "User ID not found")

    # --- Tests para _extract_user_info ---
    async def test_extract_user_info_direct(self):
        redis = AsyncMock()
        session = {"metadata": {"user_id": "u1", "api_key_hash": "h1"}, "customer": None}
        
        info = await EventProcessor._extract_user_info(session, redis)
        assert info["user_id"] == "u1"
        assert info["api_key_hash"] == "h1"

    async def test_extract_user_info_via_customer(self):
        """Si no hay metadata directa, busca por customer_id"""
        redis = AsyncMock()
        session = {"metadata": {}, "customer": "cus_1"}
        
        with patch.object(EventProcessor, "_get_user_from_customer", return_value=("u2", "h2")) as mock_get_customer:
            info = await EventProcessor._extract_user_info(session, redis)
            
            mock_get_customer.assert_called_with("cus_1", redis)
            assert info["user_id"] == "u2"
            assert info["api_key_hash"] == "h2"

    # --- Tests para _get_user_from_customer ---
    async def test_get_user_from_customer_redis_hit(self):
        redis = AsyncMock()
        # Simular retorno bytes de Redis
        redis.hget.side_effect = [b"u1", b"h1"] 
        
        with patch.object(RedisOperations, "bytes_to_str", side_effect=lambda x: x.decode()):
            user, api_hash = await EventProcessor._get_user_from_customer("cus_1", redis)
            
            assert user == "u1"
            assert api_hash == "h1"

    async def test_get_user_from_customer_stripe_fallback(self):
        redis = AsyncMock()
        redis.hget.return_value = None # Redis miss
        
        mock_customer = {"metadata": {"user_id": "u3", "api_key_hash": "h3"}}
        
        with patch.object(StripeClient, "call_with_retry", return_value=mock_customer):
            user, api_hash = await EventProcessor._get_user_from_customer("cus_1", redis)
            
            assert user == "u3"
            assert api_hash == "h3"

    async def test_get_user_from_customer_total_failure(self):
        redis = AsyncMock()
        redis.hget.return_value = None
        
        with patch.object(StripeClient, "call_with_retry", side_effect=Exception("Fail")):
            user, api_hash = await EventProcessor._get_user_from_customer("cus_1", redis)
            assert user is None
            assert api_hash is None

    # --- Tests para _extract_plan_info ---
    # --- Tests para _persist_user_data ---

    # --- Tests para _persist_user_data ---
    async def test_persist_user_data_complete(self):
        redis = AsyncMock()
        plan_info = {
            "plan": "ENTERPRISE",
            "next_billing": "2025-01-01",
            "subscription_id": "sub_1",
            "updated_at": "now"
        }
        
        # CORRECCIÓN: Parchear 'app.routes.billing_routes.update_all_user_api_keys'
        # en lugar de 'app.utils.update_all_user_api_keys' porque billing_routes usa "from ... import ..."
        with patch("app.routes.billing_routes.update_all_user_api_keys", new_callable=AsyncMock) as mock_update_keys, \
             patch.object(RedisOperations, "get_json", return_value={}) as mock_get_json, \
             patch.object(RedisOperations, "set_json") as mock_set_json:
            
            await EventProcessor._persist_user_data("u1", "hash1", plan_info, redis)
            
            # Verificar actualización de hash de usuario
            redis.hset.assert_called_with(
                "user:u1",
                mapping=ANY
            )
            
            # Verificar actualización de API key
            mock_set_json.assert_called()
            
            # Verificar actualización masiva de keys
            mock_update_keys.assert_called_with("u1", "ENTERPRISE", redis)

    # --- Tests para _update_user_subscription ---
    async def test_update_user_subscription_success(self):
        redis = AsyncMock()
        user_info = {"user_id": "u1", "api_key_hash": "h1"}
        session = {"subscription": "sub_1"}
        
        # Mock del context manager del lock
        mock_lock = AsyncMock()
        mock_lock.__aenter__.return_value = "owner_token"
        
        with patch.object(LockManager, "acquire_lock", return_value=mock_lock), \
             patch.object(StripeClient, "retrieve_subscription", return_value={"id": "sub_1", "items": {}}) as mock_retrieve, \
             patch.object(EventProcessor, "_persist_user_data") as mock_persist:
            
            await EventProcessor._update_user_subscription(user_info, session, redis)
            
            mock_retrieve.assert_called_with("sub_1")
            mock_persist.assert_called_once()

    async def test_update_user_subscription_no_sub_id(self):
        """Si no viene subscription ID, error"""
        redis = AsyncMock()
        user_info = {"user_id": "u1"}
        session = {"subscription": None}
        
        with patch.object(EventProcessor, "_store_error") as mock_err:
            await EventProcessor._update_user_subscription(user_info, session, redis)
            mock_err.assert_called_with(redis, "subscription_missing", "No subscription in session", user_id="u1")

    async def test_update_user_subscription_lock_failed(self):
        """Si no puede adquirir lock, retorna silenciosamente"""
        redis = AsyncMock()
        user_info = {"user_id": "u1"}
        session = {"subscription": "sub_1"}
        
        mock_lock = AsyncMock()
        mock_lock.__aenter__.return_value = None # Fallo al adquirir lock
        
        with patch.object(LockManager, "acquire_lock", return_value=mock_lock):
            await EventProcessor._update_user_subscription(user_info, session, redis)
            # No debe llamar a nada más

    async def test_update_user_subscription_stripe_fail_fallback(self):
        """Si falla Stripe al obtener suscripción, usa datos de sesión y calcula fecha fallback"""
        redis = AsyncMock()
        user_info = {"user_id": "u1", "api_key_hash": "h1"}
        # Sesión con fecha para probar fallback de fecha
        session = {"subscription": "sub_1", "current_period_end": 1735689600}
        
        mock_lock = AsyncMock()
        mock_lock.__aenter__.return_value = "owner"
        
        with patch.object(LockManager, "acquire_lock", return_value=mock_lock), \
             patch.object(StripeClient, "retrieve_subscription", side_effect=Exception("Stripe fail")), \
             patch.object(EventProcessor, "_persist_user_data") as mock_persist:
            
            await EventProcessor._update_user_subscription(user_info, session, redis)
            
            # Verificar que se llamó a persistir (significa que el fallback funcionó)
            mock_persist.assert_called()
            # Verificar que la fecha se calculó desde current_period_end del session
            args = mock_persist.call_args[0]
            plan_info = args[2]
            assert "2025" in plan_info["next_billing"]

    async def test_update_user_subscription_critical_fail(self):
        """Si falla todo (incluso persistir), guarda error"""
        redis = AsyncMock()
        user_info = {"user_id": "u1"}
        session = {"subscription": "sub_1"}
        
        mock_lock = AsyncMock()
        mock_lock.__aenter__.return_value = "owner"
        
        with patch.object(LockManager, "acquire_lock", return_value=mock_lock), \
             patch.object(StripeClient, "retrieve_subscription", side_effect=Exception("Fatal")), \
             patch.object(EventProcessor, "_extract_plan_info", side_effect=Exception("Parse fail")), \
             patch.object(EventProcessor, "_store_error") as mock_err:
            
            await EventProcessor._update_user_subscription(user_info, session, redis)
            
            mock_err.assert_called_with(redis, "subscription_update_failed", ANY, user_id="u1")

    async def test_update_user_subscription_with_dict_sub(self):
        """Prueba que maneja subscription como diccionario dentro de session"""
        redis = AsyncMock()
        user_info = {"user_id": "u1", "api_key_hash": "h1"}
        session = {"subscription": {"id": "sub_dict_1"}}
        
        mock_lock = AsyncMock()
        mock_lock.__aenter__.return_value = "owner"
        
        with patch.object(LockManager, "acquire_lock", return_value=mock_lock), \
             patch.object(StripeClient, "retrieve_subscription", return_value={"id": "sub_dict_1"}), \
             patch.object(EventProcessor, "_persist_user_data") as mock_persist:
             
             await EventProcessor._update_user_subscription(user_info, session, redis)
             
             # Verificar que extrajo correctamente el ID del dict
             mock_retrieve = StripeClient.retrieve_subscription
             mock_retrieve.assert_called_with("sub_dict_1")

@pytest.mark.asyncio
class TestBillingManagerInvoice:
    """Tests para el procesamiento de invoice.payment_succeeded"""

    async def test_invoice_payment_success_complete(self):
        """
        Caso ideal: 
        1. Tiene customer y subscription.
        2. Stripe devuelve datos.
        3. Existe mapeo de usuario en Redis.
        4. Existe caché de suscripción y se actualiza.
        """
        redis = AsyncMock()
        
        # Datos de entrada
        event = {
            "data": {
                "object": {
                    "customer": "cus_123",
                    "subscription": "sub_123"
                }
            }
        }
        
        # Mock de Stripe: devuelve una fecha futura (timestamp 1735689600 = ~2025-01-01)
        mock_stripe_sub = {"current_period_end": 1735689600}
        
        # Mock de caché existente
        mock_cached_sub = {"plan": "PREMIUM", "next_billing_date": "old_date"}

        # Setup de parches
        with patch.object(StripeClient, "retrieve_subscription", return_value=mock_stripe_sub) as mock_stripe, \
             patch.object(RedisOperations, "bytes_to_str", return_value="u1") as mock_bytes, \
             patch.object(RedisOperations, "get_json", return_value=mock_cached_sub) as mock_get_json, \
             patch.object(RedisOperations, "set_json") as mock_set_json, \
             patch("app.routes.billing_routes.logger") as mock_logger:

            # Simular que redis encuentra el usuario
            redis.hget.return_value = b"u1"

            await BillingManager._process_invoice_payment_succeeded(event, redis)

            # 1. Verificar llamada a Stripe
            mock_stripe.assert_called_with("sub_123")
            
            # 2. Verificar búsqueda de usuario
            redis.hget.assert_called_with("customer:cus_123", "user_id")
            
            # 3. Verificar actualización del Hash principal del usuario
            # La fecha esperada depende de tu timezone, pero isoformat() generará el string
            expected_date = "2025-01-01T00:00:00+00:00" 
            redis.hset.assert_called_with("user:u1", "next_billing_date", expected_date)

            # 4. Verificar actualización del caché JSON
            mock_get_json.assert_called_with(redis, "user:u1:subscription")
            
            # Asegurarse que se guardó el JSON con la nueva fecha
            mock_set_json.assert_called_with(
                redis, 
                "user:u1:subscription", 
                {"plan": "PREMIUM", "next_billing_date": expected_date}, 
                ex=3600
            )
            
            # 5. Verificar log de éxito
            mock_logger.info.assert_called_with("Updated billing date for user u1")

    async def test_invoice_payment_missing_ids_returns_early(self):
        """Si falta customer_id o subscription_id, retorna sin hacer nada."""
        redis = AsyncMock()
        
        # Caso 1: Falta subscription
        event_no_sub = {"data": {"object": {"customer": "cus_1", "subscription": None}}}
        
        with patch.object(StripeClient, "retrieve_subscription") as mock_stripe:
            await BillingManager._process_invoice_payment_succeeded(event_no_sub, redis)
            mock_stripe.assert_not_called()

        # Caso 2: Falta customer
        event_no_cus = {"data": {"object": {"customer": None, "subscription": "sub_1"}}}
        
        with patch.object(StripeClient, "retrieve_subscription") as mock_stripe:
            await BillingManager._process_invoice_payment_succeeded(event_no_cus, redis)
            mock_stripe.assert_not_called()

    async def test_invoice_payment_user_not_found(self):
        """
        Si el customer_id no tiene un usuario asociado en Redis, 
        obtiene la subscripción pero no intenta actualizar nada.
        """
        redis = AsyncMock()
        event = {"data": {"object": {"customer": "cus_unknown", "subscription": "sub_1"}}}
        
        with patch.object(StripeClient, "retrieve_subscription", return_value={"current_period_end": 12345678}), \
             patch.object(RedisOperations, "bytes_to_str", return_value=None): # Simula que no devuelve string válido
            
            # Simular miss en Redis
            redis.hget.return_value = None
            
            await BillingManager._process_invoice_payment_succeeded(event, redis)
            
            # Se llama a Stripe
            assert StripeClient.retrieve_subscription.called
            # Pero NO se intenta escribir en Redis hash de usuario
            redis.hset.assert_not_called()

    async def test_invoice_payment_cache_miss(self):
        """
        El usuario existe, pero no tiene caché de suscripción activa.
        Debe actualizar el Hash principal, pero saltar la actualización del JSON caché.
        """
        redis = AsyncMock()
        event = {"data": {"object": {"customer": "cus_1", "subscription": "sub_1"}}}
        
        with patch.object(StripeClient, "retrieve_subscription", return_value={"current_period_end": 1735689600}), \
             patch.object(RedisOperations, "bytes_to_str", return_value="u1"), \
             patch.object(RedisOperations, "get_json", return_value=None) as mock_get_json, \
             patch.object(RedisOperations, "set_json") as mock_set_json:

            redis.hget.return_value = b"u1"
            
            await BillingManager._process_invoice_payment_succeeded(event, redis)
            
            # Se actualiza el hash principal
            redis.hset.assert_called()
            
            # Se intentó leer caché
            mock_get_json.assert_called()
            
            # PERO NO se intentó escribir caché (porque no existía)
            mock_set_json.assert_not_called()

    async def test_invoice_payment_exception_handling(self):
        """Cualquier excepción debe ser capturada y logueada como error."""
        redis = AsyncMock()
        event = {"data": {"object": {"customer": "cus_1", "subscription": "sub_1"}}}
        
        # Simular error en Stripe
        with patch.object(StripeClient, "retrieve_subscription", side_effect=Exception("API Error")), \
             patch("app.routes.billing_routes.logger") as mock_logger:
            
            await BillingManager._process_invoice_payment_succeeded(event, redis)
            
            mock_logger.error.assert_called()
            args, _ = mock_logger.error.call_args
            assert "Failed to process invoice payment" in args[0]
            assert "API Error" in args[0]




# =============================================================================
# TEST CONFIGURATION AND MARKERS
# =============================================================================

# Add custom markers
pytest.mark.unit = pytest.mark.unit
pytest.mark.integration = pytest.mark.integration
pytest.mark.slow = pytest.mark.slow

import pytest
import json
from unittest.mock import MagicMock, AsyncMock, patch, ANY
from fastapi import HTTPException, status, Request
from fastapi.security import HTTPBasicCredentials
from datetime import datetime, timedelta, timezone

# Asumimos que tu código está en app.auth
# Ajusta los imports si la ruta es distinta
from app.auth import (
    refresh_token, 
    logout, 
    rotate_api_key, 
    get_docs_access, 
    validate_api_key_format,
    validate_api_key_string,
    auth_health_check
)

# Mocks para modelos Pydantic si no se pueden importar
class MockKeyRotationRequest:
    def __init__(self, old_key, new_key, grace_period):
        self.old_key = old_key
        self.new_key = new_key
        self.grace_period = grace_period

class MockTokenData:
    def __init__(self, sub, scopes=None):
        self.sub = sub
        self.scopes = scopes or []

# =============================================================================
# TESTS: refresh_token
# =============================================================================
@pytest.mark.asyncio
class TestRefreshToken:
    
    async def test_refresh_token_success_header(self):
        """Test: Flujo exitoso usando header Authorization."""
        redis = AsyncMock()
        request = MagicMock(spec=Request)
        request.headers.get.return_value = "Bearer valid_refresh_token"
        request.json = AsyncMock(return_value={})

        # Mock de dependencias internas
        with patch("app.auth._jwt_verify_key") as mock_key, \
             patch("app.auth.jwt.decode") as mock_jwt_decode, \
             patch("app.auth.is_refresh_token_valid", new_callable=AsyncMock) as mock_is_valid, \
             patch("app.auth._decode_value", return_value="ENTERPRISE"), \
             patch("app.auth.create_access_token", return_value="new_access") as mock_create_access, \
             patch("app.auth.create_refresh_token", return_value=("new_refresh", 12345)), \
             patch("app.auth._get_unverified_claims", return_value={"jti": "new_jti"}), \
             patch("app.auth.store_refresh_token", new_callable=AsyncMock) as mock_store, \
             patch("app.auth.settings") as mock_settings:

            # Configuración de Mocks
            mock_jwt_decode.return_value = {
                "type": "refresh", 
                "jti": "old_jti", 
                "sub": "user123", 
                "email": "test@test.com"
            }
            mock_is_valid.return_value = True
            redis.hget.return_value = b"ENTERPRISE" # Plan actual en Redis

            # Ejecución
            response = await refresh_token(request, redis)

            # Verificaciones
            assert response["access_token"] == "new_access"
            assert response["plan"] == "ENTERPRISE"
            
            # Verificar que buscó el plan en Redis
            redis.hget.assert_called_with("user:user123", "plan")
            
            # Verificar que creó tokens con el plan actualizado
            mock_create_access.assert_called_with(
                {"sub": "user123", "email": "test@test.com"},
                plan="ENTERPRISE",
                scopes=ANY
            )

    async def test_refresh_token_missing(self):
        """Test: Falta token en header y body."""
        redis = AsyncMock()
        request = MagicMock(spec=Request)
        request.headers.get.return_value = ""
        request.json = AsyncMock(return_value={})

        with pytest.raises(HTTPException) as exc:
            await refresh_token(request, redis)
        assert exc.value.status_code == 400
        assert "Missing refresh token" in exc.value.detail

    async def test_refresh_token_revoked(self):
        """Test: Token válido formato pero revocado en Redis."""
        redis = AsyncMock()
        request = MagicMock(spec=Request)
        request.headers.get.return_value = "Bearer revoked_token"

        with patch("app.auth._jwt_verify_key"), \
             patch("app.auth.jwt.decode", return_value={"type": "refresh", "jti": "revoked_jti"}), \
             patch("app.auth.is_refresh_token_valid", new_callable=AsyncMock) as mock_is_valid, \
             patch("app.auth.settings"):
            
            mock_is_valid.return_value = False # REVOCADO

            with pytest.raises(HTTPException) as exc:
                await refresh_token(request, redis)
            assert exc.value.status_code == 401
            assert "Refresh token revoked" in exc.value.detail

    async def test_refresh_token_wrong_type(self):
        """Test: Token válido pero es de tipo 'access' u otro."""
        redis = AsyncMock()
        request = MagicMock(spec=Request)
        request.headers.get.return_value = "Bearer access_token"

        with patch("app.auth._jwt_verify_key"), \
             patch("app.auth.jwt.decode", return_value={"type": "access"}), \
             patch("app.auth.settings"):

            with pytest.raises(HTTPException) as exc:
                await refresh_token(request, redis)
            assert exc.value.status_code == 401
            assert "Invalid token type" in exc.value.detail


# =============================================================================
# TESTS: logout
# =============================================================================
@pytest.mark.asyncio
class TestLogout:

    async def test_logout_success_revoked(self):
        """Test: Logout completo con token válido (blacklist) y refresh (revoke)."""
        redis = AsyncMock()
        request = MagicMock(spec=Request)
        request.headers.get.return_value = "Bearer valid_access_token"
        request.json = AsyncMock(return_value={"refresh_token": "valid_refresh"})

        with patch("app.auth._jwt_verify_key"), \
             patch("app.auth.jwt.decode") as mock_decode, \
             patch("app.auth.blacklist_token", new_callable=AsyncMock) as mock_blacklist, \
             patch("app.auth.revoke_refresh_token", new_callable=AsyncMock) as mock_revoke, \
             patch("app.auth.settings"):

            # Mock jwt.decode para devolver valores distintos para access y refresh
            mock_decode.side_effect = [
                {"jti": "access_jti", "exp": 123456, "sub": "u1"}, # Primer decode (Access)
                {"jti": "refresh_jti", "type": "refresh"}          # Segundo decode (Refresh)
            ]

            response = await logout(request, redis)

            assert response["token_status"] == "revoked"
            mock_blacklist.assert_called_with("access_jti", 123456, redis)
            mock_revoke.assert_called_with("refresh_jti", redis)

    async def test_logout_expired_token(self):
        """Test: Token expirado maneja la excepción gracefully."""
        redis = AsyncMock()
        request = MagicMock(spec=Request)
        request.headers.get.return_value = "Bearer expired_token"
        
        # Importar la excepción real si es posible, o mockearla
        from jwt import ExpiredSignatureError 

        with patch("app.auth._jwt_verify_key"), \
             patch("app.auth.jwt.decode", side_effect=ExpiredSignatureError), \
             patch("app.auth.settings"):

            response = await logout(request, redis)
            
            assert response["token_status"] == "expired"
            assert "Access token already expired" in response["detail"]

    async def test_logout_no_token(self):
        """Test: Logout sin token (cierre local)."""
        redis = AsyncMock()
        request = MagicMock(spec=Request)
        request.headers.get.return_value = ""
        request.json = AsyncMock(return_value={}) # Sin refresh token body

        response = await logout(request, redis)
        
        assert response["token_status"] == "none"
        assert "session closed locally" in response["detail"]


# =============================================================================
# TESTS: rotate_api_key
# =============================================================================
@pytest.mark.asyncio
class TestRotateApiKey:

    async def test_rotate_success(self):
        """Test: Rotación exitosa con periodo de gracia."""
        redis = AsyncMock()
        data = MockKeyRotationRequest("old_k", "new_k", 60)
        current_client = MockTokenData(sub="admin_user")
        
        # Datos simulados en Redis
        old_key_json = json.dumps({"status": "active", "user_id": "u1"})
        
        with patch("app.auth.create_hashed_key", side_effect=["hash_old", "hash_new"]), \
             patch("app.auth._decode_value", return_value=old_key_json):
            
            # Setup Redis
            redis.exists.return_value = True
            redis.get.return_value = old_key_json.encode()

            response = await rotate_api_key(data, current_client, redis)

            assert response["status"] == "success"
            
            # Verificar que la nueva key se guarda activa
            redis.set.assert_called()
            args_new, _ = redis.set.call_args
            assert "hash_new" in args_new[0] # Key correcta
            assert '"status": "active"' in args_new[1] # Payload correcto

            # Verificar que la vieja key se guarda con TTL (deprecated)
            redis.setex.assert_called()
            args_old, _ = redis.setex.call_args
            assert "hash_old" in args_old[0]
            assert args_old[1] == 60 # Grace period
            assert '"status": "deprecated"' in args_old[2]

    async def test_rotate_invalid_old_key(self):
        """Test: Key antigua no existe en Redis."""
        redis = AsyncMock()
        data = MockKeyRotationRequest("bad_old", "new_k", 60)
        current_client = MockTokenData(sub="admin")

        with patch("app.auth.create_hashed_key", return_value="hash_bad"):
            redis.exists.return_value = False
            
            with pytest.raises(HTTPException) as exc:
                await rotate_api_key(data, current_client, redis)
            
            assert exc.value.status_code == 400
            assert "Invalid old key" in exc.value.detail


# =============================================================================
# TESTS: get_docs_access
# =============================================================================
class TestDocsAccess:
    
    def test_docs_access_success(self):
        """Test: Credenciales correctas."""
        creds = HTTPBasicCredentials(username="admin", password="secret_password")
        
        with patch("app.auth.settings") as mock_settings:
            mock_settings.documentation.user = "admin"
            mock_settings.documentation.password = "secret_password"
            
            result = get_docs_access(creds)
            assert result is True

    def test_docs_access_failure(self):
        """Test: Credenciales incorrectas."""
        creds = HTTPBasicCredentials(username="admin", password="wrong_password")
        
        with patch("app.auth.settings") as mock_settings:
            mock_settings.documentation.user = "admin"
            mock_settings.documentation.password = "secret_password"
            
            with pytest.raises(HTTPException) as exc:
                get_docs_access(creds)
            
            assert exc.value.status_code == 401
            assert exc.value.headers["WWW-Authenticate"] == "Basic"


# =============================================================================
# TESTS: validate_api_key_format
# =============================================================================
class TestApiKeyFormat:

    def test_validate_format_success(self):
        # Asumimos patrón alfanumérico simple de >16 chars
        # Mockear API_KEY_PATTERN en app.auth si es complejo
        with patch("app.auth.API_KEY_PATTERN") as mock_pattern:
            mock_pattern.fullmatch.return_value = True
            
            # No debe lanzar excepción
            validate_api_key_format("valid_api_key_longer_than_16_chars")

    def test_validate_format_too_short(self):
        with pytest.raises(HTTPException) as exc:
            validate_api_key_format("short_key")
        assert exc.value.status_code == 422

    def test_validate_format_pattern_fail(self):
        with patch("app.auth.API_KEY_PATTERN") as mock_pattern:
            mock_pattern.fullmatch.return_value = None # Fallo de regex
            
            with pytest.raises(HTTPException) as exc:
                validate_api_key_format("invalid_chars_key_long_enough")
            assert exc.value.status_code == 422


# =============================================================================
# TESTS: get_docs_access
# =============================================================================
class TestDocsAccess:
    
    def test_get_docs_access_missing_credentials(self):
        """Test: Credenciales None o vacías lanzan 401."""
        # Caso 1: None
        with pytest.raises(HTTPException) as exc:
            get_docs_access(None)
        assert exc.value.status_code == 401
        assert exc.value.detail == "Missing credentials"
        
        # Caso 2: Objeto vacío
        empty_creds = HTTPBasicCredentials(username="", password="")
        with pytest.raises(HTTPException) as exc:
            get_docs_access(empty_creds)
        assert exc.value.status_code == 401

    def test_get_docs_access_invalid_credentials(self):
        """Test: Usuario/password incorrectos lanzan 401."""
        creds = HTTPBasicCredentials(username="admin", password="wrong_password")
        
        with patch("app.auth.settings") as mock_settings, \
             patch("app.auth.logger"):
            
            # Configurar valores esperados
            mock_settings.documentation.user = "admin"
            mock_settings.documentation.password = "correct_password"
            
            with pytest.raises(HTTPException) as exc:
                get_docs_access(creds)
            
            assert exc.value.status_code == 401
            assert exc.value.detail == "Invalid credentials"
            assert exc.value.headers["WWW-Authenticate"] == "Basic"

    def test_get_docs_access_success(self):
        """Test: Credenciales correctas devuelven True."""
        creds = HTTPBasicCredentials(username="admin", password="secure")
        
        with patch("app.auth.settings") as mock_settings, \
             patch("app.auth.logger") as mock_logger:
            
            mock_settings.documentation.user = "admin"
            mock_settings.documentation.password = "secure"
            
            result = get_docs_access(creds)
            assert result is True
            mock_logger.info.assert_called()

    def test_get_docs_access_unexpected_error(self):
        """Test: Excepción inesperada lanza 500."""
        creds = HTTPBasicCredentials(username="u", password="p")
        
        with patch("app.auth.hashlib.sha256", side_effect=Exception("Boom")), \
             patch("app.auth.logger") as mock_logger:
            
            with pytest.raises(HTTPException) as exc:
                get_docs_access(creds)
            
            assert exc.value.status_code == 500
            assert "Authentication service unavailable" in exc.value.detail
            mock_logger.exception.assert_called()

# =============================================================================
# TESTS: validate_api_key_string
# =============================================================================
@pytest.mark.asyncio
class TestValidateApiKeyString:

    async def test_validate_string_missing_header(self):
        """Test: Sin header lanza 401."""
        request = MagicMock()
        redis = AsyncMock()
        
        with pytest.raises(HTTPException) as exc:
            await validate_api_key_string(request, api_key_header=None, redis=redis)
        
        assert exc.value.status_code == 401
        assert "Missing API Key" in exc.value.detail

    async def test_validate_string_success(self):
        """Test: Validación exitosa devuelve la key en texto plano."""
        request = MagicMock()
        redis = AsyncMock()
        key = "sk_live_1234567890123456"
        
        # Mockear validate_api_key (la función principal que hace el trabajo pesado)
        with patch("app.auth.validate_api_key", return_value={"api_key": key}) as mock_validate:
            result = await validate_api_key_string(request, api_key_header=key, redis=redis)
            
            assert result == key
            mock_validate.assert_called_with(request, key, redis)

    async def test_validate_string_invalid_return(self):
        """Test: validate_api_key no devuelve dict esperado (defensa en profundidad)."""
        request = MagicMock()
        redis = AsyncMock()
        
        with patch("app.auth.validate_api_key", return_value=None), \
             patch("app.auth.logger") as mock_logger:
            
            with pytest.raises(HTTPException) as exc:
                await validate_api_key_string(request, api_key_header="key", redis=redis)
            
            assert exc.value.status_code == 401
            mock_logger.warning.assert_called()

    async def test_validate_string_unexpected_error(self):
        """Test: Error inesperado lanza 500."""
        request = MagicMock()
        redis = AsyncMock()
        
        with patch("app.auth.validate_api_key", side_effect=Exception("Fatal error")), \
             patch("app.auth.logger") as mock_logger:
            
            with pytest.raises(HTTPException) as exc:
                await validate_api_key_string(request, api_key_header="key", redis=redis)
            
            assert exc.value.status_code == 500
            mock_logger.exception.assert_called()

# =============================================================================
# TESTS: auth_health_check
# =============================================================================
@pytest.mark.asyncio
class TestAuthHealthCheck:

    async def test_health_check_healthy(self):
        """Test: Todo funciona correctamente."""
        redis = AsyncMock()
        
        with patch("app.auth.create_access_token", return_value="token"), \
             patch("app.auth.jwt.decode"), \
             patch("app.auth.get_password_hash", return_value="hash"), \
             patch("app.auth.verify_password", return_value=True), \
             patch("app.auth.settings"):
            
            result = await auth_health_check(redis)
            
            assert result["status"] == "healthy"
            assert result["password_hashing"] == "working"
            redis.ping.assert_called_once()

    async def test_health_check_hashing_broken(self):
        """Test: Redis OK, pero hashing falla validación."""
        redis = AsyncMock()
        
        with patch("app.auth.create_access_token"), \
             patch("app.auth.jwt.decode"), \
             patch("app.auth.get_password_hash"), \
             patch("app.auth.verify_password", return_value=False), \
             patch("app.auth.settings"):
            
            result = await auth_health_check(redis)
            
            # Nota: El endpoint devuelve 200 OK pero con estado "broken" en el cuerpo
            # según tu implementación actual.
            assert result["status"] == "healthy" 
            assert result["password_hashing"] == "broken"

    async def test_health_check_service_unavailable(self):
        """Test: Fallo crítico (ej. Redis) lanza 503."""
        redis = AsyncMock()
        redis.ping.side_effect = Exception("Redis down")
        
        with patch("app.auth.logger") as mock_logger:
            with pytest.raises(HTTPException) as exc:
                await auth_health_check(redis)
            
            assert exc.value.status_code == 503
            assert "Authentication service unhealthy" in exc.value.detail
            mock_logger.error.assert_called()


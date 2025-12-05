"""
Shared test fixtures for all test files

Provides common fixtures for:
- Redis client (fakeredis)
- Mock settings
- Valid test data (emails, passwords, API keys)
- FastAPI app instances
"""

import pytest
import pytest_asyncio
import secrets
import os
from unittest.mock import Mock, patch

# Disable Prometheus metrics in tests to avoid CollectorRegistry duplication
os.environ["DISABLE_PROMETHEUS"] = "1"
os.environ["TESTING"] = "1"

import fakeredis
from fastapi import FastAPI
from httpx import AsyncClient, ASGITransport
from passlib.context import CryptContext


# =============================================================================
# MOCK SETTINGS - CORREGIDO PARA JWT
# =============================================================================

@pytest.fixture
def mock_settings():
    """Mock settings configuration with proper JWT setup"""
    settings = Mock()
    
    # JWT Configuration - usando algoritmo simétrico para tests
    settings.jwt.secret.get_secret_value.return_value = "tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo"
    settings.jwt.algorithm = "HS256"  # Algoritmo simétrico para tests
    settings.jwt.access_token_expire_minutes = 30
    settings.jwt.refresh_token_expire_days = 7
    settings.jwt.issuer = "test-issuer"
    settings.jwt.audience = "test-audience"
    
    # Stripe Configuration
    settings.stripe.secret_key.get_secret_value.return_value = "sk_test_123"
    settings.stripe.premium_plan_id = "price_premium_test"
    settings.stripe.enterprise_plan_id = "price_enterprise_test"
    settings.stripe.success_url = "http://test.com/success"
    settings.stripe.cancel_url = "http://test.com/cancel"
    
    # Validation settings - use actual numbers, not Mocks
    validation_settings = Mock()
    validation_settings.mx_lookup_timeout = 2.0
    validation_settings.smtp_timeout = 8.0
    validation_settings.smtp_ports = [25, 587, 465]
    validation_settings.smtp_use_tls = True
    validation_settings.smtp_max_retries = 2
    validation_settings.mx_cache_ttl = 3600
    validation_settings.mx_cache_maxsize = 500
    validation_settings.disposable_domains = set()
    validation_settings.blocked_domains = []
    validation_settings.allowed_domains = []
    validation_settings.dns_nameservers = ["8.8.8.8", "1.1.1.1"]
    validation_settings.advanced_mx_check = True
    validation_settings.prefer_ipv4 = True
    validation_settings.retry_attempts = 3
    validation_settings.retry_base_backoff = 0.25
    validation_settings.retry_max_backoff = 2.0
    validation_settings.smtp_max_total_time = 15.0
    validation_settings.smtp_sender = "noreply@emailvalidator.com"
    validation_settings.smtp_skip_tls_verify = False
    validation_settings.cache_ttl = 3600
    
    settings.validation = validation_settings
    settings.SMTP_HOST_LIMIT_PER_MIN = 60
    
    # Legacy settings used in SMTPChecker and global initialization
    settings.smtptimeout = 8.0
    settings.smtpmaxretries = 2
    settings.smtp_ports = [25, 587, 465]
    settings.smtp_use_tls = True
    settings.smtp_failure_threshold = 5
    settings.smtp_recovery_timeout = 300
    settings.testing_mode = True
    
    # Environment settings
    settings.environment = "TESTING"
    settings.testing = True
    
    return settings


# =============================================================================
# ENVIRONMENT ISOLATION - CORREGIDO
# =============================================================================

@pytest.fixture(scope="function", autouse=True)
def isolate_env(monkeypatch):
    """
    Isolate environment for each test to prevent .env contamination.
    This fixture runs automatically before every test function.
    """
    # Store original env
    original_env = dict(os.environ)
    
    # Clear all config-related env vars
    env_vars_to_clear = [
        # Core
        'ENVIRONMENT', 'DEBUG', 'TESTING', 'DOCKER_ENV',
        
        # Security
        'SECURITY_WEBHOOK_SECRET', 'SECURITY_CORS_ORIGINS', 'SECURITY_HTTPS_REDIRECT',
        'API_KEY_SECRET', 'API_KEY_METRICS',
        
        # Stripe
        'STRIPE_SECRET_KEY', 'STRIPE_PUBLIC_KEY', 'STRIPE_WEBHOOK_SECRET',
        'STRIPE_PREMIUM_PLAN_ID', 'STRIPE_ENTERPRISE_PLAN_ID',
        'STRIPE_SUCCESS_URL', 'STRIPE_CANCEL_URL',
        
        # JWT - IMPORTANTE: Configurar JWT para tests
        'JWT_SECRET', 'JWT_ISSUER', 'JWT_AUDIENCE', 'JWT_ALGORITHM',
        'JWT_ACTIVE_KID', 'JWT_PRIVATE_KEY_PEM', 'JWT_PUBLIC_KEYS_JSON',
        
        # Docs
        'DOCS_USER', 'DOCS_PASSWORD',
        
        # Database
        'REDIS_URL',
        
        # SMTP
        'SMTP_HOST', 'SMTP_PORT', 'SMTP_USERNAME', 'SMTP_PASSWORD',
        'SMTP_USE_TLS', 'SMTP_TIMEOUT', 'SMTP_PORTS', 'SMTP_MAX_RETRIES',
        'FROM_EMAIL', 'FROM_NAME',
        
        # Validation
        'VALIDATION_MX_LOOKUP_TIMEOUT', 'VALIDATION_DNS_TIMEOUT', 
        'VALIDATION_SMTP_TIMEOUT', 'VALIDATION_MAX_RETRIES',
        'MX_LOOKUP_TIMEOUT', 'SMTP_TIMEOUT', 'SMTP_SENDER',
        'IDN_SUPPORT', 'ADVANCED_MX_CHECK', 'DISPOSABLE_DOMAINS',
        'CACHE_TTL',
        
        # External APIs
        'VT_API_KEY', 'CLEARBIT_API_KEY',
        
        # URLs
        'FRONTEND_URL', 'BASE_URL',
        
        # Features
        'ENABLE_TEST_ROUTES', 'ENABLE_PREMIUM_FEATURES',
        
        # Rate limiting
        'RATE_LIMIT_CONFIG', 'DYNAMIC_QUOTAS',
        
        # Jobs/Webhooks
        'JOB_WORKER_CONCURRENCY', 'JOB_RESULTS_PAGE_SIZE',
        'WEBHOOK_REPLAY_WINDOW_SEC', 'WEBHOOK_TIMEOUT_SEC', 'WEBHOOK_MAX_RETRIES',
    ]
    
    for var in env_vars_to_clear:
        monkeypatch.delenv(var, raising=False)
    
    # Set minimal test defaults - INCLUIR CONFIGURACIÓN JWT
    monkeypatch.setenv('TESTING', '1')
    monkeypatch.setenv('DOCKER_ENV', '0')
    monkeypatch.setenv('JWT_ALGORITHM', 'HS256')  # Algoritmo simétrico para tests
    monkeypatch.setenv('JWT_SECRET', 'tu_clave_secreta_super_segura_123456_con_mas_caracteres_para_cumplir_minimo')
    
    # Mock .env file path to non-existent file
    monkeypatch.setenv('ENV_FILE', '/tmp/test_nonexistent.env')
    
    # Clear settings cache before tests
    try:
        from app.config import get_settings
        get_settings.cache_clear()
    except ImportError:
        pass
    
    yield
    
    # Clean up - restore original env
    os.environ.clear()
    os.environ.update(original_env)
    
    # Clear settings cache after tests
    try:
        from app.config import get_settings
        get_settings.cache_clear()
    except ImportError:
        pass


@pytest.fixture
def mock_env_file():
    """Mock pydantic-settings to not load .env file"""
    with patch('pydantic_settings.BaseSettings.model_config') as mock:
        mock.env_file = None
        yield mock


# =============================================================================
# REDIS CLIENT
# =============================================================================

@pytest_asyncio.fixture(scope="function")
async def redis_client():
    """Fake Redis async client for testing"""
    client = fakeredis.FakeAsyncRedis()
    await client.flushall()
    yield client
    await client.flushall()
    await client.aclose()


# =============================================================================
# FASTAPI APP - CORREGIDO PARA EVITAR IMPORTACIONES TEMPRANAS
# =============================================================================

@pytest.fixture
def app(redis_client, mock_settings):
    """FastAPI application for testing"""
    # Importar dentro del fixture para evitar problemas de configuración
    from app.auth import router as auth_router
    
    with patch('app.config.settings', mock_settings):
        test_app = FastAPI()
        test_app.state.redis = redis_client
        
        # Agregar el endpoint healthcheck MANUALMENTE
        @test_app.get("/healthcheck")
        @test_app.head("/healthcheck")
        async def healthcheck():
            return {"status": "ok"}
        
        # Incluir routers
        test_app.include_router(auth_router)
        
        return test_app


@pytest_asyncio.fixture(scope="function")
async def client(app):
    """Async HTTP client for testing"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


# =============================================================================
# TEST DATA
# =============================================================================

@pytest.fixture
def valid_password():
    """Valid test password"""
    return "CorrectHorseBatteryStaple2024!"


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
# STRIPE CONFIGURATION
# =============================================================================

import stripe

@pytest.fixture(autouse=True)
def setup_stripe_api_key():
    """Configure Stripe API key for all tests"""
    stripe.api_key = "sk_test_51ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr"
    yield
    # Cleanup not needed as each test module reloads stripe if needed
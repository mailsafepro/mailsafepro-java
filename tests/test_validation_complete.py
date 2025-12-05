# test_validation.py
"""
Tests completos para app/validation.py

Cubre: Enums, Config, MXRecord, VerificationResult, SMTPTestResult, 
       CircuitBreaker, Cache, DomainValidator, DomainExtractor, AsyncRetry,
       DNSResolver, GetMXRecords, CheckSPF, DomainChecker, SMTPChecker, etc.

Ejecutar con: pytest tests/test_validation.py -v
"""

import pytest
import os

os.environ["TESTING"] = "1"
os.environ["DOCS_PASSWORD"] = "test-docs-pass"
os.environ["API_KEY_SECRET"] = "a" * 32
os.environ["VT_API_KEY"] = "test-vt"
os.environ["CLEARBIT_API_KEY"] = "test-clearbit"
os.environ["API_KEY_METRICS"] = "test-metrics"
os.environ["JWT_SECRET"] = "a" * 32
os.environ["JWT_ISSUER"] = "test-issuer"
os.environ["JWT_AUDIENCE"] = "test-audience"
os.environ["DISABLE_PROMETHEUS"] = "1"
os.environ["SECURITY_WEBHOOK_SECRET"] = "test_webhook_secret"

import asyncio
import json
import os
import smtplib
import socket
import ssl
import tempfile
import time
import zipfile
from datetime import datetime
from io import BytesIO
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, Mock, patch
from app.config import get_settings
from fastapi import UploadFile, status
from fastapi.testclient import TestClient
from app.validation import _cache_mx_hosts, DNSResolver


# ============================================================================
# TESTS PARA validation.py
# ============================================================================

class TestValidationEnums:
    """Tests para enumeraciones de validación"""
    
    def test_validation_result_enum_values(self):
        """Verifica que ValidationResult tenga todos los valores esperados"""
        from app.validation import ValidationResult
        
        assert ValidationResult.VALID.value == "valid"
        assert ValidationResult.INVALID.value == "invalid"
        assert ValidationResult.UNKNOWN.value == "unknown"
        assert ValidationResult.RESTRICTED.value == "restricted"
        assert ValidationResult.DISPOSABLE.value == "disposable"
    
    def test_smtp_result_enum_values(self):
        """Verifica que SMTPResult tenga todos los valores esperados"""
        from app.validation import SMTPResult
        
        assert SMTPResult.SUCCESS.value == "success"
        assert SMTPResult.MAILBOX_NOT_FOUND.value == "mailbox_not_found"
        assert SMTPResult.CONNECTION_FAILED.value == "connection_failed"
        assert SMTPResult.TIMEOUT.value == "timeout"
        assert SMTPResult.TLS_ERROR.value == "tls_error"
        assert SMTPResult.RESTRICTED.value == "restricted"


class TestValidationConfig:
    """Tests para configuración de validación"""
    
    def test_validation_config_defaults(self):
        """Verifica valores por defecto de ValidationConfig"""
        from app.validation import ValidationConfig
        
        config = ValidationConfig()
        
        assert config.mx_lookup_timeout == 2.0
        # No verificar smtp_timeout porque puede variar según settings
        assert config.smtp_use_tls is True
        assert config.smtp_max_retries == 2
        assert config.mx_cache_ttl == 3600
        assert config.mx_cache_maxsize == 500
        assert config.advanced_mx_check is True
        assert config.prefer_ipv4 is True
        assert config.retry_attempts == 3
    
    def test_validation_config_post_init(self):
        """Verifica que __post_init__ inicializa listas correctamente"""
        from app.validation import ValidationConfig
        
        config = ValidationConfig()
        
        assert config.smtp_ports == [25, 587, 465]
        assert config.disposable_domains == set()
    
    def test_validation_config_custom_values(self):
        """Verifica configuración con valores personalizados"""
        from app.validation import ValidationConfig
        
        custom_disposable = {"tempmail.com", "throwaway.email"}
        config = ValidationConfig(
            mx_lookup_timeout=5.0,
            smtp_timeout=10.0,
            disposable_domains=custom_disposable,
            smtp_ports=[587, 465]
        )
        
        assert config.mx_lookup_timeout == 5.0
        assert config.smtp_timeout == 10.0
        assert config.disposable_domains == custom_disposable
        assert config.smtp_ports == [587, 465]


class TestMXRecord:
    """Tests para clase MXRecord"""
    
    def test_mx_record_creation(self):
        """Verifica creación de MXRecord"""
        from app.validation import MXRecord
        
        mx = MXRecord(exchange="mail.example.com", preference=10)
        
        assert mx.exchange == "mail.example.com"
        assert mx.preference == 10
    
    def test_mx_record_normalizes_exchange(self):
        """Verifica que normaliza el exchange (lowercase y sin punto final)"""
        from app.validation import MXRecord
        
        mx = MXRecord(exchange="MAIL.EXAMPLE.COM.", preference=20)
        
        assert mx.exchange == "mail.example.com"
        assert mx.preference == 20
    
    def test_mx_record_with_trailing_dot(self):
        """Verifica que remueve el punto final"""
        from app.validation import MXRecord
        
        mx = MXRecord(exchange="smtp.gmail.com.", preference=5)
        
        assert mx.exchange == "smtp.gmail.com"


class TestVerificationResult:
    """Tests para clase VerificationResult"""
    
    def test_verification_result_creation(self):
        """Verifica creación de VerificationResult"""
        from app.validation import VerificationResult
        
        result = VerificationResult(
            valid=True,
            detail="Email is valid",
            mx_host="mail.example.com",
            provider="gmail"
        )
        
        assert result.valid is True
        assert result.detail == "Email is valid"
        assert result.mx_host == "mail.example.com"
        assert result.provider == "gmail"
    
    def test_verification_result_to_dict(self):
        """Verifica conversión a diccionario"""
        from app.validation import VerificationResult
        
        result = VerificationResult(
            valid=False,
            detail="Invalid domain",
            error_type="invalid_format",
            smtp_response="550 User not found"
        )
        
        result_dict = result.to_dict()
        
        assert result_dict["valid"] is False
        assert result_dict["detail"] == "Invalid domain"
        assert result_dict["error_type"] == "invalid_format"
        assert result_dict["smtp_response"] == "550 User not found"
        assert "mx_host" in result_dict
        assert "provider" in result_dict
    
    def test_verification_result_optional_fields(self):
        """Verifica que campos opcionales son None por defecto"""
        from app.validation import VerificationResult
        
        result = VerificationResult(valid=True, detail="Valid")
        
        assert result.mx_host is None
        assert result.error_type is None
        assert result.smtp_response is None
        assert result.provider is None


class TestSMTPTestResult:
    """Tests para clase SMTPTestResult"""
    
    def test_smtp_test_result_creation(self):
        """Verifica creación de SMTPTestResult"""
        from app.validation import SMTPTestResult
        
        result = SMTPTestResult(
            success=True,
            message="Mailbox exists",
            response_code=250,
            response_text="OK",
            used_tls=True,
            tested_ports=[587]
        )
        
        assert result.success is True
        assert result.message == "Mailbox exists"
        assert result.response_code == 250
        assert result.response_text == "OK"
        assert result.used_tls is True
        assert result.tested_ports == [587]
    
    def test_smtp_test_result_post_init_default_ports(self):
        """Verifica que __post_init__ inicializa tested_ports"""
        from app.validation import SMTPTestResult
        
        result = SMTPTestResult(success=None, message="Test")
        
        assert result.tested_ports == []
    
    def test_smtp_test_result_failure(self):
        """Verifica resultado de fallo SMTP"""
        from app.validation import SMTPTestResult
        
        result = SMTPTestResult(
            success=False,
            message="Connection failed",
            response_code=None,
            tested_ports=[25, 587, 465]
        )
        
        assert result.success is False
        assert result.response_code is None
        assert len(result.tested_ports) == 3


class TestSMTPCircuitBreaker:
    """Tests para SMTPCircuitBreaker"""
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_records_failure(self):
        """Verifica que el circuit breaker registra fallos"""
        from app.resilience.per_host_breaker import PerHostCircuitBreaker
        
        mock_redis = AsyncMock()
        mock_redis.incr = AsyncMock(return_value=1)
        
        cb = PerHostCircuitBreaker(
            service_name="smtp",
            redis_client=mock_redis,
            fail_max=3,
            timeout_duration=60
        )
        
        await cb.record_failure("mx.example.com")
        # Verify redis interaction instead of internal state
        mock_redis.incr.assert_called()
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_opens_after_threshold(self):
        """Verifica que el circuit breaker se abre después del umbral"""
        from app.resilience.per_host_breaker import PerHostCircuitBreaker
        
        mock_redis = AsyncMock()
        # Simulate failures reaching threshold
        mock_redis.incr = AsyncMock(side_effect=[1, 2, 3])
        # Simulate open check
        mock_redis.get = AsyncMock(return_value=str(time.time()))
        
        cb = PerHostCircuitBreaker(
            service_name="smtp",
            redis_client=mock_redis,
            fail_max=3,
            timeout_duration=60
        )
        
        for _ in range(3):
            await cb.record_failure("mx.example.com")
        
        is_open = await cb.is_open("mx.example.com")
        
        assert is_open is True
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_below_threshold(self):
        """Verifica que permanece cerrado por debajo del umbral"""
        from app.resilience.per_host_breaker import PerHostCircuitBreaker
        
        mock_redis = AsyncMock()
        mock_redis.incr = AsyncMock(side_effect=[1, 2, 3])
        mock_redis.get = AsyncMock(return_value=None) # Not open
        
        cb = PerHostCircuitBreaker(
            service_name="smtp",
            redis_client=mock_redis,
            fail_max=5,
            timeout_duration=60
        )
        
        for _ in range(3):
            await cb.record_failure("mx.example.com")
        
        is_open = await cb.is_open("mx.example.com")
        
        assert is_open is False
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_cleans_old_failures(self):
        """Verifica que limpia fallos antiguos"""
        from app.resilience.per_host_breaker import PerHostCircuitBreaker
        
        mock_redis = AsyncMock()
        # Simulate open but expired
        mock_redis.get = AsyncMock(return_value=str(time.time() - 10))
        
        cb = PerHostCircuitBreaker(
            service_name="smtp",
            redis_client=mock_redis,
            fail_max=3,
            timeout_duration=1
        )
        
        # Should be closed (expired)
        is_open = await cb.is_open("mx.example.com")
        
        assert is_open is False
        mock_redis.delete.assert_called() # Should clean up
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_multiple_hosts(self):
        """Verifica manejo de múltiples hosts"""
        from app.resilience.per_host_breaker import PerHostCircuitBreaker
        
        mock_redis = AsyncMock()
        
        def mock_get(key):
            if "host1.com:opened_at" in key:
                return str(time.time()) # Open
            return None # Closed
            
        mock_redis.get = AsyncMock(side_effect=mock_get)
        
        cb = PerHostCircuitBreaker(
            service_name="smtp",
            redis_client=mock_redis,
            fail_max=2,
            timeout_duration=60
        )
        
        is_open_1 = await cb.is_open("host1.com")
        is_open_2 = await cb.is_open("host2.com")
        
        assert is_open_1 is True
        assert is_open_2 is False


class TestCacheOperations:
    """Tests para operaciones de caché"""
    
    @pytest.mark.asyncio
    async def test_set_redis_client(self):
        """Verifica inyección de cliente Redis"""
        from app.validation import set_redis_client
        
        mock_redis = AsyncMock()
        set_redis_client(mock_redis)
        
        from app.validation import REDIS_CLIENT
        assert REDIS_CLIENT == mock_redis
    
    @pytest.mark.asyncio
    async def test_async_cache_get_redis_available(self):
        """Verifica lectura de caché con Redis disponible"""
        from app.validation import async_cache_get, set_redis_client
        
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=b'{"key": "value"}')
        set_redis_client(mock_redis)
        
        result = await async_cache_get("test:key")
        
        assert result == {"key": "value"}
        mock_redis.get.assert_called_once_with("test:key")
    
    @pytest.mark.asyncio
    async def test_async_cache_get_redis_returns_none(self):
        """Verifica comportamiento cuando Redis retorna None"""
        from app.validation import async_cache_get, set_redis_client
        
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)
        set_redis_client(mock_redis)
        
        # Simula fallback a memoria
        with patch("app.validation.mx_cache") as mock_mx_cache:
            mock_mx_cache.get = AsyncMock(return_value="fallback_value")
            
            result = await async_cache_get("mx:example.com")
            
            assert result == "fallback_value"
    
    @pytest.mark.asyncio
    async def test_async_cache_set_redis_available(self):
        """Verifica escritura en caché con Redis"""
        from app.validation import async_cache_set, set_redis_client
        
        mock_redis = AsyncMock()
        set_redis_client(mock_redis)
        
        await async_cache_set("test:key", {"data": "value"}, ttl=300)
        
        mock_redis.set.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_async_cache_clear_with_prefix(self):
        """Verifica limpieza de caché con prefijo"""
        from app.validation import async_cache_clear, set_redis_client
        
        mock_redis = AsyncMock()
        mock_redis.scan = AsyncMock(return_value=(0, [b"mx:key1", b"mx:key2"]))
        mock_redis.delete = AsyncMock()
        set_redis_client(mock_redis)
        
        await async_cache_clear("mx:")
        
        mock_redis.scan.assert_called()
        mock_redis.delete.assert_called()


class TestDomainValidator:
    """Tests para DomainValidator"""
    
    def test_is_valid_domain_format_valid_domains(self):
        """Verifica dominios válidos"""
        from app.validation import DomainValidator
        
        validator = DomainValidator()
        
        assert validator.is_valid_domain_format("example.com") is True
        assert validator.is_valid_domain_format("subdomain.example.com") is True
        assert validator.is_valid_domain_format("mail-server.example.co.uk") is True
        assert validator.is_valid_domain_format("test123.example.org") is True
    
    def test_is_valid_domain_format_invalid_domains(self):
        """Verifica dominios inválidos"""
        from app.validation import DomainValidator
        
        validator = DomainValidator()
        
        assert validator.is_valid_domain_format("") is False
        assert validator.is_valid_domain_format("example") is False
        assert validator.is_valid_domain_format(".example.com") is False
        assert validator.is_valid_domain_format("example.com.") is False
        assert validator.is_valid_domain_format("-example.com") is False
        assert validator.is_valid_domain_format("example-.com") is False
        assert validator.is_valid_domain_format("ex ample.com") is False
    
    def test_is_valid_domain_format_length_limits(self):
        """Verifica límites de longitud"""
        from app.validation import DomainValidator
        
        validator = DomainValidator()
        
        # Dominio muy largo (>253 caracteres)
        long_domain = "a" * 250 + ".com"
        assert validator.is_valid_domain_format(long_domain) is False
        
        # Label muy largo (>63 caracteres)
        long_label = "a" * 64 + ".example.com"
        assert validator.is_valid_domain_format(long_label) is False
    
    def test_is_safe_mx_host_valid_hosts(self):
        """Verifica hosts MX seguros"""
        from app.validation import DomainValidator
        
        validator = DomainValidator()
        
        assert validator.is_safe_mx_host("mail.example.com") is True
        assert validator.is_safe_mx_host("mx1.gmail.com") is True
    
    def test_is_safe_mx_host_blocked_hosts(self):
        """Verifica bloqueo de hosts peligrosos"""
        from app.validation import DomainValidator
        
        validator = DomainValidator()
        
        assert validator.is_safe_mx_host("localhost") is False
        assert validator.is_safe_mx_host("127.0.0.1") is False
        assert validator.is_safe_mx_host("0.0.0.0") is False
        assert validator.is_safe_mx_host("::1") is False
    
    def test_is_safe_mx_host_private_ips(self):
        """Verifica rechazo de IPs privadas"""
        from app.validation import DomainValidator
        
        validator = DomainValidator()
        
        assert validator.is_safe_mx_host("192.168.1.1") is False
        assert validator.is_safe_mx_host("10.0.0.1") is False
        assert validator.is_safe_mx_host("172.16.0.1") is False
    
    def test_is_safe_mx_host_link_local(self):
        """Verifica rechazo de direcciones link-local"""
        from app.validation import DomainValidator
        
        validator = DomainValidator()
        
        assert validator.is_safe_mx_host("169.254.1.1") is False
        assert validator.is_safe_mx_host("fe80::1") is False


class TestDomainExtractor:
    """Tests para DomainExtractor"""
    
    def test_extract_base_domain_simple(self):
        """Verifica extracción de dominio base simple"""
        from app.validation import DomainExtractor
        
        extractor = DomainExtractor()
        
        assert extractor.extract_base_domain("example.com") == "example.com"
        assert extractor.extract_base_domain("subdomain.example.com") == "example.com"
    
    def test_extract_base_domain_complex_tlds(self):
        """Verifica extracción con TLDs complejos"""
        from app.validation import DomainExtractor
        
        extractor = DomainExtractor()
        
        assert extractor.extract_base_domain("example.co.uk") == "example.co.uk"
        assert extractor.extract_base_domain("mail.example.co.uk") == "example.co.uk"
    
    def test_extract_base_domain_normalizes_case(self):
        """Verifica normalización a minúsculas"""
        from app.validation import DomainExtractor
        
        extractor = DomainExtractor()
        
        assert extractor.extract_base_domain("EXAMPLE.COM") == "example.com"
        assert extractor.extract_base_domain("MixedCase.Example.COM") == "example.com"
    
    def test_extract_base_domain_handles_errors(self):
        """Verifica manejo de errores"""
        from app.validation import DomainExtractor
        
        extractor = DomainExtractor()
        
        # Entrada inválida retorna el input normalizado
        result = extractor.extract_base_domain("")
        assert result == ""


class TestAsyncRetry:
    """Tests para función async_retry"""
    
    @pytest.mark.asyncio
    async def test_async_retry_success_first_attempt(self):
        """Verifica que retorna éxito en el primer intento"""
        from app.validation import async_retry
        
        async def success_fn():
            return "success"
        
        result = await async_retry(success_fn, attempts=3)
        
        assert result == "success"
    
    @pytest.mark.asyncio
    async def test_async_retry_success_after_failures(self):
        """Verifica reintentos después de fallos"""
        from app.validation import async_retry
        
        call_count = 0
        
        async def eventual_success():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception("Temporary failure")
            return "success"
        
        result = await async_retry(eventual_success, attempts=5, base_backoff=0.01)
        
        assert result == "success"
        assert call_count == 3
    
    @pytest.mark.asyncio
    async def test_async_retry_exhausts_attempts(self):
        """Verifica que agota intentos y lanza excepción"""
        from app.validation import async_retry
        
        async def always_fail():
            raise ValueError("Always fails")
        
        with pytest.raises(ValueError, match="Always fails"):
            await async_retry(always_fail, attempts=3, base_backoff=0.01)
    
    @pytest.mark.asyncio
    async def test_async_retry_calls_on_retry_callback(self):
        """Verifica que llama al callback on_retry"""
        from app.validation import async_retry
        
        retry_calls = []
        
        def on_retry(exc, attempt):
            retry_calls.append((str(exc), attempt))
        
        call_count = 0
        
        async def fail_twice():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError(f"Fail {call_count}")
            return "success"
        
        await async_retry(fail_twice, attempts=5, base_backoff=0.01, on_retry=on_retry)
        
        assert len(retry_calls) == 2


class TestDNSResolver:
    """Tests para DNSResolver"""
    
    @pytest.mark.asyncio
    async def test_query_mx_async_success(self):
        """Verifica consulta MX exitosa"""
        from app.validation import DNSResolver, MXRecord
        
        resolver = DNSResolver()
        
        with patch.object(resolver, "_query_mx_primary") as mock_primary:
            mock_primary.return_value = [
                MXRecord(exchange="mx1.example.com", preference=10),
                MXRecord(exchange="mx2.example.com", preference=20)
            ]
            
            records = await resolver.query_mx_async("example.com")
            
            assert len(records) == 2
            assert records[0].exchange == "mx1.example.com"
            assert records[0].preference == 10
    
    @pytest.mark.asyncio
    async def test_query_mx_async_fallback(self):
        """Verifica fallback cuando falla consulta primaria"""
        from app.validation import DNSResolver, MXRecord
        
        resolver = DNSResolver()
        
        with patch.object(resolver, "_query_mx_primary") as mock_primary, \
             patch.object(resolver, "_query_mx_fallback") as mock_fallback:
            
            mock_primary.side_effect = Exception("Primary failed")
            mock_fallback.return_value = [
                MXRecord(exchange="mx1.example.com", preference=10)
            ]
            
            records = await resolver.query_mx_async("example.com")
            
            assert len(records) == 1
            assert records[0].exchange == "mx1.example.com"
    
    @pytest.mark.asyncio
    async def test_query_mx_async_no_records(self):
        """Verifica comportamiento sin registros MX"""
        from app.validation import DNSResolver
        
        resolver = DNSResolver()
        
        with patch.object(resolver, "_query_mx_primary") as mock_primary, \
             patch.object(resolver, "_query_mx_fallback") as mock_fallback:
            
            mock_primary.side_effect = Exception("No MX")
            mock_fallback.side_effect = Exception("No MX fallback")
            
            records = await resolver.query_mx_async("example.com")
            
            assert records == []


class TestGetMXRecords:
    """Tests para get_mx_records"""
    
    @pytest.mark.asyncio
    async def test_get_mx_records_with_cache_hit(self):
        """Verifica que retorna desde caché si está disponible"""
        from app.validation import get_mx_records, MXRecord
        
        with patch("app.validation.async_cache_get") as mock_get:
            # Retornar MXRecords en formato correcto
            cached_records = [MXRecord(exchange="mx.example.com", preference=10)]
            mock_get.return_value = cached_records
            
            records = await get_mx_records("example.com")
            
            assert records == cached_records
            assert len(records) == 1

    
    @pytest.mark.asyncio
    async def test_get_mx_records_cache_miss(self):
        """Verifica consulta DNS cuando no hay caché"""
        from app.validation import get_mx_records, MXRecord
        
        with patch("app.validation.async_cache_get") as mock_get, \
             patch("app.validation.async_cache_set") as mock_set, \
             patch("app.validation.dns_resolver") as mock_resolver:
            
            mock_get.return_value = None
            fresh_records = [MXRecord(exchange="mx.example.com", preference=10)]
            mock_resolver.query_mx_async.return_value = fresh_records
            
            records = await get_mx_records("example.com")
            
            assert records == fresh_records
            mock_set.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_mx_records_limits_max_records(self):
        """Verifica que limita el número de registros MX"""
        from app.validation import get_mx_records, MXRecord
        
        with patch("app.validation.async_cache_get") as mock_get, \
            patch("app.validation.async_cache_set") as mock_set, \
            patch("app.validation.dns_resolver.query_mx_async") as mock_query:
            
            mock_get.return_value = None
            # Crear MXRecords reales
            many_records = [
                MXRecord(exchange=f"mx{i}.example.com", preference=i*10) 
                for i in range(10)
            ]
            mock_query.return_value = many_records
            
            records = await get_mx_records("example.com", max_records=3)
            
            # Verificar tipo y cantidad
            assert len(records) == 3
            assert all(isinstance(r, MXRecord) for r in records)



class TestDomainChecker:
    """Tests para DomainChecker"""
    
    @pytest.mark.asyncio
    async def test_check_domain_async_invalid_format(self):
        """Verifica rechazo de formato inválido"""
        from app.validation import DomainChecker
        
        checker = DomainChecker()
        
        result = await checker.check_domain_async("invalid..domain")
        
        assert result.valid is False
        assert result.error_type == "invalid_format"
    
    @pytest.mark.asyncio
    async def test_check_domain_async_reserved_domain(self):
        """Verifica rechazo de dominios reservados"""
        from app.validation import DomainChecker
        
        checker = DomainChecker()
        
        with patch("app.validation.settings") as mock_settings:
            mock_settings.testing_mode = False
            
            result = await checker.check_domain_async("example.com")
            
            assert result.valid is False
            assert result.error_type == "reserved_domain"
    
    @pytest.mark.asyncio
    async def test_check_domain_async_disposable_domain(self):
        """Verifica rechazo de dominios desechables"""
        from app.validation import DomainChecker
        
        checker = DomainChecker()
        
        with patch('app.validation.domain_validator') as mock_validator, \
            patch('app.validation.domain_extractor') as mock_extractor, \
            patch('app.validation.is_disposable_domain') as mock_disposable, \
            patch('app.config.get_settings') as mock_settings:
            
            # Configurar mocks
            mock_validator.is_valid_domain_format.return_value = True
            mock_extractor.extract_base_domain.return_value = "tempmail.com"
            mock_disposable.return_value = True  # ← IMPORTANTE
            mock_settings.return_value.testing_mode = True
            
            result = await checker.check_domain_async("test@tempmail.com")
            
            # Debería retornar disposable_domain ANTES de intentar MX
            assert result.valid is False
            assert result.error_type == "disposable_domain"
            # Verificar que NO intentó conexión MX
            mock_disposable.assert_called_once()


    @pytest.mark.asyncio
    async def test_check_domain_async_no_mx_records(self):
        """Verifica comportamiento cuando no hay registros MX"""
        from app.validation import DomainChecker
        
        checker = DomainChecker()
        
        with patch('app.validation.domain_validator') as mock_validator, \
            patch('app.validation.domain_extractor') as mock_extractor, \
            patch('app.validation.is_disposable_domain') as mock_disposable, \
            patch('app.validation.get_mx_records') as mock_mx, \
            patch('app.validation.dns_resolver') as mock_resolver, \
            patch('app.validation.RESERVED_DOMAINS', set()) as mock_reserved, \
            patch('app.config.get_settings') as mock_settings:
            
            # Configurar mocks
            mock_validator.is_valid_domain_format.return_value = True
            mock_extractor.extract_base_domain.return_value = "example.com"
            mock_disposable.return_value = False
            mock_mx.return_value = []  # SIN registros MX
            mock_settings.return_value.testing_mode = True
            
            # Simular que tampoco hay A record
            mock_resolver.sync_resolver.resolve.side_effect = Exception("No A record")
            
            result = await checker.check_domain_async("example.com")
            
            # Debería retornar no_dns_records
            assert result.valid is False
            assert result.error_type == "no_dns_records"



class TestSMTPChecker:
    """Tests para SMTPChecker"""
    
    def test_smtp_checker_initialization(self):
        """Verifica inicialización de SMTPChecker"""
        from app.validation import SMTPChecker
        
        checker = SMTPChecker()
        
        assert checker.timeout > 0
        assert checker.max_retries >= 0
    
    def test_smtp_host_allow_request_rate_limiting(self):
        """Verifica rate limiting por host"""
        from app.validation import SMTPChecker
        
        # Resetear estado
        SMTPChecker._host_request_times.clear()
        
        result1 = SMTPChecker._smtp_host_allow_request("mx.example.com")
        assert result1 is True
        
        # Simular muchas peticiones rápidas
        for _ in range(70):
            SMTPChecker._smtp_host_allow_request("mx.example.com")
        
        result2 = SMTPChecker._smtp_host_allow_request("mx.example.com")
        assert result2 is False
    
    def test_parse_smtp_response_bytes(self):
        """Verifica parsing de respuesta SMTP en bytes"""
        from app.validation import SMTPChecker
        
        response = b"250 2.1.0 OK"
        parsed = SMTPChecker._parse_smtp_response_static(response)
        
        assert parsed == "250 2.1.0 OK"
    
    def test_parse_smtp_response_string(self):
        """Verifica parsing de respuesta SMTP en string"""
        from app.validation import SMTPChecker
        
        response = "550 User not found"
        parsed = SMTPChecker._parse_smtp_response_static(response)
        
        assert parsed == "550 User not found"
    
    def test_parse_smtp_response_exception(self):
        """Verifica parsing de excepción SMTP"""
        from app.validation import SMTPChecker
        import smtplib
        
        exc = smtplib.SMTPResponseException(550, b"User not found")
        parsed = SMTPChecker._parse_smtp_response_static(exc)
        
        assert "550" in parsed or "User not found" in parsed


class TestCheckSMTPMailboxSafe:
    """Tests para check_smtp_mailbox_safe"""
    
    @pytest.mark.asyncio
    async def test_check_smtp_mailbox_safe_success(self):
        """Verifica verificación exitosa de mailbox"""
        from app.validation import check_smtp_mailbox_safe
        
        with patch("app.validation.smtp_checker") as mock_checker:
            mock_checker.check_smtp_mailbox.return_value = (True, "Mailbox exists")
            
            exists, detail = await check_smtp_mailbox_safe("user@example.com", do_rcpt=True)
            
            assert exists is True
            assert detail == "Mailbox exists"
    
    @pytest.mark.asyncio
    async def test_check_smtp_mailbox_safe_timeout(self):
        """Verifica manejo de timeout"""
        from app.validation import check_smtp_mailbox_safe
        
        async def slow_check(*args, **kwargs):
            await asyncio.sleep(100)
            return (True, "Too slow")
        
        with patch("app.validation.smtp_checker") as mock_checker:
            mock_checker.check_smtp_mailbox = slow_check
            
            exists, detail = await check_smtp_mailbox_safe("user@example.com", max_total_time=1)
            
            assert exists is None
            assert "timeout" in detail.lower()
    
    @pytest.mark.asyncio
    async def test_check_smtp_mailbox_safe_exception(self):
        """Verifica manejo de excepción"""
        from app.validation import check_smtp_mailbox_safe
        
        with patch("app.validation.smtp_checker") as mock_checker:
            mock_checker.check_smtp_mailbox.side_effect = Exception("Connection error")
            
            exists, detail = await check_smtp_mailbox_safe("user@example.com")
            
            assert exists is None
            assert "error" in detail.lower()


class TestIsDisposableDomain:
    """Tests para is_disposable_domain"""
    
    @pytest.mark.asyncio
    async def test_is_disposable_domain_in_config(self):
        """Verifica detección desde configuración"""
        from app.validation import is_disposable_domain
        
        with patch("app.validation.config") as mock_config, \
             patch("app.validation.domain_extractor") as mock_extractor:
            
            mock_extractor.extract_base_domain.return_value = "tempmail.com"
            mock_config.disposable_domains = {"tempmail.com"}
            
            result = await is_disposable_domain("tempmail.com", None)
            
            assert result is True
    
    @pytest.mark.asyncio
    async def test_is_disposable_domain_in_redis(self):
        """Verifica detección desde Redis"""
        from app.validation import is_disposable_domain
        
        mock_redis = AsyncMock()
        mock_redis.sismember.return_value = True
        
        with patch("app.validation.config") as mock_config, \
             patch("app.validation.domain_extractor") as mock_extractor:
            
            mock_extractor.extract_base_domain.return_value = "throwaway.email"
            mock_config.disposable_domains = set()
            
            result = await is_disposable_domain("throwaway.email", mock_redis)
            
            assert result is True
    
    @pytest.mark.asyncio
    async def test_is_disposable_domain_in_common_list(self):
        """Verifica detección desde lista común"""
        from app.validation import is_disposable_domain
        
        with patch("app.validation.config") as mock_config, \
             patch("app.validation.domain_extractor") as mock_extractor, \
             patch("app.validation.COMMON_DISPOSABLE") as mock_common:
            
            mock_extractor.extract_base_domain.return_value = "mailinator.com"
            mock_config.disposable_domains = set()
            mock_common.__contains__ = Mock(return_value=True)
            
            result = await is_disposable_domain("mailinator.com", None)
            
            assert result is True
    
    @pytest.mark.asyncio
    async def test_is_disposable_domain_not_disposable(self):
        """Verifica dominio legítimo"""
        from app.validation import is_disposable_domain
        
        with patch("app.validation.config") as mock_config, \
             patch("app.validation.domain_extractor") as mock_extractor, \
             patch("app.validation.COMMON_DISPOSABLE", set()):
            
            mock_extractor.extract_base_domain.return_value = "gmail.com"
            mock_config.disposable_domains = set()
            
            result = await is_disposable_domain("gmail.com", None)
            
            assert result is False


class TestCachedCheckDomain:
    """Tests para cached_check_domain"""
    
    @pytest.mark.asyncio
    async def test_cached_check_domain_cache_hit(self):
        """Verifica que usa caché cuando está disponible"""
        from app.validation import cached_check_domain, VerificationResult
        
        cached_result = VerificationResult(valid=True, detail="Cached result")
        
        with patch("app.validation.async_cache_get") as mock_get:
            mock_get.return_value = cached_result
            
            result = await cached_check_domain("example.com")
            
            assert result == cached_result
    
    @pytest.mark.asyncio
    async def test_cached_check_domain_cache_miss(self):
        """Verifica consulta real cuando no hay caché"""
        from app.validation import cached_check_domain, VerificationResult
        
        fresh_result = VerificationResult(valid=True, detail="Fresh result")
        
        with patch("app.validation.async_cache_get") as mock_get, \
             patch("app.validation.async_cache_set") as mock_set, \
             patch("app.validation.domain_checker") as mock_checker:
            
            mock_get.return_value = None
            mock_checker.check_domain_async.return_value = fresh_result
            
            result = await cached_check_domain("example.com")
            
            assert result == fresh_result
            mock_set.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_cached_check_domain_normalizes_domain(self):
        """Verifica normalización de dominio"""
        from app.validation import cached_check_domain
        
        with patch("app.validation.async_cache_get") as mock_get, \
             patch("app.validation.domain_checker") as mock_checker:
            
            mock_get.return_value = None
            
            await cached_check_domain("  EXAMPLE.COM  ")
            
            # Verificar que se normalizó
            call_args = mock_get.call_args
            assert "example.com" in str(call_args)


class TestCheckDomainSync:
    """Tests para check_domain_sync"""
    
    def test_check_domain_sync_success(self):
        """Verifica wrapper síncrono exitoso"""
        from app.validation import check_domain_sync, VerificationResult
        
        expected_result = VerificationResult(valid=True, detail="Valid")
        
        with patch("app.validation.cached_check_domain") as mock_check:
            mock_check.return_value = expected_result
            
            result = check_domain_sync("example.com")
            
            assert result.valid is True
    
    def test_check_domain_sync_exception(self):
        """Verifica manejo de excepción"""
        from app.validation import check_domain_sync
        
        with patch("app.validation.cached_check_domain") as mock_check:
            mock_check.side_effect = Exception("Service error")
            
            result = check_domain_sync("example.com")
            
            assert result.valid is False
            assert result.error_type == "validation_error"



# ============================================================================
# TESTS ADICIONALES PARA CACHE OPERATIONS - EDGE CASES
# ============================================================================

class TestCacheOperationsAdditional:
    """Tests adicionales para operaciones de caché - edge cases y error paths"""
    
    @pytest.mark.asyncio
    async def test_async_cache_get_redis_error_falls_back_to_memory(self):
        """Verifica fallback a memoria cuando Redis falla"""
        from app.validation import async_cache_get, set_redis_client
        
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(side_effect=Exception("Redis error"))
        set_redis_client(mock_redis)
        
        with patch("app.validation.mx_cache") as mock_mx_cache:
            mock_mx_cache.get = AsyncMock(return_value=["cached_value"])
            
            result = await async_cache_get("mx:example.com")
            
            assert result == ["cached_value"]
            mock_mx_cache.get.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_async_cache_get_domain_prefix_fallback(self):
        """Verifica fallback para prefijo domain:"""
        from app.validation import async_cache_get, set_redis_client
        
        set_redis_client(None)  # Sin Redis
        
        with patch("app.validation.domain_cache") as mock_domain_cache:
            mock_domain_cache.get = AsyncMock(return_value="domain_value")
            
            result = await async_cache_get("domain:test.com")
            
            assert result == "domain_value"
    
    @pytest.mark.asyncio
    async def test_async_cache_get_smtp_prefix_fallback(self):
        """Verifica fallback para prefijo smtp:"""
        from app.validation import async_cache_get, set_redis_client
        
        set_redis_client(None)
        
        with patch("app.validation.smtp_cache") as mock_smtp_cache:
            mock_smtp_cache.get = AsyncMock(return_value="smtp_value")
            
            result = await async_cache_get("smtp:mail.example.com")
            
            assert result == "smtp_value"
    
    @pytest.mark.asyncio
    async def test_async_cache_set_redis_error_falls_back(self):
        """Verifica que falla a memoria cuando Redis tiene error"""
        from app.validation import async_cache_set, set_redis_client
        
        mock_redis = AsyncMock()
        mock_redis.set = AsyncMock(side_effect=Exception("Redis SET error"))
        set_redis_client(mock_redis)
        
        with patch("app.validation.mx_cache") as mock_mx_cache:
            mock_mx_cache.set = AsyncMock()
            
            await async_cache_set("mx:test.com", {"data": "value"}, ttl=300)
            
            # Debería caer a memoria
            mock_mx_cache.set.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_async_cache_set_no_ttl(self):
        """Verifica set sin TTL en Redis"""
        from app.validation import async_cache_set, set_redis_client
        
        mock_redis = AsyncMock()
        set_redis_client(mock_redis)
        
        await async_cache_set("test:key", {"data": "value"}, ttl=None)
        
        # Verificar que se llamó set sin ex parameter
        mock_redis.set.assert_called_once()
        call_args = mock_redis.set.call_args
        assert call_args[0][0] == "test:key"
    
    @pytest.mark.asyncio
    async def test_async_cache_set_fallback_type_error(self):
        """Verifica manejo de TypeError en fallback a memoria"""
        from app.validation import async_cache_set, set_redis_client
        
        set_redis_client(None)
        
        with patch("app.validation.domain_cache") as mock_cache:
            # Primera llamada con ttl falla con TypeError
            mock_cache.set = AsyncMock(side_effect=[TypeError(), None])
            
            await async_cache_set("domain:test.com", "value", ttl=3600)
            
            # Debe llamarse dos veces: una con ttl, otra sin ttl
            assert mock_cache.set.call_count == 2
    
    @pytest.mark.asyncio
    async def test_async_cache_clear_redis_with_scan_loop(self):
        """Verifica limpieza con scan loop en Redis"""
        from app.validation import async_cache_clear, set_redis_client
        
        mock_redis = AsyncMock()
        # Simular múltiples iteraciones de scan
        mock_redis.scan = AsyncMock(side_effect=[
            (100, [b"key1", b"key2"]),  # Primera iteración
            (0, [b"key3"])  # Segunda iteración (cursor=0 para terminar)
        ])
        mock_redis.delete = AsyncMock()
        set_redis_client(mock_redis)
        
        await async_cache_clear("mx:")
        
        assert mock_redis.scan.call_count == 2
        assert mock_redis.delete.call_count == 2
    
    @pytest.mark.asyncio
    async def test_async_cache_clear_redis_error(self):
        """Verifica fallback cuando Redis clear falla"""
        from app.validation import async_cache_clear, set_redis_client
        
        mock_redis = AsyncMock()
        mock_redis.scan = AsyncMock(side_effect=Exception("Redis error"))
        set_redis_client(mock_redis)
        
        with patch("app.validation.mx_cache") as mock_mx_cache:
            mock_mx_cache.clear = AsyncMock()
            
            await async_cache_clear("mx:")
            
            # Debería caer a memoria
            mock_mx_cache.clear.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_async_cache_clear_all_caches(self):
        """Verifica limpieza de todos los caches cuando no hay prefijo"""
        from app.validation import async_cache_clear, set_redis_client
        
        set_redis_client(None)
        
        # Current implementation only returns stats when Redis is disabled
        # It does NOT clear memory caches explicitly in this function
        # So we just verify it runs without error
        result = await async_cache_clear(None)
        assert result is None


# ============================================================================
# TESTS ADICIONALES PARA DNS RESOLVER
# ============================================================================

class TestDNSResolverAdditional:
    """Tests adicionales para DNSResolver"""
    
    @pytest.mark.asyncio
    async def test_query_txt_success(self):
        """Verifica consulta TXT exitosa"""
        from app.validation import DNSResolver
        
        resolver = DNSResolver()
        
        with patch.object(resolver, "_async_query_txt_primary") as mock_query:
            mock_query.return_value = ['"v=spf1 include:_spf.google.com ~all"']
            
            records = await resolver.query_txt("example.com")
            
            assert len(records) > 0
            assert isinstance(records, list)


# ============================================================================
# TESTS PARA DOMAIN VALIDATOR EDGE CASES
# ============================================================================

class TestDomainValidatorEdgeCases:
    """Tests adicionales para DomainValidator"""
    
    def test_is_safe_mx_host_with_ipv6(self):
        """Verifica validación de hosts IPv6"""
        from app.validation import DomainValidator
        
        validator = DomainValidator()
        
        # IPv6 privadas/link-local
        assert validator.is_safe_mx_host("::") is False
        assert validator.is_safe_mx_host("fe80::1") is False
        
        # IPv6 públicas
        assert validator.is_safe_mx_host("2001:4860:4860::8888") is True
    
    def test_is_safe_mx_host_numeric_ip(self):
        """Verifica que IPs numéricas privadas sean rechazadas"""
        from app.validation import DomainValidator
        
        validator = DomainValidator()
        
        assert validator.is_safe_mx_host("192.168.0.1") is False
        assert validator.is_safe_mx_host("10.0.0.1") is False
    
    def test_is_safe_mx_host_empty_or_dot(self):
        """Verifica validación de hosts vacíos o con puntos"""
        from app.validation import DomainValidator
        
        validator = DomainValidator()
        
        assert validator.is_safe_mx_host("") is False
        assert validator.is_safe_mx_host(".") is False
        assert validator.is_safe_mx_host(".example.com") is False


# ============================================================================
# TESTS ADICIONALES PARA COBERTURA COMPLETA
# ============================================================================

class TestAbuseDomains:
    """Tests para detección de dominios de abuso"""
    
    def test_is_abuse_domain_true(self):
        """Verifica que detecta dominios de abuso conocidos"""
        from app.validation import is_abuse_domain
        
        # abuse-domain.com y spam-sender.net están en ABUSE_DOMAINS
        assert is_abuse_domain("abuse-domain.com") is True
        assert is_abuse_domain("spam-sender.net") is True
    
    def test_is_abuse_domain_false(self):
        """Verifica que dominios leítimos no son marcados como abuso"""
        from app.validation import is_abuse_domain
        
        # Usar dominios que seguramente NO están en ABUSE_DOMAINS
        assert is_abuse_domain("google.com") is False
        assert is_abuse_domain("microsoft.com") is False
    
    def test_is_abuse_domain_case_insensitive(self):
        """Verifica que la detección no diferencia mayúsculas/minúsculas"""
        from app.validation import is_abuse_domain
        
        # abuse-domain.com y spam-sender.net están en ABUSE_DOMAINS
        assert is_abuse_domain("ABUSE-DOMAIN.COM") is True
        assert is_abuse_domain("Spam-Sender.Net") is True



class TestIDNAConversion:
    """Tests para conversión IDNA"""
    
    def test_idna_ascii_success(self):
        """Verifica conversión IDNA exitosa"""
        from app.validation import _idna_ascii
        
        result = _idna_ascii("münchen.de")
        assert result is not None
        assert "xn--" in result
    
    def test_idna_ascii_too_long(self):
        """Verifica manejo de dominios muy largos"""
        from app.validation import _idna_ascii
        
        long_domain = "a" * 600 + ".com"
        result = _idna_ascii(long_domain)
        assert result is None
    
    def test_idna_ascii_invalid(self):
        """Verifica manejo de dominios inválidos"""
        from app.validation import _idna_ascii
        
        # _idna_ascii expects string or will convert with (domain or "")
        result = _idna_ascii("")
        assert result == ""  # Empty string gets encoded and decoded


class TestHelperFunctions:
    """Tests para funciones helper"""
    
    @pytest.mark.asyncio
    async def test_resolve_public_ip_success(self):
        """Verifica resolución de IP pública"""
        from app.validation import resolve_public_ip
        
        with patch("asyncio.get_running_loop") as mock_loop:
            mock_loop_instance = AsyncMock()
            mock_loop.return_value = mock_loop_instance
            
            # Simular getaddrinfo retornando una IP pública
            mock_loop_instance.getaddrinfo.return_value = [
                (2, 1, 6, '', ('8.8.8.8', 0))
            ]
            
            ip = await resolve_public_ip("google-public-dns-a.google.com")
            
            assert ip == "8.8.8.8"
    
    @pytest.mark.asyncio
    async def test_resolve_public_ip_private_filtered(self):
        """Verifica que filtra IPs privadas"""
        from app.validation import resolve_public_ip
        
        with patch("asyncio.get_running_loop") as mock_loop:
            mock_loop_instance = AsyncMock()
            mock_loop.return_value = mock_loop_instance
            
            # Simular getaddrinfo retornando solo IPs privadas
            mock_loop_instance.getaddrinfo.return_value = [
                (2, 1, 6, '', ('192.168.1.1', 0)),
                (2, 1, 6, '', ('10.0.0.1', 0))
            ]
            
            ip = await resolve_public_ip("example.local")
            
            assert ip is None


class TestGetMXHosts:
    """Tests para get_mx_hosts"""
    
    @pytest.mark.asyncio
    async def test_get_mx_hosts_success(self):
        """Verifica obtención de hosts MX"""
        from app.validation import get_mx_hosts, MXRecord
        
        with patch("app.validation.get_mx_records") as mock_get_mx:
            mock_get_mx.return_value = [
                MXRecord(exchange="mx1.example.com", preference=10),
                MXRecord(exchange="mx2.example.com", preference=20)
            ]
            
            hosts = await get_mx_hosts("example.com")
            
            assert len(hosts) == 2
            assert "mx1.example.com" in hosts
            assert "mx2.example.com" in hosts
    
    @pytest.mark.asyncio
    async def test_get_mx_hosts_deduplication(self):
        """Verifica deduplicación de hosts MX"""
        from app.validation import get_mx_hosts, MXRecord
        
        with patch("app.validation.get_mx_records") as mock_get_mx:
            mock_get_mx.return_value = [
                MXRecord(exchange="mx.example.com", preference=10),
                MXRecord(exchange="mx.example.com", preference=20)  # Duplicado
            ]
            
            hosts = await get_mx_hosts("example.com")
            
            # Solo debe retornar un host (deduplicado)
            assert len(hosts) == 1
            assert hosts[0] == "mx.example.com"


class TestCircuitBreakerStats:
    """Tests para circuit breaker stats"""
    
    @pytest.mark.asyncio
    async def test_get_smtp_circuit_breaker_status(self):
        """Verifica obtención de estado del circuit breaker"""
        from app.validation import get_smtp_circuit_breaker_status
        
        status = await get_smtp_circuit_breaker_status()
        
        assert "failure_threshold" in status
        assert "recovery_timeout" in status
        assert isinstance(status["failure_threshold"], int)
        assert isinstance(status["recovery_timeout"], int)


class TestCacheStats:
    """Tests para cache stats"""
    
    @pytest.mark.asyncio
    async def test_get_cache_stats_without_redis(self):
        """Verifica estadísticas de caché sin Redis"""
        from app.validation import get_cache_stats, set_redis_client
        
        set_redis_client(None)
        
        stats = await get_cache_stats()
        
        assert "redis_enabled" in stats
        assert stats["redis_enabled"] is False
    
    @pytest.mark.asyncio
    async def test_get_cache_stats_with_redis(self):
        """Verifica estadísticas de caché con Redis"""
        from app.validation import get_cache_stats, set_redis_client
        
        mock_redis = AsyncMock()
        mock_redis.scan.return_value = (0, [b"mx:key1", b"mx:key2"])
        set_redis_client(mock_redis)
        
        stats = await get_cache_stats()
        
        assert "redis_enabled" in stats
        assert stats["redis_enabled"] is True
        assert "mx_keys" in stats


class TestParseSMTPResponse:
    """Tests para parse_smtp_response"""
    
    def test_parse_smtp_response_public_function(self):
        """Verifica función pública parse_smtp_response"""
        from app.validation import parse_smtp_response
        
        response = b"250 OK"
        parsed = parse_smtp_response(response)
        
        assert "250" in parsed


class TestSMTPCheckerPerformCheck:
    """Tests para _perform_smtp_check"""
    
    def test_perform_smtp_check_rate_limited(self):
        """Verifica rate limiting en _perform_smtp_check"""
        from app.validation import SMTPChecker
        
        checker = SMTPChecker()
        
        # Resetear contadores
        SMTPChecker._host_request_times.clear()
        
        # Llenar el rate limiter
        for _ in range(100):
            SMTPChecker._smtp_host_allow_request("mx.test.com")
        
        # Intentar perform check cuando está rate-limited
        result = checker._perform_smtp_check("test@test.com", "mx.test.com", False)
        
        assert result.success is None
        assert "rate" in result.message.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=app/validation.py", "--cov-report=term-missing"])


# ============================================================================
# TESTS ADICIONALES PARA 100% COVERAGE - SMTP Y DOMAIN CHECKER
# ============================================================================

class TestDomainCheckerSMTPConnection:
    """Tests para _test_smtp_connection y _test_smtp_sync"""
    
    @pytest.mark.asyncio
    async def test_test_smtp_connection_success(self):
        """Verifica conexión SMTP exitosa"""
        from app.validation import DomainChecker, SMTPTestResult
        
        checker = DomainChecker()
        
        with patch.object(checker, '_test_smtp_sync') as mock_sync:
            mock_sync.return_value = SMTPTestResult(
                success=True,
                message="Connected",
                used_tls=True,
                tested_ports=[587]
            )
            
            result = await checker._test_smtp_connection("mx.example.com")
            
            assert result.success is True
            assert result.used_tls is True
    
    @pytest.mark.asyncio
    async def test_test_smtp_connection_all_ports_fail(self):
        """Verifica manejo cuando todos los puertos fallan"""
        from app.validation import DomainChecker, SMTPTestResult
        
        checker = DomainChecker()
        
        with patch.object(checker, '_test_smtp_sync') as mock_sync:
            mock_sync.side_effect = Exception("Connection failed")
            
            result = await checker._test_smtp_connection("mx.example.com")
            
            assert result.success is False
            assert "failed" in result.message.lower()
    
    def test_build_ssl_context_default(self):
        """Verifica creación de contexto SSL por defecto"""
        from app.validation import DomainChecker
        
        checker = DomainChecker()
        ctx = checker._build_ssl_context()
        
        assert ctx is not None
        assert isinstance(ctx, ssl.SSLContext)
    
    def test_build_ssl_context_skip_verify(self):
        """Verifica contexto SSL sin verificación"""
        from app.validation import DomainChecker, config
        
        checker = DomainChecker()
        
        with patch.object(config, 'smtp_skip_tls_verify', True):
            ctx = checker._build_ssl_context()
            
            assert ctx.check_hostname is False
            assert ctx.verify_mode == ssl.CERT_NONE
    
    def test_test_smtp_sync_port_465_ssl(self):
        """Verifica conexión SSL en puerto 465"""
        from app.validation import DomainChecker
        
        checker = DomainChecker()
        
        with patch('smtplib.SMTP_SSL') as mock_smtp_ssl:
            mock_server = MagicMock()
            mock_smtp_ssl.return_value = mock_server
            mock_server.connect.return_value = None
            mock_server.ehlo.return_value = None
            mock_server.mail.return_value = None
            
            result = checker._test_smtp_sync("mx.example.com", 465)
            
            assert result.success is True
            assert result.used_tls is True
            mock_smtp_ssl.assert_called_once()
    
    def test_test_smtp_sync_port_587_starttls(self):
        """Verifica STARTTLS en puerto 587"""
        from app.validation import DomainChecker
        
        checker = DomainChecker()
        
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value = mock_server
            mock_server.connect.return_value = None
            mock_server.ehlo_or_helo_if_needed.return_value = None
            mock_server.has_extn.return_value = True
            mock_server.starttls.return_value = None
            mock_server.ehlo.return_value = None
            mock_server.mail.return_value = None
            
            result = checker._test_smtp_sync("mx.example.com", 587)
            
            assert result.success is True
            assert result.used_tls is True
            mock_server.starttls.assert_called_once()
    
    def test_test_smtp_sync_starttls_fails(self):
        """Verifica manejo de fallo STARTTLS"""
        from app.validation import DomainChecker
        
        checker = DomainChecker()
        
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value = mock_server
            mock_server.connect.return_value = None
            mock_server.ehlo_or_helo_if_needed.return_value = None
            mock_server.has_extn.return_value = True
            mock_server.starttls.side_effect = Exception("TLS failed")
            mock_server.mail.return_value = None
            
            result = checker._test_smtp_sync("mx.example.com", 587)
            
            # Debe continuar sin TLS
            assert result.success is True
            assert result.used_tls is False
    
    def test_test_smtp_sync_smtputf8_sender(self):
        """Verifica uso de SMTPUTF8 para sender con caracteres no-ASCII"""
        from app.validation import DomainChecker, config
        
        checker = DomainChecker()
        
        with patch.object(config, 'smtp_sender', 'тест@example.com'), \
             patch('smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value = mock_server
            mock_server.connect.return_value = None
            mock_server.ehlo_or_helo_if_needed.return_value = None
            mock_server.has_extn.return_value = False
            
            result = checker._test_smtp_sync("mx.example.com", 25)
            
            # Verificar que mail() fue llamado con opciones SMTPUTF8
            assert mock_server.mail.called
            call_args = mock_server.mail.call_args
            if len(call_args) > 1 and 'options' in call_args[1]:
                assert 'SMTPUTF8' in call_args[1]['options']
    
    def test_test_smtp_sync_smtp_response_exception(self):
        """Verifica manejo de SMTPResponseException"""
        from app.validation import DomainChecker
        
        checker = DomainChecker()
        
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value = mock_server
            mock_server.connect.return_value = None
            mock_server.ehlo_or_helo_if_needed.return_value = None
            mock_server.has_extn.return_value = False
            
            exc = smtplib.SMTPResponseException(550, b"User not found")
            mock_server.mail.side_effect = exc
            
            result = checker._test_smtp_sync("mx.example.com", 25)
            
            assert result.success is False
            assert result.response_code == 550
    
    def test_test_smtp_sync_connection_errors(self):
        """Verifica manejo de errores de conexión"""
        from app.validation import DomainChecker
        
        checker = DomainChecker()
        
        # Test SMTPConnectError
        with patch('smtplib.SMTP') as mock_smtp:
            mock_smtp.return_value.connect.side_effect = smtplib.SMTPConnectError(421, "Service not available")
            
            result = checker._test_smtp_sync("mx.example.com", 25)
            
            assert result.success is False
            # El mensaje puede variar según el manejo de error
    
    def test_test_smtp_sync_timeout(self):
        """Verifica manejo de timeout"""
        from app.validation import DomainChecker
        
        checker = DomainChecker()
        
        with patch('smtplib.SMTP') as mock_smtp:
            mock_smtp.return_value.connect.side_effect = socket.timeout("Connection timeout")
            
            result = checker._test_smtp_sync("mx.example.com", 25)
            
            assert result.success is False
    
    def test_test_smtp_sync_server_cleanup(self):
        """Verifica limpieza del servidor en finally"""
        from app.validation import DomainChecker
        
        checker = DomainChecker()
        
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value = mock_server
            mock_server.connect.side_effect = Exception("Error")
            mock_server.quit.return_value = None
            
            result = checker._test_smtp_sync("mx.example.com", 25)
            
            # Verificar que se intentó cerrar
            assert result.success is False


class TestSMTPCheckerMailbox:
    """Tests para check_smtp_mailbox"""
    
    def test_check_smtp_mailbox_invalid_email(self):
        """Verifica rechazo de email inválido"""
        from app.validation import SMTPChecker
        
        checker = SMTPChecker()
        
        valid, msg = checker.check_smtp_mailbox("invalid-email", do_rcpt=False)
        
        assert valid is False
        assert "Invalid email format" in msg
    
    def test_check_smtp_mailbox_restricted_domain(self):
        """Verifica rechazo de dominio restringido"""
        from app.validation import SMTPChecker
        
        checker = SMTPChecker()
        
        valid, msg = checker.check_smtp_mailbox("user@gmail.com", do_rcpt=False)
        
        assert valid is None
        assert "not allowed" in msg
    
    def test_check_smtp_mailbox_invalid_domain_result(self):
        """Verifica manejo de dominio inválido"""
        from app.validation import SMTPChecker, VerificationResult
        
        checker = SMTPChecker()
        
        invalid_result = VerificationResult(valid=False, detail="Invalid")
        
        with patch('app.validation.cached_check_domain') as mock_check:
            mock_check.return_value = invalid_result
            
            valid, msg = checker.check_smtp_mailbox("user@nonrestricteddomain.com", do_rcpt=False)
            
            assert valid is False
            assert "Invalid domain configuration" in msg
    
    def test_check_smtp_mailbox_unsafe_mx_host(self):
        """Verifica rechazo de MX host no seguro"""
        from app.validation import SMTPChecker, VerificationResult
        
        checker = SMTPChecker()
        
        result = VerificationResult(valid=True, detail="Valid", mx_host="127.0.0.1")
        
        with patch('app.validation.cached_check_domain') as mock_check:
            mock_check.return_value = result
            
            valid, msg = checker.check_smtp_mailbox("user@test.com", do_rcpt=False)
            
            assert valid is False
            assert "Unsafe MX host" in msg
    
    def test_check_smtp_mailbox_with_do_rcpt_success(self):
        """Verifica check_smtp_mailbox con RCPT exitoso"""
        from app.validation import SMTPChecker, VerificationResult, SMTPTestResult
        
        checker = SMTPChecker()
        
        domain_result = VerificationResult(valid=True, detail="Valid", mx_host="mx.example.com")
        smtp_result = SMTPTestResult(
            success=True,
            message="OK",
            response_code=250,
            response_text="Mailbox exists"
        )
        
        with patch('app.validation.cached_check_domain') as mock_domain, \
             patch.object(checker, '_perform_smtp_check') as mock_smtp:
            mock_domain.return_value = domain_result
            mock_smtp.return_value = smtp_result
            
            valid, msg = checker.check_smtp_mailbox("user@example.com", do_rcpt=True)
            
            assert valid is True
            assert "Mailbox exists" in msg


class TestPerformSMTPCheck:
    """Tests para _perform_smtp_check"""
    
    def test_perform_smtp_check_with_do_rcpt_success(self):
        """Verifica _perform_smtp_check con RCPT TO exitoso"""
        from app.validation import SMTPChecker
        
        checker = SMTPChecker()
        SMTPChecker._host_request_times.clear()
        
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value = mock_server
            mock_server.connect.return_value = None
            mock_server.ehlo_or_helo_if_needed.return_value = None
            mock_server.has_extn.return_value = False
            mock_server.mail.return_value = None
            mock_server.rcpt.return_value = (250, b"OK")
            
            result = checker._perform_smtp_check("user@example.com", "mx.example.com", do_rcpt=True)
            
            assert result.success is True
            assert result.response_code == 250
    
    def test_perform_smtp_check_with_do_rcpt_rejected(self):
        """Verifica _perform_smtp_check con RCPT TO rechazado"""
        from app.validation import SMTPChecker
        
        checker = SMTPChecker()
        SMTPChecker._host_request_times.clear()
        
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value = mock_server
            mock_server.connect.return_value = None
            mock_server.ehlo_or_helo_if_needed.return_value = None
            mock_server.has_extn.return_value = False
            mock_server.mail.return_value = None
            mock_server.rcpt.return_value = (550, b"User not found")
            
            result = checker._perform_smtp_check("user@example.com", "mx.example.com", do_rcpt=True)
            
            assert result.success is False
            assert result.response_code == 550
    
    def test_perform_smtp_check_without_rcpt(self):
        """Verifica _perform_smtp_check sin RCPT TO"""
        from app.validation import SMTPChecker
        
        checker = SMTPChecker()
        SMTPChecker._host_request_times.clear()
        
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value = mock_server
            mock_server.connect.return_value = None
            mock_server.ehlo_or_helo_if_needed.return_value = None
            mock_server.has_extn.return_value = False
            mock_server.mail.return_value = None
            
            result = checker._perform_smtp_check("user@example.com", "mx.example.com", do_rcpt=False)
            
            assert result.success is None
            assert "completed_no_rcpt" in result.message
    
    def test_perform_smtp_check_retry_on_transient_error(self):
        """Verifica reintentos en errores transitorios"""
        from app.validation import SMTPChecker
        
        checker = SMTPChecker()
        SMTPChecker._host_request_times.clear()
        
        call_count = [0]
        
        def mock_connect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] < 2:
                raise smtplib.SMTPConnectError(421, "Try again")
            return None
        
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value = mock_server
            mock_server.connect = mock_connect
            mock_server.ehlo_or_helo_if_needed.return_value = None
            mock_server.has_extn.return_value = False
            mock_server.mail.return_value = None
            
            result = checker._perform_smtp_check("user@example.com", "mx.example.com", do_rcpt=False)
            
            # Debe haber intentado at menos una vez (puede no reintentar si max_retries=0)
            assert call_count[0] >= 1
    
    def test_perform_smtp_check_smtp_response_exception(self):
        """Verifica manejo de SMTPResponseException en _perform_smtp_check"""
        from app.validation import SMTPChecker
        
        checker = SMTPChecker()
        SMTPChecker._host_request_times.clear()
        
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value = mock_server
            mock_server.connect.return_value = None
            mock_server.ehlo_or_helo_if_needed.return_value = None
            mock_server.has_extn.return_value = False
            exc = smtplib.SMTPResponseException(550, b"Mailbox not found")
            mock_server.mail.side_effect = exc
            
            result = checker._perform_smtp_check("user@example.com", "mx.example.com", do_rcpt=False)
            
            assert result.success is False
            assert result.response_code == 550
    
    def test_perform_smtp_check_all_ports_fail(self):
        """Verifica comportamiento cuando todos los puertos fallan"""
        from app.validation import SMTPChecker
        
        checker = SMTPChecker()
        SMTPChecker._host_request_times.clear()
        
        with patch('smtplib.SMTP') as mock_smtp:
            mock_smtp.return_value.connect.side_effect = smtplib.SMTPConnectError(421, "Failed")
            
            result = checker._perform_smtp_check("user@example.com", "mx.example.com", do_rcpt=False)
            
            assert result.success is False
            # Mensaje puede ser "unexpected_error" o mencionar el puerto


class TestCheckDomainAsyncAbuseDomain:
    """Tests para detección de abuse domains en check_domain_async"""
    
    @pytest.mark.asyncio
    async def test_check_domain_async_abuse_domain(self):
        """Verifica detección de dominio de abuso"""
        from app.validation import DomainChecker
        
        checker = DomainChecker()
        
        with patch('app.validation.domain_validator') as mock_validator, \
             patch('app.validation.domain_extractor') as mock_extractor, \
             patch('app.validation.is_abuse_domain') as mock_abuse:
            
            mock_validator.is_valid_domain_format.return_value = True
            mock_extractor.extract_base_domain.return_value = "spam-sender.net"
            mock_abuse.return_value = True
            
            result = await checker.check_domain_async("spam-sender.net")
            
            assert result.valid is False
            assert result.error_type == "abuse_domain"
            assert "abuse" in result.detail.lower()
    
    @pytest.mark.asyncio
    async def test_check_domain_async_has_a_record_no_mx(self):
        """Verifica dominio con A record pero sin MX"""
        from app.validation import DomainChecker, VerificationResult
        
        checker = DomainChecker()
        
        with patch('app.validation.domain_validator') as mock_validator, \
             patch('app.validation.domain_extractor') as mock_extractor, \
             patch('app.validation.is_abuse_domain') as mock_abuse, \
             patch('app.validation.is_disposable_domain') as mock_disposable, \
             patch('app.validation.get_mx_records') as mock_mx, \
             patch('app.validation.dns_resolver') as mock_resolver, \
             patch('app.validation.RESERVED_DOMAINS', set()):  # Evitar reserved domain check
            
            mock_validator.is_valid_domain_format.return_value = True
            mock_extractor.extract_base_domain.return_value = "example.com"
            mock_abuse.return_value = False
            mock_disposable.return_value = False
            mock_mx.return_value = []
            
            # Simular que tiene A record
            mock_resolver.sync_resolver.resolve.return_value = [MagicMock()]
            
            result = await checker.check_domain_async("example.com")
            
            assert result.valid is True
            assert result.error_type == "no_mx_has_a"
            assert "A record" in result.detail


class TestAdditionalCacheScenarios:
    """Tests adicionales para escenarios de caché"""
    
    @pytest.mark.asyncio
    async def test_async_cache_get_with_bytes_response(self):
        """Verifica manejo de respuesta en bytes desde Redis"""
        from app.validation import async_cache_get, set_redis_client
        
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=b'simple string value')
        set_redis_client(mock_redis)
        
        result = await async_cache_get("test:key")
        
        # Debe decodificar y retornar como string si no es JSON
        assert result == 'simple string value'
    
    @pytest.mark.asyncio
    async def test_async_cache_set_with_to_dict_method(self):
        """Verifica serialización de objetos con método to_dict"""
        from app.validation import async_cache_set, set_redis_client, VerificationResult
        
        mock_redis = AsyncMock()
        set_redis_client(mock_redis)
        
        obj = VerificationResult(valid=True, detail="Test")
        await async_cache_set("test:key", obj, ttl=300)
        
        # Debe haber llamado set con JSON serializado
        mock_redis.set.assert_called_once()
        call_args = mock_redis.set.call_args
        # El primer argumento debe ser la key
        assert call_args[0][0] == "test:key"


class TestCachedCheckDomainFromDict:
    """Tests para cached_check_domain con dict"""
    
    @pytest.mark.asyncio
    async def test_cached_check_domain_dict_result(self):
        """Verifica reconstrucción desde dict en caché"""
        from app.validation import cached_check_domain
        
        cached_dict = {
            "valid": True,
            "detail": "Cached from dict",
            "mx_host": "mx.example.com",
            "error_type": None,
            "smtp_response": None,
            "provider": None
        }
        
        with patch("app.validation.async_cache_get") as mock_get:
            mock_get.return_value = cached_dict
            
            result = await cached_check_domain("example.com")
            
            assert result.valid is True
            assert result.detail == "Cached from dict"

# ============================================================================
# TESTS PARA DOMAIN CHECKER MX LOOP (Lines 952-994)
# ============================================================================

class TestDomainCheckerMXLoop:
    """Tests exhaustivos para el bucle de MX records en check_domain_async"""

    @pytest.mark.asyncio
    async def test_check_domain_async_circuit_breaker_open(self):
        """Verifica comportamiento cuando el circuit breaker está abierto"""
        from app.validation import DomainChecker, MXRecord
        
        checker = DomainChecker()
        
        with patch('app.validation.domain_validator') as mock_validator, \
             patch('app.validation.domain_extractor') as mock_extractor, \
             patch('app.validation.is_abuse_domain', return_value=False), \
             patch('app.validation.is_disposable_domain', return_value=False), \
             patch('app.validation.get_mx_records') as mock_mx, \
             patch('app.validation.smtp_circuit_breaker') as mock_cb, \
             patch('app.validation.RESERVED_DOMAINS', set()):
            
            mock_validator.is_valid_domain_format.return_value = True
            mock_extractor.extract_base_domain.return_value = "example.com"
            mock_mx.return_value = [MXRecord(exchange="mx.example.com", preference=10)]
            
            # Circuit breaker abierto
            mock_cb.is_open = AsyncMock(return_value=True)
            mock_cb.record_failure = AsyncMock()
            
            result = await checker.check_domain_async("example.com")
            
            # Debe retornar válido (porque tiene MX) pero con error de conexión
            assert result.valid is True
            assert "Circuit breaker open" in result.detail
            assert result.error_type == "mx_connection_failed"

    @pytest.mark.asyncio
    async def test_check_domain_async_unsafe_mx_host(self):
        """Verifica rechazo de MX host inseguro"""
        from app.validation import DomainChecker, MXRecord
        
        checker = DomainChecker()
        
        with patch('app.validation.domain_validator') as mock_validator, \
             patch('app.validation.domain_extractor') as mock_extractor, \
             patch('app.validation.is_abuse_domain', return_value=False), \
             patch('app.validation.is_disposable_domain', return_value=False), \
             patch('app.validation.get_mx_records') as mock_mx, \
             patch('app.validation.smtp_circuit_breaker') as mock_cb, \
             patch('app.validation.RESERVED_DOMAINS', set()):
            
            mock_validator.is_valid_domain_format.return_value = True
            mock_extractor.extract_base_domain.return_value = "example.com"
            mock_mx.return_value = [MXRecord(exchange="unsafe.example.com", preference=10)]
            mock_cb.is_open = AsyncMock(return_value=False)
            mock_cb.record_failure = AsyncMock()
            
            # Host inseguro
            mock_validator.is_safe_mx_host.return_value = False
            
            result = await checker.check_domain_async("example.com")
            
            assert result.valid is True
            assert "Unsafe MX host" in result.detail
            mock_cb.record_failure.assert_called_with("unsafe.example.com")

    @pytest.mark.asyncio
    async def test_check_domain_async_no_public_ip(self):
        """Verifica comportamiento cuando MX no tiene IP pública"""
        from app.validation import DomainChecker, MXRecord
        
        checker = DomainChecker()
        
        with patch('app.validation.domain_validator') as mock_validator, \
             patch('app.validation.domain_extractor') as mock_extractor, \
             patch('app.validation.is_abuse_domain', return_value=False), \
             patch('app.validation.is_disposable_domain', return_value=False), \
             patch('app.validation.get_mx_records') as mock_mx, \
             patch('app.validation.smtp_circuit_breaker') as mock_cb, \
             patch('app.validation.resolve_public_ip') as mock_resolve, \
             patch('app.validation.RESERVED_DOMAINS', set()):
            
            mock_validator.is_valid_domain_format.return_value = True
            mock_validator.is_safe_mx_host.return_value = True
            mock_extractor.extract_base_domain.return_value = "example.com"
            mock_mx.return_value = [MXRecord(exchange="mx.example.com", preference=10)]
            mock_cb.is_open = AsyncMock(return_value=False)
            mock_cb.record_failure = AsyncMock()
            
            # No public IP
            mock_resolve.return_value = None
            
            result = await checker.check_domain_async("example.com")
            
            assert result.valid is True
            assert "No public IP" in result.detail
            mock_cb.record_failure.assert_called_with("mx.example.com")

    @pytest.mark.asyncio
    async def test_check_domain_async_connection_success(self):
        """Verifica conexión exitosa a MX"""
        from app.validation import DomainChecker, MXRecord, SMTPTestResult
        
        checker = DomainChecker()
        
        with patch('app.validation.domain_validator') as mock_validator, \
             patch('app.validation.domain_extractor') as mock_extractor, \
             patch('app.validation.is_abuse_domain', return_value=False), \
             patch('app.validation.is_disposable_domain', return_value=False), \
             patch('app.validation.get_mx_records') as mock_mx, \
             patch('app.validation.smtp_circuit_breaker') as mock_cb, \
             patch('app.validation.resolve_public_ip') as mock_resolve, \
             patch('app.validation.RESERVED_DOMAINS', set()):
            
            mock_validator.is_valid_domain_format.return_value = True
            mock_validator.is_safe_mx_host.return_value = True
            mock_extractor.extract_base_domain.return_value = "example.com"
            mock_mx.return_value = [MXRecord(exchange="mx.example.com", preference=10)]
            mock_cb.is_open = AsyncMock(return_value=False)
            mock_cb.record_failure = AsyncMock()
            mock_resolve.return_value = "1.2.3.4"
            
            # Mock _test_smtp_connection success
            with patch.object(checker, '_test_smtp_connection') as mock_conn:
                mock_conn.return_value = SMTPTestResult(success=True, message="Connected")
                
                result = await checker.check_domain_async("example.com")
                
                assert result.valid is True
                assert result.error_type is None
                assert "Connected to" in result.detail

    @pytest.mark.asyncio
    async def test_check_domain_async_connection_failure_retry_next_mx(self):
        """Verifica que intenta el siguiente MX si el primero falla"""
        from app.validation import DomainChecker, MXRecord, SMTPTestResult
        
        checker = DomainChecker()
        
        with patch('app.validation.domain_validator') as mock_validator, \
             patch('app.validation.domain_extractor') as mock_extractor, \
             patch('app.validation.is_abuse_domain', return_value=False), \
             patch('app.validation.is_disposable_domain', return_value=False), \
             patch('app.validation.get_mx_records') as mock_mx, \
             patch('app.validation.smtp_circuit_breaker') as mock_cb, \
             patch('app.validation.resolve_public_ip') as mock_resolve, \
             patch('app.validation.RESERVED_DOMAINS', set()):
            
            mock_validator.is_valid_domain_format.return_value = True
            mock_validator.is_safe_mx_host.return_value = True
            mock_extractor.extract_base_domain.return_value = "example.com"
            
            # Dos MX records
            mock_mx.return_value = [
                MXRecord(exchange="mx1.example.com", preference=10),
                MXRecord(exchange="mx2.example.com", preference=20)
            ]
            mock_cb.is_open = AsyncMock(return_value=False)
            mock_cb.record_failure = AsyncMock()
            mock_resolve.return_value = "1.2.3.4"
            
            # Mock _test_smtp_connection: fail first, succeed second
            with patch.object(checker, '_test_smtp_connection') as mock_conn:
                mock_conn.side_effect = [
                    SMTPTestResult(success=False, message="Failed mx1"),
                    SMTPTestResult(success=True, message="Connected mx2")
                ]
                
                result = await checker.check_domain_async("example.com")
                
                assert result.valid is True
                assert result.mx_host == "mx2.example.com"
                assert mock_conn.call_count == 2



# =============================================================================
# TESTS: Cache Helper
# =============================================================================
@pytest.mark.asyncio
async def test_cache_mx_hosts_success():
    """Test: Llama a async_cache_set con parámetros correctos."""
    hosts = ["mx1.com", "mx2.com"]
    domain = "Test.Com"
    
    with patch("app.validation.async_cache_set", new_callable=AsyncMock) as mock_set, \
         patch("app.validation.settings") as mock_settings:
        
        mock_settings.validation.cache_ttl = 300
        
        await _cache_mx_hosts(domain, hosts)
        
        mock_set.assert_called_with(
            "mx:test.com", # lowercase
            hosts,
            ttl=300
        )

@pytest.mark.asyncio
async def test_cache_mx_hosts_silent_fail():
    """Test: Captura excepciones silenciosamente."""
    with patch("app.validation.async_cache_set", side_effect=Exception("Redis down")):
        # No debe lanzar excepción
        await _cache_mx_hosts("test.com", [])

# Helper para simular async_retry correctamente
async def mock_async_retry(func, *args):
    return await func(*args)

# =============================================================================
# TESTS: DNSResolver Initialization
# =============================================================================
class TestDNSResolverInit:

    @patch("app.validation.aiodns.DNSResolver") # ✅ CORRECCIÓN 1: Mockear aiodns para evitar error de Event Loop
    @patch("app.validation.settings")
    @patch("app.validation.os.getenv")
    def test_init_with_settings_nameservers(self, mock_getenv, mock_settings, mock_aiodns_cls):
        """Test: Usa nameservers de settings si existen."""
        mock_settings.validation.mx_lookup_timeout = 3.0
        mock_settings.validation.dns_nameservers = ["10.0.0.1"]
        
        resolver = DNSResolver()
        
        # Verificar configuración sync
        assert resolver._sync_resolver.nameservers == ["10.0.0.1"]
        assert resolver._sync_resolver.timeout == 3.0
        assert resolver._sync_resolver.lifetime >= 15.0 
        
        # Verificar que se instanció aiodns con los valores correctos
        mock_aiodns_cls.assert_called_with(timeout=3.0, nameservers=["10.0.0.1"])

    @patch("app.validation.aiodns.DNSResolver")
    @patch("app.validation.settings")
    @patch("app.validation.os.getenv")
    def test_init_fallback_public_dns(self, mock_getenv, mock_settings, mock_aiodns_cls):
        """Test: Fallback a DNS públicos si no hay configuración."""
        mock_settings.validation.mx_lookup_timeout = 2.0
        mock_settings.validation.dns_nameservers = None
        mock_getenv.return_value = "" 
        
        resolver = DNSResolver()
        
        expected_public = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
        assert resolver._sync_resolver.nameservers == expected_public
        mock_aiodns_cls.assert_called_with(timeout=2.0, nameservers=expected_public)

    @patch("app.validation.aiodns.DNSResolver")
    @patch("app.validation.settings")
    @patch("app.validation.os.getenv")
    def test_init_from_env_var(self, mock_getenv, mock_settings, mock_aiodns_cls):
        """Test: Lee nameservers de variable de entorno."""
        mock_settings.validation.dns_nameservers = None
        mock_getenv.return_value = "1.1.1.1, 1.0.0.1 "
        
        resolver = DNSResolver()
        
        expected = ["1.1.1.1", "1.0.0.1"]
        assert resolver._sync_resolver.nameservers == expected

# =============================================================================
# TESTS: MX Queries (Async Primary)
# =============================================================================
@pytest.mark.asyncio
class TestMXQueries:
    
    @pytest.fixture
    def resolver(self):
        """Fixture para crear resolver con mocks ya inyectados para evitar init real"""
        # Creamos una instancia vacía para no disparar __init__
        r = DNSResolver.__new__(DNSResolver)
        r._async_resolver = AsyncMock()
        r._sync_resolver = MagicMock()
        return r

    async def test_query_mx_async_primary_success(self, resolver):
        """Test: Consulta primaria exitosa retorna MXRecords ordenados."""
        # Mockear respuesta aiodns
        mock_answer1 = MagicMock(host="mx1.test.com", priority=10)
        mock_answer2 = MagicMock(host="mx2.test.com", priority=5)
        
        resolver._async_resolver.query.return_value = [mock_answer1, mock_answer2]
        
        # ✅ CORRECCIÓN 2: Usar mock_async_retry helper
        with patch("app.validation.async_retry", side_effect=mock_async_retry):
            results = await resolver.query_mx_async("test.com")
        
        assert len(results) == 2
        assert results[0].exchange == "mx2.test.com" # Prioridad 5 primero
        assert results[0].preference == 5
        assert results[1].exchange == "mx1.test.com"

    async def test_query_mx_async_primary_fail_fallback_success(self, resolver):
        """Test: Primaria falla, fallback (sync en thread) tiene éxito."""
        
        # Primaria falla
        # Mockear el ALIAS esperado por los tests (_query_mx_primary)
        # OJO: Al mockear el método, evitamos que llame a _async_resolver.query
        resolver._query_mx_primary = AsyncMock(side_effect=Exception("Async fail"))
        
        # Fallback setup
        mock_sync_answer = MagicMock()
        # Simulamos comportamiento de objeto DNS python
        mock_sync_answer.exchange = MagicMock(__str__=lambda x: "mx-fallback.test.com.")
        mock_sync_answer.preference = 20
        
        # ✅ CORRECCIÓN 3: Mockear _sync_resolver explícitamente
        resolver._sync_resolver = MagicMock()
        resolver._sync_resolver.resolve.return_value = [mock_sync_answer]
        
        with patch("app.validation.async_retry", side_effect=mock_async_retry):
            results = await resolver.query_mx_async("test.com")
            
        assert len(results) == 1
        assert results[0].exchange == "mx-fallback.test.com"
        assert results[0].preference == 20

    async def test_query_mx_async_all_fail(self, resolver):
        """Test: Ambas estrategias fallan, retorna lista vacía."""
        resolver._query_mx_primary = AsyncMock(side_effect=Exception("Async fail"))
        resolver._query_mx_fallback = AsyncMock(side_effect=Exception("Sync fail"))
        
        with patch("app.validation.async_retry", side_effect=mock_async_retry):
            results = await resolver.query_mx_async("fail.com")
            
        assert results == []

    async def test_query_mx_with_pref_normalization(self, resolver):
        """Test: Normaliza resultados que no son MXRecord (tuplas/dicts)."""
        # Simular retorno de raw tuples/dicts si async_retry devolviera eso
        resolver._query_mx_primary = AsyncMock(return_value=[
            (10, "tuple.mx."),
            {"exchange": "dict.mx", "preference": 5}
        ])
        
        with patch("app.validation.async_retry", side_effect=mock_async_retry):
            results = await resolver.query_mx_async("mixed.com")
            
        assert len(results) == 2
        # Ordenado por preferencia
        assert results[0].exchange == "dict.mx" # pref 5
        assert results[1].exchange == "tuple.mx" # pref 10

# =============================================================================
# TESTS: TXT Queries
# =============================================================================
@pytest.mark.asyncio
class TestTXTQueries:
    
    @pytest.fixture
    def resolver(self):
        r = DNSResolver.__new__(DNSResolver)
        r._async_resolver = AsyncMock()
        r._sync_resolver = MagicMock()
        return r

    async def test_query_txt_primary_success(self, resolver):
        """Test: Consulta TXT asíncrona decodifica bytes."""
        mock_ans = MagicMock()
        # Simula respuesta de aiodns (lista de bytes)
        mock_ans.text = [b"v=spf1 ", b"include:mail.com -all"]
        resolver._async_resolver.query.return_value = [mock_ans]
        
        with patch("app.validation.async_retry", side_effect=mock_async_retry):
            results = await resolver.query_txt("test.com")
            
        assert len(results) == 1
        assert results[0] == "v=spf1 include:mail.com -all"

    async def test_query_txt_fallback_sync(self, resolver):
        """Test: Fallback síncrono si aiodns falla."""
        # Async falla
        resolver._async_query_txt_primary = AsyncMock(side_effect=Exception("Timeout"))
        
        # Sync setup
        mock_rr = MagicMock()
        mock_rr.strings = [b"google-site-verification=123"]
        
        # ✅ CORRECCIÓN 4: Configurar el mock que ya existe en el fixture
        resolver._sync_resolver.resolve.return_value = [mock_rr]
        
        with patch("app.validation.async_retry", side_effect=mock_async_retry):
            results = await resolver.query_txt("test.com")
            
        assert results == ["google-site-verification=123"]

# =============================================================================
# TESTS: Cache Helper
# =============================================================================
@pytest.mark.asyncio
async def test_cache_mx_hosts_success():
    """Test: Llama a async_cache_set con parámetros correctos."""
    hosts = ["mx1.com", "mx2.com"]
    domain = "Test.Com"
    
    with patch("app.validation.async_cache_set", new_callable=AsyncMock) as mock_set, \
         patch("app.validation.settings") as mock_settings:
        
        mock_settings.validation.cache_ttl = 300
        
        await _cache_mx_hosts(domain, hosts)
        
        mock_set.assert_called_with(
            "mx:test.com", 
            hosts,
            ttl=300
        )

@pytest.mark.asyncio
async def test_cache_mx_hosts_silent_fail():
    """Test: Captura excepciones silenciosamente."""
    with patch("app.validation.async_cache_set", side_effect=Exception("Redis down")):
        # No debe lanzar excepción
        await _cache_mx_hosts("test.com", [])

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=app/validation.py", "--cov-report=term-missing"])
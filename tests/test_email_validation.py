# test_validation_providers_routes.py
"""
Suite completa de tests para validation.py, providers.py y validation_routes.py
Ejecutar con: pytest test_validation_providers_routes.py -v
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
        assert config.smtp_timeout == 5.0
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


# ============================================
# SMTP Circuit Breaker Tests (DEPRECATED)
# ============================================
# These tests have been commented out because SMTPCircuitBreaker has been replaced
# with pybreaker.CircuitBreaker for standardization. The new Circuit Breaker
# is tested via integration tests and doesn't need these dedicated unit tests.

# @pytest.mark.asyncio
# class TestSMTPCircuitBreaker:
#     """Tests para SMTPCircuitBreaker"""
#
#     async def test_circuit_breaker_records_failure(self):
#         """Verifica que se registran fallos"""
#         from app.validation import SMTPCircuitBreaker
#
#         cb = SMTPCircuitBreaker(failure_threshold=3, recovery_timeout=60)
#         await cb.record_failure("smtp.example.com")
#
#         count = await cb.get_failure_count("smtp.example.com")
#         assert count == 1
#
#     async def test_circuit_breaker_opens_after_threshold(self):
#         \"\"\"Verifica que el breaker se abre tras alcanzar el umbral\"\"\"
#         from app.validation import SMTPCircuitBreaker
#
#         cb = SMTPCircuitBreaker(failure_threshold=3, recovery_timeout=60)
#
#         for _ in range(3):
#             await cb.record_failure(\"smtp.example.com\")
#
#         is_open = await cb.is_open(\"smtp.example.com\")
#         assert is_open is True
#
#     async def test_circuit_breaker_below_threshold(self):
#         \"\"\"Verifica que el breaker permanece cerrado bajo el umbral\"\"\"
#         from app.validation import SMTPCircuitBreaker
#
#         cb = SMTPCircuitBreaker(failure_threshold=5, recovery_timeout=60)
#
#         for _ in range(3):
#             await cb.record_failure(\"smtp.example.com\")
#
#         is_open = await cb.is_open(\"smtp.example.com\")
#         assert is_open is False
#
#     async def test_circuit_breaker_cleans_old_failures(self):
#         \"\"\"Verifica que se limpian fallos antiguos\"\"\"
#         from app.validation import SMTPCircuitBreaker
#
#         cb = SMTPCircuitBreaker(failure_threshold=3, recovery_timeout=1)
#         await cb.record_failure(\"smtp.example.com\")
#         await asyncio.sleep(1.5)
#
#         count = await cb.get_failure_count(\"smtp.example.com\")
#         assert count == 0
#
#     async def test_circuit_breaker_multiple_hosts(self):
#         \"\"\"Verifica gestión independiente de múltiples hosts\"\"\"
#         from app.validation import SMTPCircuitBreaker
#
#         cb = SMTPCircuitBreaker(failure_threshold=2, recovery_timeout=60)
#
#         await cb.record_failure(\"smtp1.example.com\")
#         await cb.record_failure(\"smtp1.example.com\")
#         await cb.record_failure(\"smtp2.example.com\")
#
#         assert await cb.is_open(\"smtp1.example.com\") is True
#         assert await cb.is_open(\"smtp2.example.com\") is False
       

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


class TestCheckSPF:
    """Tests para check_spf"""
    
    @pytest.mark.asyncio
    async def test_check_spf_found(self):
        """Verifica detección de registro SPF"""
        from app.providers import check_spf
        from unittest.mock import MagicMock
        
        with patch("dns.resolver.resolve") as mock_resolve:
            # Mock response object
            mock_rdata = MagicMock()
            mock_rdata.strings = [b"v=spf1 include:_spf.google.com ~all"]
            mock_resolve.return_value = [mock_rdata]
            
            spf = await check_spf("example.com")
            
            assert "v=spf1" in spf
            assert "include:_spf.google.com" in spf
    
    @pytest.mark.asyncio
    async def test_check_spf_not_found(self):
        """Verifica respuesta cuando no hay SPF"""
        from app.providers import check_spf
        from unittest.mock import MagicMock

        with patch("dns.resolver.resolve") as mock_resolve:
            # Mock response with non-SPF record
            mock_rdata = MagicMock()
            mock_rdata.strings = [b"other record", b"not spf"]
            mock_resolve.return_value = [mock_rdata]
            
            spf_record = await check_spf("example.com")
            
            assert spf_record == "no-spf"
    
    @pytest.mark.asyncio
    async def test_check_spf_query_error(self):
        """Verifica manejo de errores de consulta"""
        from app.providers import check_spf
        
        with patch("dns.resolver.resolve") as mock_resolve:
            mock_resolve.side_effect = Exception("DNS error")
            
            spf_record = await check_spf("example.com")
            
            assert spf_record == "no-spf"


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
    
# TestTTLCache removed (consolidated into AsyncTTLCache)


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
# SMTP Circuit Breaker Tests (DEPRECATED)
# ============================================================================
# These tests are commented out because SMTPCircuitBreaker has been replaced
# with pybreaker.CircuitBreaker for standardization. The new Circuit Breaker
# is tested via integration tests and doesn't need dedicated unit tests.
#
# @pytest.mark.asyncio
# class TestSMTPCircuitBreaker:
#     async def test_circuit_breaker_records_failure(self):
#         from app.providers import SMTPCircuitBreaker
#         cb = SMTPCircuitBreaker()
#         host = "smtp.example.com"
#         await cb.record_failure(host)
#         assert host in cb._failures
#         assert cb._failures[host]["count"] == 1
#
#     async def test_circuit_breaker_opens_after_threshold(self):
#         from app.providers import SMTPCircuitBreaker, config
#         cb = SMTPCircuitBreaker()
#         host = "smtp.example.com"
#         threshold = config.smtp_failure_threshold
#         for _ in range(threshold):
#             await cb.record_failure(host)
#         assert await cb.is_open(host) is True
#
#     async def test_circuit_breaker_below_threshold(self):
#         from app.providers import SMTPCircuitBreaker, config
#         cb = SMTPCircuitBreaker()
#         host = "smtp.example.com"
#         threshold = config.smtp_failure_threshold
#         for _ in range(threshold - 1):
#             await cb.record_failure(host)
#         assert await cb.is_open(host) is False
#
#     async def test_circuit_breaker_cleans_old_failures(self):
#         from app.providers import SMTPCircuitBreaker, config
#         cb = SMTPCircuitBreaker()
#         host = "smtp.example.com"
#         config.smtp_failure_window = 1 # 1 second window
#         await cb.record_failure(host)
#         await asyncio.sleep(1.1) # Wait for window to pass
#         await cb.record_failure(host) # This should be the first failure in a new window
#         assert cb._failures[host]["count"] == 1
#
#     async def test_circuit_breaker_multiple_hosts(self):
#         from app.providers import SMTPCircuitBreaker, config
#         cb = SMTPCircuitBreaker()
#         host1 = "smtp1.example.com"
#         host2 = "smtp2.example.com"
#         threshold = config.smtp_failure_threshold
#
#         for _ in range(threshold):
#             await cb.record_failure(host1)
#
#         assert await cb.is_open(host1) is True
#         assert await cb.is_open(host2) is False # host2 should not be affected


# ============================================================================
# TESTS PARA providers.py
# ============================================================================

class TestProviderEnums:
    """Tests para enumeraciones de providers"""
    
    def test_dns_record_type_enum(self):
        """Verifica enumeración DNSRecordType"""
        from app.providers import DNSRecordType
        
        assert DNSRecordType.MX.value == "MX"
        assert DNSRecordType.TXT.value == "TXT"
        assert DNSRecordType.A.value == "A"


class TestProviderConfig:
    """Tests para ProviderConfig"""
    
    def test_provider_config_defaults(self):
        """Verifica valores por defecto"""
        from app.providers import ProviderConfig
        from unittest.mock import Mock
        
        # Mock settings to ensure defaults are used
        with patch.dict(os.environ, {}, clear=True), \
             patch("app.providers.settings") as mock_settings:
            
            # Configure mock to trigger defaults
            class EmptyConfig: pass
            empty = EmptyConfig()
            mock_settings.validation = empty
            mock_settings.email_validation = empty
            
            config = ProviderConfig()
            
            assert config.dns_timeout == 2.0
            assert config.mx_limit == 10
            assert config.prefer_ipv4 is True
            assert config.retry_attempts == 2
    
    def test_provider_config_from_environment(self):
        """Verifica carga desde variables de entorno"""
        from app.providers import ProviderConfig
        
        with patch.dict(os.environ, {
            "DNS_TIMEOUT": "5.0",
            "MX_LIMIT": "20",
            "RETRY_ATTEMPTS": "5"
        }):
            config = ProviderConfig()
            
            assert config.dns_timeout == 5.0
            assert config.mx_limit == 20
            assert config.retry_attempts == 5


class TestProviderCacheOperations:
    """Tests para operaciones de caché de providers"""
    
    @pytest.mark.asyncio
    async def test_async_cache_get_from_redis(self):
        """Verifica lectura desde Redis"""
        from app.providers import async_cache_get, set_redis_client
        
        mock_redis = AsyncMock()
        mock_redis.get.return_value = b'{"test": "value"}'
        set_redis_client(mock_redis)
        
        result = await async_cache_get("test:key")
        
        assert result == {"test": "value"}
    
    @pytest.mark.asyncio
    async def test_async_cache_set_to_redis(self):
        """Verifica escritura a Redis"""
        from app.providers import async_cache_set, set_redis_client
        
        mock_redis = AsyncMock()
        set_redis_client(mock_redis)
        
        await async_cache_set("test:key", {"data": "value"}, ttl=300)
        
        mock_redis.set.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_async_cache_clear_with_redis(self):
        """Verifica limpieza con Redis usando SCAN"""
        from app.providers import async_cache_clear, set_redis_client
        
        mock_redis = AsyncMock()
        
        # Mock scan to return (cursor, keys)
        mock_redis.scan.return_value = (0, [b"mx:key1", b"mx:key2"])
        
        set_redis_client(mock_redis)
        
        await async_cache_clear("mx:")
        
        # Verify delete was called with the keys returned by scan
        mock_redis.delete.assert_called()


class TestWHOISCircuitBreaker:
    """Tests para WHOISCircuitBreaker"""
    
    @pytest.mark.asyncio
    async def test_whois_circuit_breaker_not_blocked_initially(self):
        """Verifica que no está bloqueado inicialmente"""
        from app.providers import WHOISCircuitBreaker
        
        cb = WHOISCircuitBreaker()
        
        is_blocked = await cb.is_blocked("1.2.3.4")
        
        assert is_blocked is False
    
    @pytest.mark.asyncio
    async def test_whois_circuit_breaker_blocks_after_threshold(self):
        """Verifica bloqueo después del umbral"""
        from app.providers import WHOISCircuitBreaker, config
        
        cb = WHOISCircuitBreaker()
        threshold = config.whois_failure_threshold
        
        for _ in range(threshold):
            await cb.record_failure("1.2.3.4")
        
        is_blocked = await cb.is_blocked("1.2.3.4")
        
        assert is_blocked is True
    
    @pytest.mark.asyncio
    async def test_whois_circuit_breaker_recovers_after_timeout(self):
        """Verifica recuperación después del timeout"""
        from app.providers import WHOISCircuitBreaker
        
        cb = WHOISCircuitBreaker()
        
        # Forzar bloqueo
        for _ in range(10):
            await cb.record_failure("1.2.3.4")
        
        # Simular expiración modificando blocked_until
        cb.blocked_until["1.2.3.4"] = time.time() - 1
        
        is_blocked = await cb.is_blocked("1.2.3.4")
        
        assert is_blocked is False


class TestProviderDNSResolver:
    """Tests para DNSResolver de providers"""
    
    @pytest.mark.asyncio
    async def test_query_txt_success(self):
        """Verifica consulta TXT exitosa"""
        from app.validation import DNSResolver
        
        resolver = DNSResolver()
        
        with patch.object(resolver, "_async_query_txt_primary") as mock_primary:
            mock_primary.return_value = ["v=spf1 include:_spf.google.com ~all"]
            
            records = await resolver.query_txt("example.com")
            
            assert len(records) == 1
            assert "v=spf1" in records[0]
    
    @pytest.mark.asyncio
    async def test_query_txt_fallback(self):
        """Verifica fallback de consulta TXT"""
        from app.validation import DNSResolver
        
        resolver = DNSResolver()
        
        with patch.object(resolver, "_async_query_txt_primary") as mock_primary, \
             patch.object(resolver, "_async_query_txt_fallback") as mock_fallback:
            
            mock_primary.side_effect = Exception("Primary failed")
            mock_fallback.return_value = ["v=spf1 -all"]
            
            records = await resolver.query_txt("example.com")
            
            assert len(records) == 1
    
    @pytest.mark.asyncio
    async def test_query_mx_with_pref_success(self):
        """Verifica consulta MX con preferencia"""
        from app.validation import DNSResolver
        
        resolver = DNSResolver()
        
        with patch.object(resolver, "_async_query_mx_primary") as mock_primary:
            mock_primary.return_value = [(10, "mx1.example.com"), (20, "mx2.example.com")]
            
            records = await resolver.query_mx_with_pref("example.com")
            
            assert len(records) == 2
            assert records[0] == (10, "mx1.example.com")


class TestProviderHelpers:
    """Tests para funciones helper de providers"""
    
    def test_normalize_domain(self):
        """Verifica normalización de dominio"""
        from app.providers import normalize_domain
        
        assert normalize_domain("EXAMPLE.COM") == "example.com"
        assert normalize_domain("  example.com.  ") == "example.com"
        assert normalize_domain("ExAmPlE.CoM") == "example.com"
    
    def test_safe_base64_decode_valid(self):
        """Verifica decodificación base64 válida"""
        from app.providers import safe_base64_decode
        import base64
        
        encoded = base64.b64encode(b"test data").decode()
        decoded = safe_base64_decode(encoded)
        
        assert decoded == b"test data"
    
    def test_safe_base64_decode_invalid(self):
        """Verifica manejo de base64 inválido"""
        from app.providers import safe_base64_decode
        
        decoded = safe_base64_decode("invalid!@#$%")
        
        assert decoded is None
    
    def test_is_public_ip_public(self):
        """Verifica detección de IP pública"""
        from app.providers import _is_public_ip
        
        assert _is_public_ip("8.8.8.8") is True
        assert _is_public_ip("1.1.1.1") is True
    
    def test_is_public_ip_private(self):
        """Verifica detección de IP privada"""
        from app.providers import _is_public_ip
        
        assert _is_public_ip("192.168.1.1") is False
        assert _is_public_ip("10.0.0.1") is False
        assert _is_public_ip("127.0.0.1") is False
    
    def test_is_public_ip_invalid(self):
        """Verifica manejo de IP inválida"""
        from app.providers import _is_public_ip
        
        assert _is_public_ip("invalid") is False


class TestDKIMInfo:
    """Tests para DKIMInfo y funciones relacionadas"""
    
    def test_extract_dkim_parts_valid(self):
        """Verifica extracción de partes DKIM"""
        from app.providers import extract_dkim_parts
        
        dkim_record = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ..."
        
        info = extract_dkim_parts(dkim_record)
        
        assert info.status == "valid"
        assert info.key_type == "rsa"
        assert info.key_length is not None
    
    def test_extract_dkim_parts_empty(self):
        """Verifica manejo de registro vacío"""
        from app.providers import extract_dkim_parts
        
        info = extract_dkim_parts("")
        
        assert info.status == "not found"
        assert info.record == ""
    
    def test_extract_dkim_parts_no_public_key(self):
        """Verifica DKIM sin clave pública"""
        from app.providers import extract_dkim_parts
        
        dkim_record = "v=DKIM1; k=rsa"
        
        info = extract_dkim_parts(dkim_record)
        
        assert info.status == "not found"


class TestASNInfo:
    """Tests para ASNInfo"""
    
    def test_asn_info_creation(self):
        """Verifica creación de ASNInfo"""
        from app.providers import ASNInfo
        
        asn = ASNInfo(
            asn="AS15169",
            asn_description="Google LLC",
            network_name="GOOGLE"
        )
        
        assert asn.asn == "AS15169"
        assert asn.asn_description == "Google LLC"
        assert asn.network_name == "GOOGLE"
    
    def test_asn_info_from_dict(self):
        """Verifica creación desde diccionario"""
        from app.providers import ASNInfo
        
        data = {
            "asn": "AS8075",
            "asn_description": "Microsoft Corporation",
            "network_name": "MICROSOFT"
        }
        
        asn = ASNInfo.from_dict(data)
        
        assert asn.asn == "AS8075"
        assert asn.asn_description == "Microsoft Corporation"


class TestGetMXRecordsProvider:
    """Tests para get_mx_records de providers"""
    
    @pytest.mark.asyncio
    async def test_get_mx_records_with_cache(self):
        """Verifica uso de caché"""
        from app.validation import get_mx_records, MXRecord
        
        # get_mx_records is in app.validation, so patch app.validation.async_cache_get
        with patch("app.validation.async_cache_get") as mock_get:
            # Return MXRecord dicts (as the cache would store them)
            mock_get.return_value = [
                {"exchange": "mx1.example.com", "preference": 10},
                {"exchange": "mx2.example.com", "preference": 20}
            ]
            
            records = await get_mx_records("example.com")
            
            assert len(records) == 2
    
    @pytest.mark.asyncio
    async def test_get_mx_records_cache_miss(self):
        """Verifica consulta DNS en cache miss"""
        from app.validation import get_mx_records, MXRecord
        
        with patch("app.validation.async_cache_get") as mock_get, \
             patch("app.validation.async_cache_set") as mock_set, \
             patch("app.validation.dns_resolver") as mock_resolver:
            
            mock_get.return_value = None
            # Mock query_mx_async to return MXRecords
            mock_resolver.query_mx_async = AsyncMock(return_value=[
                MXRecord(exchange="mx1.example.com", preference=10),
                MXRecord(exchange="mx2.example.com", preference=20)
            ])
            
            records = await get_mx_records("example.com")
            
            assert len(records) == 2
            assert records[0].exchange == "mx1.example.com"


class TestResolveMXToIP:
    """Tests para resolve_mx_to_ip"""
    
    @pytest.mark.asyncio
    async def test_resolve_mx_to_ip_success(self):
        """Verifica resolución exitosa"""
        from app.providers import resolve_mx_to_ip
        
        with patch("app.providers.async_cache_get") as mock_get, \
             patch("asyncio.get_running_loop") as mock_loop:
            
            mock_get.return_value = None
            mock_event_loop = AsyncMock()
            mock_loop.return_value = mock_event_loop
            
            # Simular getaddrinfo
            mock_event_loop.getaddrinfo.return_value = [
                (2, 1, 6, '', ('1.2.3.4', 25))
            ]
            
            ip = await resolve_mx_to_ip("mx.example.com")
            
            assert ip == "1.2.3.4"
    
    @pytest.mark.asyncio
    async def test_resolve_mx_to_ip_cached(self):
        """Verifica uso de caché"""
        from app.providers import resolve_mx_to_ip
        
        with patch("app.providers.async_cache_get") as mock_get:
            mock_get.return_value = "1.2.3.4"
            
            ip = await resolve_mx_to_ip("mx.example.com")
            
            assert ip == "1.2.3.4"


class TestGetASNInfo:
    """Tests para get_asn_info"""
    
    @pytest.mark.asyncio
    async def test_get_asn_info_with_cache(self):
        """Verifica uso de caché"""
        from app.providers import get_asn_info, ASNInfo
        
        cached_data = {
            "asn": "AS15169",
            "asn_description": "Google",
            "network_name": "GOOGLE"
        }
        
        with patch("app.providers.async_cache_get") as mock_get:
            mock_get.return_value = cached_data
            
            asn = await get_asn_info("8.8.8.8")
            
            assert asn.asn == "AS15169"
    
    @pytest.mark.asyncio
    async def test_get_asn_info_blocked_by_breaker(self):
        """Verifica bloqueo por circuit breaker"""
        from app.providers import get_asn_info, WHOIS_CB
        
        with patch.object(WHOIS_CB, "is_blocked") as mock_blocked:
            mock_blocked.return_value = True
            
            asn = await get_asn_info("1.2.3.4")
            
            assert asn is None


class TestSPFChecks:
    """Tests para check_spf de providers"""
    
    @pytest.mark.asyncio
    async def test_check_spf_found(self):
        """Verifica detección de registro SPF"""
        from app.providers import check_spf
        
        # Mock dns.resolver.resolve
        with patch("dns.resolver.resolve") as mock_resolve:
            # Create a mock response object
            mock_answer = MagicMock()
            mock_answer.strings = [b"v=spf1 include:_spf.google.com ~all"]
            mock_resolve.return_value = [mock_answer]
            
            spf = await check_spf("example.com")
            
            assert "v=spf1" in spf
            assert "include:_spf.google.com" in spf
    
    @pytest.mark.asyncio
    async def test_check_spf_not_found(self):
        """Verifica respuesta sin SPF"""
        from app.providers import check_spf
        import dns.resolver
        
        with patch("dns.resolver.resolve") as mock_resolve:
            # Simulate no answer or empty answer
            mock_resolve.side_effect = dns.resolver.NoAnswer
            
            spf = await check_spf("example.com")
            
            assert spf == "no-spf"


class TestDKIMChecks:
    """Tests para check_dkim"""
    
    @pytest.mark.asyncio
    async def test_check_dkim_found(self):
        """Verifica detección de DKIM"""
        from app.providers import check_dkim
        
        with patch("dns.resolver.resolve") as mock_resolve:
            mock_answer = MagicMock()
            mock_answer.strings = [b"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ..."]
            mock_resolve.return_value = [mock_answer]
            
            dkim = await check_dkim("example.com")
            
            assert dkim.status == "valid"
    
    @pytest.mark.asyncio
    async def test_check_dkim_not_found(self):
        """Verifica respuesta sin DKIM"""
        from app.providers import check_dkim
        import dns.resolver
        
        with patch("dns.resolver.resolve") as mock_resolve:
            mock_resolve.side_effect = dns.resolver.NoAnswer
            
            dkim = await check_dkim("example.com")
            
            assert dkim.status == "not_found"


class TestDMARCChecks:
    """Tests para check_dmarc"""
    
    @pytest.mark.asyncio
    async def test_check_dmarc_found(self):
        """Verifica detección de DMARC"""
        from app.providers import check_dmarc
        
        with patch("dns.resolver.resolve") as mock_resolve:
            mock_answer = MagicMock()
            mock_answer.strings = [b"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
            mock_resolve.return_value = [mock_answer]
            
            dmarc = await check_dmarc("example.com")
            
            assert "v=DMARC1" in dmarc
    
    @pytest.mark.asyncio
    async def test_check_dmarc_not_found(self):
        """Verifica respuesta sin DMARC"""
        from app.providers import check_dmarc
        import dns.resolver
        
        with patch("dns.resolver.resolve") as mock_resolve:
            mock_resolve.side_effect = dns.resolver.NoAnswer
            
            dmarc = await check_dmarc("example.com")
            
            assert dmarc == "no-dmarc"


class TestProviderClassifier:
    """Tests para ProviderClassifier"""
    
    def test_provider_classifier_initialization(self):
        """Verifica inicialización"""
        from app.providers import ProviderClassifier
        
        classifier = ProviderClassifier()
        
        assert len(classifier.provider_patterns) > 0
        assert "gmail" in classifier.provider_patterns
    
    def test_classify_gmail_by_mx(self):
        """Verifica clasificación de Gmail por MX"""
        from app.providers import ProviderClassifier
        
        classifier = ProviderClassifier()
        
        provider = classifier.classify("aspmx.l.google.com", None)
        
        assert provider == "gmail"
    
    def test_classify_outlook_by_mx(self):
        """Verifica clasificación de Outlook por MX"""
        from app.providers import ProviderClassifier
        
        classifier = ProviderClassifier()
        
        provider = classifier.classify("mail.protection.outlook.com", None)
        
        assert provider == "outlook"
    
    def test_classify_by_asn_number(self):
        """Verifica clasificación por número ASN"""
        from app.providers import ProviderClassifier, ASNInfo
        
        classifier = ProviderClassifier()
        asn_info = ASNInfo(asn="AS15169", asn_description="", network_name="")
        
        provider = classifier.classify("unknown-mx.com", asn_info)
        
        assert provider == "gmail"
    
    def test_classify_unknown(self):
        """Verifica clasificación como desconocido"""
        from app.providers import ProviderClassifier
        
        classifier = ProviderClassifier()
        
        provider = classifier.classify("", None)
        
        assert provider == "unknown"


class TestReputation:
    """Tests para funciones de reputación"""
    
    def test_generate_fingerprint(self):
        """Verifica generación de fingerprint"""
        from app.providers import generate_fingerprint, ASNInfo, DKIMInfo
        
        asn = ASNInfo(asn="AS15169", asn_description="Google", network_name="GOOGLE")
        dkim = DKIMInfo(status="valid", record=None, selector="default", key_type="rsa", key_length=2048)
        
        fp = generate_fingerprint("mx.example.com", asn, "v=spf1 ~all", dkim, "v=DMARC1; p=none")
        
        assert isinstance(fp, str)
        assert len(fp) == 64  # SHA256 hex digest
    
    def test_calculate_initial_reputation_high(self):
        """Verifica cálculo de reputación alta"""
        from app.providers import calculate_initial_reputation, DKIMInfo
        
        dkim = DKIMInfo(status="valid", record=None, selector=None, key_type="rsa", key_length=4096)
        
        rep = calculate_initial_reputation("generic", "v=spf1 -all", dkim, "v=DMARC1; p=reject")
        
        assert rep > 0.7
    
    def test_calculate_initial_reputation_low(self):
        """Verifica cálculo de reputación baja"""
        from app.providers import calculate_initial_reputation, DKIMInfo
        
        dkim = DKIMInfo(status="missing", record=None, selector=None, key_type=None, key_length=None)
        
        rep = calculate_initial_reputation("", "no-spf", dkim, "no-dmarc")
        
        assert rep < 0.5
    
    @pytest.mark.asyncio
    async def test_update_reputation_success(self):
        """Verifica actualización de reputación con éxito"""
        from app.providers import update_reputation
        
        mock_redis = AsyncMock()
        
        with patch("app.providers.async_cache_get") as mock_get, \
             patch("app.providers.async_cache_set") as mock_set:
            
            mock_get.return_value = "0.5"
            
            await update_reputation(mock_redis, "test_fingerprint", success=True)
            
            # Verificar que se incrementó
            mock_set.assert_called_once()
            call_args = mock_set.call_args[0]
            new_rep = float(call_args[1])
            assert new_rep > 0.5
    
    @pytest.mark.asyncio
    async def test_update_reputation_failure(self):
        """Verifica actualización de reputación con fallo"""
        from app.providers import update_reputation
        
        mock_redis = AsyncMock()
        
        with patch("app.providers.async_cache_get") as mock_get, \
             patch("app.providers.async_cache_set") as mock_set:
            
            mock_get.return_value = "0.5"
            
            await update_reputation(mock_redis, "test_fingerprint", success=False)
            
            mock_set.assert_called_once()
            call_args = mock_set.call_args[0]
            new_rep = float(call_args[1])
            assert new_rep < 0.5


# ============================================================================
# TESTS PARA validation_routes.py
# ============================================================================

class TestValidationLimits:
    """Tests para ValidationLimits"""
    
    def test_validation_limits_constants(self):
        """Verifica constantes de límites"""
        from app.routes.validation_routes import ValidationLimits
        
        assert ValidationLimits.FREE_DAILY == 100
        assert ValidationLimits.PREMIUM_DAILY == 10_000
        assert ValidationLimits.ENTERPRISE_DAILY == 100_000
        assert ValidationLimits.BATCH_MAX_SIZE == 1000
        assert ValidationLimits.FILE_MAX_SIZE == 5 * 1024 * 1024


class TestEmailResponse:
    """Tests para EmailResponse"""
    
    def test_enhanced_email_response_creation(self):
        """Verifica creación de respuesta mejorada"""
        from app.routes.validation_routes import EmailResponse
        
        response = EmailResponse(
            email="test@example.com",
            valid=True,
            detail="Valid email",
            risk_score=0.2,
            quality_score=0.9,
            validation_tier="premium",
            suggested_action="accept"
        )
        
        assert response.email == "test@example.com"
        assert response.risk_score == 0.2
        assert response.quality_score == 0.9


class TestValidationService:
    """Tests para ValidationService"""
    
    @pytest.mark.asyncio
    async def test_check_rate_limits_allowed(self):
        """Verifica límites no excedidos"""
        from app.routes.validation_routes import ValidationService
        
        service = ValidationService()
        mock_redis = AsyncMock()
        mock_redis.get.return_value = b"50"
        
        result = await service.check_rate_limits(mock_redis, "user123", "PREMIUM", 10)
        
        assert result["allowed"] is True
        assert result["remaining"] >= 0
    
    @pytest.mark.asyncio
    async def test_check_rate_limits_exceeded(self):
        """Verifica límites excedidos"""
        from app.routes.validation_routes import ValidationService
        
        service = ValidationService()
        mock_redis = AsyncMock()
        mock_redis.get.return_value = b"99"
        
        result = await service.check_rate_limits(mock_redis, "user123", "FREE", 10)
        
        assert result["allowed"] is False
        assert result["remaining"] == 1
    
    @pytest.mark.asyncio
    async def test_get_redis_int_valid(self):
        """Verifica obtención de entero desde Redis"""
        from app.routes.validation_routes import ValidationService
        
        service = ValidationService()
        mock_redis = AsyncMock()
        mock_redis.get.return_value = b"42"
        
        value = await service._get_redis_int(mock_redis, "test:key")
        
        assert value == 42
    
    @pytest.mark.asyncio
    async def test_get_redis_int_none(self):
        """Verifica valor por defecto cuando Redis retorna None"""
        from app.routes.validation_routes import ValidationService
        
        service = ValidationService()
        mock_redis = AsyncMock()
        mock_redis.get.return_value = None
        
        value = await service._get_redis_int(mock_redis, "test:key", default=0)
        
        assert value == 0


class TestResponseBuilder:
    """Tests para ResponseBuilder"""
    
    @pytest.mark.asyncio
    async def test_build_validation_response_valid(self):
        """Verifica construcción de respuesta válida"""
        from app.routes.validation_routes import ResponseBuilder
        
        response = await ResponseBuilder.build_validation_response(
            email="test@example.com",
            start_time=time.time(),
            valid=True,
            detail="Email is valid",
            smtp_checked=True,
            mailbox_exists=True
        )
        
        content = json.loads(response.body.decode())
        
        assert content["valid"] is True
        assert content["email"] == "test@example.com"
        assert "processing_time" in content
        assert "risk_score" in content
    
    @pytest.mark.asyncio
    async def test_build_validation_response_invalid(self):
        """Verifica construcción de respuesta inválida"""
        from app.routes.validation_routes import ResponseBuilder
        
        response = await ResponseBuilder.build_validation_response(
            email="invalid@example.com",
            start_time=time.time(),
            valid=False,
            detail="Invalid domain",
            status_code=400,
            error_type="invalid_domain"
        )
        
        content = json.loads(response.body.decode())
        
        assert content["valid"] is False
        assert content["error_type"] == "invalid_domain"
        assert response.status_code == 400
    
    def test_calculate_risk_score_high_risk(self):
        """Verifica cálculo de alto riesgo"""
        from app.routes.validation_routes import ResponseBuilder
        
        score = ResponseBuilder.calculate_risk_score(
            valid=False,
            reputation=0.2,
            smtp_checked=True,
            mailbox_exists=False
        )
        
        assert score > 0.7
    
    def test_calculate_risk_score_low_risk(self):
        """Verifica cálculo de bajo riesgo"""
        from app.routes.validation_routes import ResponseBuilder
        
        score = ResponseBuilder.calculate_risk_score(
            valid=True,
            reputation=0.9,
            smtp_checked=True,
            mailbox_exists=True
        )
        
        assert score < 0.5
    
    def test_calculate_quality_score_high(self):
        """Verifica cálculo de alta calidad"""
        from app.routes.validation_routes import ResponseBuilder
        
        score = ResponseBuilder._calculate_quality_score(
            spf_status="valid",
            dkim_status="valid",
            dmarc_status="valid",
            reputation=0.8
        )
        
        assert score > 0.8
    
    def test_calculate_quality_score_low(self):
        """Verifica cálculo de baja calidad"""
        from app.routes.validation_routes import ResponseBuilder
        
        score = ResponseBuilder._calculate_quality_score(
            spf_status="invalid",
            dkim_status="invalid",
            dmarc_status="invalid",
            reputation=0.3
        )
        
        assert score < 0.5
    
    def test_get_validation_tier(self):
        """Verifica determinación de tier de validación"""
        from app.routes.validation_routes import ResponseBuilder
        
        assert ResponseBuilder._get_validation_tier(True, True) == "premium"
        assert ResponseBuilder._get_validation_tier(True, False) == "standard"
        assert ResponseBuilder._get_validation_tier(False, False) == "basic"
    
    def test_get_suggested_action(self):
        """Verifica sugerencia de acción"""
        from app.routes.validation_routes import ResponseBuilder
        
        assert ResponseBuilder._get_suggested_action(False, 0.8) == "reject"
        assert ResponseBuilder._get_suggested_action(True, 0.8) == "review"
        assert ResponseBuilder._get_suggested_action(True, 0.5) == "monitor"
        assert ResponseBuilder._get_suggested_action(True, 0.2) == "accept"


class TestEmailValidationEngine:
    """Tests para EmailValidationEngine"""
    
    @pytest.mark.asyncio
    async def test_validate_email_format_valid(self):
        """Verifica validación de formato válido"""
        from app.routes.validation_routes import EmailValidationEngine
        
        engine = EmailValidationEngine()
        
        with patch("app.routes.validation_routes.validate_email_lib") as mock_validate:
            mock_result = Mock()
            mock_result.normalized = "test@example.com"
            mock_validate.return_value = mock_result
            
            normalized = await engine._validate_email_format("test@example.com")
            
            assert normalized == "test@example.com"
    
    @pytest.mark.asyncio
    async def test_validate_email_format_invalid(self):
        """Verifica rechazo de formato inválido"""
        from app.routes.validation_routes import EmailValidationEngine
        from app.exceptions import APIException
        from email_validator import EmailNotValidError
        
        engine = EmailValidationEngine()
        
        with patch("app.routes.validation_routes.validate_email_lib") as mock_validate:
            mock_validate.side_effect = EmailNotValidError("Invalid")
            
            with pytest.raises(APIException) as exc_info:
                await engine._validate_email_format("invalid-email")
            
            assert exc_info.value.error_type == "invalid_format"
    
    @pytest.mark.asyncio
    async def test_validate_email_format_whitespace(self):
        """Verifica rechazo de espacios"""
        from app.routes.validation_routes import EmailValidationEngine
        from app.exceptions import APIException
        
        engine = EmailValidationEngine()
        
        with pytest.raises(APIException) as exc_info:
            await engine._validate_email_format("  test@example.com  ")
        
        assert exc_info.value.error_type == "invalid_format"
    
    @pytest.mark.asyncio
    async def test_validate_domain_success(self):
        """Verifica validación exitosa de dominio"""
        from app.routes.validation_routes import EmailValidationEngine, VerificationResult
        
        engine = EmailValidationEngine()
        
        with patch("app.routes.validation_routes.cached_check_domain") as mock_check, \
             patch("app.routes.validation_routes.is_disposable_domain") as mock_disposable:
            
            mock_check.return_value = VerificationResult(
                valid=True,
                detail="Valid domain",
                mx_host="mx.example.com"
            )
            mock_disposable.return_value = False
            
            result = await engine._validate_domain("test@example.com", AsyncMock())
            
            assert result.valid is True
    
    @pytest.mark.asyncio
    async def test_validate_domain_disposable(self):
        """Verifica rechazo de dominio desechable"""
        from app.routes.validation_routes import EmailValidationEngine, VerificationResult
        
        engine = EmailValidationEngine()
        
        with patch("app.routes.validation_routes.cached_check_domain") as mock_check, \
             patch("app.routes.validation_routes.is_disposable_domain") as mock_disposable:
            
            mock_check.return_value = VerificationResult(valid=True, detail="Valid")
            mock_disposable.return_value = True
            
            result = await engine._validate_domain("test@tempmail.com", AsyncMock())
            
            assert result.valid is False
            assert result.error_type == "disposable_domain"
    
    @pytest.mark.asyncio
    async def test_perform_smtp_validation_restricted_domain(self):
        """Verifica que salta SMTP para dominios restringidos"""
        from app.routes.validation_routes import EmailValidationEngine
        
        engine = EmailValidationEngine()
        
        result = await engine._perform_smtp_validation(
            "user@gmail.com",
            "mx.gmail.com",
            check_smtp=True,
            plan="PREMIUM",
            redis=AsyncMock()
        )
        
        assert result["checked"] is False
        assert "restricted" in result["skip_reason"].lower()
    
    @pytest.mark.asyncio
    async def test_perform_smtp_validation_free_plan(self):
        """Verifica que FREE plan no puede hacer SMTP"""
        from app.routes.validation_routes import EmailValidationEngine
        
        engine = EmailValidationEngine()
        
        result = await engine._perform_smtp_validation(
            "user@example.com",
            "mx.example.com",
            check_smtp=True,
            plan="FREE",
            redis=AsyncMock()
        )
        
        assert result["checked"] is False
        assert "not available in FREE" in result["skip_reason"]
    
class TestEmailValidationEngine:
    
    @pytest.mark.asyncio
    async def test_check_concurrency_limits_exceeded(self):  # ← AGREGAR self
        """Verifica límites de concurrencia excedidos"""
        from app.routes.validation_routes import EmailValidationEngine
        from app.exceptions import APIException
        
        engine = EmailValidationEngine()
        mock_redis = AsyncMock()
        
        # Simular: ya hay 5 validaciones activas (en el límite)
        mock_redis.get.return_value = b'5'  # 5 validaciones activas
        
        with patch('app.routes.validation_routes.get_settings') as mock_settings:
            mock_settings.return_value.plan_features = {
                "PREMIUM": {"concurrent": 5}
            }
            
            # El sexto intento debe fallar
            with pytest.raises(APIException) as excinfo:
                await engine.check_concurrency_limits(mock_redis, "user123", "PREMIUM")
            
            assert excinfo.value.error_type == "concurrent_limit_exceeded"
            # Verificar que NO incrementó
            mock_redis.incr.assert_not_called()

    @pytest.mark.asyncio
    async def test_check_concurrency_limits_allowed(self):  # ← AGREGAR self
        """Verifica que permite cuando está por debajo del límite"""
        from app.routes.validation_routes import EmailValidationEngine
        
        engine = EmailValidationEngine()
        mock_redis = AsyncMock()
        
        # Simular: hay 2 validaciones activas (por debajo del límite de 5)
        mock_redis.get.return_value = b'2'
        mock_redis.incr.return_value = 3  # Después de incrementar será 3
        
        with patch('app.routes.validation_routes.get_settings') as mock_settings:
            mock_settings.return_value.plan_features = {
                "PREMIUM": {"concurrent": 5}
            }
            
            # No debe lanzar excepción
            await engine.check_concurrency_limits(mock_redis, "user123", "PREMIUM")
            
            # Debe haber incrementado
            mock_redis.incr.assert_called_once_with("concurrent:user123")

    
    @pytest.mark.asyncio
    async def test_cleanup_concurrency_limits(self):
        """Verifica limpieza de límites de concurrencia"""
        from app.routes.validation_routes import EmailValidationEngine
        
        engine = EmailValidationEngine()
        mock_redis = AsyncMock()
        
        await engine._cleanup_concurrency_limits(mock_redis, "user123")
        
        mock_redis.decr.assert_called_once_with("concurrent:user123")


class TestFileValidationService:
    """Tests para FileValidationService"""
    
    @pytest.mark.asyncio
    async def test_process_uploaded_file_csv(self):
        """Verifica procesamiento de archivo CSV"""
        from app.routes.validation_routes import FileValidationService
        
        service = FileValidationService()
        
        csv_content = "email\ntest1@example.com\ntest2@example.com\n"
        file = UploadFile(
            filename="test.csv",
            file=BytesIO(csv_content.encode())
        )
        
        with patch.object(service, "_extract_from_file_on_disk") as mock_extract:
            mock_extract.return_value = ["test1@example.com", "test2@example.com"]
            
            emails = await service.process_uploaded_file(file)
            
            assert len(emails) == 2
    
    @pytest.mark.asyncio
    async def test_process_uploaded_file_invalid_extension(self):
        """Verifica rechazo de extensión inválida"""
        from app.routes.validation_routes import FileValidationService
        from app.exceptions import APIException
        
        service = FileValidationService()
        
        file = UploadFile(
            filename="test.pdf",
            file=BytesIO(b"content")
        )
        
        with pytest.raises(APIException) as exc_info:
            await service.process_uploaded_file(file)
        
        assert exc_info.value.error_type == "invalid_file_type"
    
    def test_extract_emails_from_content_csv(self):
        """Verifica extracción de emails desde CSV"""
        from app.routes.validation_routes import FileValidationService
        
        service = FileValidationService()
        
        csv_content = "name,email,age\nJohn,john@example.com,30\nJane,jane@example.com,25\n"
        
        emails = service._extract_emails_from_content(
            csv_content,
            file_type="csv",
            column="email",
            max_emails=100
        )
        
        assert len(emails) == 2
        assert "john@example.com" in emails
        assert "jane@example.com" in emails
    
    def test_extract_emails_from_content_txt(self):
        """Verifica extracción de emails desde texto"""
        from app.routes.validation_routes import FileValidationService
        
        service = FileValidationService()
        
        txt_content = "Contact us:\ntest1@example.com\ntest2@example.com\nInvalid line"
        
        emails = service._extract_emails_from_content(
            txt_content,
            file_type="txt",
            max_emails=100
        )
        
        assert len(emails) == 2
    
    def test_generate_csv_report(self):
        """Verifica generación de reporte CSV"""
        from app.routes.validation_routes import FileValidationService
        
        service = FileValidationService()
        
        results = [
            {
                "email": "test1@example.com",
                "valid": True,
                "detail": "Valid",
                "risk_score": 0.1,
                "quality_score": 0.9
            },
            {
                "email": "test2@example.com",
                "valid": False,
                "detail": "Invalid",
                "risk_score": 0.8,
                "quality_score": 0.2
            }
        ]
        
        csv_content = service.generate_csv_report(results)
        
        assert isinstance(csv_content, str)
        assert "test1@example.com" in csv_content
        assert "test2@example.com" in csv_content
    
    def test_calculate_risk_distribution(self):
        """Verifica cálculo de distribución de riesgo"""
        from app.routes.validation_routes import FileValidationService
        
        service = FileValidationService()
        
        results = [
            {"risk_score": 0.1},
            {"risk_score": 0.5},
            {"risk_score": 0.9}
        ]
        
        distribution = service._calculate_risk_distribution(results)
        
        assert "low" in distribution
        assert "medium" in distribution
        assert "high" in distribution
    
    def test_calculate_provider_breakdown(self):
        """Verifica cálculo de desglose por proveedor"""
        from app.routes.validation_routes import FileValidationService
        
        service = FileValidationService()
        
        results = [
            {"provider_analysis": {"provider": "gmail"}},
            {"provider_analysis": {"provider": "gmail"}},
            {"provider_analysis": {"provider": "outlook"}}
        ]
        
        breakdown = service._calculate_provider_breakdown(results)
        
        assert breakdown.get("gmail", 0) == 2
        assert breakdown.get("outlook", 0) == 1


import io
import anyio
import httpx
from fastapi import FastAPI, status
from app.exceptions import APIException

import app.routes.validation_routes as vr 

# --------- Dobles de prueba ---------

class FakePrincipal:
    def __init__(self, sub="user-1", plan="PREMIUM"):
        self.sub = sub
        self.plan = plan

class FakeRedis:
    def __init__(self):
        self.store = {}
        self.should_fail_ping = False
        self.should_fail_operations = False
        self._lock = asyncio.Lock()
        self.expirations = {}
        self._pipeline_commands = []

    # Método pipeline corregido
    def pipeline(self, transaction=True):
        """Devuelve una instancia de FakePipeline para simular pipeline de Redis."""
        return FakePipeline(self)

    async def incr(self, k):
        if self.should_fail_operations:
            raise RuntimeError("Redis operation failed")
        async with self._lock:
            current = int(self.store.get(k, 0))
            new_val = current + 1
            self.store[k] = str(new_val)
            return new_val

    async def decr(self, k):
        if self.should_fail_operations:
            raise RuntimeError("Redis operation failed")
        async with self._lock:
            current = int(self.store.get(k, 0))
            new_val = current - 1
            if new_val <= 0:
                if k in self.store:
                    del self.store[k]
                return 0
            self.store[k] = str(new_val)
            return new_val

    async def expire(self, k, ttl):
        async with self._lock:
            self.expirations[k] = time.time() + ttl
            return True

    async def delete(self, key):
        async with self._lock:
            if key in self.store:
                del self.store[key]
                return 1
            return 0

    async def ping(self):
        if self.should_fail_ping:
            raise RuntimeError("Redis not reachable")
        return True

    async def get(self, k):
        async with self._lock:
            return self.store.get(k)
            
    async def set(self, k, v, ex=None):
        async with self._lock:
            self.store[k] = v
            return True
            
    async def info(self, section=None):
        return {
            "used_memory_rss": 1024 * 1024,
            "total_system_memory": 16 * 1024 * 1024 * 1024,
            "used_memory": 512 * 1024,
            "used_memory_human": "512KB"
        }


class FakePipeline:
    """Clase auxiliar para simular pipeline de Redis."""
    
    def __init__(self, redis):
        self.redis = redis
        self.commands = []
        self.results = []
        
    def incr(self, key):
        self.commands.append(('incr', key))
        return self
        
    def expire(self, key, ttl):
        self.commands.append(('expire', key, ttl))
        return self
        
    async def execute(self):
        """Ejecuta todos los comandos en el pipeline."""
        results = []
        for cmd in self.commands:
            if cmd[0] == 'incr':
                result = await self.redis.incr(cmd[1])
                results.append(result)
            elif cmd[0] == 'expire':
                result = await self.redis.expire(cmd[1], cmd[2])
                results.append(result)
        self.commands.clear()
        return results
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if not exc_type:
            await self.execute()
        return False

@pytest.fixture
def test_app(monkeypatch):
    app = FastAPI()
    app.include_router(vr.router, prefix="")

    principal = FakePrincipal(sub="user-1", plan="PREMIUM")
    fake_redis = FakeRedis()

    async def _content_type_override(content_type: str = "application/json"):
        return "application/json"
    
    app.dependency_overrides[vr.validate_api_key_or_token] = lambda: principal
    app.dependency_overrides[vr.get_redis] = lambda: fake_redis
    app.dependency_overrides[vr.validate_content_type] = _content_type_override

    # Stubs deterministas para llamadas externas
    async def ok_cached_check_domain(domain: str):
        class VR:
            def __init__(self):
                self.valid = True
                self.detail = "ok"
                self.error_type = None
                self.mx_host = "mx.example.com"
        return VR()

    async def ok_is_disposable(domain: str, redis):
        return False

    async def ok_check_smtp_mailbox_safe(email: str, do_rcpt=True):
        await asyncio.sleep(0)
        return True, "250 OK"

    async def ok_analyze_email_provider(email: str, redis):
        return _ProviderAnalysisStub()

    monkeypatch.setattr(vr, "cached_check_domain", ok_cached_check_domain, raising=True)
    monkeypatch.setattr(vr, "is_disposable_domain", ok_is_disposable, raising=True)
    monkeypatch.setattr(vr, "check_smtp_mailbox_safe", ok_check_smtp_mailbox_safe, raising=True)
    monkeypatch.setattr(vr, "analyze_email_provider", ok_analyze_email_provider, raising=True)

    # Mock robusto para file_validation_service
    class MockFileValidationService:
        def __init__(self):
            self.process_call_count = 0
            
        async def process_uploaded_file(self, file, column=None):
            self.process_call_count += 1
            # Simular el procesamiento real de un archivo CSV
            content = await file.read()
            if hasattr(file, 'seek'):
                await file.seek(0)
                
            # Parsear CSV real del contenido
            import csv
            import io
            emails = []
            
            try:
                # Intentar como CSV
                content_str = content.decode('utf-8') if isinstance(content, bytes) else content
                csv_file = io.StringIO(content_str)
                reader = csv.DictReader(csv_file)
                
                if reader.fieldnames:
                    target_column = self._determine_target_column(reader.fieldnames, column)
                    for row in reader:
                        email = row.get(target_column, "").strip()
                        if email and self._is_valid_email(email):
                            emails.append(email.lower())
                
                # Si no se encontraron emails en CSV, intentar como texto plano
                if not emails:
                    for line in content_str.splitlines():
                        line = line.strip()
                        if line and self._is_valid_email(line):
                            emails.append(line.lower())
            except Exception:
                # Fallback: devolver emails de prueba
                emails = ["u1@example.com", "u2@example.com"]
            
            return emails[:5000]  # Respetar límites

        def _determine_target_column(self, fieldnames, specified_column):
            if specified_column and specified_column in fieldnames:
                return specified_column
            for common in ["email", "e-mail", "mail"]:
                if common in fieldnames:
                    return common
            return fieldnames[0] if fieldnames else "email"

        def _is_valid_email(self, email):
            import re
            pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            return bool(re.match(pattern, email))

        def generate_csv_report(self, results):
            return "email,valid\ntest@example.com,true\n"

        def _calculate_risk_distribution(self, results):
            return {"low": 0, "medium": 1, "high": 0}

        def _calculate_provider_breakdown(self, results):
            return {"generic": 1}

    # Reemplazar completamente el servicio de archivos
    mock_file_service = MockFileValidationService()
    monkeypatch.setattr(vr, "file_validation_service", mock_file_service)

    # Settings para tests
    class _S:
        testing_mode = True
        plan_features = {
            "FREE": {"batch_size": 10, "raw_dns": False, "concurrent": 1},
            "PREMIUM": {"batch_size": 100, "raw_dns": True, "concurrent": 5},
            "ENTERPRISE": {"batch_size": 1000, "raw_dns": True, "concurrent": 20},
        }
        BLOCKING_THREADPOOL_MAX_WORKERS = 4
    monkeypatch.setattr(vr, "get_settings", lambda: _S(), raising=True)

    return app, principal, fake_redis


# Dependencias para overrides
async def fake_get_redis():
    return FakeRedis()

def make_fake_auth(principal: FakePrincipal):
    async def _dep(*args, **kwargs):
        return principal
    return _dep

# Stubs de funciones externas llamadas por el engine
class _DNSAuthStub:
    def __init__(self, spf="v=spf1 ~all", dkim_status="valid", dmarc="v=DMARC1; p=none"):
        class DKIM:
            def __init__(self):
                self.status = dkim_status
                self.record = "v=DKIM1; k=rsa; p=AAA..."
                self.selector = "default"
                self.key_type = "rsa"
                self.key_length = 1024
        self.spf = spf
        self.dkim = DKIM()
        self.dmarc = dmarc

class _ProviderAnalysisStub:
    def __init__(self):
        self.provider = "generic"
        self.fingerprint = "fp-123"
        self.reputation = 0.7
        self.dns_auth = _DNSAuthStub()
        self.error = None

@pytest.fixture
def test_app(monkeypatch):
    # App con router real y overrides de dependencias
    app = FastAPI()
    app.include_router(vr.router, prefix="")

    # Overrides por defecto (plan PREMIUM)
    principal = FakePrincipal(sub="user-1", plan="PREMIUM")
    fake_redis = FakeRedis()

    # *** FIX PRINCIPAL ***
    async def _content_type_override(content_type: str = "application/json"):
        return "application/json"
    
    app.dependency_overrides[vr.validate_api_key_or_token] = lambda: principal
    app.dependency_overrides[vr.get_redis] = lambda: fake_redis
    app.dependency_overrides[vr.validate_content_type] = _content_type_override

    # Stubs deterministas para llamadas externas
    async def ok_cached_check_domain(domain: str):
        class VR:
            def __init__(self):
                self.valid = True
                self.detail = "ok"
                self.error_type = None
                self.mx_host = "mx.example.com"
        return VR()

    async def ok_is_disposable(domain: str, redis):
        return False

    async def ok_check_smtp_mailbox_safe(email: str, do_rcpt=True):
        await asyncio.sleep(0)
        return True, "250 OK"

    async def ok_analyze_email_provider(email: str, redis):
        return _ProviderAnalysisStub()

    monkeypatch.setattr(vr, "cached_check_domain", ok_cached_check_domain, raising=True)
    monkeypatch.setattr(vr, "is_disposable_domain", ok_is_disposable, raising=True)
    monkeypatch.setattr(vr, "check_smtp_mailbox_safe", ok_check_smtp_mailbox_safe, raising=True)
    monkeypatch.setattr(vr, "analyze_email_provider", ok_analyze_email_provider, raising=True)

    # Settings para tests (plan_features mínimos)
    class _S:
        testing_mode = True
        plan_features = {
            "FREE": {"batch_size": 10, "raw_dns": False, "concurrent": 1},
            "PREMIUM": {"batch_size": 100, "raw_dns": True, "concurrent": 5},
            "ENTERPRISE": {"batch_size": 1000, "raw_dns": True, "concurrent": 20},
        }
        BLOCKING_THREADPOOL_MAX_WORKERS = 4
    monkeypatch.setattr(vr, "get_settings", lambda: _S(), raising=True)

    return app, principal, fake_redis


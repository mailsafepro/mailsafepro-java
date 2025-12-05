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


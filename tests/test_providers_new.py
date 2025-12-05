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
        
        with patch.dict(os.environ, {}, clear=True), \
             patch("app.providers.settings") as mock_settings:
            # Mock settings to return defaults
            mock_settings.validation.dns_timeout = 2.0
            mock_settings.email_validation.mx_lookup_timeout = 2.0
            # Ensure attributes exist to avoid AttributeError
            mock_settings.validation.mx_limit = 10
            mock_settings.validation.prefer_ipv4 = True
            mock_settings.validation.max_retries = 3
            
            config = ProviderConfig()
            
            assert config.dns_timeout == 2.0
            assert config.mx_limit == 10
            assert config.prefer_ipv4 is True
            assert config.retry_attempts == 3
    
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
        
        # The set might be called with different argument patterns
        assert mock_redis.set.called or mock_redis.setex.called
    
    @pytest.mark.asyncio
    async def test_async_cache_clear_with_redis(self):
        """Verifica limpieza con Redis usando SCAN"""
        from app.providers import async_cache_clear, set_redis_client
        
        mock_redis = AsyncMock()
        
        # Mock scan to return (cursor, keys)
        mock_redis.scan.return_value = (0, [b"mx:key1", b"mx:key2"])
        
        set_redis_client(mock_redis)
        
        await async_cache_clear("mx:")
        
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
        
        with patch("dns.resolver.resolve") as mock_resolve:
            mock_rrset = MagicMock()
            mock_rrset.strings = [b"v=spf1 include:_spf.google.com ~all"]
            mock_resolve.return_value = [mock_rrset]
            
            spf = await check_spf("example.com")
            
            assert "v=spf1" in spf
            assert "include:_spf.google.com" in spf
    
    @pytest.mark.asyncio
    async def test_check_spf_not_found(self):
        """Verifica respuesta sin SPF"""
        from app.providers import check_spf
        
        with patch("dns.resolver.resolve", side_effect=Exception("No answer")):
            spf = await check_spf("example.com")
            
            assert spf == "no-spf"


class TestDKIMChecks:
    """Tests para check_dkim"""
    
    @pytest.mark.asyncio
    async def test_check_dkim_found(self):
        """Verifica detección de DKIM"""
        from app.providers import check_dkim
        
        with patch("dns.resolver.resolve") as mock_resolve:
            mock_rrset = MagicMock()
            mock_rrset.strings = [b"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ..."]
            mock_resolve.return_value = [mock_rrset]
            
            dkim = await check_dkim("example.com")
            
            assert dkim.status == "valid"
    
    @pytest.mark.asyncio
    async def test_check_dkim_not_found(self):
        """Verifica respuesta sin DKIM"""
        from app.providers import check_dkim
        
        with patch("dns.resolver.resolve", side_effect=Exception("NXDOMAIN")):
            dkim = await check_dkim("example.com")
            
            assert dkim.status == "not_found"


class TestDMARCChecks:
    """Tests para check_dmarc"""
    
    @pytest.mark.asyncio
    async def test_check_dmarc_found(self):
        """Verifica detección de DMARC"""
        from app.providers import check_dmarc
        
        with patch("dns.resolver.resolve") as mock_resolve:
            mock_rrset = MagicMock()
            mock_rrset.strings = [b"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
            mock_resolve.return_value = [mock_rrset]
            
            dmarc = await check_dmarc("example.com")
            
            assert "v=DMARC1" in dmarc
    
    @pytest.mark.asyncio
    async def test_check_dmarc_not_found(self):
        """Verifica respuesta sin DMARC"""
        from app.providers import check_dmarc
        
        with patch("dns.resolver.resolve", side_effect=Exception("NXDOMAIN")):
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



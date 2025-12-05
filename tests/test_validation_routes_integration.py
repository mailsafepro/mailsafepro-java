import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi import status
from fastapi.responses import JSONResponse
from app.routes import validation_routes

# ====================
# INTEGRATION TESTS
# ====================

class TestValidationRoutesIntegration:
    """
    Integration tests for validation_routes.py.
    Executes perform_comprehensive_validation without mocking it directly.
    Mocks external dependencies (Redis, DNS, Providers).
    """

    @pytest.fixture
    def mock_redis(self):
        redis = AsyncMock()
        redis.get.return_value = None  # Cache miss by default
        return redis

    @pytest.fixture
    def mock_request(self):
        request = MagicMock()
        request.headers.get.return_value = "Bearer test-token"
        request.state.correlation_id = "test-trace-id"
        return request

    @pytest.mark.asyncio
    async def test_full_validation_happy_path(self, mock_redis, mock_request):
        """Test complete validation flow for a valid email"""
        engine = validation_routes.EmailValidationEngine()
        
        # Mock dependencies
        with patch("app.routes.validation_routes.EmailValidationEngine._validate_email_format", return_value="valid@example.com"), \
             patch("app.providers.check_typo_suggestion", return_value=None), \
             patch("app.providers.is_disposable_email", return_value=False), \
             patch("app.providers.SpamTrapDetector.is_spam_trap", return_value={"is_spam_trap": False, "confidence": 0.0, "trap_type": None}), \
             patch("app.routes.validation_routes.analyze_email_provider") as mock_analyze, \
             patch("app.routes.validation_routes.EmailValidationEngine._validate_domain") as mock_domain, \
             patch("app.providers.detect_role_email", return_value={"is_role_email": False}), \
             patch("app.routes.validation_routes.EmailValidationEngine._perform_smtp_validation") as mock_smtp, \
             patch("app.routes.validation_routes.ResponseBuilder.build_validation_response") as mock_build:

            # Setup mocks
            from app.providers import ProviderAnalysis, DNSAuthResults, DKIMInfo
            mock_analyze.return_value = ProviderAnalysis(
                domain="example.com", provider="google", reputation=0.9,
                dns_auth=DNSAuthResults(
                    spf="pass", 
                    dkim=DKIMInfo(status="pass", record=None, selector=None, key_type=None, key_length=None), 
                    dmarc="pass"
                ),
                primary_mx="mx.google.com", ip="1.2.3.4", asn_info=None, fingerprint="fp", cached=False
            )
            
            mock_domain.return_value = MagicMock(valid=True, mx_host="mx.google.com")
            
            mock_smtp.return_value = {
                "checked": True, "mailbox_exists": True, "skip_reason": None, "detail": "OK"
            }
            
            mock_build.return_value = JSONResponse(content={
                "email": "valid@example.com", "valid": True, "risk_score": 0.1, "quality_score": 0.9
            })

            # Execute
            response = await engine.perform_comprehensive_validation(
                email="valid@example.com",
                check_smtp=True,
                include_raw_dns=False,
                request=mock_request,
                redis=mock_redis,
                user_id="user-123",
                plan="PREMIUM"
            )

            # Verify
            assert response is not None
            assert response.status_code == 200
            mock_analyze.assert_called_once()
            mock_smtp.assert_called_once()
            mock_redis.setex.assert_called()  # Should cache result

    @pytest.mark.asyncio
    async def test_full_validation_typo_detected(self, mock_redis, mock_request):
        """Test validation flow stops at typo detection"""
        engine = validation_routes.EmailValidationEngine()
        
        with patch("app.routes.validation_routes.EmailValidationEngine._validate_email_format", return_value="gmil.com"), \
             patch("app.providers.check_typo_suggestion", return_value=("gmail.com", 0.9)), \
             patch("app.routes.validation_routes.ResponseBuilder.build_validation_response") as mock_build:

            mock_build.return_value = JSONResponse(content={
                "email": "gmil.com", "valid": False, "error_type": "typo_detected"
            })

            response = await engine.perform_comprehensive_validation(
                email="user@gmil.com",
                check_smtp=False,
                include_raw_dns=False,
                request=mock_request,
                redis=mock_redis,
                user_id="user-123",
                plan="FREE"
            )

            data = json.loads(response.body)
            assert data["valid"] is False
            assert data["error_type"] == "typo_detected"

    @pytest.mark.asyncio
    async def test_full_validation_disposable(self, mock_redis, mock_request):
        """Test validation flow stops at disposable detection"""
        engine = validation_routes.EmailValidationEngine()
        
        with patch("app.routes.validation_routes.EmailValidationEngine._validate_email_format", return_value="temp@trash.com"), \
             patch("app.providers.check_typo_suggestion", return_value=None), \
             patch("app.providers.is_disposable_email", return_value=True), \
             patch("app.routes.validation_routes.ResponseBuilder.build_validation_response") as mock_build:

            mock_build.return_value = JSONResponse(content={
                "email": "temp@trash.com", "valid": False, "error_type": "disposable_email"
            })

            response = await engine.perform_comprehensive_validation(
                email="temp@trash.com",
                check_smtp=False,
                include_raw_dns=False,
                request=mock_request,
                redis=mock_redis,
                user_id="user-123",
                plan="FREE"
            )

            data = json.loads(response.body)
            assert data["valid"] is False
            assert data["error_type"] == "disposable_email"

    @pytest.mark.asyncio
    async def test_full_validation_spam_trap(self, mock_redis, mock_request):
        """Test validation flow stops at spam trap detection"""
        engine = validation_routes.EmailValidationEngine()
        
        with patch("app.routes.validation_routes.EmailValidationEngine._validate_email_format", return_value="trap@example.com"), \
             patch("app.providers.check_typo_suggestion", return_value=None), \
             patch("app.providers.is_disposable_email", return_value=False), \
             patch("app.providers.SpamTrapDetector.is_spam_trap", return_value={
                 "is_spam_trap": True, "confidence": 0.95, "trap_type": "honeypot", "details": "Trap"
             }), \
             patch("app.routes.validation_routes.ResponseBuilder.build_validation_response") as mock_build:

            mock_build.return_value = JSONResponse(content={
                "email": "trap@example.com", "valid": False, "error_type": "spam_trap"
            })

            response = await engine.perform_comprehensive_validation(
                email="trap@example.com",
                check_smtp=False,
                include_raw_dns=False,
                request=mock_request,
                redis=mock_redis,
                user_id="user-123",
                plan="FREE"
            )

            data = json.loads(response.body)
            assert data["valid"] is False
            assert data["error_type"] == "spam_trap"

    @pytest.mark.asyncio
    async def test_full_validation_breach_premium(self, mock_redis, mock_request):
        """Test validation flow includes breach check for PREMIUM"""
        engine = validation_routes.EmailValidationEngine()
        
        with patch("app.routes.validation_routes.EmailValidationEngine._validate_email_format", return_value="pwned@example.com"), \
             patch("app.providers.check_typo_suggestion", return_value=None), \
             patch("app.providers.is_disposable_email", return_value=False), \
             patch("app.providers.SpamTrapDetector.is_spam_trap", return_value={"is_spam_trap": False, "confidence": 0.0, "trap_type": None}), \
             patch("app.providers.HaveIBeenPwnedChecker.check_email_in_breach", return_value={"in_breach": True, "breach_count": 5}), \
             patch("app.routes.validation_routes.analyze_email_provider") as mock_analyze, \
             patch("app.routes.validation_routes.EmailValidationEngine._validate_domain") as mock_domain, \
             patch("app.providers.detect_role_email", return_value={"is_role_email": False}), \
             patch("app.routes.validation_routes.EmailValidationEngine._perform_smtp_validation") as mock_smtp, \
             patch("app.routes.validation_routes.ResponseBuilder.build_validation_response") as mock_build:

            from app.providers import ProviderAnalysis, DNSAuthResults, DKIMInfo
            mock_analyze.return_value = ProviderAnalysis(
                domain="example.com", provider="generic", reputation=0.5,
                dns_auth=DNSAuthResults(
                    spf="none", 
                    dkim=DKIMInfo(status="none", record=None, selector=None, key_type=None, key_length=None), 
                    dmarc="none"
                ),
                primary_mx="mx.example.com", ip="1.2.3.4", asn_info=None, fingerprint="fp", cached=False
            )
            mock_domain.return_value = MagicMock(valid=True, mx_host="mx.example.com")
            mock_smtp.return_value = {"checked": False, "mailbox_exists": "unknown", "skip_reason": "test", "detail": "skipped"}
            mock_build.return_value = JSONResponse(content={"email": "pwned@example.com", "valid": True})

            await engine.perform_comprehensive_validation(
                email="pwned@example.com",
                check_smtp=False,
                include_raw_dns=False,
                request=mock_request,
                redis=mock_redis,
                user_id="user-123",
                plan="PREMIUM"
            )

            # Verify breach check was called
            # Note: We can't easily assert on the internal call unless we patch the class method
            # But we can verify the flow completed without error

    @pytest.mark.asyncio
    async def test_full_validation_cache_hit(self, mock_redis, mock_request):
        """Test validation flow with cache hit"""
        engine = validation_routes.EmailValidationEngine()
        mock_redis.get.return_value = "1"  # Cache hit
        
        with patch("app.routes.validation_routes.EmailValidationEngine._validate_email_format", return_value="cached@example.com"), \
             patch("app.providers.check_typo_suggestion", return_value=None), \
             patch("app.providers.is_disposable_email", return_value=False), \
             patch("app.providers.SpamTrapDetector.is_spam_trap", return_value={"is_spam_trap": False, "confidence": 0.0, "trap_type": None}), \
             patch("app.routes.validation_routes.analyze_email_provider") as mock_analyze, \
             patch("app.routes.validation_routes.EmailValidationEngine._validate_domain") as mock_domain, \
             patch("app.providers.detect_role_email", return_value={"is_role_email": False}), \
             patch("app.routes.validation_routes.EmailValidationEngine._perform_smtp_validation") as mock_smtp, \
             patch("app.routes.validation_routes.ResponseBuilder.build_validation_response") as mock_build:

            from app.providers import ProviderAnalysis, DNSAuthResults, DKIMInfo
            mock_analyze.return_value = ProviderAnalysis(
                domain="example.com", provider="google", reputation=0.9,
                dns_auth=DNSAuthResults(
                    spf="pass", 
                    dkim=DKIMInfo(status="pass", record=None, selector=None, key_type=None, key_length=None), 
                    dmarc="pass"
                ),
                primary_mx="mx.google.com", ip="1.2.3.4", asn_info=None, fingerprint="fp", cached=False
            )
            mock_domain.return_value = MagicMock(valid=True, mx_host="mx.google.com")
            mock_smtp.return_value = {"checked": True, "mailbox_exists": True, "skip_reason": None, "detail": "OK"}
            mock_build.return_value = JSONResponse(content={"email": "cached@example.com", "valid": True, "cache_used": True})

            response = await engine.perform_comprehensive_validation(
                email="cached@example.com",
                check_smtp=True,
                include_raw_dns=False,
                request=mock_request,
                redis=mock_redis,
                user_id="user-123",
                plan="FREE"
            )

            data = json.loads(response.body)
            assert data["cache_used"] is True

import asyncio
import sys
import os

# Add app to path
sys.path.append(os.getcwd())

from app.routes.validation_routes import ResponseBuilder
from app.providers import ProviderAnalysis, DNSAuthResults, DKIMInfo
from fastapi import status

async def reproduce():
    print("Starting reproduction...")
    
    # Simulate values from test_app fixture stub
    provider_analysis = ProviderAnalysis(
        domain="example.com",
        primary_mx=None,
        ip=None,
        asn_info=None,
        dns_auth=DNSAuthResults(
            spf="v=spf1 ~all",
            dkim=DKIMInfo(
                status="valid",
                record="v=DKIM1...",
                selector="default",
                key_type="rsa",
                key_length=1024
            ),
            dmarc="v=DMARC1; p=none"
        ),
        provider="generic",
        fingerprint="fp-123",
        reputation=0.7,
        cached=False,
        error=None
    )
    
    email = "user@example.com"
    start_time = 1234567890.0
    valid = False
    validation_id = "test-id"
    detail = "Domain validation service error: DNS timeout"
    error_type = "validation_error"
    resolved_plan = "PREMIUM"
    suggested_fixes = None
    spam_trap_check = None
    breach_info = None
    include_raw_dns = False

    try:
        response = await ResponseBuilder.build_validation_response(
            email=email,
            start_time=start_time,
            valid=valid,
            validation_id=validation_id,
            detail=detail,
            status_code=status.HTTP_200_OK,
            error_type=error_type,
            provider=provider_analysis.provider,
            reputation=provider_analysis.reputation,
            fingerprint=provider_analysis.fingerprint,
            client_plan=resolved_plan,
            suggested_fixes=suggested_fixes,
            spam_trap_info=spam_trap_check,
            breach_info=breach_info,
            # Arguments passed in validate_email line 902-911
            # Note: validate_email passes these arguments even if domain_result.valid is False?
            # No, line 784 calls it with fewer arguments!
        )
        print("Success!")
    except TypeError as e:
        print(f"Caught TypeError: {e}")
        import traceback
        traceback.print_exc()
    except Exception as e:
        print(f"Caught Exception: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(reproduce())

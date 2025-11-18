"""
MailSafePro SDK - Official Python client for Email Validation API
"""

__version__ = "1.0.0"
__author__ = "MailSafePro Team"
__license__ = "MIT"

from .client import MailSafePro
from .models import (
    ValidationResult,
    BatchResult,
    SMTPInfo,
    DNSInfo,
    DNSRecordSPF,
    DNSRecordDKIM,
    DNSRecordDMARC,
    ProviderAnalysis,
    SecurityInfo,
    SpamTrapCheck,
    RoleEmailInfo,
    BreachInfo,
    SuggestedFixes,
    Metadata,
)
from .exceptions import (
    MailSafeProError,
    AuthenticationError,
    RateLimitError,
    ValidationError,
    QuotaExceededError,
    ServerError,
    NetworkError,
)

__all__ = [
    "MailSafePro",
    "ValidationResult",
    "BatchResult",
    "SMTPInfo",
    "DNSInfo",
    "DNSRecordSPF",
    "DNSRecordDKIM",
    "DNSRecordDMARC",
    "ProviderAnalysis",
    "SecurityInfo",
    "SpamTrapCheck",
    "RoleEmailInfo",
    "BreachInfo",
    "SuggestedFixes",
    "Metadata",
    "MailSafeProError",
    "AuthenticationError",
    "RateLimitError",
    "ValidationError",
    "QuotaExceededError",
    "ServerError",
    "NetworkError",
]

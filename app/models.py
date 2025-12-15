"""
Data Models Module

Defines comprehensive Pydantic models for request/response validation,
business logic, and API contracts with enterprise-grade validation.
"""

from __future__ import annotations

import re
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Optional, List, Dict, Any, Annotated

from annotated_types import Len
from email_validator import validate_email as validate_email_lib, EmailNotValidError
from pydantic import (
    BaseModel,
    Field,
    EmailStr,
    ConfigDict,
    field_validator,
    model_validator,
    ValidationInfo,
    constr,
)

# --------------------------
# Enums de dominio
# --------------------------

class PriorityEnum(str, Enum):
    low = "low"
    standard = "standard"
    high = "high"


class PlanEnum(str, Enum):
    FREE = "FREE"
    PREMIUM = "PREMIUM"
    ENTERPRISE = "ENTERPRISE"


class RiskLevelEnum(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    unknown = "unknown"


class SubscriptionStatusEnum(str, Enum):
    active = "active"
    inactive = "inactive"
    past_due = "past_due"
    canceled = "canceled"
    trialing = "trialing"


# --------------------------
# Base y utilidades
# --------------------------

class BaseAPIModel(BaseModel):
    """Base model with common configuration for all API models"""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        str_min_length=1,
        str_max_length=1024,
        use_enum_values=True,
        validate_assignment=True,
        extra="forbid",
        frozen=False,
        from_attributes=True,
    )


# --------------------------
# Modelos de dominio
# --------------------------

class EmailDomain(BaseAPIModel):
    """Email domain information model"""
    domain: str = Field(..., description="Email domain name", min_length=1, max_length=255)
    mx_records: List[str] = Field(default_factory=list, description="MX records")
    has_mx: bool = Field(default=False, description="Domain has MX records")
    disposable: bool = Field(default=False, description="Is disposable email domain")
    deliverable: bool = Field(default=False, description="Domain accepts emails")


class EmailValidationRequest(BaseAPIModel):
    """Request model for single email validation"""
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "email": "user@example.com",
                    "check_smtp": True,
                    "include_raw_dns": False,
                    "priority": "standard",
                    "testing_mode": False
                }
            ]
        }
    )

    email: constr(min_length=3, max_length=320, strip_whitespace=True) = Field(
        ...,
        description="Email address to validate (RFC 5321 compliant)"
    )
    check_smtp: bool = Field(
        default=False, 
        description="Enable SMTP mailbox verification"
    )
    include_raw_dns: bool = Field(
        default=False, 
        description="Include raw DNS records"
    )
    testing_mode: bool = Field(
        default=False,
        description="Enable testing mode (allows special TLDs like .test, .example, etc.)",
    )
    priority: PriorityEnum = Field(
        default=PriorityEnum.standard,
        description="Validation priority level",
    )

    @field_validator('email')
    def validate_email_format(cls, v):
        """
        Strict email validation to prevent injection attacks.
        
        Validates:
        - No dangerous characters (<, >, ", \\, newlines, etc.)
        - Exactly one @ symbol
        - RFC 5321 length limits (local <= 64, domain <= 255)
        - Basic format compliance
        """
        from app.security.input_validation import validate_email_strict
        return validate_email_strict(v)

    @field_validator("email", mode="before")
    @classmethod
    def ensure_string(cls, v: str) -> str:
        """
        Solo garantizar que es string; la sintaxis se valida en el motor.
        No llamamos aquí a email-validator para no provocar 422 globales.
        """
        if not isinstance(v, str):
            raise TypeError("Email must be a string")
        return v


class AdvancedEmailRequest(EmailValidationRequest):
    """Extended email validation request with advanced options"""
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "email": "user@example.com",
                    "check_smtp": True,
                    "include_raw_dns": True,
                    "priority": "high",
                    "historical_check": False,
                    "bulk_validation": False,
                    "timeout_seconds": 30,
                }
            ]
        }
    )

    historical_check: bool = Field(default=False, description="Check historical email data")
    bulk_validation: bool = Field(default=False, description="Optimize for bulk validation")
    timeout_seconds: int = Field(default=30, ge=1, le=300, description="Maximum validation timeout in seconds")


class BatchValidationRequest(BaseAPIModel):
    """Request model for batch email validation"""
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "emails": ["user1@example.com", "user2@example.org"],
                    "check_smtp": False,
                    "include_raw_dns": False,
                    "batch_size": 100,
                    "concurrent_requests": 5,
                }
            ]
        }
    )

    # 🔹 CAMBIO CRÍTICO: EmailStr → str
    emails: List[str] = Field(
        ...,
        description="List of email addresses to validate (can include invalid formats)",
        min_length=1,
        max_length=1000,
        examples=[["user1@example.com", "user2@example.org"]],
    )
    check_smtp: bool = Field(
        default=False, 
        description="Perform SMTP verification for all emails"
    )
    include_raw_dns: bool = Field(
        default=False, 
        description="Include raw DNS records in responses"
    )
    batch_size: int = Field(
        default=100, 
        ge=1, 
        le=1000, 
        description="Number of emails to process in each batch"
    )
    concurrent_requests: int = Field(
        default=5, 
        ge=1, 
        le=50, 
        description="Maximum concurrent validation requests"
    )

    @field_validator("emails")
    @classmethod
    def validate_email_count(cls, v: List[str]) -> List[str]:
        """Validate reasonable number of emails and basic format"""
        if len(v) > 10_000:
            raise ValueError("Cannot process more than 10,000 emails in a single batch")
        
        # Validar que no sean strings vacíos
        non_empty = [e for e in v if e and e.strip()]
        if not non_empty:
            raise ValueError("All emails are empty or whitespace")
        
        return v  # Retornar original para que el endpoint maneje inválidos

    @model_validator(mode="after")
    def validate_batch_config(self) -> "BatchValidationRequest":
        """Validate batch configuration constraints"""
        if self.batch_size > len(self.emails):
            object.__setattr__(self, "batch_size", len(self.emails))
        if self.concurrent_requests > self.batch_size:
            object.__setattr__(self, "concurrent_requests", self.batch_size)
        return self


# --------------------------
# DNS / SMTP
# --------------------------

class DNSRecordSPF(BaseAPIModel):
    """SPF DNS record information"""
    status: Optional[str] = Field(None, description="SPF validation status")
    record: Optional[str] = Field(None, description="Raw SPF record")
    mechanism: Optional[str] = Field(None, description="SPF mechanism type")
    domain: Optional[str] = Field(None, description="Domain in SPF record")


class DNSRecordDKIM(BaseAPIModel):
    """DKIM DNS record information"""
    status: Optional[str] = Field(None, description="DKIM validation status")
    selector: Optional[str] = Field(None, description="DKIM selector")
    key_type: Optional[str] = Field(None, description="Public key algorithm")
    key_length: Optional[int] = Field(None, description="Public key length in bits")
    record: Optional[str] = Field(None, description="Raw DKIM record")


class DNSRecordDMARC(BaseAPIModel):
    """DMARC DNS record information"""
    status: Optional[str] = Field(None, description="DMARC validation status")
    policy: Optional[str] = Field(None, description="DMARC policy")
    record: Optional[str] = Field(None, description="Raw DMARC record")
    pct: Optional[int] = Field(None, description="Percentage of messages filtered")


class DNSInfo(BaseAPIModel):
    """Comprehensive DNS information for email validation"""
    spf: Optional[DNSRecordSPF] = Field(None, description="SPF record details")
    dkim: Optional[DNSRecordDKIM] = Field(None, description="DKIM record details")
    dmarc: Optional[DNSRecordDMARC] = Field(None, description="DMARC record details")
    mx_records: List[str] = Field(default_factory=list, description="MX records")
    ns_records: List[str] = Field(default_factory=list, description="Name servers")


class SMTPInfo(BaseAPIModel):
    """SMTP verification results"""
    checked: bool = Field(..., description="SMTP check was performed")
    mailbox_exists: Optional[bool] = Field(None, description="Mailbox existence")
    mx_server: Optional[str] = Field(None, description="MX server used for check")
    response_time: Optional[float] = Field(None, description="SMTP response time in seconds")
    error_message: Optional[str] = Field(None, description="SMTP error if any")


# --------------------------
# Respuestas de validación
# --------------------------

class EmailResponse(BaseAPIModel):
    """Comprehensive email validation response"""
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "email": "user@example.com",
                    "valid": True,
                    "detail": "Valid email address",
                    "processing_time": 1.234,
                    "provider": "gmail",
                    "reputation": 0.95,
                    "fingerprint": "a1b2c3d4e5f6",
                    "smtp": {
                        "checked": True,
                        "mailbox_exists": True,
                        "mx_server": "gmail-smtp-in.l.google.com",
                        "response_time": 0.123,
                    },
                    "dns": {
                        "spf": {"status": "valid", "record": "v=spf1 include:_spf.google.com ~all"},
                        "dkim": {"status": "valid", "selector": "20221208", "key_type": "rsa", "key_length": 2048},
                        "dmarc": {"status": "valid", "policy": "quarantine"},
                        "mx_records": ["gmail-smtp-in.l.google.com"],
                    },
                    "quality_score": 0.95,
                    "risk_level": "low",
                    "suggestions": ["Consider using a custom domain for business"],
                }
            ]
        }
    )

    email: str = Field(..., description="Validated email address", min_length=5, max_length=254)
    valid: bool = Field(..., description="Overall validation result")
    detail: str = Field("", description="Validation details summary")
    processing_time: Optional[float] = Field(None, description="Total processing time in seconds", ge=0)
    provider: Optional[str] = Field(None, description="Email service provider")
    reputation: Optional[float] = Field(None, ge=0, le=1, description="Reputation score")
    fingerprint: Optional[str] = Field(None, description="Unique email fingerprint")
    quality_score: Optional[float] = Field(None, ge=0, le=1, description="Email quality score")
    risk_level: Optional[RiskLevelEnum] = Field(None, description="Risk assessment level")
    suggestions: List[str] = Field(default_factory=list, description="Improvement suggestions")
    smtp: Optional[SMTPInfo] = Field(None, description="SMTP verification results")
    dns: Optional[DNSInfo] = Field(None, description="DNS validation results")
    risk_score: Optional[float] = Field(
        None,
        description="Puntuación de riesgo calculada",
        ge=0,
        le=1
    )
    validation_tier: Optional[str] = Field(
        None,
        description="Nivel de validación realizado (basic/advanced/premium)"
    )
    suggested_action: Optional[str] = Field(
        None,
        description="Acción sugerida basada en el resultado de validación"
    )

class BatchEmailResponse(BaseAPIModel):
    """Batch validation response"""
    count: int = Field(..., description="Total emails processed", ge=0)
    valid_count: int = Field(..., description="Number of valid emails", ge=0)
    invalid_count: int = Field(..., description="Number of invalid emails", ge=0)
    processing_time: float = Field(..., description="Total processing time in seconds", ge=0)
    average_time: float = Field(..., description="Average processing time per email", ge=0)
    results: List[EmailResponse] = Field(..., description="Individual validation results")


# --------------------------
# API Keys
# --------------------------

class APIKeyCreateRequest(BaseAPIModel):
    """API Key creation request"""
    name: Optional[str] = Field(
        None,
        description="Descriptive name for the API Key",
        min_length=1,
        max_length=100,
        examples=["Production API Key"],
    )
    scopes: List[str] = Field(default_factory=list, description="Access scopes for the API Key")

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, v: List[str]) -> List[str]:
        """Validate API key scopes"""
        valid_scopes = {
            "validate:single", "validate:batch", "batch:upload", "billing",
            "job:create", "job:read", "job:results", "webhook:manage",
            "read", "write", "admin"
        }

        for scope in v:
            if scope not in valid_scopes:
                raise ValueError(f"Invalid scope: {scope}. Must be one of {valid_scopes}")
        return v


class APIKeyMeta(BaseAPIModel):
    """API Key metadata"""
    id: str = Field(..., description="Unique key identifier")
    key_hash: str = Field(..., description="Hashed key value")
    plan: PlanEnum = Field(..., description="Associated plan")
    created_at: datetime = Field(..., description="Creation timestamp")
    revoked: bool = Field(..., description="Revocation status")
    revoked_at: Optional[datetime] = Field(None, description="Revocation timestamp")
    scopes: List[str] = Field(default_factory=list, description="Access scopes")
    name: Optional[str] = Field(None, description="Key name")
    last_used: Optional[datetime] = Field(None, description="Last usage timestamp")


class APIKeyListResponse(BaseAPIModel):
    """API Key list response"""
    keys: List[APIKeyMeta] = Field(..., description="List of API keys")
    total_count: int = Field(..., description="Total number of keys", ge=0)
    active_count: int = Field(..., description="Number of active keys", ge=0)


class APIKeyResponse(BaseAPIModel):
    """API Key creation response"""
    message: str = Field(..., description="Operation result message")
    client_id: str = Field(..., description="Client identifier")
    scopes: List[str] = Field(..., description="Granted access scopes")
    key_type: str = Field(..., description="Type of API key")
    remaining_quota: Optional[int] = Field(None, description="Remaining API quota", ge=0)


class KeyRotationRequest(BaseAPIModel):
    """API Key rotation request"""
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "old_key": "abcdefgh12345678_ABCDEFGHIJKL9012",
                    "new_key": "mnopqrst12345678_MNOPQRSTUV9012",
                    "grace_period": 86400,
                }
            ]
        }
    )

    old_key: Annotated[str, Len(min_length=32, max_length=128)] = Field(..., description="Current API key to rotate from")
    new_key: Annotated[str, Len(min_length=32, max_length=128)] = Field(..., description="New API key to rotate to")
    grace_period: int = Field(default=86400, ge=0, le=2_592_000, description="Grace period in seconds (max 30 days)")

    @field_validator("old_key", "new_key", mode="before")
    @classmethod
    def validate_key_format(cls, v: str, info: ValidationInfo) -> str:
        """Validate API key format"""
        if not isinstance(v, str) or v.strip() != v:
            raise ValueError("API Key cannot have leading or trailing whitespace")
        if not re.fullmatch(r"[A-Za-z0-9_-]+", v):
            raise ValueError("API Key can only contain letters, digits, hyphens, and underscores")
        return v

    @model_validator(mode="after")
    def validate_different_keys(self) -> "KeyRotationRequest":
        """Ensure old and new keys are different"""
        if self.old_key == self.new_key:
            raise ValueError("Old and new API keys must be different")
        return self


# --------------------------
# Usuarios y autenticación
# --------------------------

class UserRegister(BaseAPIModel):
    """User registration request"""
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="User password"
    )
    plan: PlanEnum = Field(default=PlanEnum.FREE, description="Subscription plan")
    
    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Validate password meets security requirements"""
        import re
        
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        
        return v


class UserLogin(BaseAPIModel):
    """User login request"""
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., description="User password", min_length=8, max_length=128)


class UserInDB(BaseAPIModel):
    """User database model"""
    id: str = Field(..., description="Unique user identifier")
    email: EmailStr = Field(..., description="User email address")
    hashed_password: str = Field(..., description="Hashed password")
    plan: PlanEnum = Field(..., description="Subscription plan")
    created_at: datetime = Field(..., description="Account creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    is_active: bool = Field(default=True, description="Account active status")
    email_verified: bool = Field(default=False, description="Email verification status")


from datetime import datetime, timezone
from typing import List, Optional, Literal

class TokenData(BaseAPIModel):
    """JWT token payload data - validated token claims"""
    
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_default=True,
        use_enum_values=False,
        frozen=False,
    )
    
    # Claims requeridos
    sub: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Subject (user ID)",
        example="user_123abc"
    )
    exp: int = Field(
        ...,
        ge=1_000_000_000,
        le=9_999_999_999,
        description="Expiration timestamp (Unix epoch seconds)",
        example=1730790000
    )
    jti: str = Field(
        ...,
        min_length=16,
        max_length=512,
        description="JWT unique identifier (never reuse)",
        example="550e8400e29b41d4a716446655440000"
    )
    iss: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Issuer",
        example="api.email-validator.com"
    )
    aud: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Audience",
        example="email-validator-frontend"
    )
    
    # Claims con valores por defecto
    iat: int = Field(
        default_factory=lambda: int(datetime.now(timezone.utc).timestamp()),
        ge=1_000_000_000,
        le=9_999_999_999,
        description="Issued at timestamp (Unix epoch seconds)",
    )
    nbf: Optional[int] = Field(
        None,
        ge=1_000_000_000,
        le=9_999_999_999,
        description="Not before timestamp (Unix epoch seconds)",
    )
    
    # Claims de negocio
    plan: PlanEnum = Field(
        default=PlanEnum.FREE,
        description="User subscription plan"
    )
    scopes: List[str] = Field(
        default_factory=list,
        description="Access scopes granted to this token",
        example=["validate:single", "email"]
    )
    type: Literal["access", "refresh", "api_key"] = Field(
        default="access",
        description="Token type - access, refresh or api_key"
    )
    email: Optional[str] = Field(
        None,
        pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$",
        max_length=254,
        description="User email address (optional for refresh tokens)",
        example="user@example.com"
    )
    
    # Campos opcionales para extensibilidad
    user_id: Optional[str] = Field(
        None,
        description="User ID (puede ser igual a sub en algunos casos)",
    )
    
    @field_validator("sub", mode="before")
    @classmethod
    def validate_sub(cls, v: str) -> str:
        """Validate subject claim"""
        if not v or not isinstance(v, str):
            raise ValueError("sub must be a non-empty string")
        return v.strip()
    
    @field_validator("jti", mode="before")
    @classmethod
    def validate_jti(cls, v: str) -> str:
        """Validate JWT ID"""
        if not v or not isinstance(v, str):
            raise ValueError("jti must be a non-empty string")
        return v.strip()
    
    @field_validator("scopes", mode="before")
    @classmethod
    def validate_scopes(cls, v: List[str]) -> List[str]:
        """Validate JWT scopes - only allow whitelisted scopes"""
        valid_scopes = {
            # Validación
            "validate:single",
            "validate:batch",
            "batch:upload",
            # Facturación
            "billing",
            # Jobs
            "job:create",
            "job:read",
            "job:results",
            # Webhooks
            "webhook:manage",
            # CRUD básicos
            "read",
            "write",
            # Admin
            "admin",
            # Email
            "email",
        }
        
        if not isinstance(v, list):
            if isinstance(v, str):
                v = [v]
            else:
                raise ValueError("scopes must be a list or string")
        
        # Validar cada scope
        invalid_scopes = [scope for scope in v if scope not in valid_scopes]
        if invalid_scopes:
            raise ValueError(f"Invalid scopes: {', '.join(invalid_scopes)}. Valid scopes: {', '.join(sorted(valid_scopes))}")
        
        return list(set(v))  # Deduplica scopes
    
    @field_validator("type", mode="before")
    @classmethod
    def validate_type(cls, v: str) -> str:
        """Validate token type"""
        if v not in ("access", "refresh", "api_key"):
            raise ValueError("type must be 'access', 'refresh' or 'api_key'")
        return v.lower()
    
    @field_validator("email", mode="before")
    @classmethod
    def validate_email_optional(cls, v: Optional[str]) -> Optional[str]:
        """Validate email if provided"""
        if v is None:
            return None
        if not isinstance(v, str):
            raise ValueError("email must be a string")
        return v.lower().strip()
    
    def is_expired(self) -> bool:
        """Check if token is expired"""
        return int(datetime.now(timezone.utc).timestamp()) >= self.exp
    
    def is_valid_now(self) -> bool:
        """Check if token is valid at current time"""
        now = int(datetime.now(timezone.utc).timestamp())
        
        # Verificar expiración
        if now >= self.exp:
            return False
        
        # Verificar nbf (not before)
        if self.nbf and now < self.nbf:
            return False
        
        return True
    
    def has_scope(self, scope: str) -> bool:
        """Check if token has a specific scope"""
        return scope in self.scopes or "*" in self.scopes or "admin" in self.scopes
    
    def has_any_scope(self, scopes: List[str]) -> bool:
        """Check if token has any of the provided scopes"""
        return any(self.has_scope(scope) for scope in scopes)
    
    def has_all_scopes(self, scopes: List[str]) -> bool:
        """Check if token has all provided scopes"""
        return all(self.has_scope(scope) for scope in scopes)



# --------------------------
# Respuestas estándar / varios
# --------------------------

class ErrorResponse(BaseAPIModel):
    """Standardized error response"""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "type": "validation_error",
                "title": "Invalid Request",
                "status": 422,
                "detail": "Email validation failed",
                "instance": "/api/v1/validate/email",
                "trace_id": "abc123-xzy-456",
                "timestamp": "2023-01-01T12:00:00Z",
            }
        }
    )

    type: str = Field(..., description="Error type category")
    title: str = Field(..., description="Human-readable error title")
    status: int = Field(..., description="HTTP status code")
    detail: Optional[str] = Field(None, description="Detailed error description")
    instance: Optional[str] = Field(None, description="API endpoint instance")
    trace_id: Optional[str] = Field(None, description="Correlation ID for debugging")
    timestamp: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z",
        description="Error occurrence timestamp",
    )


class SubscriptionStatus(BaseAPIModel):
    """Subscription status information"""
    plan: PlanEnum = Field(..., description="Current subscription plan")
    status: SubscriptionStatusEnum = Field(..., description="Subscription status")
    current_period_start: datetime = Field(..., description="Current period start")
    current_period_end: datetime = Field(..., description="Current period end")
    cancel_at_period_end: bool = Field(..., description="Scheduled cancellation")
    stripe_subscription_id: Optional[str] = Field(None, description="Stripe subscription ID")


class CheckoutSessionResponse(BaseAPIModel):
    """Checkout session creation response"""
    session_id: str = Field(..., description="Stripe checkout session ID")
    url: Optional[str] = Field(None, description="Checkout session URL")


class HealthCheckResponse(BaseAPIModel):
    """Health check response"""
    status: str = Field(..., description="Service status")
    timestamp: str = Field(..., description="Check timestamp")
    version: str = Field(..., description="API version")
    environment: str = Field(..., description="Deployment environment")
    uptime: float = Field(..., description="Service uptime in seconds", ge=0)
    dependencies: Dict[str, str] = Field(..., description="Dependency statuses")


class UsageMetrics(BaseAPIModel):
    """API usage metrics"""
    period: str = Field(..., description="Metrics period")
    total_requests: int = Field(..., description="Total API requests", ge=0)
    successful_requests: int = Field(..., description="Successful requests", ge=0)
    failed_requests: int = Field(..., description="Failed requests", ge=0)
    average_response_time: float = Field(..., description="Average response time", ge=0)
    quota_usage: float = Field(..., description="Quota usage percentage", ge=0)


class PaginationParams(BaseAPIModel):
    """Pagination parameters"""
    page: int = Field(default=1, ge=1, description="Page number")
    size: int = Field(default=50, ge=1, le=1000, description="Page size")

    @model_validator(mode="after")
    def validate_pagination(self) -> "PaginationParams":
        """Validate pagination constraints"""
        if self.size > 1000:
            raise ValueError("Page size cannot exceed 1000")
        return self


class SuccessResponse(BaseAPIModel):
    """Standard success response"""
    message: str = Field(..., description="Success message")
    data: Optional[Dict[str, Any]] = Field(None, description="Response data")
    timestamp: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z",
        description="Response timestamp",
    )



"""
Data Models for API responses
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any


@dataclass
class DNSRecordSPF:
    """SPF DNS record information"""
    status: Optional[str] = None
    record: Optional[str] = None
    mechanism: Optional[str] = None
    domain: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DNSRecordSPF":
        return cls(
            status=data.get("status"),
            record=data.get("record"),
            mechanism=data.get("mechanism"),
            domain=data.get("domain"),
        )


@dataclass
class DNSRecordDKIM:
    """DKIM DNS record information"""
    status: Optional[str] = None
    selector: Optional[str] = None
    key_type: Optional[str] = None
    key_length: Optional[int] = None
    record: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DNSRecordDKIM":
        return cls(
            status=data.get("status"),
            selector=data.get("selector"),
            key_type=data.get("keytype") or data.get("key_type"),
            key_length=data.get("keylength") or data.get("key_length"),
            record=data.get("record"),
        )


@dataclass
class DNSRecordDMARC:
    """DMARC DNS record information"""
    status: Optional[str] = None
    policy: Optional[str] = None
    record: Optional[str] = None
    pct: Optional[int] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DNSRecordDMARC":
        return cls(
            status=data.get("status"),
            policy=data.get("policy"),
            record=data.get("record"),
            pct=data.get("pct"),
        )


@dataclass
class DNSInfo:
    """Comprehensive DNS information for email validation"""
    spf: Optional[DNSRecordSPF] = None
    dkim: Optional[DNSRecordDKIM] = None
    dmarc: Optional[DNSRecordDMARC] = None
    mx_records: List[str] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DNSInfo":
        return cls(
            spf=DNSRecordSPF.from_dict(data.get("spf", {})) if data.get("spf") else None,
            dkim=DNSRecordDKIM.from_dict(data.get("dkim", {})) if data.get("dkim") else None,
            dmarc=DNSRecordDMARC.from_dict(data.get("dmarc", {})) if data.get("dmarc") else None,
            mx_records=data.get("mx_records", []) or data.get("mxrecords", []),
            ns_records=data.get("ns_records", []) or data.get("nsrecords", []),
        )


@dataclass
class SMTPInfo:
    """SMTP verification results"""
    checked: bool
    mailbox_exists: Optional[bool] = None
    mx_server: Optional[str] = None
    response_time: Optional[float] = None
    error_message: Optional[str] = None
    skip_reason: Optional[str] = None
    detail: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SMTPInfo":
        return cls(
            checked=data.get("checked", False),
            mailbox_exists=data.get("mailbox_exists") or data.get("mailboxexists"),
            mx_server=data.get("mx_server") or data.get("mxserver"),
            response_time=data.get("response_time") or data.get("responsetime"),
            error_message=data.get("error_message") or data.get("errormessage"),
            skip_reason=data.get("skip_reason") or data.get("skipreason"),
            detail=data.get("detail"),
        )


@dataclass
class ProviderAnalysis:
    """Email provider analysis"""
    provider: str
    reputation: float
    fingerprint: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProviderAnalysis":
        return cls(
            provider=data.get("provider", "unknown"),
            reputation=data.get("reputation", 0.5),
            fingerprint=data.get("fingerprint"),
        )


@dataclass
class SecurityInfo:
    """Security breach information"""
    in_breach: bool
    breach_count: int = 0
    risk_level: Optional[str] = None
    checked_at: Optional[str] = None
    cached: bool = False
    recent_breaches: List[str] = field(default_factory=list)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityInfo":
        return cls(
            in_breach=data.get("in_breach") or data.get("inbreach", False),
            breach_count=data.get("breach_count") or data.get("breachcount", 0),
            risk_level=data.get("risk_level") or data.get("risklevel"),
            checked_at=data.get("checked_at") or data.get("checkedat"),
            cached=data.get("cached", False),
            recent_breaches=data.get("recent_breaches") or data.get("recentbreaches", []),
        )


@dataclass
class SpamTrapCheck:
    """Spam trap detection results"""
    checked: bool
    is_spam_trap: bool
    confidence: float
    trap_type: str
    source: str
    details: str
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SpamTrapCheck":
        return cls(
            checked=data.get("checked", False),
            is_spam_trap=data.get("is_spam_trap") or data.get("isspamtrap", False),
            confidence=data.get("confidence", 0.0),
            trap_type=data.get("trap_type") or data.get("traptype", "unknown"),
            source=data.get("source", "unknown"),
            details=data.get("details", ""),
        )


@dataclass
class RoleEmailInfo:
    """Role email detection results"""
    is_role_email: bool
    role_type: Optional[str] = None
    deliverability_risk: Optional[str] = None
    confidence: float = 0.0
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RoleEmailInfo":
        return cls(
            is_role_email=data.get("is_role_email") or data.get("isroleemail", False),
            role_type=data.get("role_type") or data.get("roletype"),
            deliverability_risk=data.get("deliverability_risk") or data.get("deliverabilityrisk"),
            confidence=data.get("confidence", 0.0),
        )


@dataclass
class BreachInfo:
    """Data breach information (PREMIUM/ENTERPRISE)"""
    in_breach: bool
    breach_count: int = 0
    risk_level: Optional[str] = None
    checked_at: Optional[str] = None
    cached: bool = False
    recent_breaches: List[str] = field(default_factory=list)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BreachInfo":
        return cls(
            in_breach=data.get("in_breach") or data.get("inbreach", False),
            breach_count=data.get("breach_count") or data.get("breachcount", 0),
            risk_level=data.get("risk_level") or data.get("risklevel"),
            checked_at=data.get("checked_at") or data.get("checkedat"),
            cached=data.get("cached", False),
            recent_breaches=data.get("recent_breaches") or data.get("recentbreaches", []),
        )


@dataclass
class SuggestedFixes:
    """Suggested email fixes for typos"""
    typo_detected: bool
    suggested_email: Optional[str] = None
    confidence: float = 0.0
    reason: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SuggestedFixes":
        return cls(
            typo_detected=data.get("typo_detected") or data.get("typodetected", False),
            suggested_email=data.get("suggested_email") or data.get("suggestedemail"),
            confidence=data.get("confidence", 0.0),
            reason=data.get("reason"),
        )


@dataclass
class Metadata:
    """Validation metadata"""
    timestamp: str
    validation_id: str
    cache_used: bool
    client_plan: str = "UNKNOWN"
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Metadata":
        return cls(
            timestamp=data.get("timestamp", ""),
            validation_id=data.get("validation_id") or data.get("validationid", ""),
            cache_used=data.get("cache_used") or data.get("cacheused", False),
            client_plan=data.get("client_plan") or data.get("clientplan", "UNKNOWN"),
        )


@dataclass
class ValidationResult:
    """
    Comprehensive email validation result
    
    Attributes:
        email: Validated email address
        valid: Overall validation result (True/False)
        detail: Validation details summary
        processing_time: Total processing time in seconds
        risk_score: Risk assessment score (0.0-1.0, higher = riskier)
        quality_score: Email quality score (0.0-1.0, higher = better)
        validation_tier: Validation level performed (basic/standard/premium)
        suggested_action: Recommended action (accept/review/monitor/reject)
        status: Email status (deliverable/risky/undeliverable/unknown)
        provider_analysis: Email provider information
        smtp: SMTP verification results
        dns_security: DNS authentication details (SPF/DKIM/DMARC)
        spam_trap_check: Spam trap detection results
        role_email_info: Role email detection results
        breach_info: Data breach information (PREMIUM/ENTERPRISE)
        suggested_fixes: Typo correction suggestions
        metadata: Validation metadata
    """
    email: str
    valid: bool
    detail: str
    processing_time: float
    risk_score: float
    quality_score: float
    validation_tier: str
    suggested_action: str
    status: str
    provider_analysis: ProviderAnalysis
    smtp: SMTPInfo
    dns_security: Optional[DNSInfo] = None
    spam_trap_check: Optional[SpamTrapCheck] = None
    role_email_info: Optional[RoleEmailInfo] = None
    breach_info: Optional[BreachInfo] = None
    suggested_fixes: Optional[SuggestedFixes] = None
    metadata: Optional[Metadata] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ValidationResult":
        """Create ValidationResult from API response dictionary"""
        return cls(
            email=data.get("email", ""),
            valid=data.get("valid", False),
            detail=data.get("detail", ""),
            processing_time=data.get("processing_time") or data.get("processingtime", 0.0),
            risk_score=data.get("risk_score") or data.get("riskscore", 0.5),
            quality_score=data.get("quality_score") or data.get("qualityscore", 0.5),
            validation_tier=data.get("validation_tier") or data.get("validationtier", "basic"),
            suggested_action=data.get("suggested_action") or data.get("suggestedaction", "review"),
            status=data.get("status", "unknown"),
            provider_analysis=ProviderAnalysis.from_dict(
                data.get("provider_analysis") or data.get("provideranalysis", {})
            ),
            smtp=SMTPInfo.from_dict(
                data.get("smtp_validation") or data.get("smtpvalidation") or data.get("smtp", {})
            ),
            dns_security=DNSInfo.from_dict(
                data.get("dns_security") or data.get("dnssecurity", {})
            ) if data.get("dns_security") or data.get("dnssecurity") else None,
            spam_trap_check=SpamTrapCheck.from_dict(
                data.get("spam_trap_check") or data.get("spamtrapcheck", {})
            ) if data.get("spam_trap_check") or data.get("spamtrapcheck", {}).get("checked") else None,
            role_email_info=RoleEmailInfo.from_dict(
                data.get("email_type") or data.get("emailtype", {})
            ) if data.get("email_type") or data.get("emailtype") else None,
            breach_info=BreachInfo.from_dict(
                data.get("security") or {}
            ) if data.get("security") else None,
            suggested_fixes=SuggestedFixes.from_dict(
                data.get("suggested_fixes") or data.get("suggestedfixes", {})
            ) if data.get("suggested_fixes") or data.get("suggestedfixes") else None,
            metadata=Metadata.from_dict(
                data.get("metadata", {})
            ) if data.get("metadata") else None,
        )
    
    def __repr__(self) -> str:
        return (
            f"<ValidationResult(email={self.email!r}, valid={self.valid}, "
            f"risk_score={self.risk_score:.2f}, action={self.suggested_action})>"
        )


@dataclass
class BatchResult:
    """
    Batch validation results
    
    Attributes:
        count: Total emails processed
        valid_count: Number of valid emails
        invalid_count: Number of invalid emails
        processing_time: Total processing time in seconds
        average_time: Average processing time per email
        results: List of individual validation results
        summary: Batch summary with additional statistics
    """
    count: int
    valid_count: int
    invalid_count: int
    processing_time: float
    average_time: float
    results: List[ValidationResult]
    summary: Optional[Dict[str, Any]] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BatchResult":
        """Create BatchResult from API response dictionary"""
        results_data = data.get("results", [])
        results = [ValidationResult.from_dict(r) for r in results_data]
        
        return cls(
            count=data.get("count", len(results)),
            valid_count=data.get("valid_count") or data.get("validcount", 0),
            invalid_count=data.get("invalid_count") or data.get("invalidcount", 0),
            processing_time=data.get("processing_time") or data.get("processingtime", 0.0),
            average_time=data.get("average_time") or data.get("averagetime", 0.0),
            results=results,
            summary=data.get("summary"),
        )
    
    def __repr__(self) -> str:
        return (
            f"<BatchResult(count={self.count}, valid={self.valid_count}, "
            f"invalid={self.invalid_count})>"
        )

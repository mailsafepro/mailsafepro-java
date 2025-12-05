"""
Graceful Degradation for Non-Critical Features

Defines safe fallback behavior when optional services fail.
Ensures validation never fails due to optional features being unavailable.
"""

from typing import Dict, Any
from app.logger import logger

class GracefulDegradation:
    """
    Manage graceful degradation for non-critical features.
    
    Returns safe defaults when optional services fail.
    """
    
    @staticmethod
    def breach_detection_fallback(email: str) -> Dict[str, Any]:
        """
        Fallback when breach detection (HIBP API) fails.
        
        Returns safe unknown state instead of failing.
        
        Args:
            email: Email address
        
        Returns:
            Safe breach detection result with degraded flag
        """
        logger.warning(
            f"Breach detection unavailable",
            extra={
                "email": email,
                "degraded_feature": "breach_detection"
            }
        )
        
        return {
            "breached": None,  # Unknown state
            "breach_count": 0,
            "data_classes": [],
            "severity": "unknown",
            "service_available": False,
            "degraded": True,
            "message": "Breach detection temporarily unavailable"
        }
    
    @staticmethod
    def disposable_email_fallback(email: str) -> Dict[str, Any]:
        """
        Fallback for disposable email detection.
        
        Uses basic domain check against known disposable providers.
        
        Args:
            email: Email address
        
        Returns:
            Basic disposable check result with degraded flag
        """
        logger.warning(
            f"Disposable detection using basic fallback",
            extra={
                "email": email,
                "degraded_feature": "disposable_detection"
            }
        )
        
        # Basic check against common disposable domains
        common_disposable = [
            "tempmail.com", "guerrillamail.com", "10minutemail.com",
            "mailinator.com", "throwaway.email", "temp-mail.org",
            "fakeinbox.com", "trashmail.com", "yopmail.com"
        ]
        
        domain = email.split('@')[1].lower() if '@' in email else ""
        is_disposable = domain in common_disposable
        
        return {
            "is_disposable": is_disposable,
            "confidence": "low",
            "provider": domain if is_disposable else None,
            "service_available": False,
            "degraded": True,
            "message": "Using basic disposable check"
        }
    
    @staticmethod
    def spam_trap_fallback(email: str) -> Dict[str, Any]:
        """
        Fallback for spam trap detection.
        
        Returns optimistic default (assume not spam trap).
        
        Args:
            email: Email address
        
        Returns:
            Safe spam trap result (optimistic)
        """
        logger.warning(
            f"Spam trap detection unavailable",
            extra={
                "email": email,
                "degraded_feature": "spam_trap"
            }
        )
        
        return {
            "is_spam_trap": False,  # Optimistic default
            "confidence": 0.0,
            "reason": None,
            "service_available": False,
            "degraded": True,
            "message": "Spam trap detection temporarily unavailable"
        }
    
    @staticmethod
    def provider_reputation_fallback(domain: str) -> Dict[str, Any]:
        """
        Fallback for provider reputation check.
        
        Returns neutral reputation score.
        
        Args:
            domain: Email domain
        
        Returns:
            Neutral reputation with degraded flag
        """
        logger.warning(
            f"Provider reputation unavailable",
            extra={
                "domain": domain,
                "degraded_feature": "provider_reputation"
            }
        )
        
        return {
            "reputation": 0.5,  # Neutral score
            "reputation_score": "unknown",
            "has_spf": None,
            "has_dkim": None,
            "has_dmarc": None,
            "service_available": False,
            "degraded": True,
            "message": "Provider reputation temporarily unavailable"
        }
    
    @staticmethod
    def typo_suggestion_fallback(email: str) -> Dict[str, Any]:
        """
        Fallback for typo/suggestion feature.
        
        Returns no suggestions.
        
        Args:
            email: Email address
        
        Returns:
            Empty suggestion result
        """
        logger.warning(
            f"Typo suggestions unavailable",
            extra={
                "email": email,
                "degraded_feature": "typo_suggestions"
            }
        )
        
        return {
            "has_typo": False,
            "suggested_email": None,
            "confidence": 0.0,
            "service_available": False,
            "degraded": True,
            "message": "Typo suggestions temporarily unavailable"
        }
    
    @staticmethod
    def collect_degraded_features(validation_result: Dict[str, Any]) -> List[str]:
        """
        Collect all degraded features from validation result.
        
        Args:
            validation_result: Full validation response
        
        Returns:
            List of degraded feature names
        """
        degraded = []
        
        # Check each optional feature
        features_to_check = [
            ("breach_data", "breach_detection"),
            ("disposable", "disposable_detection"),
            ("spam_trap", "spam_trap_detection"),
            ("provider", "provider_reputation"),
            ("typo_suggestion", "typo_suggestions")
        ]
        
        for field_name, feature_name in features_to_check:
            if field_name in validation_result:
                field_data = validation_result[field_name]
                if isinstance(field_data, dict) and field_data.get("degraded"):
                    degraded.append(feature_name)
        
        return degraded

"""
Secrets Management System

Provides secure generation, validation, and lifecycle management for:
- API keys
- Webhook secrets
- JWT secrets
- Other sensitive tokens
"""

import secrets
import hashlib
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from app.logger import logger

class SecretsManager:
    """
    Centralized secrets management with security best practices.
    """
    
    # Key formats
    API_KEY_PREFIX = "msp_live_"
    TEST_API_KEY_PREFIX = "msp_test_"
    WEBHOOK_SECRET_PREFIX = "whsec_"
    
    # Minimum security requirements
    MIN_SECRET_LENGTH = 32
    MIN_ENTROPY_BITS = 128
    
    @staticmethod
    def generate_api_key(test_mode: bool = False, length: int = 32) -> str:
        """
        Generate cryptographically secure API key.
        
        Format: msp_live_XXXXX or msp_test_XXXXX
        
        Args:
            test_mode: If True, generates test key
            length: Length of random part (default 32)
        
        Returns:
            Secure API key with prefix
        
        Example:
            >>> key = SecretsManager.generate_api_key()
            >>> key.startswith('msp_live_')
            True
        """
        prefix = SecretsManager.TEST_API_KEY_PREFIX if test_mode else SecretsManager.API_KEY_PREFIX
        
        # Generate cryptographically secure random string
        random_part = secrets.token_urlsafe(length)
        
        api_key = f"{prefix}{random_part}"
        
        logger.info(
            f"Generated API key",
            extra={
                "security_event": True,
                "key_type": "test" if test_mode else "live",
                "key_prefix": prefix,
                "masked_key": SecretsManager.mask_secret(api_key)
            }
        )
        
        return api_key
    
    @staticmethod
    def generate_webhook_secret(length: int = 32) -> str:
        """
        Generate webhook signing secret.
        
        Format: whsec_XXXXX
        
        Args:
            length: Length of random part
        
        Returns:
            Secure webhook secret
        """
        random_part = secrets.token_urlsafe(length)
        secret = f"{SecretsManager.WEBHOOK_SECRET_PREFIX}{random_part}"
        
        logger.info(
            f"Generated webhook secret",
            extra={
                "security_event": True,
                "secret_type": "webhook",
                "masked_secret": SecretsManager.mask_secret(secret)
            }
        )
        
        return secret
    
    @staticmethod
    def generate_jwt_secret(length: int = 64) -> str:
        """
        Generate JWT signing secret (extra long for security).
        
        Args:
            length: Length in bytes (default 64 = 512 bits)
        
        Returns:
            Hex-encoded secret
        """
        # Use token_bytes for JWT secrets (binary -> hex)
        secret_bytes = secrets.token_bytes(length)
        secret = secret_bytes.hex()
        
        logger.info(
            f"Generated JWT secret",
            extra={
                "security_event": True,
                "secret_type": "jwt",
                "length_bits": length * 8,
                "masked_secret": SecretsManager.mask_secret(secret)
            }
        )
        
        return secret
    
    @staticmethod
    def mask_secret(secret: str, visible_chars: int = 8) -> str:
        """
        Mask secret for safe logging.
        
        Shows only prefix and masks the rest.
        
        Args:
            secret: Secret to mask
            visible_chars: Number of visible characters
        
        Returns:
            Masked secret
        
        Example:
            >>> SecretsManager.mask_secret("msp_live_abc123def456")
            'msp_live...'
        """
        if not secret:
            return "***"
        
        if len(secret) <= visible_chars:
            return "***"
        
        return f"{secret[:visible_chars]}..."
    
    @staticmethod
    def hash_secret(secret: str) -> str:
        """
        Hash secret for storage (API key verification).
        
        Uses SHA-256 for one-way hashing.
        
        Args:
            secret: Plain secret to hash
        
        Returns:
            Hex-encoded hash
        """
        return hashlib.sha256(secret.encode()).hexdigest()
    
    @staticmethod
    def check_secret_strength(secret: str) -> Dict[str, Any]:
        """
        Validate secret meets security requirements.
        
        Checks:
        - Length >= 32 characters
        - Entropy >= 128 bits
        - Character diversity
        
        Args:
            secret: Secret to validate
        
        Returns:
            {
                "is_strong": bool,
                "length": int,
                "entropy_bits": float,
                "issues": List[str]
            }
        """
        issues = []
        
        # Length check
        if len(secret) < SecretsManager.MIN_SECRET_LENGTH:
            issues.append(f"Secret too short (min {SecretsManager.MIN_SECRET_LENGTH} chars)")
        
        # Entropy estimation (Shannon entropy)
        unique_chars = len(set(secret))
        
        # Approximate entropy: unique_chars * log2(charset_size)
        # For alphanumeric + symbols: ~6.5 bits per char
        entropy = unique_chars * 6.5
        
        if entropy < SecretsManager.MIN_ENTROPY_BITS:
            issues.append(f"Low entropy (< {SecretsManager.MIN_ENTROPY_BITS} bits)")
        
        # Character diversity
        has_upper = any(c.isupper() for c in secret)
        has_lower = any(c.islower() for c in secret)
        has_digit = any(c.isdigit() for c in secret)
        
        if not (has_upper and has_lower and has_digit):
            issues.append("Lacks character diversity (needs upper, lower, digit)")
        
        is_strong = len(issues) == 0
        
        if not is_strong:
            logger.warning(
                f"Weak secret detected",
                extra={
                    "security_event": True,
                    "issues": issues,
                    "length": len(secret),
                    "entropy": entropy
                }
            )
        
        return {
            "is_strong": is_strong,
            "length": len(secret),
            "entropy_bits": entropy,
            "issues": issues
        }

class SecretRotationPolicy:
    """
    Define and enforce secret rotation policies.
    """
    
    # Rotation intervals
    API_KEY_MAX_AGE = timedelta(days=90)  # 3 months
    WEBHOOK_SECRET_MAX_AGE = timedelta(days=180)  # 6 months
    JWT_SECRET_MAX_AGE = timedelta(days=365)  # 1 year
    
    @staticmethod
    def check_rotation_needed(
        secret_type: str,
        created_at: datetime
    ) -> Dict[str, Any]:
        """
        Check if secret needs rotation based on age.
        
        Args:
            secret_type: Type of secret (api_key, webhook_secret, jwt_secret)
            created_at: When secret was created
        
        Returns:
            {
                "needs_rotation": bool,
                "age_days": int,
                "max_age_days": int,
                "urgency": "normal" | "warning" | "critical"
            }
        """
        age = datetime.utcnow() - created_at
        age_days = age.days
        
        # Determine max age for this secret type
        max_ages = {
            "api_key": SecretRotationPolicy.API_KEY_MAX_AGE,
            "webhook_secret": SecretRotationPolicy.WEBHOOK_SECRET_MAX_AGE,
            "jwt_secret": SecretRotationPolicy.JWT_SECRET_MAX_AGE,
        }
        
        max_age = max_ages.get(secret_type, timedelta(days=90))
        max_age_days = max_age.days
        
        needs_rotation = age > max_age
        
        # Calculate urgency
        if age_days < max_age_days * 0.8:
            urgency = "normal"
        elif age_days < max_age_days:
            urgency = "warning"
        else:
            urgency = "critical"
        
        if needs_rotation:
            logger.warning(
                f"Secret rotation needed",
                extra={
                    "security_event": True,
                    "secret_type": secret_type,
                    "age_days": age_days,
                    "max_age_days": max_age_days,
                    "urgency": urgency
                }
            )
        
        return {
            "needs_rotation": needs_rotation,
            "age_days": age_days,
            "max_age_days": max_age_days,
            "urgency": urgency
        }

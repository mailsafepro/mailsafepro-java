"""
Tests for secrets management.
"""

import pytest
from datetime import datetime, timedelta
from app.security.secrets import SecretsManager, SecretRotationPolicy

def test_generate_api_key():
    """Test API key generation."""
    key = SecretsManager.generate_api_key()
    assert key.startswith("msp_live_")
    assert len(key) > 40  # Prefix + random part

def test_generate_test_api_key():
    """Test key generation."""
    key = SecretsManager.generate_api_key(test_mode=True)
    assert key.startswith("msp_test_")

def test_generate_webhook_secret():
    """Test webhook secret generation."""
    secret = SecretsManager.generate_webhook_secret()
    assert secret.startswith("whsec_")
    assert len(secret) > 30

def test_generate_jwt_secret():
    """Test JWT secret generation."""
    secret = SecretsManager.generate_jwt_secret()
    assert len(secret) == 128  # 64 bytes * 2 (hex encoding)

def test_mask_secret():
    """Test secret masking."""
    secret = "msp_live_abc123def456"
    masked = SecretsManager.mask_secret(secret)
    assert masked == "msp_live..."
    assert "abc123" not in masked

def test_hash_secret():
    """Test secret hashing."""
    secret = "my_secret_key"
    hash1 = SecretsManager.hash_secret(secret)
    hash2 = SecretsManager.hash_secret(secret)
    
    # Same secret produces same hash
    assert hash1 == hash2
    
    # Hash is hex string
    assert len(hash1) == 64  # SHA-256

def test_check_secret_strength_strong():
    """Test strong secret validation."""
    # Generate strong secret
    strong_secret = SecretsManager.generate_api_key()
    result = SecretsManager.check_secret_strength(strong_secret)
    
    assert result["is_strong"] is True
    assert result["length"] >= 32
    assert len(result["issues"]) == 0

def test_check_secret_strength_weak():
    """Test weak secret detection."""
    weak_secret = "abc123"  # Too short, no uppercase
    result = SecretsManager.check_secret_strength(weak_secret)
    
    assert result["is_strong"] is False
    assert len(result["issues"]) > 0

def test_rotation_not_needed():
    """Test rotation check for recent secret."""
    created_at = datetime.utcnow() - timedelta(days=30)
    result = SecretRotationPolicy.check_rotation_needed("api_key", created_at)
    
    assert result["needs_rotation"] is False
    assert result["age_days"] == 30
    assert result["urgency"] == "normal"

def test_rotation_needed():
    """Test rotation check for old secret."""
    created_at = datetime.utcnow() - timedelta(days=100)
    result = SecretRotationPolicy.check_rotation_needed("api_key", created_at)
    
    assert result["needs_rotation"] is True
    assert result["age_days"] == 100
    assert result["urgency"] == "critical"

def test_rotation_warning_threshold():
    """Test rotation warning before expiry."""
    # 85 days out of 90 = warning
    created_at = datetime.utcnow() - timedelta(days=85)
    result = SecretRotationPolicy.check_rotation_needed("api_key", created_at)
    
    assert result["needs_rotation"] is False
    assert result["urgency"] == "warning"

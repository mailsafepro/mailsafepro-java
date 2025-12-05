"""
Tests for injection prevention and sanitization.
"""

import pytest
from app.security.sanitization import (
    sanitize_redis_key,
    sanitize_email_for_key,
    sanitize_user_id,
    escape_lua_string,
    build_safe_cache_key
)

def test_sanitize_redis_key_valid():
    """Test valid Redis keys pass through."""
    assert sanitize_redis_key("user:123:cache") == "user:123:cache"
    assert sanitize_redis_key("email@example.com") == "email@example.com"
    assert sanitize_redis_key("key_with-dots.test") == "key_with-dots.test"

def test_sanitize_redis_key_invalid():
    """Test invalid Redis keys are rejected."""
    # SQL injection attempt
    with pytest.raises(ValueError, match="invalid characters"):
        sanitize_redis_key("user'; DROP TABLE users;--")
    
    # Command injection
    with pytest.raises(ValueError, match="invalid characters"):
        sanitize_redis_key("user`rm -rf /`")
    
    # Newlines
    with pytest.raises(ValueError, match="invalid characters"):
        sanitize_redis_key("user\nkey")
    
    # Null bytes
    with pytest.raises(ValueError, match="invalid characters"):
        sanitize_redis_key("user\x00key")

def test_sanitize_redis_key_length():
    """Test excessively long keys are rejected."""
    long_key = "a" * 201
    with pytest.raises(ValueError, match="exceeds maximum length"):
        sanitize_redis_key(long_key)

def test_sanitize_email_for_key():
    """Test email sanitization for keys."""
    assert sanitize_email_for_key("Test@Example.COM") == "test@example.com"
    assert sanitize_email_for_key("user+tag@domain.com") == "user+tag@domain.com"

def test_sanitize_email_injection():
    """Test email injection attempts are blocked."""
    # SQL injection in email
    with pytest.raises(ValueError):
        sanitize_email_for_key("test'; DROP--@example.com")
    
    # Command injection
    with pytest.raises(ValueError):
        sanitize_email_for_key("test@example.com; rm -rf")

def test_escape_lua_string():
    """Test Lua string escaping."""
    # Single quotes
    assert escape_lua_string("it's") == "it\\'s"
    
    # Injection attempt
    malicious = "'; return 'hacked"
    escaped = escape_lua_string(malicious)
    assert "\\'" in escaped
    
    # Newlines
    assert escape_lua_string("line1\nline2") == "line1\\nline2"

def test_build_safe_cache_key():
    """Test safe cache key building."""
    key = build_safe_cache_key("user", "123", "validation", "test@example.com")
    assert key == "user:123:validation:test@example.com"
    
    # Test with invalid part
    with pytest.raises(ValueError):
        build_safe_cache_key("user", "123'; DROP--", "cache")

def test_sanitize_user_id():
    """Test user ID sanitization."""
    assert sanitize_user_id("user-123") == "user-123"
    assert sanitize_user_id("550e8400-e29b-41d4-a716-446655440000") == "550e8400-e29b-41d4-a716-446655440000"
    
    # Injection attempt
    with pytest.raises(ValueError):
        sanitize_user_id("user'; DELETE--")

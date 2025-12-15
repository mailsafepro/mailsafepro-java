"""
Sanitization utilities for injection prevention.

Prevents:
- Redis key injection
- Lua script injection  
- NoSQL injection via user input
"""

import re
import logging
from typing import Any

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('sanitization_debug.log')
    ]
)
logger = logging.getLogger(__name__)

# Allowed characters for Redis keys (alphanumeric + safe separators + plus for emails)
REDIS_KEY_PATTERN = re.compile(r'^[a-zA-Z0-9:_\-\.@\+]+$')

# Maximum key length to prevent abuse
MAX_KEY_LENGTH = 200

def sanitize_redis_key(key: str, max_length: int = MAX_KEY_LENGTH) -> str:
    """
    Sanitize Redis key to prevent injection attacks.
    
    Only allows: a-z, A-Z, 0-9, :, _, -, ., @, +
    
    Args:
        key: Raw key component from user input
        max_length: Maximum allowed key length
    
    Returns:
        Sanitized key
    
    Raises:
        ValueError: If key contains invalid characters or exceeds length
    
    Example:
        >>> sanitize_redis_key("user@example.com")
        'user@example.com'
        >>> sanitize_redis_key("user'; DROP TABLE--")
        ValueError: Key contains invalid characters
    """
    if not key:
        raise ValueError("Key cannot be empty")
    
    if len(key) > max_length:
        raise ValueError(f"Key exceeds maximum length of {max_length} characters")
    
    # Remove whitespace
    key = key.strip()
    
    # Debug: Log the key and its components
    logger = logging.getLogger(__name__)
    logger.debug(f"Validating Redis key: {key!r}")
    
    # Check for invalid characters
    invalid_chars = [ch for ch in key if not re.match(REDIS_KEY_PATTERN, ch)]
    if invalid_chars:
        logger.error(f"Invalid characters in key '{key}': {invalid_chars}")
        logger.error(f"Key type: {type(key)}")
        logger.error(f"Key length: {len(key)}")
        logger.error(f"Key hex: {' '.join(f'{ord(c):02x}' for c in key)}")
        raise ValueError(
            f"Key contains invalid characters: {invalid_chars}. "
            f"Only alphanumeric, colon, underscore, hyphen, dot, @, and + allowed"
        )
    
    # Validate against pattern
    if not REDIS_KEY_PATTERN.match(key):
        raise ValueError(
            "Key contains invalid characters. "
            "Only alphanumeric, colon, underscore, hyphen, dot, and @ allowed"
        )
    
    return key

def sanitize_email_for_key(email: str) -> str:
    """
    Sanitize email address for use in Redis keys.
    
    Normalizes email to lowercase and validates format.
    Prevents injection via email field.
    
    Args:
        email: Email address
    
    Returns:
        Sanitized lowercase email
    
    Raises:
        ValueError: If email is invalid
    """
    if not email:
        raise ValueError("Email cannot be empty")
    
    # Normalize
    email = email.lower().strip()
    
    # Must contain exactly one @
    if email.count('@') != 1:
        raise ValueError("Invalid email format")
    
    # Remove any dangerous characters
    dangerous_chars = [';', '"', "'", '\\', '\n', '\r', '\0', '<', '>']
    if any(char in email for char in dangerous_chars):
        raise ValueError("Email contains dangerous characters")
    
    # Validate with pattern
    if not REDIS_KEY_PATTERN.match(email):
        raise ValueError("Email contains invalid characters for key")
    
    return email

def sanitize_user_id(user_id: str) -> str:
    """
    Sanitize user ID for Redis keys.
    
    Ensures user ID is safe UUID or alphanumeric string.
    """
    if not user_id:
        raise ValueError("User ID cannot be empty")
    
    user_id = user_id.strip()
    
    # Check length
    if len(user_id) > 100:
        raise ValueError("User ID too long")
    
    # Validate pattern
    if not REDIS_KEY_PATTERN.match(user_id):
        raise ValueError("User ID contains invalid characters")
    
    return user_id

def escape_lua_string(s: str) -> str:
    """
    Escape string for safe use in Lua scripts.
    
    Prevents Lua injection in EVAL commands.
    
    Args:
        s: Raw string to escape
    
    Returns:
        Escaped string safe for Lua
    
    Example:
        >>> escape_lua_string("hello'; return 'hacked")
        "hello\\'; return \\'hacked"
    """
    # Escape backslashes first
    s = s.replace('\\', '\\\\')
    
    # Escape quotes
    s = s.replace('"', '\\"')
    s = s.replace("'", "\\'")
    
    # Escape newlines
    s = s.replace('\n', '\\n')
    s = s.replace('\r', '\\r')
    s = s.replace('\t', '\\t')
    
    # Escape null bytes
    s = s.replace('\0', '\\0')
    
    return s

def build_safe_cache_key(*parts: str) -> str:
    """
    Build Redis cache key from sanitized parts.
    
    Args:
        *parts: Key components to join with ':'
    
    Returns:
        Safe cache key
    
    Example:
        >>> build_safe_cache_key("user", "123", "validation", "test@example.com")
        'user:123:validation:test@example.com'
    """
    import logging
    logger = logging.getLogger(__name__)
    
    if not parts:
        raise ValueError("At least one key part required")
    
    logger.debug(f"Building cache key from parts: {parts}")
    
    sanitized_parts = []
    for i, part in enumerate(parts):
        if not isinstance(part, str):
            part = str(part)
        
        logger.debug(f"  Part {i}: {part!r} (type: {type(part).__name__})")
        
        try:
            # Sanitize each part
            sanitized = sanitize_redis_key(part)
            sanitized_parts.append(sanitized)
            logger.debug(f"  Sanitized part: {sanitized!r}")
        except ValueError as e:
            logger.error(f"Error sanitizing part {i} {part!r}: {str(e)}")
            logger.error(f"Part type: {type(part)}")
            logger.error(f"Part length: {len(part)}")
            logger.error(f"Part repr: {repr(part)}")
            logger.error(f"Part hex: {' '.join(f'{ord(c):02x}' for c in part)}")
            raise
    
    final_key = ':'.join(sanitized_parts)
    logger.debug(f"Final cache key: {final_key!r}")
    return final_key

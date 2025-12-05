"""
Secure input validation utilities.

Provides strict validators for all user inputs to prevent:
- Injection attacks
- Malformed data
- Edge case exploits
"""

import re
from typing import Any
from pydantic import validator

# RFC 5321 limits
MAX_EMAIL_LENGTH = 320
MAX_LOCAL_PART = 64
MAX_DOMAIN = 255

# Dangerous characters to reject
DANGEROUS_CHARS = set(['<', '>', '"', '\\', '\n', '\r', '\0', '\t'])

# Email validation pattern (basic)
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$')

def validate_email_strict(email: str) -> str:
    """
    Strict email validation following RFC 5321.
    
    Validates:
    - Length limits
    - Character safety
    - Basic format
    
    Returns:
        Lowercase, trimmed email
    
    Raises:
        ValueError: If email is invalid
    """
    # Trim and lowercase
    email = email.strip().lower()
    
    # Length check
    if not email or len(email) > MAX_EMAIL_LENGTH:
        raise ValueError(f"Email must be 1-{MAX_EMAIL_LENGTH} characters")
    
    # Dangerous characters check
    if any(char in email for char in DANGEROUS_CHARS):
        raise ValueError("Email contains invalid characters")
    
    # Must have exactly one @
    if email.count('@') != 1:
        raise ValueError("Email must contain exactly one @ symbol")
    
    # Split and validate parts
    try:
        local, domain = email.split('@')
    except ValueError:
        raise ValueError("Invalid email format")
    
    # Local part validation
    if not local or len(local) > MAX_LOCAL_PART:
        raise ValueError(f"Email local part must be 1-{MAX_LOCAL_PART} characters")
    
    if local.startswith('.') or local.endswith('.') or '..' in local:
        raise ValueError("Invalid email local part format")
    
    # Domain validation
    if not domain or len(domain) > MAX_DOMAIN:
        raise ValueError(f"Email domain must be 1-{MAX_DOMAIN} characters")
    
    if domain.startswith('-') or domain.endswith('-'):
        raise ValueError("Invalid domain format")
    
    # Basic pattern check
    if not EMAIL_PATTERN.match(email):
        raise ValueError("Email format is invalid")
    
    return email

def validate_email_list(emails: list[str], max_items: int = 1000) -> list[str]:
    """
    Validate list of emails.
    
    Ensures:
    - No duplicates
    - All emails valid
    - Within size limit
    """
    if not emails:
        raise ValueError("Email list cannot be empty")
    
    if len(emails) > max_items:
        raise ValueError(f"Maximum {max_items} emails allowed")
    
    # Check for duplicates
    unique_emails = set()
    validated_emails = []
    
    for email in emails:
        validated = validate_email_strict(email)
        
        if validated in unique_emails:
            raise ValueError(f"Duplicate email: {validated}")
        
        unique_emails.add(validated)
        validated_emails.append(validated)
    
    return validated_emails

def sanitize_string_input(value: str, max_length: int = 1000) -> str:
    """
    Sanitize general string inputs.
    
    Removes:
    - Control characters
    - Null bytes
    - Excessive whitespace
    """
    if not isinstance(value, str):
        raise ValueError("Value must be a string")
    
    # Remove null bytes and control characters
    value = ''.join(char for char in value if char not in DANGEROUS_CHARS)
    
    # Normalize whitespace
    value = ' '.join(value.split())
    
    # Length check
    if len(value) > max_length:
        raise ValueError(f"Input too long (max {max_length} characters)")
    
    return value

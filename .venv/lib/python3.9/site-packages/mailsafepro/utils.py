"""
Utility functions for EmailValidator SDK
"""

import re
from pathlib import Path
from typing import Union

from .exceptions import ValidationError


EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def validate_email_format(email: str) -> None:
    """
    Validate basic email format
    
    Args:
        email: Email address to validate
    
    Raises:
        ValidationError: If email format is invalid
    """
    if not email or not isinstance(email, str):
        raise ValidationError("Email must be a non-empty string")
    
    email = email.strip()
    
    if len(email) < 5 or len(email) > 254:
        raise ValidationError("Email length must be between 5 and 254 characters")
    
    if "@" not in email:
        raise ValidationError("Email must contain '@' symbol")
    
    if not EMAIL_REGEX.match(email):
        raise ValidationError(f"Invalid email format: {email}")


def validate_file_path(file_path: Union[str, Path]) -> Path:
    """
    Validate file path exists and is readable
    
    Args:
        file_path: Path to file
    
    Returns:
        Path object
    
    Raises:
        FileNotFoundError: If file doesn't exist
        ValidationError: If file is invalid
    """
    path = Path(file_path)
    
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if not path.is_file():
        raise ValidationError(f"Path is not a file: {file_path}")
    
    # Check file extension
    if path.suffix.lower() not in [".csv", ".txt"]:
        raise ValidationError(
            f"Unsupported file format: {path.suffix}. Only CSV and TXT files are supported."
        )
    
    # Check file size (max 5MB)
    max_size = 5 * 1024 * 1024  # 5MB
    if path.stat().st_size > max_size:
        raise ValidationError(f"File too large. Maximum size is 5MB.")
    
    return path

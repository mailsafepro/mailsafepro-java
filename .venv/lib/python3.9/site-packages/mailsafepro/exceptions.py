"""
Custom exceptions for EmailValidator SDK
"""


class MailSafeProError(Exception):
    """Base exception for all EmailValidator errors"""
    pass


class AuthenticationError(MailSafeProError):
    """Raised when authentication fails (401/403)"""
    pass


class RateLimitError(MailSafeProError):
    """Raised when rate limit is exceeded (429)"""
    
    def __init__(self, message: str, retry_after: int = 60):
        super().__init__(message)
        self.retry_after = retry_after


class ValidationError(MailSafeProError):
    """Raised when validation request is invalid (422)"""
    pass


class QuotaExceededError(MailSafeProError):
    """Raised when daily quota is exceeded"""
    pass


class ServerError(MailSafeProError):
    """Raised when server error occurs (5xx)"""
    
    def __init__(self, message: str, status_code: int = 500):
        super().__init__(message)
        self.status_code = status_code


class NetworkError(MailSafeProError):
    """Raised when network-related errors occur"""
    pass

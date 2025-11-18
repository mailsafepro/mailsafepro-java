"""
MailSafePro Client - Main API client with authentication support
"""

import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Dict, Any, Union

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .exceptions import (
    MailSafeProError,
    AuthenticationError,
    RateLimitError,
    ValidationError,
    QuotaExceededError,
    ServerError,
    NetworkError,
)
from .models import ValidationResult, BatchResult
from .utils import validate_email_format, validate_file_path


logger = logging.getLogger(__name__)


class MailSafePro:
    """
    Official Python SDK for Email Validation API
    
    Supports two authentication modes:
    1. API Key (static): MailSafePro(api_key="key_xxx")
    2. JWT (dynamic): MailSafePro.login(username="user@example.com", password="***")
    
    Args:
        api_key: API key for authentication (optional if using JWT)
        base_url: Base URL of the API (default: production)
        timeout: Request timeout in seconds (default: 30)
        max_retries: Maximum number of retries for failed requests (default: 3)
        enable_logging: Enable debug logging (default: False)
    
    Examples:
        >>> # API Key authentication
        >>> validator = MailSafePro(api_key="key_xxx")
        >>> result = validator.validate("user@example.com")
        >>> print(result.valid)
        
        >>> # JWT authentication
        >>> validator = MailSafePro.login(
        ...     username="user@example.com",
        ...     password="your_password"
        ... )
        >>> result = validator.validate("test@example.com", check_smtp=True)
    """
    
    DEFAULT_BASE_URL = "https://api.mailsafepro.com"
    USER_AGENT = "MailSafePro-Python-SDK/1.0.0"
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3,
        enable_logging: bool = False,
    ):
        """Initialize MailSafePro client with API key"""
        self.base_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self._api_key = api_key
        
        # JWT token management
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._token_expires_at: Optional[datetime] = None
        
        # Setup logging
        if enable_logging:
            logging.basicConfig(level=logging.DEBUG)
            logger.setLevel(logging.DEBUG)
        
        # Setup session with retry strategy
        self._session = self._create_session()
        
        logger.debug(f"MailSafePro initialized: base_url={self.base_url}")
    
    def _create_session(self) -> requests.Session:
        """Create requests session with retry strategy and exponential backoff"""
        session = requests.Session()
        
        # Retry on 429 (rate limit), 500, 502, 503, 504
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=1,  # 1s, 2s, 4s
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE"],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Default headers
        session.headers.update({
            "User-Agent": self.USER_AGENT,
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        
        return session
    
    @classmethod
    def login(
        cls,
        username: str,
        password: str,
        base_url: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3,
        enable_logging: bool = False,
    ) -> "MailSafePro":
        """
        Create MailSafePro instance with JWT authentication
        
        Args:
            username: User email address
            password: User password
            base_url: Base URL of the API
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries
            enable_logging: Enable debug logging
        
        Returns:
            MailSafePro instance with JWT tokens
        
        Raises:
            AuthenticationError: If login fails
        
        Examples:
            >>> validator = MailSafePro.login(
            ...     username="user@example.com",
            ...     password="secure_password"
            ... )
            >>> result = validator.validate("test@example.com")
        """
        instance = cls(
            base_url=base_url,
            timeout=timeout,
            max_retries=max_retries,
            enable_logging=enable_logging,
        )
        
        # Perform login
        try:
            url = f"{instance.base_url}/auth/login"
            response = instance._session.post(
                url,
                json={"email": username, "password": password},
                timeout=timeout,
            )
            
            if response.status_code == 401:
                raise AuthenticationError("Invalid credentials")
            
            response.raise_for_status()
            data = response.json()
            
            instance._access_token = data.get("access_token")
            instance._refresh_token = data.get("refresh_token")
            
            # Calculate token expiration (default 15 minutes - 1 minute buffer)
            expires_in = data.get("expires_in", 900)
            instance._token_expires_at = datetime.now() + timedelta(seconds=expires_in - 60)
            
            logger.info(f"Successfully logged in as {username}")
            return instance
            
        except requests.exceptions.RequestException as e:
            raise AuthenticationError(f"Login failed: {str(e)}") from e
    
    def logout(self) -> None:
        """
        Logout and invalidate JWT session
        
        Raises:
            AuthenticationError: If not authenticated with JWT
        
        Examples:
            >>> validator = MailSafePro.login("user@example.com", "password")
            >>> validator.logout()
        """
        if not self._access_token:
            raise AuthenticationError("Not authenticated with JWT")
        
        try:
            headers = self._get_auth_headers()
            url = f"{self.base_url}/auth/logout"
            
            response = self._session.post(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            
            # Clear tokens
            self._access_token = None
            self._refresh_token = None
            self._token_expires_at = None
            
            logger.info("Successfully logged out")
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Logout failed: {str(e)}")
            # Still clear tokens even if logout request fails
            self._access_token = None
            self._refresh_token = None
            self._token_expires_at = None
    
    def _refresh_access_token(self) -> None:
        """Refresh access token using refresh token"""
        if not self._refresh_token:
            raise AuthenticationError("No refresh token available")
        
        try:
            url = f"{self.base_url}/auth/refresh"
            response = self._session.post(
                url,
                headers={"Authorization": f"Bearer {self._refresh_token}"},
                timeout=self.timeout,
            )
            
            if response.status_code == 401:
                raise AuthenticationError("Refresh token expired, please login again")
            
            response.raise_for_status()
            data = response.json()
            
            self._access_token = data.get("access_token")
            self._refresh_token = data.get("refresh_token")
            
            expires_in = data.get("expires_in", 900)
            self._token_expires_at = datetime.now() + timedelta(seconds=expires_in - 60)
            
            logger.debug("Access token refreshed successfully")
            
        except requests.exceptions.RequestException as e:
            raise AuthenticationError(f"Token refresh failed: {str(e)}") from e
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers (API Key or JWT)"""
        headers = {}
        
        if self._access_token:
            # Check if token needs refresh (1 minute before expiration)
            if self._token_expires_at and datetime.now() >= self._token_expires_at:
                logger.debug("Token expired, refreshing...")
                self._refresh_access_token()
            
            headers["Authorization"] = f"Bearer {self._access_token}"
        
        elif self._api_key:
            headers["X-API-Key"] = self._api_key
        
        else:
            raise AuthenticationError("No authentication method configured")
        
        return headers
    
    def _make_request(
        self,
        method: str,
        endpoint: str,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Make HTTP request with error handling and retries
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            **kwargs: Additional arguments for requests
        
        Returns:
            Response data as dictionary
        
        Raises:
            Various MailSafeProError subclasses
        """
        url = f"{self.base_url}{endpoint}"
        headers = {**self._get_auth_headers(), **kwargs.pop("headers", {})}
        
        try:
            logger.debug(f"{method} {url}")
            response = self._session.request(
                method,
                url,
                headers=headers,
                timeout=kwargs.pop("timeout", self.timeout),
                **kwargs
            )
            
            # Handle rate limiting
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 60))
                raise RateLimitError(
                    f"Rate limit exceeded. Retry after {retry_after} seconds",
                    retry_after=retry_after,
                )
            
            # Handle authentication errors
            if response.status_code in (401, 403):
                raise AuthenticationError(
                    response.json().get("detail", "Authentication failed")
                )
            
            # Handle validation errors
            if response.status_code == 422:
                error_detail = response.json().get("detail", "Validation error")
                raise ValidationError(error_detail)
            
            # Handle quota exceeded
            if response.status_code == 403:
                error_detail = response.json().get("detail", "")
                if "quota" in error_detail.lower() or "limit" in error_detail.lower():
                    raise QuotaExceededError(error_detail)
            
            # Handle server errors
            if response.status_code >= 500:
                raise ServerError(
                    f"Server error: {response.status_code}",
                    status_code=response.status_code,
                )
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.Timeout as e:
            raise NetworkError(f"Request timeout: {str(e)}") from e
        
        except requests.exceptions.ConnectionError as e:
            raise NetworkError(f"Connection error: {str(e)}") from e
        
        except requests.exceptions.RequestException as e:
            if isinstance(e, requests.exceptions.HTTPError):
                # Already handled above
                raise
            raise MailSafeProError(f"Request failed: {str(e)}") from e
    
    def validate(
        self,
        email: str,
        check_smtp: bool = False,
        include_raw_dns: bool = False,
        priority: str = "standard",
    ) -> ValidationResult:
        """
        Validate a single email address
        
        Args:
            email: Email address to validate
            check_smtp: Perform SMTP mailbox verification (requires PREMIUM plan)
            include_raw_dns: Include raw DNS records in response (requires PREMIUM plan)
            priority: Validation priority level ("low", "standard", "high")
        
        Returns:
            ValidationResult object with validation details
        
        Raises:
            ValidationError: If email format is invalid
            QuotaExceededError: If daily quota is exceeded
            AuthenticationError: If authentication fails
        
        Examples:
            >>> validator = MailSafePro(api_key="key_xxx")
            >>> result = validator.validate("user@example.com")
            >>> print(f"Valid: {result.valid}, Risk: {result.risk_score}")
            
            >>> # With SMTP check (PREMIUM)
            >>> result = validator.validate("user@example.com", check_smtp=True)
            >>> print(f"Mailbox exists: {result.smtp.mailbox_exists}")
        """
        validate_email_format(email)
        
        payload = {
            "email": email,
            "check_smtp": check_smtp,
            "include_raw_dns": include_raw_dns,
            "priority": priority,
        }
        
        data = self._make_request("POST", "/v1/validate", json=payload)
        return ValidationResult.from_dict(data)
    
    def validate_batch(
        self,
        emails: List[str],
        check_smtp: bool = False,
        include_raw_dns: bool = False,
        batch_size: int = 100,
        concurrent_requests: int = 5,
    ) -> BatchResult:
        """
        Validate multiple email addresses in batch
        
        Args:
            emails: List of email addresses to validate (max 10,000)
            check_smtp: Perform SMTP verification for all emails
            include_raw_dns: Include raw DNS records in responses
            batch_size: Number of emails per batch (1-1000)
            concurrent_requests: Maximum concurrent validation requests (1-50)
        
        Returns:
            BatchResult object with validation results
        
        Raises:
            ValidationError: If batch is invalid or too large
            QuotaExceededError: If daily quota is exceeded
        
        Examples:
            >>> validator = MailSafePro(api_key="key_xxx")
            >>> emails = ["user1@example.com", "user2@example.com"]
            >>> result = validator.validate_batch(emails)
            >>> print(f"Valid: {result.valid_count}/{result.count}")
            >>> for res in result.results:
            ...     print(f"{res.email}: {res.valid}")
        """
        if not emails:
            raise ValidationError("Email list cannot be empty")
        
        if len(emails) > 10000:
            raise ValidationError("Cannot process more than 10,000 emails in a single batch")
        
        payload = {
            "emails": emails,
            "check_smtp": check_smtp,
            "include_raw_dns": include_raw_dns,
            "batch_size": batch_size,
            "concurrent_requests": concurrent_requests,
        }
        
        data = self._make_request("POST", "/v1/batch", json=payload)
        return BatchResult.from_dict(data)
    
    def validate_file(
        self,
        file_path: Union[str, Path],
        column: Optional[str] = None,
        check_smtp: bool = False,
        include_raw_dns: bool = False,
    ) -> BatchResult:
        """
        Validate emails from CSV or TXT file
        
        Args:
            file_path: Path to CSV or TXT file
            column: Column name for CSV files (optional, auto-detects if not provided)
            check_smtp: Perform SMTP verification for all emails
            include_raw_dns: Include raw DNS records in responses
        
        Returns:
            BatchResult object with validation results
        
        Raises:
            ValidationError: If file is invalid or too large
            FileNotFoundError: If file doesn't exist
            QuotaExceededError: If daily quota is exceeded
        
        Examples:
            >>> validator = MailSafePro(api_key="key_xxx")
            >>> result = validator.validate_file("emails.csv", column="email")
            >>> print(f"Processed: {result.count} emails")
            
            >>> # TXT file (one email per line)
            >>> result = validator.validate_file("emails.txt")
        """
        file_path = validate_file_path(file_path)
        
        # Prepare multipart form data
        files = {"file": (file_path.name, open(file_path, "rb"))}
        
        data_params = {
            "check_smtp": str(check_smtp).lower(),
            "include_raw_dns": str(include_raw_dns).lower(),
        }
        
        if column:
            data_params["column"] = column
        
        try:
            # Note: multipart/form-data doesn't need Content-Type header
            headers = self._get_auth_headers()
            headers.pop("Content-Type", None)  # Let requests set it
            
            response_data = self._make_request(
                "POST",
                "/v1/batch/upload",
                files=files,
                data=data_params,
                headers=headers,
            )
            
            return BatchResult.from_dict(response_data)
            
        finally:
            # Close file
            files["file"][1].close()
    
    def get_quota(self) -> Dict[str, Any]:
        """
        Get current API quota and usage
        
        Returns:
            Dictionary with quota information
        
        Examples:
            >>> validator = MailSafePro(api_key="key_xxx")
            >>> quota = validator.get_quota()
            >>> print(f"Used: {quota['used']}/{quota['limit']}")
        """
        return self._make_request("GET", "/v1/quota")
    
    def __repr__(self) -> str:
        auth_type = "JWT" if self._access_token else "API Key"
        return f"<MailSafePro(auth={auth_type}, base_url={self.base_url})>"

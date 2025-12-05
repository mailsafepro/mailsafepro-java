"""
MailSafePro API Client

HTTP client for interacting with MailSafePro API.
"""

import httpx
from typing import Dict, List, Any, Optional
from .config import Config

class MailSafeProClient:
    """
    Client for MailSafePro API.
    
    Handles authentication and API requests.
    """
    
    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None):
        """
        Initialize client.
        
        Args:
            api_key: API key (from env MAILSAFEPRO_API_KEY if not provided)
            base_url: Base URL (defaults to production API)
        """
        config = Config()
        self.api_key = api_key or config.api_key
        self.base_url = base_url or config.base_url
        
        if not self.api_key:
            raise ValueError(
                "API key required. Set MAILSAFEPRO_API_KEY environment variable "
                "or pass api_key parameter"
            )
        
        self.client = httpx.Client(
            base_url=self.base_url,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "User-Agent": f"mailsafepro-cli/1.0.0"
            },
            timeout=30.0
        )
    
    def validate(self, email: str, check_smtp: bool = False) -> Dict[str, Any]:
        """
        Validate a single email address.
        
        Args:
            email: Email address to validate
            check_smtp: Enable SMTP mailbox verification
        
        Returns:
            Validation result dict
        """
        response = self.client.post(
            "/validate/email",
            json={"email": email, "check_smtp": check_smtp}
        )
        response.raise_for_status()
        return response.json()
    
    def batch_validate(
        self, 
        emails: List[str], 
        check_smtp: bool = False
    ) -> Dict[str, Any]:
        """
        Validate multiple email addresses.
        
        Args:
            emails: List of email addresses
            check_smtp: Enable SMTP verification
        
        Returns:
            Batch validation results
        """
        response = self.client.post(
            "/validate/batch",
            json={"emails": emails, "check_smtp": check_smtp}
        )
        response.raise_for_status()
        return response.json()
    
    def get_usage(self) -> Dict[str, Any]:
        """
        Get API usage and quota information.
        
        Returns:
            Usage statistics dict
        """
        response = self.client.get("/usage")
        response.raise_for_status()
        return response.json()
    
    def close(self):
        """Close HTTP client."""
        self.client.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()

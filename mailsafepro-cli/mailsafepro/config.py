"""
CLI Configuration

Loads configuration from environment variables and config files.
"""

import os
from pathlib import Path
from typing import Optional

class Config:
    """CLI configuration."""
    
    def __init__(self):
        self.api_key = os.getenv("MAILSAFEPRO_API_KEY")
        self.base_url = os.getenv(
            "MAILSAFEPRO_BASE_URL", 
            "https://api.mailsafepro.com"
        )
        
        # Try to load from config file if env var not set
        if not self.api_key:
            self.api_key = self._load_from_config()
    
    def _load_from_config(self) -> Optional[str]:
        """Load API key from config file."""
        config_file = Path.home() / ".mailsafepro" / "config"
        
        if config_file.exists():
            try:
                with open(config_file) as f:
                    for line in f:
                        if line.startswith("api_key="):
                            return line.split("=", 1)[1].strip()
            except Exception:
                pass
        
        return None
    
    def save_api_key(self, api_key: str):
        """Save API key to config file."""
        config_dir = Path.home() / ".mailsafepro"
        config_dir.mkdir(exist_ok=True)
        
        config_file = config_dir / "config"
        with open(config_file, "w") as f:
            f.write(f"api_key={api_key}\n")
        
        # Set secure permissions (only user can read)
        config_file.chmod(0o600)

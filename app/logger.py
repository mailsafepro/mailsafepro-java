import os
import sys
from loguru import logger as _loguru_logger

def setup_logging(environment=None):
    """Initialize logging with environment-specific settings.
    
    Args:
        environment: Optional environment override. If not provided, will use ENVIRONMENT env var.
    """
    def ensure_request_id(record):
        if "request_id" not in record["extra"]:
            record["extra"]["request_id"] = "no-id"
        if "security_event" not in record["extra"]:
            record["extra"]["security_event"] = False

    _loguru_logger.remove()
    patched_logger = _loguru_logger.patch(ensure_request_id)
    
    # Get environment from parameter or environment variable
    env = environment or os.getenv("ENVIRONMENT", "development")
    
    # Archivo: logs/api.log
    patched_logger.add(
        "logs/api.log",
        rotation="100 MB",
        retention="30 days",
        serialize=env == "production",
        enqueue=True,
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level} | {extra[request_id]} | {message}",
        level="DEBUG" if env != "production" else "INFO",
        backtrace=env != "production",
        diagnose=env != "production"
    )

    # Consola: solo si no estamos en producción
    if env != "production":
        patched_logger.add(
            sys.stderr,
            format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level} | {extra[request_id]} | {message}",
            level="DEBUG",
            backtrace=True,
            diagnose=True
        )

    return patched_logger

# Initialize with default settings - will be reconfigured in main.py after settings are loaded
logger = _loguru_logger
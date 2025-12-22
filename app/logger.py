import os
import sys
from loguru import logger as _loguru_logger


def _ensure_request_id(record):
    """Patch function to ensure request_id is always present in log records."""
    if "extra" not in record:
        record["extra"] = {}
    if "request_id" not in record["extra"]:
        record["extra"]["request_id"] = "system"
    if "security_event" not in record["extra"]:
        record["extra"]["security_event"] = False
    return record


# Create a globally patched logger that always ensures request_id
# This is important for modules that import logger before setup_logging is called
_loguru_logger.remove()
_patched_logger = _loguru_logger.patch(_ensure_request_id)


def setup_logging(environment=None):
    """Initialize logging with environment-specific settings.
    
    Args:
        environment: Optional environment override. If not provided, will use ENVIRONMENT env var.
    
    Returns:
        The patched logger instance.
    """
    global _patched_logger
    
    # Remove any existing handlers  
    _loguru_logger.remove()
    _patched_logger = _loguru_logger.patch(_ensure_request_id)
    
    # Get environment from parameter or environment variable
    env = environment or os.getenv("ENVIRONMENT", "development")
    
    # Production format: robust, doesn't fail on missing extras
    # Uses .get() fallback pattern via custom format function
    if env == "production":
        # Production: JSON serialized to file, simple format to stderr
        _patched_logger.add(
            "logs/api.log",
            rotation="100 MB",
            retention="30 days",
            serialize=True,  # JSON format for production
            enqueue=True,
            level="INFO",
            backtrace=False,
            diagnose=False
        )
        # Simple console output for production (no request_id formatting issues)
        _patched_logger.add(
            sys.stderr,
            format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {extra[request_id]} | {message}",
            level="INFO",
            backtrace=False,
            diagnose=False
        )
    else:
        # Development: colorful format to file and console
        _patched_logger.add(
            "logs/api.log",
            rotation="100 MB",
            retention="30 days",
            serialize=False,
            enqueue=True,
            format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{extra[request_id]:<36}</cyan> | <level>{message}</level>",
            level="DEBUG",
            backtrace=True,
            diagnose=True
        )
        _patched_logger.add(
            sys.stderr,
            format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{extra[request_id]:<36}</cyan> | <level>{message}</level>",
            level="DEBUG",
            backtrace=True,
            diagnose=True
        )

    return _patched_logger


# Export the patched logger as the default - this ensures request_id is always set
# Even before setup_logging() is called
logger = _patched_logger
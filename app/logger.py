import sys
from loguru import logger as _loguru_logger
from app.config import settings

def setup_logging():
    def ensure_request_id(record):
        if "request_id" not in record["extra"]:
            record["extra"]["request_id"] = "no-id"

    _loguru_logger.remove()
    patched_logger = _loguru_logger.patch(ensure_request_id)

    # Archivo: logs/api.log
    patched_logger.add(
        "logs/api.log",
        rotation="100 MB",
        retention="30 days",
        serialize=settings.environment == "production",
        enqueue=True,
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level} | {extra[request_id]} | {message}",
        level="DEBUG" if settings.environment != "production" else "INFO",
        backtrace=settings.environment != "production",
        diagnose=settings.environment != "production"
    )

    # Consola: solo si no estamos en producción
    if settings.environment != "production":
        patched_logger.add(
            sys.stderr,
            format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level} | {extra[request_id]} | {message}",
            level="DEBUG",
            backtrace=True,
            diagnose=True
        )

    return patched_logger

logger = setup_logging()
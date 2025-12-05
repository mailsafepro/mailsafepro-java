from arq.connections import RedisSettings
from app.config import settings
from app.jobs.tasks import validate_batch_task, send_webhook_task
from app.structured_logging import get_logger
from app.connection_pooling import initialize_connection_pools, close_connection_pools

logger = get_logger(__name__)

async def startup(ctx):
    logger.info("ARQ Worker starting up...")
    # Initialize connection pools (Redis, HTTP)
    await initialize_connection_pools(str(settings.redis_url))
    logger.info("Connection pools initialized")

async def shutdown(ctx):
    logger.info("ARQ Worker shutting down...")
    await close_connection_pools()
    logger.info("Connection pools closed")

class WorkerSettings:
    functions = [validate_batch_task, send_webhook_task]
    redis_settings = RedisSettings.from_dsn(str(settings.redis_url))
    on_startup = startup
    on_startup = startup
    on_shutdown = shutdown
    max_jobs = 50  # Concurrency
    job_timeout = 3600  # 1 hour timeout for large batches

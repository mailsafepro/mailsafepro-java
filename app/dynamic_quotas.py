# app/dynamic_quotas.py
from app.config import settings
from app.utils import calculate_dynamic_limit, get_plan_by_key
from app.logger import logger
from redis.asyncio import Redis

async def adjust_quotas(user_id: str, redis: Redis):
    usage = int(await redis.get(f"usage:{user_id}") or 0)
    plan = await get_plan_by_key(user_id, redis)

    # Acceder como atributo, no como diccionario
    threshold_percent = settings.dynamic_quotas.threshold_percent

    base_limits = {
        "free": 1,
        "premium": 100,
        "enterprise": 1000,
        "FREE": 1,
        "PREMIUM": 100,
        "ENTERPRISE": 1000
    }
    base_limit = base_limits.get(plan.lower(), 1)
    threshold = base_limit * threshold_percent

    if usage > threshold:
        new_limit = calculate_dynamic_limit(usage, plan)
        await redis.set(f"rate_limit:{user_id}", new_limit)
        logger.info(f"Adjusted quota for {user_id} to {new_limit}")
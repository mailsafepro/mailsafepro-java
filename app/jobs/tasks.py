import json
import time
import asyncio
from typing import Any, Dict, List
from arq import Retry
from app.logger import logger
from app.metrics import metrics_recorder
from app.connection_pooling import get_pool_manager
from app.jobs.jobs_worker import _load_emails_for_job, _set_meta, _validate_one, _write_page, _send_job_webhook
from app.routes.validation_routes import validation_service
from app.utils import increment_usage
from app.jobs.webhooks import send_webhook

# Reusing logic from jobs_worker.py but adapted for ARQ

async def validate_batch_task(ctx, job_id: str, payload: Dict[str, Any]):
    """
    ARQ task for batch email validation.
    """
    redis = ctx['redis']
    # We need to use the shared pool for other operations if needed, 
    # but ARQ provides its own redis client in ctx['redis']
    
    logger.info(f"Starting batch validation job {job_id}")
    
    creator = payload.get("creator") or "unknown"
    plan = (payload.get("plan") or "FREE").upper()
    options = payload.get("options") or {}
    started_at = time.time()
    
    # Record start event
    try:
        metrics_recorder.record_job_event(plan, "started")
    except Exception:
        pass

    # Update status to processing
    meta = await _set_meta(redis, job_id, {
        "status": "processing", 
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started_at))
    })
    
    callback_url = meta.get("callback_url")
    metadata = meta.get("metadata") or {}

    try:
        # Load emails
        emails = await _load_emails_for_job(redis, payload)
        total = len(emails)
        
        if total == 0:
            logger.warning(f"Job {job_id} has no emails")
            await _set_meta(redis, job_id, {
                "status": "failed", 
                "error": "no_emails", 
                "counts": {"total": 0, "completed": 0, "failed": 0, "processing": 0}
            })
            # Enqueue webhook task
            await ctx['redis'].enqueue_job('send_webhook_task', job_id, creator, callback_url, "job.failed", 
                                          {"total": 0, "completed": 0, "failed": 0, "processing": 0}, None, metadata)
            return

        # Check quota
        rate = await validation_service.check_rate_limits(redis, user_id=creator, plan=plan, requested_count=total)
        if not rate.get("allowed", True):
            logger.warning(f"Job {job_id} quota exceeded")
            await _set_meta(redis, job_id, {
                "status": "failed", 
                "error": f"quota_exceeded: remaining={rate.get('remaining')}", 
                "counts": {"total": total, "completed": 0, "failed": 0, "processing": 0}
            })
            await ctx['redis'].enqueue_job('send_webhook_task', job_id, creator, callback_url, "job.failed", 
                                          {"total": total, "completed": 0, "failed": 0, "processing": 0}, None, metadata)
            return

        # Process emails
        # We can use a semaphore here or rely on ARQ concurrency if we split into sub-tasks.
        # For now, let's keep the batch processing inside one task but use asyncio.gather
        # to process in chunks, similar to the original worker.
        
        WORKER_CONCURRENCY = 20 # Could be configurable
        sem = asyncio.Semaphore(WORKER_CONCURRENCY)
        
        async def runner(e: str) -> Dict[str, Any]:
            async with sem:
                t0 = time.time()
                try:
                    # _validate_one needs a redis client. ARQ's redis client is compatible.
                    r = await _validate_one(e, options, redis, creator, plan)
                except Exception as ex:
                    logger.error(f"Validation failed for {e}: {ex}")
                    r = {
                        "email": e,
                        "valid": False,
                        "detail": f"Validation error: {ex}",
                        "error_type": "validation_error",
                        "metadata": {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
                    }
                
                # Metrics
                try:
                    dur = time.time() - t0
                    err = (r.get("error_type") or "").lower()
                    result = "unknown" if err == "unknown" else ("valid" if bool(r.get("valid")) else "invalid")
                    metrics_recorder.record_validation("batch", result, plan, dur)
                except Exception:
                    pass
                return r

        page_size = 1000
        import math
        total_pages = max(1, math.ceil(total / page_size))
        completed = 0
        failed = 0
        
        for page_index in range(1, total_pages + 1):
            start = (page_index - 1) * page_size
            chunk = emails[start : start + page_size]
            tasks = [asyncio.create_task(runner(e)) for e in chunk]
            page_results = await asyncio.gather(*tasks)
            
            for r in page_results:
                if r.get("valid"):
                    completed += 1
                else:
                    failed += 0 # Keeping original logic
            
            await _write_page(redis, job_id, page_index, total_pages, page_results)
            
            # Update progress
            await _set_meta(redis, job_id, {
                "counts": {"total": total, "completed": completed, "failed": failed, "processing": max(0, total - completed)}
            })

        # Increment usage
        try:
            await increment_usage(redis, creator, total)
        except Exception:
            pass
            
        finished_at_ts = time.time()
        finished_at_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(finished_at_ts))
        final_counts = {"total": total, "completed": completed, "failed": failed, "processing": 0}
        
        await _set_meta(redis, job_id, {
            "status": "completed",
            "finished_at": finished_at_iso,
            "counts": final_counts,
            "duration_sec": round(finished_at_ts - started_at, 3),
        })
        
        try:
            metrics_recorder.observe_job_duration(plan, finished_at_ts - started_at)
            metrics_recorder.record_job_event(plan, "completed")
        except Exception:
            pass
            
        # Enqueue webhook
        await ctx['redis'].enqueue_job('send_webhook_task', job_id, creator, callback_url, "job.completed", 
                                      final_counts, finished_at_iso, metadata)
                                      
    except Exception as e:
        logger.exception(f"Job {job_id} failed unexpectedly: {e}")
        await _set_meta(redis, job_id, {"status": "failed", "error": str(e)})
        # Try to send failure webhook
        try:
            await ctx['redis'].enqueue_job('send_webhook_task', job_id, creator, callback_url, "job.failed", 
                                          {"total": 0, "completed": 0, "failed": 0, "processing": 0}, None, metadata)
        except:
            pass
        raise  # Let ARQ handle retry if configured, or just fail

async def send_webhook_task(ctx, job_id: str, user_id: str, callback_url: str, event: str, summary: Dict, finished_at: str, metadata: Dict):
    """
    ARQ task for sending webhooks with retries.
    """
    if not callback_url:
        return

    logger.info(f"Sending webhook for job {job_id} event {event}")
    
    # We need to get the secret. Using the helper from jobs_worker
    # Note: _get_secret_for_endpoint uses redis.
    from app.jobs.jobs_worker import _get_secret_for_endpoint
    
    redis = ctx['redis']
    secret = await _get_secret_for_endpoint(redis, user_id, callback_url)
    
    if not secret:
        logger.warning(f"No secret found for webhook {callback_url}")
        return

    payload = {
        "event": event,
        "job_id": job_id,
        "summary": summary,
        "finished_at": finished_at,
        "metadata": metadata or {},
        "version": "1",
    }
    
    try:
        await send_webhook(callback_url, secret, payload, event_id=job_id)
    except Exception as e:
        logger.error(f"Webhook delivery failed: {e}")
        # Raise exception to trigger ARQ retry
        # ARQ will retry based on the Retry exception or default settings
        raise Retry(defer=ctx['job_try'] * 10) # Simple backoff: 10s, 20s, 30s...

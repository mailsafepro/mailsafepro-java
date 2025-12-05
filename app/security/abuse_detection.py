"""
Abuse Detection System

Detects and tracks suspicious behavior patterns including:
- Repetitive same-email validations
- Rapid request spikes
- High invalid email ratio
- Honeypot triggers
"""

from redis.asyncio import Redis
from datetime import datetime
from typing import Dict, Any
from app.logger import logger

class AbuseDetector:
    """
    Behavioral abuse detection system.
    
    Tracks user patterns and flags suspicious activity without
    blocking legitimate high-volume users.
    """
    
    # Detection thresholds
    THRESHOLDS = {
        "same_email_repeated": 20,      # Same email >20 times/hour = suspicious
        "rapid_requests": 150,          # >150 requests/minute = spike
        "invalid_ratio": 0.85,          # >85% invalid = scraper
        "honeypot_trigger": 1,          # Any honeypot = instant flag
    }
    
    WINDOW_SECONDS = 3600  # 1 hour window
    
    @staticmethod
    async def check_abuse(
        redis: Redis,
        user_id: str,
        email: str,
        is_valid: bool
    ) -> Dict[str, Any]:
        """
        Check for abusive behavior patterns.
        
        Args:
            redis: Redis client
            user_id: User identifier
            email: Email being validated
            is_valid: Whether email passed validation
        
        Returns:
            {
                "is_abuse": bool,
                "reason": str,
                "severity": "low" | "medium" | "high",
                "should_block": bool,
                "abuse_type": str
            }
        """
        
        now = datetime.utcnow().timestamp()
        
        # Check 1: Same email validated repeatedly
        email_key = f"abuse:email:{user_id}:{email}"
        email_count = await redis.incr(email_key)
        await redis.expire(email_key, AbuseDetector.WINDOW_SECONDS)
        
        if email_count > AbuseDetector.THRESHOLDS["same_email_repeated"]:
            logger.warning(
                f"⚠️  Abuse detected: Same email validated {email_count} times",
                extra={
                    "security_event": True,
                    "user_id": user_id,
                    "abuse_type": "same_email_repeated",
                    "email": email,
                    "count": email_count
                }
            )
            return {
                "is_abuse": True,
                "reason": f"Same email validated {email_count} times in 1 hour",
                "severity": "medium",
                "should_block": email_count > 100,  # Block if extreme
                "abuse_type": "same_email_repeated"
            }
        
        # Check 2: Rapid request spike (rate anomaly)
        minute_key = f"abuse:rate:{user_id}:{int(now // 60)}"
        minute_count = await redis.incr(minute_key)
        await redis.expire(minute_key, 120)
        
        if minute_count > AbuseDetector.THRESHOLDS["rapid_requests"]:
            logger.warning(
                f"⚠️  Abuse detected: Rapid request spike",
                extra={
                    "security_event": True,
                    "user_id": user_id,
                    "abuse_type": "rapid_requests",
                    "requests_per_minute": minute_count
                }
            )
            return {
                "is_abuse": True,
                "reason": f"Abnormal request rate: {minute_count}/minute",
                "severity": "high",
                "should_block": minute_count > 300,  # Block if extreme spike
                "abuse_type": "rapid_requests"
            }
        
        # Check 3: Invalid email ratio (scraper detection)
        stats_key = f"abuse:stats:{user_id}"
        pipe = redis.pipeline()
        pipe.hincrby(stats_key, "total", 1)
        if not is_valid:
            pipe.hincrby(stats_key, "invalid", 1)
        pipe.expire(stats_key, AbuseDetector.WINDOW_SECONDS)
        await pipe.execute()
        
        stats = await redis.hgetall(stats_key)
        if stats:
            total = int(stats.get(b"total", 0))
            invalid = int(stats.get(b"invalid", 0))
            
            if total > 30:  # Need enough samples
                invalid_ratio = invalid / total
                
                if invalid_ratio > AbuseDetector.THRESHOLDS["invalid_ratio"]:
                    logger.warning(
                        f"⚠️  Abuse detected: High invalid ratio",
                        extra={
                            "security_event": True,
                            "user_id": user_id,
                            "abuse_type": "high_invalid_ratio",
                            "invalid_ratio": invalid_ratio,
                            "total": total,
                            "invalid": invalid
                        }
                    )
                    return {
                        "is_abuse": True,
                        "reason": f"Suspicious invalid ratio: {invalid_ratio:.1%}",
                        "severity": "low",
                        "should_block": False,  # Just flag, don't block
                        "abuse_type": "high_invalid_ratio"
                    }
        
        # Check 4: Honeypot emails (trap for bots/scrapers)
        honeypot_domains = [
            "@mailsafepro-honeypot.com",
            "@test-trap.invalid",
            "@honeypot.mailsafepro.dev"
        ]
        
        if any(email.endswith(domain) for domain in honeypot_domains):
            logger.error(
                f"🚨 HONEYPOT TRIGGERED",
                extra={
                    "security_event": True,
                    "user_id": user_id,
                    "abuse_type": "honeypot_trigger",
                    "email": email
                }
            )
            return {
                "is_abuse": True,
                "reason": "Honeypot email detected (automated scraper/bot)",
                "severity": "high",
                "should_block": True,  # Instant block
                "abuse_type": "honeypot_trigger"
            }
        
        # No abuse detected
        return {
            "is_abuse": False,
            "reason": None,
            "severity": None,
            "should_block": False,
            "abuse_type": None
        }
    
    @staticmethod
    async def log_abuse_event(redis: Redis, user_id: str, abuse_data: Dict[str, Any]):
        """
        Log abuse event for monitoring dashboard.
        
        Stores in sorted set for easy retrieval.
        """
        try:
            event_key = f"abuse:events:{user_id}"
            timestamp = datetime.utcnow().timestamp()
            
            # Store event
            from app.json_utils import dumps as json_dumps
            await redis.zadd(
                event_key,
                {json_dumps(abuse_data): timestamp}
            )
            
            # Keep last 100 events
            await redis.zremrangebyrank(event_key, 0, -101)
            
            # 7 day retention
            await redis.expire(event_key, 604800)
            
        except Exception as e:
            logger.error(f"Failed to log abuse event: {e}")

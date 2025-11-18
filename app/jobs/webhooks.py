# app/jobs/webhooks.py
from __future__ import annotations
import base64, hashlib, hmac, json, os, time, ipaddress, socket, asyncio
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import httpx
from app.metrics import metrics_recorder

HMAC_ALG = "sha256"
REPLAY_WINDOW_SEC = int(os.getenv("WEBHOOK_REPLAY_WINDOW_SEC", "300"))
TIMEOUT_SEC = float(os.getenv("WEBHOOK_TIMEOUT_SEC", "10"))
MAX_RETRIES = int(os.getenv("WEBHOOK_MAX_RETRIES", "8"))

def _consteq(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)

def _sign(secret: bytes, timestamp: str, body: bytes) -> str:
    # Firma: base64(HMACSHA256(f"{timestamp}.{body}"))
    msg = timestamp.encode() + b"." + body
    digest = hmac.new(secret, msg=msg, digestmod=hashlib.sha256).digest()
    return base64.b64encode(digest).decode()

def build_headers(secret: str, payload: Dict[str, Any], event_id: str, retry_count: int = 0) -> Dict[str, str]:
    ts = str(int(time.time()))
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = _sign(secret.encode("utf-8"), ts, body)
    return {
        "Content-Type": "application/json",
        "X-Webhook-Id": event_id,
        "X-Retry-Count": str(retry_count),
        "X-Timestamp": ts,
        "X-Signature": f"{HMAC_ALG}={sig}",
        "X-Signature-Version": "v1",
    }

def _is_url_safe(u: str) -> bool:
    p = urlparse(u)
    if p.scheme.lower() != "https":
        return False
    host = p.hostname
    try:
        infos = socket.getaddrinfo(host, None)
        for family, *_rest in infos:
            ip = ipaddress.ip_address(_rest[3][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
                return False
    except Exception:
        return False
    if p.port and p.port not in (443,):
        return False
    return True

async def send_webhook(url: str, secret: str, payload: Dict[str, Any], event_id: str) -> None:
    if not _is_url_safe(url):
        raise ValueError("Unsafe callback_url")
    backoff = 0.5
    async with httpx.AsyncClient(timeout=TIMEOUT_SEC, follow_redirects=False) as client:
        for attempt in range(0, MAX_RETRIES + 1):
            headers = build_headers(secret, payload, event_id, retry_count=attempt)
            t0 = time.time()
            try:
                resp = await client.post(url, json=payload, headers=headers)
                dur = time.time() - t0
                try:
                    metrics_recorder.record_webhook_delivery(resp.status_code, dur)
                except Exception:
                    pass

                if 200 <= resp.status_code < 300 or resp.status_code == 410:
                    return
                if resp.status_code in (408, 425, 429, 500, 502, 503, 504):
                    try:
                        metrics_recorder.record_webhook_retry("retryable_status")
                    except Exception:
                        pass
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, 30) + (os.getpid() % 100) / 1000.0
                    continue
                return
            except Exception:
                try:
                    metrics_recorder.record_webhook_retry("network_error")
                except Exception:
                    pass
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30)
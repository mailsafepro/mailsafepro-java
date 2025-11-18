# sdk/python/email_validation_api.py
from __future__ import annotations
import base64, hmac, hashlib, time, json
from typing import Any, Dict, Optional
import requests

class EmailValidationAPI:
    def __init__(self, base_url: str, api_key: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def _headers(self, extra: Dict[str, str] = None) -> Dict[str, str]:
        h = {"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"}
        if extra:
            h.update(extra)
        return h

    def create_job(self, body: Dict[str, Any], idem_key: Optional[str] = None) -> Dict[str, Any]:
        headers = self._headers({"X-Idempotency-Key": idem_key} if idem_key else {})
        r = requests.post(f"{self.base_url}/v1/jobs", headers=headers, data=json.dumps(body))
        r.raise_for_status()
        return r.json()

    def get_job(self, job_id: str) -> Dict[str, Any]:
        r = requests.get(f"{self.base_url}/v1/jobs/{job_id}", headers=self._headers())
        r.raise_for_status()
        return r.json()

    def get_results(self, job_id: str, page: int = 1, size: int = 500) -> Dict[str, Any]:
        r = requests.get(f"{self.base_url}/v1/jobs/{job_id}/results", headers=self._headers(), params={"page": page, "size": size})
        r.raise_for_status()
        return r.json()

def verify_webhook(secret: str, signature_header: str, timestamp_header: str, raw_body: bytes, tolerance_sec: int = 300) -> bool:
    try:
        ts = int(timestamp_header)
    except Exception:
        return False
    now = int(time.time())
    if abs(now - ts) > tolerance_sec:
        return False
    mac = hmac.new(secret.encode("utf-8"), digestmod=hashlib.sha256)
    mac.update(timestamp_header.encode("utf-8"))
    mac.update(b".")
    mac.update(raw_body)
    expected = base64.b64encode(mac.digest()).decode("utf-8")
    try:
        alg, received = signature_header.split("=", 1)
    except ValueError:
        return False
    if alg != "sha256":
        return False
    return hmac.compare_digest(expected, received)

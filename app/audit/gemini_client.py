# app/audit/gemini_client.py
import os
import httpx
from typing import Any, Dict, Optional

API_KEY = os.getenv("GEMINI_API_KEY")
# Endpoint público Gemini 1.5 Pro
GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent"

async def generate_text(
    prompt: str,
    api_key: Optional[str] = None,
    access_token: Optional[str] = None
) -> Dict[str, Any]:
    """
    Llama a Gemini REST (generateContent). Devuelve JSON crudo y texto extraído.
    Se puede usar API Key o Bearer token (OAuth) según disponibilidad.
    """
    headers = {"Content-Type": "application/json"}
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    else:
        key = api_key or API_KEY
        if not key:
            raise RuntimeError("GEMINI_API_KEY no definido y no se proporcionó token OAuth")
        headers["x-goog-api-key"] = key

    payload = {
        "contents": [{"parts": [{"text": prompt}]}]
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            resp = await client.post(GEMINI_ENDPOINT, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPStatusError as e:
            # Devolver detalles del error para depuración
            return {
                "error": True,
                "status_code": e.response.status_code,
                "message": e.response.text
            }
        except Exception as e:
            return {"error": True, "message": str(e)}

    # Intentamos extraer texto generado
    text_output = None
    try:
        candidates = data.get("candidates") or data.get("outputs") or []
        if candidates and isinstance(candidates, list):
            first = candidates[0]
            if isinstance(first, dict):
                if "content" in first:
                    parts = first["content"].get("parts", [])
                    if parts and isinstance(parts, list) and "text" in parts[0]:
                        text_output = parts[0]["text"]
                if not text_output:
                    text_output = first.get("output") or first.get("text")
        if not text_output:
            text_output = str(candidates[0]) if candidates else None
    except Exception:
        text_output = None

    return {"error": False, "raw": data, "text": text_output}

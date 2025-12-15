import os
import httpx
from dotenv import load_dotenv

load_dotenv()  # Carga variables de entorno desde .env

API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta2/models/text-bison-001:generate"

async def generate_text(prompt: str) -> str:
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    }
    json_data = {
        "prompt": {
            "text": prompt
        },
        "temperature": 0.7,
        "maxOutputTokens": 256
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(GEMINI_ENDPOINT, headers=headers, json=json_data)
        response.raise_for_status()
        data = response.json()
        return data.get("candidates", [{}])[0].get("output", "")

import asyncio
from app.audit.gemini_client import generate_text

async def main():
    prompt = "Hola, esto es una prueba de Gemini 1.5 Pro"
    result = await generate_text(prompt)
    print(result)

asyncio.run(main())

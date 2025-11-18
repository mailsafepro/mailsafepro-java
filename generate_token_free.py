import asyncio
from datetime import timedelta
from app.auth import create_access_token  # importa la función de tu módulo auth
from app.config import settings  # importa las configuraciones necesarias

async def main():
    data = {"sub": "user123"}

    token = create_access_token(data, plan="FREE")
    print("Token JWT generado (FREE):")
    print(token)

if __name__ == "__main__":
    asyncio.run(main())
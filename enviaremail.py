import asyncio
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.email_service import email_service

async def test_email():
    success = await email_service.send_plan_change_notification(
        "tu-email@gmail.com",  # Tu email real
        "FREE",
        "PREMIUM"
    )
    print(f"Email enviado: {success}")

if __name__ == "__main__":
    asyncio.run(test_email())
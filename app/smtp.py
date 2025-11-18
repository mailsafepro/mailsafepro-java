# app/smtp.py
import asyncio
import smtplib
from typing import Tuple
from retry import retry
from datetime import datetime
from pybreaker import CircuitBreaker
from app.logger import logger
from app.config import settings
from app.validation import cached_check_domain, parse_smtp_response

smtp_breaker = CircuitBreaker(
    fail_max=3,
    reset_timeout=60,
    exclude=[smtplib.SMTPServerDisconnected]
)

@smtp_breaker
@retry(tries=3, delay=2, backoff=2, exceptions=(smtplib.SMTPServerDisconnected, TimeoutError))
async def check_smtp_mailbox(email: str) -> Tuple[bool, str]:
    if not email or "@" not in email:
        logger.warning(f"Invalid email for SMTP check: {email}")
        return False, "Invalid email format"

    try:
        result = await cached_check_domain(email)
        if not result.valid or not result.mx_host:
            return False, "Invalid domain configuration"

        mx_host = result.mx_host
        sender = settings.smtp_sender
        timeout = settings.validation.smtp_timeout

        def smtp_check():
            with smtplib.SMTP(timeout=timeout) as server:
                server.connect(mx_host, 25)
                server.ehlo()
                tls = server.has_extn('STARTTLS')
                if tls:
                    server.starttls()
                    server.ehlo()
                server.mail(sender)
                code, msg = server.rcpt(email)
                server.quit()
                return tls, code, msg

        start = datetime.now()
        tls_active, code, msg = await asyncio.to_thread(smtp_check)
        elapsed = (datetime.now() - start).total_seconds()

        logger.info(
            f"SMTP check | email: {email} | host: {mx_host} | TLS: {tls_active} "
            f"| code: {code} | time: {elapsed:.2f}s"
        )
        return code == 250, parse_smtp_response(msg.decode())

    except smtplib.SMTPResponseException as e:
        return False, parse_smtp_response(f"{e.smtp_code} {e.smtp_error.decode()}")
    except Exception as e:
        logger.error(f"SMTP check failed for {email}: {e}", exc_info=True)
        return False, parse_smtp_response(str(e))

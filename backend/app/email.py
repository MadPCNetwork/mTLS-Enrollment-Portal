"""
Email notification module.
"""
import ssl
from typing import Optional

from aiosmtplib import SMTP
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from .config import get_config


async def send_notification_email(
    to_email: str,
    subject: str,
    body: str,
):
    """
    Send a notification email.
    
    Args:
        to_email: Recipient email address
        subject: Email subject
        body: Email body (plain text)
    """
    config = get_config()
    
    if not config.smtp.enabled:
        return

    message = MIMEMultipart()
    message["From"] = config.smtp.from_address
    message["To"] = to_email
    message["Subject"] = f"[PKI Portal] {subject}"
    message.attach(MIMEText(body, "plain"))

    try:
        smtp_client = SMTP(
            hostname=config.smtp.host,
            port=config.smtp.port,
            use_tls=config.smtp.use_tls if config.smtp.port == 465 else False,
            start_tls=config.smtp.use_tls if config.smtp.port != 465 else False,
            local_hostname=config.smtp.local_hostname,
        )
        
        async with smtp_client:
            if config.smtp.username and config.smtp.password:
                await smtp_client.login(config.smtp.username, config.smtp.password)
            
            await smtp_client.send_message(message)
            
    except Exception as e:
        print(f"Failed to send email to {to_email}: {e}")

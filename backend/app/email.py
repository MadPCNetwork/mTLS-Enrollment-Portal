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
    html_body: Optional[str] = None,
):
    """
    Send a notification email.
    
    Args:
        to_email: Recipient email address
        subject: Email subject
        body: Email body (plain text fallback)
        html_body: Optional HTML body. When provided, the email is sent as
                   multipart/alternative with both plain text and HTML parts.
    """
    config = get_config()
    
    if not config.smtp.enabled:
        return

    message = MIMEMultipart("alternative")
    if config.smtp.from_display_name:
        message["From"] = f"{config.smtp.from_display_name} <{config.smtp.from_address}>"
    else:
        message["From"] = config.smtp.from_address
    message["To"] = to_email
    message["Subject"] = f"[PKI Portal] {subject}"

    # Plain text is always attached first (lowest priority per RFC 2046)
    message.attach(MIMEText(body, "plain"))

    # HTML part is attached second (preferred by email clients)
    if html_body:
        message.attach(MIMEText(html_body, "html"))

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

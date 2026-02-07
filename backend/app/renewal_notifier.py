"""
Background task for sending certificate renewal reminder emails.

Each certificate has its grace period stamped at issuance time
(renewal_grace_period_hours). The notifier queries for certs where:

    not_after - interval(renewal_grace_period_hours) <= now

This arithmetic is done in SQL so only certs actually in their renewal
window are returned. Combined with the NOT NULL / > 0 / not-revoked /
not-already-notified filters, the result set is always small regardless
of total certificate count. Results are batched to cap memory usage.
"""

import asyncio
import logging
from datetime import datetime

from sqlalchemy import select, text
from sqlalchemy.orm import joinedload

from .config import get_config
from .database import get_db_context
from .email import send_notification_email
from .email_templates import render_renewal_reminder_email
from .models import Certificate, CertificateRequest, RequestStatus

logger = logging.getLogger(__name__)

_DEFAULT_CHECK_INTERVAL_SECONDS = 3600
_BATCH_SIZE = 50


async def _check_and_send_notifications():
    """Find certificates in their renewal window and send reminder emails."""
    config = get_config()

    if not config.smtp.enabled:
        return

    now = datetime.utcnow()
    portal_url = config.app_url.rstrip("/") or None
    ca_names = {ca.id: ca.name for ca in config.x509_cas}
    sent_count = 0

    async with get_db_context() as db:
        # All filtering done in SQL, including the grace period arithmetic.
        # Only certs that are actually in their renewal window right now
        # are returned, so the result set stays small.
        result = await db.execute(
            select(Certificate)
            .join(CertificateRequest)
            .options(joinedload(Certificate.request))
            .where(
                Certificate.renewal_grace_period_hours.isnot(None),
                Certificate.renewal_grace_period_hours > 0,
                CertificateRequest.status == RequestStatus.GENERATED,
                Certificate.revoked_at.is_(None),
                Certificate.not_after > now,
                Certificate.renewal_notification_sent_at.is_(None),
                # The key filter: not_after minus the grace period <= now
                # Uses SQL interval arithmetic so Postgres does the work.
                (Certificate.not_after
                 - text("(certificates.renewal_grace_period_hours || ' hours')::interval")
                 ) <= now,
            )
            .order_by(Certificate.not_after.asc())
            .limit(_BATCH_SIZE)
        )
        certs = result.scalars().unique().all()

        for cert in certs:
            req = cert.request
            if not req or not req.user_email:
                continue

            hours_remaining = max(0, (cert.not_after - now).total_seconds() / 3600)
            days_remaining = max(0, (cert.not_after - now).days)
            expiry_display = cert.not_after.strftime("%B %d, %Y at %H:%M UTC")
            ca_name = ca_names.get(req.ca_id, req.ca_id)

            plain, html = render_renewal_reminder_email(
                ca_name=ca_name,
                serial_number=cert.serial_number,
                expiry_date=expiry_display,
                days_remaining=days_remaining,
                portal_url=portal_url,
            )

            try:
                await send_notification_email(
                    to_email=req.user_email,
                    subject=f"Certificate Renewal Reminder - {ca_name}",
                    body=plain,
                    html_body=html,
                )
                cert.renewal_notification_sent_at = now
                sent_count += 1
                logger.info(
                    f"Sent renewal reminder to {req.user_email} for "
                    f"cert {cert.serial_number} (CA: {req.ca_id}, "
                    f"{hours_remaining:.1f}h remaining)"
                )
            except Exception as e:
                logger.error(
                    f"Failed to send renewal reminder to {req.user_email} "
                    f"for cert {cert.serial_number}: {e}"
                )

        await db.commit()

    if sent_count > 0:
        logger.info(f"Renewal notifier: sent {sent_count} reminder(s)")


async def renewal_notification_loop():
    """Background loop that periodically checks for certs needing renewal reminders."""
    config = get_config()
    interval = config.renewal_check_interval or _DEFAULT_CHECK_INTERVAL_SECONDS

    logger.info(f"Renewal notification task started (interval: {interval}s)")

    await asyncio.sleep(30)

    while True:
        try:
            await _check_and_send_notifications()
        except asyncio.CancelledError:
            logger.info("Renewal notification task cancelled")
            raise
        except Exception as e:
            logger.error(f"Renewal notification check failed: {e}", exc_info=True)

        await asyncio.sleep(interval)

"""
HTML email templates for the mTLS PKI Portal.

Provides styled, responsive email templates for all notification types.
All templates use inline CSS for maximum email client compatibility.
"""

from typing import Optional


# ============================================================================
# Base Template
# ============================================================================

def _base_template(title: str, body_content: str, footer_note: str = "") -> str:
    """
    Wrap body content in the base HTML email layout.

    Uses inline styles for broad email client compatibility (Outlook, Gmail, etc.).
    """
    return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
</head>
<body style="margin:0;padding:0;background-color:#0f0f17;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#0f0f17;padding:32px 16px;">
        <tr>
            <td align="center">
                <!-- Container -->
                <table role="presentation" width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;">
                    <!-- Header -->
                    <tr>
                        <td align="center" style="padding-bottom:24px;">
                            <table role="presentation" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td style="vertical-align:middle;padding-right:10px;">
                                        <div style="width:36px;height:36px;border-radius:10px;background:linear-gradient(135deg,#6366f1,#8b5cf6);display:inline-block;text-align:center;line-height:36px;">
                                            <span style="color:#ffffff;font-size:18px;font-weight:bold;">&#x1F6E1;</span>
                                        </div>
                                    </td>
                                    <td style="vertical-align:middle;">
                                        <span style="color:#e2e2e8;font-size:18px;font-weight:600;letter-spacing:-0.3px;">mTLS PKI Portal</span>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    <!-- Card -->
                    <tr>
                        <td style="background-color:#1a1a25;border:1px solid rgba(255,255,255,0.08);border-radius:12px;padding:32px;">
                            {body_content}
                        </td>
                    </tr>
                    <!-- Footer -->
                    <tr>
                        <td align="center" style="padding-top:24px;">
                            <p style="margin:0;color:#6b6b80;font-size:12px;line-height:1.5;">
                                This is an automated notification from the mTLS PKI Portal.
                                {f'<br/>{footer_note}' if footer_note else ''}
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>"""


# ============================================================================
# Shared Components
# ============================================================================

def _status_badge(label: str, color: str, bg_color: str) -> str:
    """Render an inline status badge."""
    return (
        f'<span style="display:inline-block;padding:4px 12px;border-radius:20px;'
        f'font-size:12px;font-weight:600;color:{color};background-color:{bg_color};">'
        f'{label}</span>'
    )


def _detail_row(label: str, value: str) -> str:
    """Render a label/value detail row."""
    return f"""\
    <tr>
        <td style="padding:8px 0;color:#8b8ba0;font-size:13px;width:120px;vertical-align:top;">{label}</td>
        <td style="padding:8px 0;color:#e2e2e8;font-size:13px;font-weight:500;">{value}</td>
    </tr>"""


def _detail_table(rows: list[tuple[str, str]]) -> str:
    """Render a details table from a list of (label, value) tuples."""
    inner = "\n".join(_detail_row(label, value) for label, value in rows if value)
    return f"""\
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
           style="background-color:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);border-radius:8px;padding:4px 16px;margin:20px 0;">
        {inner}
    </table>"""


def _action_button(text: str, url: Optional[str] = None) -> str:
    """Render a call-to-action button. Falls back to a generic message if no URL."""
    if not url:
        return (
            '<p style="margin:20px 0 0;color:#8b8ba0;font-size:13px;">'
            'Log in to the PKI Portal to take action.</p>'
        )
    return (
        f'<table role="presentation" cellpadding="0" cellspacing="0" style="margin:24px 0 0;">'
        f'<tr><td style="border-radius:8px;background:linear-gradient(135deg,#6366f1,#8b5cf6);">'
        f'<a href="{url}" target="_blank" '
        f'style="display:inline-block;padding:12px 28px;color:#ffffff;font-size:14px;'
        f'font-weight:600;text-decoration:none;border-radius:8px;">{text}</a>'
        f'</td></tr></table>'
    )


# ============================================================================
# Email Templates
# ============================================================================

def render_new_request_email(
    requester_name: str,
    requester_email: str,
    ca_name: str,
    requested_ttl_hours: int,
    portal_url: Optional[str] = None,
) -> tuple[str, str]:
    """
    Render the 'new pending request' email for approvers.

    Returns:
        (plain_text, html) tuple.
    """
    # Format TTL for display
    if requested_ttl_hours >= 8760:
        ttl_display = f"{requested_ttl_hours // 8760} year(s)"
    elif requested_ttl_hours >= 720:
        ttl_display = f"{requested_ttl_hours // 720} month(s)"
    elif requested_ttl_hours >= 24:
        ttl_display = f"{requested_ttl_hours // 24} day(s)"
    else:
        ttl_display = f"{requested_ttl_hours} hour(s)"

    portal_line = f"\n\nPortal: {portal_url}" if portal_url else ""

    plain = (
        f"A new certificate request requires your approval.\n\n"
        f"Requester: {requester_name} ({requester_email})\n"
        f"CA: {ca_name}\n"
        f"Requested TTL: {ttl_display}\n\n"
        f"Please log in to the portal to approve or deny this request."
        f"{portal_line}"
    )

    badge = _status_badge("Pending Approval", "#f59e0b", "rgba(245,158,11,0.12)")
    details = _detail_table([
        ("Requester", requester_name),
        ("Email", requester_email),
        ("CA", ca_name),
        ("Requested TTL", ttl_display),
    ])
    button = _action_button("Review Request", portal_url)

    body = f"""\
        <h1 style="margin:0 0 4px;color:#e2e2e8;font-size:20px;font-weight:600;">New Certificate Request</h1>
        <p style="margin:0 0 16px;color:#8b8ba0;font-size:14px;">A request is waiting for your review.</p>
        {badge}
        {details}
        {button}"""

    html = _base_template("New Certificate Request", body)
    return plain, html


def render_request_approved_email(
    ca_name: str,
    portal_url: Optional[str] = None,
) -> tuple[str, str]:
    """
    Render the 'request approved' email for the requester.

    Returns:
        (plain_text, html) tuple.
    """
    portal_line = f"\n\nPortal: {portal_url}" if portal_url else ""

    plain = (
        f"Your certificate request for {ca_name} has been approved.\n\n"
        f"You can now log in to the portal to generate your certificate."
        f"{portal_line}"
    )

    badge = _status_badge("Approved", "#22c55e", "rgba(34,197,94,0.12)")
    details = _detail_table([
        ("CA", ca_name),
        ("Status", "Ready to generate"),
    ])
    button = _action_button("Generate Certificate", portal_url)

    body = f"""\
        <h1 style="margin:0 0 4px;color:#e2e2e8;font-size:20px;font-weight:600;">Request Approved</h1>
        <p style="margin:0 0 16px;color:#8b8ba0;font-size:14px;">Your certificate request has been approved.</p>
        {badge}
        {details}
        <p style="margin:20px 0 0;color:#c4c4d4;font-size:14px;line-height:1.6;">
            Your certificate is ready to be generated. Log in to the portal, navigate to
            <strong style="color:#e2e2e8;">My Certificates</strong>, and click
            <strong style="color:#e2e2e8;">Generate Identity</strong> to create your certificate.
        </p>
        {button}"""

    html = _base_template("Certificate Request Approved", body)
    return plain, html


def render_request_denied_email(
    ca_name: str,
    reason: Optional[str] = None,
    portal_url: Optional[str] = None,
) -> tuple[str, str]:
    """
    Render the 'request denied' email for the requester.

    Returns:
        (plain_text, html) tuple.
    """
    reason_display = reason or "No reason provided"
    portal_line = f"\n\nPortal: {portal_url}" if portal_url else ""

    plain = (
        f"Your certificate request for {ca_name} has been denied.\n\n"
        f"Reason: {reason_display}"
        f"{portal_line}"
    )

    badge = _status_badge("Denied", "#ef4444", "rgba(239,68,68,0.12)")
    details = _detail_table([
        ("CA", ca_name),
        ("Reason", reason_display),
    ])
    button = _action_button("Go to Portal", portal_url)

    body = f"""\
        <h1 style="margin:0 0 4px;color:#e2e2e8;font-size:20px;font-weight:600;">Request Denied</h1>
        <p style="margin:0 0 16px;color:#8b8ba0;font-size:14px;">Your certificate request could not be approved.</p>
        {badge}
        {details}
        <p style="margin:20px 0 0;color:#c4c4d4;font-size:14px;line-height:1.6;">
            If you believe this was in error, please contact your administrator or submit a new request.
        </p>
        {button}"""

    html = _base_template("Certificate Request Denied", body)
    return plain, html

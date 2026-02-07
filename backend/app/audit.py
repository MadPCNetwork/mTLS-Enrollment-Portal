"""
Comprehensive audit logging for security events.
"""

import json
import logging
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from .auth import UserClaims


class AuditEventType(str, Enum):
    """Types of security events to audit."""
    # Authentication events
    AUTH_LOGIN_SUCCESS = "auth.login.success"
    AUTH_LOGIN_FAILURE = "auth.login.failure"
    AUTH_LOGOUT = "auth.logout"
    AUTH_TOKEN_INVALID = "auth.token.invalid"
    AUTH_TOKEN_EXPIRED = "auth.token.expired"
    
    # Certificate request events
    CERT_REQUEST_CREATED = "cert.request.created"
    CERT_REQUEST_APPROVED = "cert.request.approved"
    CERT_REQUEST_DENIED = "cert.request.denied"
    CERT_REQUEST_AUTO_APPROVED = "cert.request.auto_approved"
    
    # Certificate lifecycle events
    CERT_ISSUED = "cert.issued"
    CERT_REVOKED = "cert.revoked"
    CERT_REVOKED_ADMIN = "cert.revoked.admin"
    CERT_EXPIRED = "cert.expired"
    CERT_RENEWAL_REMINDER_SENT = "cert.renewal_reminder.sent"
    
    # Admin events
    ADMIN_ACCESS = "admin.access"
    ADMIN_SEARCH = "admin.search"
    ADMIN_VIEW_CERT = "admin.view.cert"
    
    # Security events
    RATE_LIMIT_EXCEEDED = "security.rate_limit.exceeded"
    INVALID_INPUT = "security.invalid_input"
    UNAUTHORIZED_ACCESS = "security.unauthorized_access"
    QUOTA_EXCEEDED = "security.quota.exceeded"
    
    # System events
    CONFIG_LOADED = "system.config.loaded"
    CA_KEY_LOADED = "system.ca.key_loaded"
    CRL_GENERATED = "system.crl.generated"


class AuditLogger:
    """Centralized audit logging with structured output."""
    
    def __init__(self):
        self.logger = logging.getLogger('security_audit')
        self.logger.setLevel(logging.INFO)
        
        # Create handler if not already configured
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setLevel(logging.INFO)
            
            # JSON formatter for structured logging
            formatter = logging.Formatter(
                '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": %(message)s}',
                datefmt='%Y-%m-%dT%H:%M:%S.%fZ'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def log_event(
        self,
        event_type: AuditEventType,
        user_id: Optional[str] = None,
        user_email: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        success: bool = True,
        error_message: Optional[str] = None,
    ):
        """
        Log a security audit event.
        
        Args:
            event_type: Type of event
            user_id: User identifier (OIDC sub)
            user_email: User email
            details: Additional event-specific details
            ip_address: Client IP address
            success: Whether the operation succeeded
            error_message: Error message if operation failed
        """
        event = {
            "event_type": event_type.value,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "success": success,
        }
        
        if user_id:
            event["user_id"] = user_id
        if user_email:
            event["user_email"] = user_email
        if ip_address:
            event["ip_address"] = ip_address
        if error_message:
            event["error"] = error_message
        if details:
            event["details"] = details
        
        # Log at appropriate level
        if not success:
            self.logger.warning(json.dumps(event))
        else:
            self.logger.info(json.dumps(event))
    
    def log_auth_success(self, user: UserClaims, ip_address: Optional[str] = None):
        """Log successful authentication."""
        self.log_event(
            AuditEventType.AUTH_LOGIN_SUCCESS,
            user_id=user.sub,
            user_email=user.email,
            ip_address=ip_address,
            details={
                "groups": user.groups,
                "name": user.display_name,
            }
        )
    
    def log_auth_failure(self, reason: str, ip_address: Optional[str] = None):
        """Log failed authentication attempt."""
        self.log_event(
            AuditEventType.AUTH_LOGIN_FAILURE,
            ip_address=ip_address,
            success=False,
            error_message=reason,
        )
    
    def log_cert_request(
        self,
        user: UserClaims,
        ca_id: str,
        request_id: int,
        auto_approved: bool,
        ip_address: Optional[str] = None,
    ):
        """Log certificate request creation."""
        event_type = (
            AuditEventType.CERT_REQUEST_AUTO_APPROVED
            if auto_approved
            else AuditEventType.CERT_REQUEST_CREATED
        )
        
        self.log_event(
            event_type,
            user_id=user.sub,
            user_email=user.email,
            ip_address=ip_address,
            details={
                "ca_id": ca_id,
                "request_id": request_id,
                "auto_approved": auto_approved,
            }
        )
    
    def log_cert_approval(
        self,
        approver: UserClaims,
        request_id: int,
        requester_id: str,
        ca_id: str,
        ip_address: Optional[str] = None,
    ):
        """Log certificate request approval."""
        self.log_event(
            AuditEventType.CERT_REQUEST_APPROVED,
            user_id=approver.sub,
            user_email=approver.email,
            ip_address=ip_address,
            details={
                "request_id": request_id,
                "requester_id": requester_id,
                "ca_id": ca_id,
            }
        )
    
    def log_cert_denial(
        self,
        approver: UserClaims,
        request_id: int,
        requester_id: str,
        ca_id: str,
        reason: Optional[str],
        ip_address: Optional[str] = None,
    ):
        """Log certificate request denial."""
        self.log_event(
            AuditEventType.CERT_REQUEST_DENIED,
            user_id=approver.sub,
            user_email=approver.email,
            ip_address=ip_address,
            details={
                "request_id": request_id,
                "requester_id": requester_id,
                "ca_id": ca_id,
                "reason": reason,
            }
        )
    
    def log_cert_issued(
        self,
        user: UserClaims,
        certificate_id: int,
        serial_number: str,
        ca_id: str,
        subject: str,
        ip_address: Optional[str] = None,
    ):
        """Log certificate issuance."""
        self.log_event(
            AuditEventType.CERT_ISSUED,
            user_id=user.sub,
            user_email=user.email,
            ip_address=ip_address,
            details={
                "certificate_id": certificate_id,
                "serial_number": serial_number,
                "ca_id": ca_id,
                "subject": subject,
            }
        )
    
    def log_cert_revoked(
        self,
        user: UserClaims,
        certificate_id: int,
        serial_number: str,
        is_admin: bool = False,
        owner_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ):
        """Log certificate revocation."""
        event_type = (
            AuditEventType.CERT_REVOKED_ADMIN
            if is_admin
            else AuditEventType.CERT_REVOKED
        )
        
        details = {
            "certificate_id": certificate_id,
            "serial_number": serial_number,
        }
        
        if is_admin and owner_id:
            details["owner_id"] = owner_id
        
        self.log_event(
            event_type,
            user_id=user.sub,
            user_email=user.email,
            ip_address=ip_address,
            details=details,
        )
    
    def log_admin_access(
        self,
        user: UserClaims,
        action: str,
        ip_address: Optional[str] = None,
    ):
        """Log admin panel access."""
        self.log_event(
            AuditEventType.ADMIN_ACCESS,
            user_id=user.sub,
            user_email=user.email,
            ip_address=ip_address,
            details={"action": action}
        )
    
    def log_rate_limit_exceeded(
        self,
        endpoint: str,
        ip_address: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        """Log rate limit violation."""
        self.log_event(
            AuditEventType.RATE_LIMIT_EXCEEDED,
            user_id=user_id,
            ip_address=ip_address,
            success=False,
            details={"endpoint": endpoint}
        )
    
    def log_unauthorized_access(
        self,
        user_id: Optional[str],
        resource: str,
        reason: str,
        ip_address: Optional[str] = None,
    ):
        """Log unauthorized access attempt."""
        self.log_event(
            AuditEventType.UNAUTHORIZED_ACCESS,
            user_id=user_id,
            ip_address=ip_address,
            success=False,
            error_message=reason,
            details={"resource": resource}
        )
    
    def log_quota_exceeded(
        self,
        user: UserClaims,
        ca_id: str,
        current_count: int,
        limit: int,
        ip_address: Optional[str] = None,
    ):
        """Log quota exceeded event."""
        self.log_event(
            AuditEventType.QUOTA_EXCEEDED,
            user_id=user.sub,
            user_email=user.email,
            ip_address=ip_address,
            success=False,
            details={
                "ca_id": ca_id,
                "current_count": current_count,
                "limit": limit,
            }
        )


# Global audit logger instance
audit_logger = AuditLogger()


def get_client_ip(request) -> Optional[str]:
    """
    Extract client IP address from request.
    Handles X-Forwarded-For header for reverse proxy scenarios.
    """
    # Check X-Forwarded-For header (set by reverse proxies)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP (client IP)
        return forwarded_for.split(",")[0].strip()
    
    # Check X-Real-IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    
    # Fall back to direct connection IP
    if request.client:
        return request.client.host
    
    return None

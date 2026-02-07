"""
API routes for certificate request management.
"""

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload, joinedload

from ..audit import audit_logger, get_client_ip
from ..auth import UserClaims, get_current_user, get_user_matching_rule
from ..config import get_config
from ..crypto import (
    format_subject_string,
    generate_crl,
    get_ca_chain_pem,
    sign_csr,
)
from ..database import get_db
from ..email import send_notification_email
from ..email_templates import (
    render_new_request_email,
    render_request_approved_email,
    render_request_denied_email,
)
from ..models import Certificate, CertificateRequest, CRLEntry, RequestStatus


router = APIRouter(prefix="/api/v1", tags=["certificates"])

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)


# ============================================================================
# Pydantic Schemas
# ============================================================================


class CAInfo(BaseModel):
    """Certificate Authority information."""
    id: str
    name: str
    can_request: bool
    can_approve: bool
    auto_approve: bool
    max_ttl_hours: int
    # Quota information
    max_active_certs: Optional[int] = None  # None = unlimited
    active_cert_count: int = 0
    allow_request_over_quota: bool = True
    quota_exceeded: bool = False  # True if at or over limit
    # Renewal grace period
    renewal_grace_period_hours: int = 0  # 0 = no grace period
    certs_in_grace_period: int = 0  # Number of certs within grace window (not counting against quota)


class CertificateRequestCreate(BaseModel):
    """Request to create a new certificate request."""
    ca_id: str
    requested_ttl_hours: Optional[int] = 720


class CertificateRequestResponse(BaseModel):
    """Response for a certificate request."""
    id: int
    ca_id: str
    ca_name: str
    status: str
    created_at: datetime
    approved_at: Optional[datetime] = None
    has_certificate: bool


class CSRSubmission(BaseModel):
    """CSR submission for signing."""
    csr_pem: str


class SignedCertificateResponse(BaseModel):
    """Response with signed certificate."""
    certificate_pem: str
    ca_chain_pem: str
    subject: str
    serial_number: str
    not_before: datetime
    not_after: datetime


class CertificateInfo(BaseModel):
    """Information about an issued certificate."""
    id: int
    request_id: int
    serial_number: str
    subject: str
    not_before: datetime
    not_after: datetime
    is_revoked: bool
    is_expired: bool
    is_valid: bool


class ApprovalRequest(BaseModel):
    """Request to approve or deny a certificate request."""
    reason: Optional[str] = None


class PendingRequestInfo(BaseModel):
    """Information about a pending request for approvers."""
    id: int
    user_id: str
    user_email: Optional[str]
    user_display_name: Optional[str]
    ca_id: str
    ca_name: str
    created_at: datetime
    requested_ttl_hours: int


# ============================================================================
# Helper Functions
# ============================================================================


async def get_active_cert_count(
    user_id: str,
    ca_id: str,
    db: AsyncSession,
    renewal_grace_period_hours: int = 0,
) -> tuple[int, int]:
    """
    Get the count of active (non-revoked, non-expired) certificates for a user and CA.
    
    Returns a tuple of:
        - total_active: All active (non-revoked, non-expired) certificates
        - quota_active: Active certificates that count against quota.
          Certificates within the renewal grace period of expiry are excluded
          from the quota count, allowing users to renew before expiry.
    """
    now = datetime.utcnow()
    
    # Total active certs (non-revoked, non-expired)
    result = await db.execute(
        select(func.count(Certificate.id))
        .join(CertificateRequest)
        .where(
            CertificateRequest.user_id == user_id,
            CertificateRequest.ca_id == ca_id,
            Certificate.revoked_at.is_(None),
            Certificate.not_after > now,
        )
    )
    total_active = result.scalar() or 0
    
    if renewal_grace_period_hours <= 0:
        return total_active, total_active
    
    # Quota-counted certs: exclude those expiring within the grace period
    grace_cutoff = now + timedelta(hours=renewal_grace_period_hours)
    result = await db.execute(
        select(func.count(Certificate.id))
        .join(CertificateRequest)
        .where(
            CertificateRequest.user_id == user_id,
            CertificateRequest.ca_id == ca_id,
            Certificate.revoked_at.is_(None),
            Certificate.not_after > now,
            # Exclude certs that expire before the grace cutoff
            Certificate.not_after > grace_cutoff,
        )
    )
    quota_active = result.scalar() or 0
    
    return total_active, quota_active


# ============================================================================
# CA Endpoints
# ============================================================================

@router.get("/cas", response_model=list[CAInfo])
@limiter.limit("30/minute")
async def list_available_cas(
    request: Request,
    user: UserClaims = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List CAs available to the current user."""
    config = get_config()
    cas = []
    
    for ca in config.x509_cas:
        rule, has_access = get_user_matching_rule(user, ca.id)
        if has_access and rule:
            # Check if user is an approver for this CA
            is_approver = False
            for r in ca.rules:
                if any(group in user.groups for group in r.approver_groups):
                    is_approver = True
                    break
            
            # Get active certificate count for quota (with grace period awareness)
            grace_hours = rule.parse_renewal_grace_period_hours()
            total_active, quota_active = await get_active_cert_count(
                user.sub, ca.id, db, renewal_grace_period_hours=grace_hours
            )
            certs_in_grace = total_active - quota_active
            
            # Determine if quota is exceeded (using grace-period-aware count)
            quota_exceeded = False
            if rule.max_active_certs is not None:
                quota_exceeded = quota_active >= rule.max_active_certs

            cas.append(CAInfo(
                id=ca.id,
                name=ca.name,
                can_request=True,
                can_approve=is_approver,
                auto_approve=rule.auto_approve,
                max_ttl_hours=rule.parse_ttl_hours(),
                max_active_certs=rule.max_active_certs,
                active_cert_count=total_active,
                allow_request_over_quota=rule.allow_request_over_quota,
                quota_exceeded=quota_exceeded,
                renewal_grace_period_hours=grace_hours,
                certs_in_grace_period=certs_in_grace,
            ))
    
    return cas


# ============================================================================
# Request Endpoints
# ============================================================================


@router.get("/requests", response_model=list[CertificateRequestResponse])
@limiter.limit("30/minute")
async def list_my_requests(
    request: Request,
    user: UserClaims = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all certificate requests for the current user."""
    config = get_config()
    ca_names = {ca.id: ca.name for ca in config.x509_cas}
    
    result = await db.execute(
        select(CertificateRequest)
        .options(selectinload(CertificateRequest.certificate))
        .where(CertificateRequest.user_id == user.sub)
        .order_by(CertificateRequest.created_at.desc())
    )
    requests = result.scalars().all()
    
    response = []
    for req in requests:
        response.append(CertificateRequestResponse(
            id=req.id,
            ca_id=req.ca_id,
            ca_name=ca_names.get(req.ca_id, req.ca_id),
            status=req.status.value,
            created_at=req.created_at,
            approved_at=req.approved_at,
            has_certificate=req.certificate is not None,
        ))
    
    return response


@router.post("/request", response_model=CertificateRequestResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")  # Strict limit on certificate requests
async def create_request(
    request: Request,
    body: CertificateRequestCreate,
    user: UserClaims = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new certificate request."""
    config = get_config()
    ca_names = {ca.id: ca.name for ca in config.x509_cas}
    ip_address = get_client_ip(request)
    
    # Verify user has access to this CA
    rule, has_access = get_user_matching_rule(user, body.ca_id)
    if not has_access or not rule:
        audit_logger.log_unauthorized_access(
            user_id=user.sub,
            resource=f"CA:{body.ca_id}",
            reason="User not in allowed groups",
            ip_address=ip_address,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have access to this CA",
        )
    
    # Validate TTL
    max_ttl = rule.parse_ttl_hours()
    requested_ttl = min(body.requested_ttl_hours or 720, max_ttl)
    
    # Check quota limits (grace-period-aware)
    force_manual_approval = False
    if rule.max_active_certs is not None:
        grace_hours = rule.parse_renewal_grace_period_hours()
        total_active, quota_active = await get_active_cert_count(
            user.sub, body.ca_id, db, renewal_grace_period_hours=grace_hours
        )
        if quota_active >= rule.max_active_certs:
            if not rule.allow_request_over_quota:
                # Hard limit - block the request entirely
                grace_msg = ""
                if grace_hours > 0 and total_active > quota_active:
                    grace_msg = f" ({total_active - quota_active} certificate(s) are within the renewal grace period and not counted.)"
                audit_logger.log_quota_exceeded(
                    user=user,
                    ca_id=body.ca_id,
                    current_count=quota_active,
                    limit=rule.max_active_certs,
                    ip_address=ip_address,
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Certificate quota exceeded. You have {quota_active} active certificate(s) counting against the limit of {rule.max_active_certs}.{grace_msg} Please revoke an existing certificate or wait for one to expire.",
                )
            else:
                # Soft limit - allow but force manual approval
                force_manual_approval = True
    
    # Determine initial status
    initial_status = (
        RequestStatus.APPROVED_AWAITING_GEN
        if rule.auto_approve and not force_manual_approval
        else RequestStatus.PENDING_APPROVAL
    )
    
    # Create the request
    is_auto_approved = rule.auto_approve and not force_manual_approval
    cert_request = CertificateRequest(
        user_id=user.sub,
        user_email=user.email,
        user_display_name=user.display_name,
        ca_id=body.ca_id,
        status=initial_status,
        requested_ttl_hours=requested_ttl,
        approved_at=datetime.utcnow() if is_auto_approved else None,
        approved_by="auto" if is_auto_approved else None,
    )
    
    db.add(cert_request)
    await db.flush()
    await db.refresh(cert_request)
    
    # Log certificate request
    audit_logger.log_cert_request(
        user=user,
        ca_id=body.ca_id,
        request_id=cert_request.id,
        auto_approved=is_auto_approved,
        ip_address=ip_address,
    )
    
    # Send email notification if pending approval
    if cert_request.status == RequestStatus.PENDING_APPROVAL:
        ca_display_name = ca_names.get(cert_request.ca_id, cert_request.ca_id)
        portal_url = config.app_url.rstrip("/") or None
        plain, html = render_new_request_email(
            requester_name=cert_request.user_display_name or "Unknown",
            requester_email=cert_request.user_email or "",
            ca_name=ca_display_name,
            requested_ttl_hours=requested_ttl,
            portal_url=portal_url,
        )
        # Notify configured approvers
        for email in config.smtp.approver_emails:
            await send_notification_email(
                to_email=email,
                subject="New Certificate Request Pending Approval",
                body=plain,
                html_body=html,
            )
        
    return CertificateRequestResponse(
        id=cert_request.id,
        ca_id=cert_request.ca_id,
        ca_name=ca_names.get(cert_request.ca_id, cert_request.ca_id),
        status=cert_request.status.value,
        created_at=cert_request.created_at,
        approved_at=cert_request.approved_at,
        has_certificate=False,
    )


@router.post("/sign/{request_id}", response_model=SignedCertificateResponse)
@limiter.limit("10/minute")  # Limit certificate generation
async def sign_certificate(
    request: Request,
    request_id: int,
    body: CSRSubmission,
    user: UserClaims = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Sign a CSR for an approved request.
    
    The subject is ENFORCED from the current OIDC claims - the CSR subject is ignored.
    """
    config = get_config()
    ip_address = get_client_ip(request)
    
    # Fetch the request
    result = await db.execute(
        select(CertificateRequest)
        .options(selectinload(CertificateRequest.certificate))
        .where(CertificateRequest.id == request_id)
    )
    cert_request = result.scalar_one_or_none()
    
    if not cert_request:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Request not found",
        )
    
    # Verify ownership
    if cert_request.user_id != user.sub:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This request does not belong to you",
        )
    
    # Verify status
    if cert_request.status != RequestStatus.APPROVED_AWAITING_GEN:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Request is not ready for generation (status: {cert_request.status.value})",
        )
    
    # Check if certificate already exists
    if cert_request.certificate:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Certificate already generated for this request",
        )
    
    # Find CA config
    ca_config = None
    for ca in config.x509_cas:
        if ca.id == cert_request.ca_id:
            ca_config = ca
            break
    
    if not ca_config:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="CA configuration not found",
        )
    
    try:
        # Sign the CSR with dynamic subject from current claims
        certificate, cert_pem = sign_csr(
            body.csr_pem,
            ca_config,
            user,
            cert_request.requested_ttl_hours,
        )
        
        # Store the certificate
        subject_str = format_subject_string(certificate.subject)
        serial_hex = format(certificate.serial_number, 'x')
        
        db_cert = Certificate(
            request_id=cert_request.id,
            serial_number=serial_hex,
            subject=subject_str,
            certificate_pem=cert_pem,
            not_before=certificate.not_valid_before_utc.replace(tzinfo=None),
            not_after=certificate.not_valid_after_utc.replace(tzinfo=None),
        )
        db.add(db_cert)
        
        # Update request status
        cert_request.status = RequestStatus.GENERATED
        
        await db.flush()
        
        # Log certificate issuance
        audit_logger.log_cert_issued(
            user=user,
            certificate_id=db_cert.id,
            serial_number=serial_hex,
            ca_id=cert_request.ca_id,
            subject=subject_str,
            ip_address=ip_address,
        )
        
        return SignedCertificateResponse(
            certificate_pem=cert_pem,
            ca_chain_pem=get_ca_chain_pem(ca_config),
            subject=subject_str,
            serial_number=serial_hex,
            not_before=db_cert.not_before,
            not_after=db_cert.not_after,
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid CSR: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to sign certificate: {str(e)}",
        )


# ============================================================================
# Certificate Management
# ============================================================================


@router.get("/certificates", response_model=list[CertificateInfo])
@limiter.limit("30/minute")
async def list_my_certificates(
    request: Request,
    user: UserClaims = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all certificates for the current user."""
    result = await db.execute(
        select(Certificate)
        .join(CertificateRequest)
        .where(CertificateRequest.user_id == user.sub)
        .order_by(Certificate.issued_at.desc())
    )
    certs = result.scalars().all()
    
    return [
        CertificateInfo(
            id=cert.id,
            request_id=cert.request_id,
            serial_number=cert.serial_number,
            subject=cert.subject,
            not_before=cert.not_before,
            not_after=cert.not_after,
            is_revoked=cert.is_revoked,
            is_expired=cert.is_expired,
            is_valid=cert.is_valid,
        )
        for cert in certs
    ]


@router.post("/revoke/{certificate_id}", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("10/minute")
async def revoke_certificate(
    request: Request,
    certificate_id: int,
    user: UserClaims = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke a certificate (immediate revocation)."""
    ip_address = get_client_ip(request)
    result = await db.execute(
        select(Certificate)
        .options(joinedload(Certificate.request))
        .join(CertificateRequest)
        .where(Certificate.id == certificate_id)
        .where(CertificateRequest.user_id == user.sub)
    )
    cert = result.scalar_one_or_none()
    
    if not cert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificate not found or not owned by you",
        )
    
    if cert.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Certificate is already revoked",
        )
    
    # Revoke the certificate
    now = datetime.utcnow()
    cert.revoked_at = now
    cert.revocation_reason = "user_requested"
    
    # Add to CRL entries
    crl_entry = CRLEntry(
        ca_id=cert.request.ca_id,
        serial_number=cert.serial_number,
        revoked_at=now,
        reason="user_requested",
    )
    db.add(crl_entry)
    
    # Update request status
    cert.request.status = RequestStatus.REVOKED
    
    await db.flush()
    
    # Log revocation
    audit_logger.log_cert_revoked(
        user=user,
        certificate_id=cert.id,
        serial_number=cert.serial_number,
        is_admin=False,
        ip_address=ip_address,
    )
    
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ============================================================================
# Approver Endpoints
# ============================================================================


@router.get("/pending", response_model=list[PendingRequestInfo])
@limiter.limit("30/minute")
async def list_pending_requests(
    request: Request,
    user: UserClaims = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List pending requests that the current user can approve."""
    config = get_config()
    
    # Find CAs where user is an approver
    approvable_ca_ids = []
    for ca in config.x509_cas:
        for rule in ca.rules:
            if any(group in user.groups for group in rule.approver_groups):
                approvable_ca_ids.append(ca.id)
                break
    
    if not approvable_ca_ids:
        return []
    
    ca_names = {ca.id: ca.name for ca in config.x509_cas}
    
    result = await db.execute(
        select(CertificateRequest)
        .where(CertificateRequest.status == RequestStatus.PENDING_APPROVAL)
        .where(CertificateRequest.ca_id.in_(approvable_ca_ids))
        .order_by(CertificateRequest.created_at.asc())
    )
    requests = result.scalars().all()
    
    return [
        PendingRequestInfo(
            id=req.id,
            user_id=req.user_id,
            user_email=req.user_email,
            user_display_name=req.user_display_name,
            ca_id=req.ca_id,
            ca_name=ca_names.get(req.ca_id, req.ca_id),
            created_at=req.created_at,
            requested_ttl_hours=req.requested_ttl_hours,
        )
        for req in requests
    ]


@router.post("/approve/{request_id}", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("20/minute")
async def approve_request(
    request: Request,
    request_id: int,
    user: UserClaims = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Approve a pending certificate request."""
    config = get_config()
    ip_address = get_client_ip(request)
    
    result = await db.execute(
        select(CertificateRequest).where(CertificateRequest.id == request_id)
    )
    cert_request = result.scalar_one_or_none()
    
    if not cert_request:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Request not found",
        )
    
    if cert_request.status != RequestStatus.PENDING_APPROVAL:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request is not pending approval",
        )
    
    # Verify user is an approver for this CA
    is_approver = False
    for ca in config.x509_cas:
        if ca.id == cert_request.ca_id:
            for rule in ca.rules:
                if any(group in user.groups for group in rule.approver_groups):
                    is_approver = True
                    break
            break
    
    if not is_approver:
        audit_logger.log_unauthorized_access(
            user_id=user.sub,
            resource=f"approve_request:{request_id}",
            reason="User not in approver groups",
            ip_address=ip_address,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to approve requests for this CA",
        )
    
    # Approve the request
    cert_request.status = RequestStatus.APPROVED_AWAITING_GEN
    cert_request.approved_at = datetime.utcnow()
    cert_request.approved_by = user.sub
    
    await db.flush()
    
    # Log approval
    audit_logger.log_cert_approval(
        approver=user,
        request_id=request_id,
        requester_id=cert_request.user_id,
        ca_id=cert_request.ca_id,
        ip_address=ip_address,
    )
    
    # Send email notification to requester
    if cert_request.user_email:
        ca_names = {ca.id: ca.name for ca in config.x509_cas}
        ca_display_name = ca_names.get(cert_request.ca_id, cert_request.ca_id)
        portal_url = config.app_url.rstrip("/") or None
        plain, html = render_request_approved_email(
            ca_name=ca_display_name,
            portal_url=portal_url,
        )
        await send_notification_email(
            to_email=cert_request.user_email,
            subject="Certificate Request Approved",
            body=plain,
            html_body=html,
        )
    
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/deny/{request_id}", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("20/minute")
async def deny_request(
    request: Request,
    request_id: int,
    body: ApprovalRequest,
    user: UserClaims = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Deny a pending certificate request."""
    config = get_config()
    ip_address = get_client_ip(request)
    
    result = await db.execute(
        select(CertificateRequest).where(CertificateRequest.id == request_id)
    )
    cert_request = result.scalar_one_or_none()
    
    if not cert_request:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Request not found",
        )
    
    if cert_request.status != RequestStatus.PENDING_APPROVAL:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request is not pending approval",
        )
    
    # Verify user is an approver for this CA
    is_approver = False
    for ca in config.x509_cas:
        if ca.id == cert_request.ca_id:
            for rule in ca.rules:
                if any(group in user.groups for group in rule.approver_groups):
                    is_approver = True
                    break
            break
    
    if not is_approver:
        audit_logger.log_unauthorized_access(
            user_id=user.sub,
            resource=f"deny_request:{request_id}",
            reason="User not in approver groups",
            ip_address=ip_address,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to deny requests for this CA",
        )
    
    # Deny the request
    cert_request.status = RequestStatus.DENIED
    cert_request.denied_at = datetime.utcnow()
    cert_request.denied_by = user.sub
    cert_request.denial_reason = body.reason
    
    await db.flush()
    
    # Log denial
    audit_logger.log_cert_denial(
        approver=user,
        request_id=request_id,
        requester_id=cert_request.user_id,
        ca_id=cert_request.ca_id,
        reason=body.reason,
        ip_address=ip_address,
    )
    
    # Send email notification to requester
    if cert_request.user_email:
        ca_names = {ca.id: ca.name for ca in config.x509_cas}
        ca_display_name = ca_names.get(cert_request.ca_id, cert_request.ca_id)
        portal_url = config.app_url.rstrip("/") or None
        plain, html = render_request_denied_email(
            ca_name=ca_display_name,
            reason=cert_request.denial_reason,
            portal_url=portal_url,
        )
        await send_notification_email(
            to_email=cert_request.user_email,
            subject="Certificate Request Denied",
            body=plain,
            html_body=html,
        )
    
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ============================================================================
# Public Endpoints (No Auth)
# ============================================================================


@router.get("/crl/{ca_id}")
async def get_crl(
    ca_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get the Certificate Revocation List for a CA (public endpoint)."""
    config = get_config()
    
    # Find CA config
    ca_config = None
    for ca in config.x509_cas:
        if ca.id == ca_id:
            ca_config = ca
            break
    
    if not ca_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="CA not found",
        )
    
    # Get revoked certificates
    result = await db.execute(
        select(CRLEntry)
        .where(CRLEntry.ca_id == ca_id)
    )
    entries = result.scalars().all()
    
    revoked_certs = [
        (int(entry.serial_number, 16), entry.revoked_at, entry.reason)
        for entry in entries
    ]
    
    # Generate CRL
    crl_der = generate_crl(ca_config, revoked_certs)
    
    return Response(
        content=crl_der,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f"attachment; filename={ca_id}.pem"},
    )


@router.get("/ca/{ca_id}")
async def get_ca_cert(
    ca_id: str,
):
    """Get the CA certificate (public endpoint)."""
    config = get_config()
    
    # Find CA config
    ca_config = None
    for ca in config.x509_cas:
        if ca.id == ca_id:
            ca_config = ca
            break
    
    if not ca_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="CA not found",
        )
    
    try:
        with open(ca_config.cert_path, "rb") as f:
            cert_pem = f.read()
            
        return Response(
            content=cert_pem,
            media_type="application/x-pem-file",
            headers={"Content-Disposition": f"attachment; filename={ca_id}.crt"},
        )
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="CA certificate file not found",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read CA certificate: {str(e)}",
        )


@router.get("/bundle/{ca_id}")
async def get_ca_bundle(
    ca_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get a bundle containing the CA certificate and CRL (public endpoint)."""
    config = get_config()
    
    # Find CA config
    ca_config = None
    for ca in config.x509_cas:
        if ca.id == ca_id:
            ca_config = ca
            break
    
    if not ca_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="CA not found",
        )
    
    # 1. Read CA Certificate
    try:
        with open(ca_config.cert_path, "rb") as f:
            cert_pem = f.read()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read CA certificate: {str(e)}",
        )

    # 2. Generate CRL
    try:
        # Get revoked certificates
        result = await db.execute(
            select(CRLEntry)
            .where(CRLEntry.ca_id == ca_id)
        )
        entries = result.scalars().all()
        
        revoked_certs = [
            (int(entry.serial_number, 16), entry.revoked_at, entry.reason)
            for entry in entries
        ]
        
        # Generate CRL
        crl_der = generate_crl(ca_config, revoked_certs)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate CRL: {str(e)}",
        )
        
    # 3. Concatenate (ensure newline between them)
    bundle_content = cert_pem
    if not bundle_content.endswith(b"\n"):
        bundle_content += b"\n"
    bundle_content += crl_der
    
    return Response(
        content=bundle_content,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f"attachment; filename={ca_id}-bundle.pem"},
    )


# ============================================================================
# Health Check
# ============================================================================


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


@router.get("/oidc-config")
async def get_oidc_config():
    """Get OIDC configuration for the frontend, including discovery endpoints."""
    import httpx
    
    config = get_config()
    
    result = {
        "issuer": config.oidc.issuer,
        "client_id": config.oidc.client_id,
        "scopes": " ".join(config.oidc.scopes),
        "authorization_endpoint": "",
        "token_endpoint": "",
    }
    
    # Fetch OIDC discovery document to get actual endpoints
    try:
        discovery_url = config.oidc.issuer.rstrip('/') + '/.well-known/openid-configuration'
        async with httpx.AsyncClient() as client:
            response = await client.get(discovery_url, timeout=10.0)
            if response.status_code == 200:
                discovery = response.json()
                result["authorization_endpoint"] = discovery.get("authorization_endpoint", "")
                result["token_endpoint"] = discovery.get("token_endpoint", "")
    except Exception as e:
        # Log but don't fail - frontend can fall back
        import logging
        logging.warning(f"Failed to fetch OIDC discovery: {e}")
    
    return result


# ============================================================================
# Admin Endpoints
# ============================================================================


class AdminCertificateInfo(BaseModel):
    """Certificate information for admin view."""
    id: int
    request_id: int
    user_id: str
    user_email: Optional[str]
    user_display_name: Optional[str]
    ca_id: str
    ca_name: str
    serial_number: str
    subject: str
    not_before: datetime
    not_after: datetime
    is_revoked: bool
    is_expired: bool
    is_valid: bool
    revoked_at: Optional[datetime] = None


def is_admin(user: UserClaims) -> bool:
    """Check if user is an admin."""
    config = get_config()
    return any(group in user.groups for group in config.admin_groups)


@router.get("/admin/is-admin")
@limiter.limit("30/minute")
async def check_is_admin(
    request: Request,
    user: UserClaims = Depends(get_current_user),
):
    """Check if current user has admin privileges."""
    ip_address = get_client_ip(request)
    
    if is_admin(user):
        audit_logger.log_admin_access(
            user=user,
            action="check_admin_status",
            ip_address=ip_address,
        )
    
    return {"is_admin": is_admin(user)}


class PaginatedCertificatesResponse(BaseModel):
    """Paginated response for admin certificates."""
    certificates: list[AdminCertificateInfo]
    total: int
    page: int
    page_size: int
    has_more: bool


@router.get("/admin/certificates", response_model=PaginatedCertificatesResponse)
@limiter.limit("60/minute")  # Higher limit for admin searches
async def list_all_certificates(
    request: Request,
    user: UserClaims = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    search: Optional[str] = Query(None, description="Search by user name, email, subject, or serial number"),
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(25, ge=5, le=100, description="Items per page"),
    status_filter: Optional[str] = Query(None, description="Filter by status: active, revoked, expired, all"),
):
    """List all certificates with pagination and search (admin only)."""
    ip_address = get_client_ip(request)
    
    if not is_admin(user):
        audit_logger.log_unauthorized_access(
            user_id=user.sub,
            resource="admin_certificates",
            reason="User not in admin groups",
            ip_address=ip_address,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    
    # Log admin access
    audit_logger.log_admin_access(
        user=user,
        action=f"list_certificates:search={search}:filter={status_filter}",
        ip_address=ip_address,
    )
    
    config = get_config()
    ca_names = {ca.id: ca.name for ca in config.x509_cas}
    
    # Build base query
    query = select(Certificate).options(joinedload(Certificate.request))
    
    # Apply search filter if provided
    if search:
        search_term = f"%{search}%"
        query = query.where(
            or_(
                Certificate.subject.ilike(search_term),
                Certificate.serial_number.ilike(search_term),
                CertificateRequest.user_email.ilike(search_term),
                CertificateRequest.user_display_name.ilike(search_term),
                CertificateRequest.user_id.ilike(search_term),
            )
        ).join(Certificate.request)
    
    # Apply status filter
    now = datetime.utcnow()
    if status_filter == "active":
        query = query.where(
            Certificate.revoked_at.is_(None),
            Certificate.not_after > now
        )
    elif status_filter == "revoked":
        query = query.where(Certificate.revoked_at.isnot(None))
    elif status_filter == "expired":
        query = query.where(
            Certificate.revoked_at.is_(None),
            Certificate.not_after <= now
        )
    
    # Get total count for pagination
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0
    
    # Apply ordering and pagination
    offset = (page - 1) * page_size
    query = query.order_by(Certificate.issued_at.desc()).offset(offset).limit(page_size)
    
    result = await db.execute(query)
    certs = result.scalars().unique().all()
    
    certificates = [
        AdminCertificateInfo(
            id=cert.id,
            request_id=cert.request_id,
            user_id=cert.request.user_id,
            user_email=cert.request.user_email,
            user_display_name=cert.request.user_display_name,
            ca_id=cert.request.ca_id,
            ca_name=ca_names.get(cert.request.ca_id, cert.request.ca_id),
            serial_number=cert.serial_number,
            subject=cert.subject,
            not_before=cert.not_before,
            not_after=cert.not_after,
            is_revoked=cert.is_revoked,
            is_expired=cert.is_expired,
            is_valid=cert.is_valid,
            revoked_at=cert.revoked_at,
        )
        for cert in certs
    ]
    
    return PaginatedCertificatesResponse(
        certificates=certificates,
        total=total,
        page=page,
        page_size=page_size,
        has_more=(offset + len(certificates)) < total,
    )


@router.post("/admin/revoke/{certificate_id}", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("20/minute")
async def admin_revoke_certificate(
    request: Request,
    certificate_id: int,
    user: UserClaims = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke any certificate (admin only)."""
    ip_address = get_client_ip(request)
    
    if not is_admin(user):
        audit_logger.log_unauthorized_access(
            user_id=user.sub,
            resource=f"admin_revoke:{certificate_id}",
            reason="User not in admin groups",
            ip_address=ip_address,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    
    result = await db.execute(
        select(Certificate)
        .options(joinedload(Certificate.request))
        .where(Certificate.id == certificate_id)
    )
    cert = result.scalar_one_or_none()
    
    if not cert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificate not found",
        )
    
    if cert.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Certificate is already revoked",
        )
    
    # Revoke the certificate
    now = datetime.utcnow()
    cert.revoked_at = now
    cert.revocation_reason = f"admin_revoked_by_{user.sub}"
    
    # Add to CRL entries
    crl_entry = CRLEntry(
        ca_id=cert.request.ca_id,
        serial_number=cert.serial_number,
        revoked_at=now,
        reason=f"admin_revoked_by_{user.sub}",
    )
    db.add(crl_entry)
    
    # Update request status
    cert.request.status = RequestStatus.REVOKED
    
    await db.flush()
    
    # Log admin revocation
    audit_logger.log_cert_revoked(
        user=user,
        certificate_id=cert.id,
        serial_number=cert.serial_number,
        is_admin=True,
        owner_id=cert.request.user_id,
        ip_address=ip_address,
    )
    
    return Response(status_code=status.HTTP_204_NO_CONTENT)


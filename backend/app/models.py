"""
Database models for the mTLS PKI Portal.
"""

import enum
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    """Base class for all models."""
    pass


class RequestStatus(enum.Enum):
    """Certificate request status."""
    PENDING_APPROVAL = "pending_approval"
    APPROVED_AWAITING_GEN = "approved_awaiting_gen"
    GENERATED = "generated"
    REVOKED = "revoked"
    DENIED = "denied"
    EXPIRED = "expired"


class CertificateRequest(Base):
    """A certificate request from a user."""
    __tablename__ = "certificate_requests"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # User info (from OIDC)
    user_id = Column(String(255), nullable=False, index=True)  # OIDC 'sub' claim
    user_email = Column(String(255), nullable=True)
    user_display_name = Column(String(255), nullable=True)
    
    # Request details
    ca_id = Column(String(100), nullable=False)
    status = Column(Enum(RequestStatus), default=RequestStatus.PENDING_APPROVAL, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Approval tracking
    approved_at = Column(DateTime, nullable=True)
    approved_by = Column(String(255), nullable=True)  # Approver's user_id
    denied_at = Column(DateTime, nullable=True)
    denied_by = Column(String(255), nullable=True)
    denial_reason = Column(Text, nullable=True)
    
    # TTL requested (in hours)
    requested_ttl_hours = Column(Integer, nullable=False, default=720)
    
    # Relationship to certificate
    certificate = relationship("Certificate", back_populates="request", uselist=False)
    
    def __repr__(self) -> str:
        return f"<CertificateRequest(id={self.id}, user_id={self.user_id}, status={self.status})>"


class Certificate(Base):
    """An issued certificate."""
    __tablename__ = "certificates"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(Integer, ForeignKey("certificate_requests.id"), nullable=False, unique=True)
    
    # Certificate details
    serial_number = Column(String(100), nullable=False, unique=True, index=True)
    subject = Column(Text, nullable=False)  # Full DN as string
    
    # PEM-encoded certificate (we store this for CRL generation)
    certificate_pem = Column(Text, nullable=False)
    
    # Validity period
    not_before = Column(DateTime, nullable=False)
    not_after = Column(DateTime, nullable=False)
    
    # Revocation
    revoked_at = Column(DateTime, nullable=True)
    revocation_reason = Column(String(255), nullable=True)
    
    # Renewal notification tracking
    renewal_notification_sent_at = Column(DateTime, nullable=True)
    renewal_grace_period_hours = Column(Integer, nullable=True)  # Grace period from the rule at issuance
    
    # Timestamps
    issued_at = Column(DateTime, server_default=func.now(), nullable=False)
    
    # Relationship
    request = relationship("CertificateRequest", back_populates="certificate")
    
    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None
    
    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.not_after
    
    @property
    def is_valid(self) -> bool:
        return not self.is_revoked and not self.is_expired
    
    def __repr__(self) -> str:
        return f"<Certificate(id={self.id}, serial={self.serial_number}, revoked={self.is_revoked})>"


class CRLEntry(Base):
    """CRL entry for tracking revoked certificates per CA."""
    __tablename__ = "crl_entries"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    ca_id = Column(String(100), nullable=False, index=True)
    serial_number = Column(String(100), nullable=False)
    revoked_at = Column(DateTime, nullable=False)
    reason = Column(String(255), nullable=True)
    
    def __repr__(self) -> str:
        return f"<CRLEntry(ca_id={self.ca_id}, serial={self.serial_number})>"

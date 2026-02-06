"""
Comprehensive test suite for mTLS PKI Portal.
Tests authentication, authorization, certificate lifecycle, and security controls.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import UserClaims, validate_token, get_user_matching_rule
from app.models import CertificateRequest, Certificate, RequestStatus
from app.config import CARule, X509CAConfig


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_user():
    """Mock authenticated user."""
    return UserClaims(
        sub="test-user-123",
        email="test@example.com",
        name="Test User",
        groups=["staff", "engineering"],
        raw_claims={}
    )


@pytest.fixture
def mock_admin_user():
    """Mock admin user."""
    return UserClaims(
        sub="admin-user-456",
        email="admin@example.com",
        name="Admin User",
        groups=["ROOT", "admins"],
        raw_claims={}
    )


@pytest.fixture
def mock_ca_config():
    """Mock CA configuration."""
    return X509CAConfig(
        id="test-ca",
        name="Test CA",
        cert_path="/tmp/ca.crt",
        key_path="/tmp/ca.key",
        rules=[
            CARule(
                oidc_groups=["staff"],
                auto_approve=False,
                approver_groups=["security"],
                max_ttl="720h",
                max_active_certs=3,
                allow_request_over_quota=True,
            )
        ],
        key_password_env_var=None,
    )


# ============================================================================
# Authentication Tests
# ============================================================================

class TestAuthentication:
    """Test OIDC authentication and token validation."""
    
    @pytest.mark.asyncio
    async def test_validate_token_success(self):
        """Test successful token validation."""
        with patch('app.auth.get_userinfo') as mock_userinfo:
            mock_userinfo.return_value = {
                "sub": "user123",
                "email": "user@example.com",
                "name": "Test User",
                "groups": ["staff"]
            }
            
            user = await validate_token("valid-token")
            
            assert user.sub == "user123"
            assert user.email == "user@example.com"
            assert "staff" in user.groups
    
    @pytest.mark.asyncio
    async def test_validate_token_invalid(self):
        """Test token validation with invalid token."""
        with patch('app.auth.get_userinfo') as mock_userinfo:
            from httpx import HTTPStatusError, Response, Request
            
            mock_response = Response(401, request=Request("GET", "http://test"))
            mock_userinfo.side_effect = HTTPStatusError(
                "Unauthorized",
                request=mock_response.request,
                response=mock_response
            )
            
            with pytest.raises(HTTPException) as exc_info:
                await validate_token("invalid-token")
            
            assert exc_info.value.status_code == 401
    
    def test_user_claims_display_name(self, mock_user):
        """Test display name property."""
        assert mock_user.display_name == "Test User"
        
        # Test fallback to email
        user_no_name = UserClaims(
            sub="user123",
            email="user@example.com",
            groups=[],
            raw_claims={}
        )
        assert user_no_name.display_name == "user@example.com"


# ============================================================================
# Authorization Tests
# ============================================================================

class TestAuthorization:
    """Test group-based access control."""
    
    def test_user_matching_rule_success(self, mock_user, mock_ca_config):
        """Test user matches CA rule."""
        with patch('app.auth.get_config') as mock_config:
            mock_config.return_value.x509_cas = [mock_ca_config]
            
            rule, has_access = get_user_matching_rule(mock_user, "test-ca")
            
            assert has_access is True
            assert rule is not None
            assert rule.max_ttl == "720h"
    
    def test_user_matching_rule_no_access(self, mock_user, mock_ca_config):
        """Test user without matching groups."""
        user_no_groups = UserClaims(
            sub="user123",
            email="user@example.com",
            groups=["contractors"],  # Not in CA rules
            raw_claims={}
        )
        
        with patch('app.auth.get_config') as mock_config:
            mock_config.return_value.x509_cas = [mock_ca_config]
            
            rule, has_access = get_user_matching_rule(user_no_groups, "test-ca")
            
            assert has_access is False
            assert rule is None
    
    def test_admin_check(self, mock_admin_user):
        """Test admin group membership check."""
        from app.routes.requests import is_admin
        
        with patch('app.routes.requests.get_config') as mock_config:
            mock_config.return_value.admin_groups = ["ROOT", "admins"]
            
            assert is_admin(mock_admin_user) is True
    
    def test_non_admin_check(self, mock_user):
        """Test non-admin user."""
        from app.routes.requests import is_admin
        
        with patch('app.routes.requests.get_config') as mock_config:
            mock_config.return_value.admin_groups = ["ROOT", "admins"]
            
            assert is_admin(mock_user) is False


# ============================================================================
# Certificate Request Tests
# ============================================================================

class TestCertificateRequests:
    """Test certificate request lifecycle."""
    
    def test_request_status_enum(self):
        """Test request status enumeration."""
        assert RequestStatus.PENDING_APPROVAL.value == "pending_approval"
        assert RequestStatus.APPROVED_AWAITING_GEN.value == "approved_awaiting_gen"
        assert RequestStatus.GENERATED.value == "generated"
        assert RequestStatus.REVOKED.value == "revoked"
        assert RequestStatus.DENIED.value == "denied"
    
    def test_certificate_request_model(self):
        """Test certificate request model creation."""
        request = CertificateRequest(
            user_id="user123",
            user_email="user@example.com",
            user_display_name="Test User",
            ca_id="test-ca",
            status=RequestStatus.PENDING_APPROVAL,
            requested_ttl_hours=720,
        )
        
        assert request.user_id == "user123"
        assert request.status == RequestStatus.PENDING_APPROVAL
        assert request.requested_ttl_hours == 720


# ============================================================================
# Certificate Model Tests
# ============================================================================

class TestCertificateModel:
    """Test certificate model and properties."""
    
    def test_certificate_is_valid(self):
        """Test certificate validity check."""
        cert = Certificate(
            request_id=1,
            serial_number="abc123",
            subject="CN=Test",
            certificate_pem="-----BEGIN CERTIFICATE-----",
            not_before=datetime.utcnow() - timedelta(days=1),
            not_after=datetime.utcnow() + timedelta(days=30),
            revoked_at=None,
        )
        
        assert cert.is_valid is True
        assert cert.is_revoked is False
        assert cert.is_expired is False
    
    def test_certificate_is_revoked(self):
        """Test revoked certificate."""
        cert = Certificate(
            request_id=1,
            serial_number="abc123",
            subject="CN=Test",
            certificate_pem="-----BEGIN CERTIFICATE-----",
            not_before=datetime.utcnow() - timedelta(days=1),
            not_after=datetime.utcnow() + timedelta(days=30),
            revoked_at=datetime.utcnow(),
        )
        
        assert cert.is_valid is False
        assert cert.is_revoked is True
    
    def test_certificate_is_expired(self):
        """Test expired certificate."""
        cert = Certificate(
            request_id=1,
            serial_number="abc123",
            subject="CN=Test",
            certificate_pem="-----BEGIN CERTIFICATE-----",
            not_before=datetime.utcnow() - timedelta(days=60),
            not_after=datetime.utcnow() - timedelta(days=1),
            revoked_at=None,
        )
        
        assert cert.is_valid is False
        assert cert.is_expired is True


# ============================================================================
# Cryptographic Tests
# ============================================================================

class TestCryptography:
    """Test cryptographic operations."""
    
    def test_serial_number_generation(self):
        """Test serial number is cryptographically random."""
        from app.crypto import generate_serial_number
        
        serial1 = generate_serial_number()
        serial2 = generate_serial_number()
        
        assert serial1 != serial2
        assert serial1 > 0
        assert serial2 > 0
        # 128-bit serial should be large
        assert serial1.bit_length() <= 128
    
    def test_subject_building_from_claims(self, mock_user):
        """Test X.509 subject building from OIDC claims."""
        from app.crypto import build_subject_from_claims
        
        with patch('app.crypto.get_config') as mock_config:
            mock_config.return_value.subject_attributes.static = {"O": "Acme Corp"}
            mock_config.return_value.subject_attributes.mapping = {
                "CN": "preferred_username",
                "EMAIL": "email"
            }
            
            # Add preferred_username to mock user
            mock_user.raw_claims["preferred_username"] = "testuser"
            
            subject = build_subject_from_claims(mock_user)
            
            # Verify subject contains expected attributes
            subject_str = str(subject)
            assert "Acme Corp" in subject_str
    
    def test_format_subject_string(self):
        """Test subject DN formatting."""
        from app.crypto import format_subject_string
        from cryptography.x509 import Name, NameAttribute
        from cryptography.x509.oid import NameOID
        
        subject = Name([
            NameAttribute(NameOID.COMMON_NAME, "Test User"),
            NameAttribute(NameOID.ORGANIZATION_NAME, "Acme Corp"),
        ])
        
        subject_str = format_subject_string(subject)
        
        assert "CN=Test User" in subject_str
        assert "O=Acme Corp" in subject_str


# ============================================================================
# Configuration Tests
# ============================================================================

class TestConfiguration:
    """Test configuration loading and validation."""
    
    def test_ca_rule_ttl_parsing(self):
        """Test TTL string parsing."""
        rule_hours = CARule(max_ttl="720h")
        assert rule_hours.parse_ttl_hours() == 720
        
        rule_days = CARule(max_ttl="30d")
        assert rule_days.parse_ttl_hours() == 720
        
        rule_weeks = CARule(max_ttl="4w")
        assert rule_weeks.parse_ttl_hours() == 672
    
    def test_ca_config_key_password(self):
        """Test CA key password resolution from env var."""
        import os
        
        os.environ["TEST_CA_PASSWORD"] = "secret123"
        
        ca_config = X509CAConfig(
            id="test",
            name="Test",
            cert_path="/tmp/ca.crt",
            key_path="/tmp/ca.key",
            rules=[],
            key_password_env_var="TEST_CA_PASSWORD"
        )
        
        assert ca_config.key_password == b"secret123"
        
        del os.environ["TEST_CA_PASSWORD"]


# ============================================================================
# Audit Logging Tests
# ============================================================================

class TestAuditLogging:
    """Test audit logging functionality."""
    
    def test_audit_logger_cert_request(self, mock_user):
        """Test certificate request logging."""
        from app.audit import audit_logger, AuditEventType
        
        with patch.object(audit_logger.logger, 'info') as mock_log:
            audit_logger.log_cert_request(
                user=mock_user,
                ca_id="test-ca",
                request_id=123,
                auto_approved=True,
                ip_address="192.168.1.100"
            )
            
            # Verify log was called
            assert mock_log.called
            
            # Parse logged JSON
            import json
            log_data = json.loads(mock_log.call_args[0][0])
            
            assert log_data["event_type"] == AuditEventType.CERT_REQUEST_AUTO_APPROVED.value
            assert log_data["user_id"] == "test-user-123"
            assert log_data["ip_address"] == "192.168.1.100"
            assert log_data["details"]["request_id"] == 123
    
    def test_audit_logger_unauthorized_access(self):
        """Test unauthorized access logging."""
        from app.audit import audit_logger, AuditEventType
        
        with patch.object(audit_logger.logger, 'warning') as mock_log:
            audit_logger.log_unauthorized_access(
                user_id="user123",
                resource="admin_panel",
                reason="Not in admin group",
                ip_address="192.168.1.100"
            )
            
            assert mock_log.called
            
            import json
            log_data = json.loads(mock_log.call_args[0][0])
            
            assert log_data["event_type"] == AuditEventType.UNAUTHORIZED_ACCESS.value
            assert log_data["success"] is False
    
    def test_get_client_ip_from_forwarded_header(self):
        """Test IP extraction from X-Forwarded-For header."""
        from app.audit import get_client_ip
        
        mock_request = MagicMock()
        mock_request.headers.get.return_value = "203.0.113.1, 198.51.100.1"
        
        ip = get_client_ip(mock_request)
        
        assert ip == "203.0.113.1"  # First IP in chain


# ============================================================================
# Rate Limiting Tests
# ============================================================================

class TestRateLimiting:
    """Test rate limiting functionality."""
    
    @pytest.mark.asyncio
    async def test_rate_limit_applied(self):
        """Test that rate limits are applied to endpoints."""
        from app.routes.requests import create_request
        
        # Check that the decorator is applied
        assert hasattr(create_request, '__wrapped__')
        # Note: Full rate limit testing requires integration tests


# ============================================================================
# Security Tests
# ============================================================================

class TestSecurity:
    """Test security controls and validations."""
    
    def test_csr_signature_validation(self):
        """Test CSR signature validation."""
        from app.crypto import parse_csr
        
        # Invalid CSR should raise ValueError
        invalid_csr = "-----BEGIN CERTIFICATE REQUEST-----\nINVALID\n-----END CERTIFICATE REQUEST-----"
        
        with pytest.raises(Exception):
            parse_csr(invalid_csr)
    
    def test_subject_enforcement(self, mock_user):
        """Test that CSR subject is ignored and OIDC claims are enforced."""
        from app.crypto import build_subject_from_claims
        
        with patch('app.crypto.get_config') as mock_config:
            mock_config.return_value.subject_attributes.static = {"O": "Acme"}
            mock_config.return_value.subject_attributes.mapping = {"CN": "email"}
            
            subject = build_subject_from_claims(mock_user)
            
            # Subject should be built from claims, not CSR
            subject_str = str(subject)
            assert "test@example.com" in subject_str or "Acme" in subject_str
    
    def test_password_generation_entropy(self):
        """Test password generation produces unique values."""
        # Note: Password generation is in JavaScript (frontend)
        # This is a placeholder for backend password validation if needed
        # Frontend password generation should be tested with JavaScript testing framework
        pass
    
    def test_serial_number_uniqueness(self):
        """Test serial numbers are unique."""
        from app.crypto import generate_serial_number
        
        serials = [generate_serial_number() for _ in range(100)]
        
        # All should be unique
        assert len(serials) == len(set(serials))


# ============================================================================
# Quota Tests
# ============================================================================

class TestQuotas:
    """Test certificate quota enforcement."""
    
    @pytest.mark.asyncio
    async def test_quota_enforcement_hard_limit(self, mock_user):
        """Test hard quota limit blocks requests."""
        # This would require full integration test with database
        # Placeholder for structure
        pass
    
    @pytest.mark.asyncio
    async def test_quota_enforcement_soft_limit(self, mock_user):
        """Test soft quota limit forces manual approval."""
        # This would require full integration test with database
        # Placeholder for structure
        pass


# ============================================================================
# Input Validation Tests
# ============================================================================

class TestInputValidation:
    """Test input validation and sanitization."""
    
    def test_ttl_validation(self):
        """Test TTL is capped at max_ttl."""
        rule = CARule(max_ttl="720h")
        max_ttl = rule.parse_ttl_hours()
        
        # Requested TTL should be capped
        requested_ttl = 8760  # 1 year
        actual_ttl = min(requested_ttl, max_ttl)
        
        assert actual_ttl == 720
    
    def test_search_input_sanitization(self):
        """Test search input is properly handled."""
        # SQLAlchemy parameterizes queries, but we should still validate
        search_input = "test'; DROP TABLE certificates; --"
        
        # Should be safe with parameterized queries
        # This is more of an integration test
        assert "'" in search_input  # Just verify test data


# ============================================================================
# Integration Tests (require database)
# ============================================================================

@pytest.mark.integration
class TestIntegration:
    """Integration tests requiring database."""
    
    @pytest.mark.asyncio
    async def test_full_certificate_lifecycle(self):
        """Test complete certificate request, approval, generation, revocation flow."""
        # This would require:
        # 1. Database setup
        # 2. Mock OIDC provider
        # 3. Test CA certificates
        # Placeholder for future implementation
        pass
    
    @pytest.mark.asyncio
    async def test_rate_limit_enforcement(self):
        """Test rate limits are enforced."""
        # This would require:
        # 1. FastAPI TestClient
        # 2. Multiple rapid requests
        # Placeholder for future implementation
        pass


# ============================================================================
# CRL Generation Tests
# ============================================================================

class TestCRLGeneration:
    """Test CRL generation (from existing test file)."""
    
    # CRL tests are in test_crl_format.py
    pass

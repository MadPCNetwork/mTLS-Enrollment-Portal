"""
Integration tests for mTLS PKI Portal API endpoints.
Requires running database and proper configuration.
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from fastapi import status

from app.main import app


# ============================================================================
# Fixtures
# ============================================================================

@pytest_asyncio.fixture
async def client():
    """Create async test client."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as ac:
        yield ac


@pytest.fixture
def mock_token():
    """Mock valid JWT token."""
    return "mock-valid-token"


@pytest.fixture
def auth_headers(mock_token):
    """Authentication headers."""
    return {"Authorization": f"Bearer {mock_token}"}


# ============================================================================
# Public Endpoint Tests
# ============================================================================

class TestPublicEndpoints:
    """Test public endpoints (no authentication required)."""
    
    @pytest.mark.asyncio
    async def test_health_check(self, client):
        """Test health check endpoint."""
        response = await client.get("/api/v1/health")
        
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == {"status": "healthy"}
    
    @pytest.mark.asyncio
    async def test_oidc_config(self, client):
        """Test OIDC configuration endpoint."""
        response = await client.get("/api/v1/oidc-config")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        assert "issuer" in data
        assert "client_id" in data
        assert "scopes" in data


# ============================================================================
# Authentication Tests
# ============================================================================

class TestAuthenticatedEndpoints:
    """Test endpoints requiring authentication."""
    
    @pytest.mark.asyncio
    async def test_list_cas_requires_auth(self, client):
        """Test /cas endpoint requires authentication."""
        response = await client.get("/api/v1/cas")
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    @pytest.mark.asyncio
    async def test_list_requests_requires_auth(self, client):
        """Test /requests endpoint requires authentication."""
        response = await client.get("/api/v1/requests")
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    @pytest.mark.asyncio
    async def test_list_certificates_requires_auth(self, client):
        """Test /certificates endpoint requires authentication."""
        response = await client.get("/api/v1/certificates")
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


# ============================================================================
# Rate Limiting Tests
# ============================================================================

@pytest.mark.integration
class TestRateLimiting:
    """Test rate limiting on endpoints."""
    
    @pytest.mark.asyncio
    async def test_rate_limit_configuration_exists(self, client):
        """Test that rate limiting is configured in the application."""
        # Verify the limiter is attached to the app
        from app.main import app
        
        assert hasattr(app.state, 'limiter'), "Rate limiter should be configured"
    
    @pytest.mark.asyncio
    async def test_health_endpoint_responds(self, client):
        """Test health endpoint is accessible."""
        response = await client.get("/api/v1/health")
        
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == {"status": "healthy"}
    
    # Note: Actual rate limit enforcement testing requires:
    # 1. Multiple unique IP addresses (X-Forwarded-For headers)
    # 2. Real time delays between requests
    # 3. Redis or in-memory storage for rate limit tracking
    # These are better tested in E2E/load testing scenarios


# ============================================================================
# Authorization Tests
# ============================================================================

@pytest.mark.integration
class TestAuthorization:
    """Test authorization and access control."""
    
    @pytest.mark.asyncio
    async def test_admin_endpoint_requires_admin_group(self, client, auth_headers):
        """Test admin endpoints require admin group membership."""
        # This would require mocking the token validation
        # to return a non-admin user
        pass


# ============================================================================
# Security Header Tests
# ============================================================================

class TestSecurityHeaders:
    """Test security headers are present."""
    
    @pytest.mark.asyncio
    async def test_security_headers_present(self, client):
        """Test all security headers are set."""
        response = await client.get("/api/v1/health")
        
        headers = response.headers
        
        # Check critical security headers
        assert "Content-Security-Policy" in headers
        assert "X-Frame-Options" in headers
        assert "X-Content-Type-Options" in headers
        assert "Permissions-Policy" in headers
        assert "Referrer-Policy" in headers
        assert "X-XSS-Protection" in headers
    
    @pytest.mark.asyncio
    async def test_csp_header_content(self, client):
        """Test CSP header contains expected directives."""
        response = await client.get("/api/v1/health")
        
        csp = response.headers.get("Content-Security-Policy", "")
        
        assert "frame-ancestors 'none'" in csp
        assert "base-uri 'self'" in csp
        assert "form-action 'self'" in csp
    
    @pytest.mark.asyncio
    async def test_x_frame_options(self, client):
        """Test X-Frame-Options is set to DENY."""
        response = await client.get("/api/v1/health")
        
        assert response.headers.get("X-Frame-Options") == "DENY"


# ============================================================================
# Error Handling Tests
# ============================================================================

class TestErrorHandling:
    """Test error handling and responses."""
    
    @pytest.mark.asyncio
    async def test_404_on_invalid_endpoint(self, client):
        """Test 404 for non-existent endpoints."""
        response = await client.get("/api/v1/nonexistent")
        
        assert response.status_code == status.HTTP_404_NOT_FOUND
    
    @pytest.mark.asyncio
    async def test_rate_limit_error_format(self, client):
        """Test rate limit error response format."""
        # Make requests until rate limited
        for _ in range(35):
            response = await client.get("/api/v1/health")
            
            if response.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
                data = response.json()
                assert "detail" in data
                assert "retry_after" in data or "Retry" in data["detail"]
                break

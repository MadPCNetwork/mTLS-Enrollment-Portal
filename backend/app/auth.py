"""
OIDC Authentication module.
Handles Bearer token validation and user claims extraction.
"""

from typing import Optional

import httpx
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel

from .config import get_config


class UserClaims(BaseModel):
    """User claims extracted from OIDC token."""
    sub: str  # Subject (unique user ID)
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    preferred_username: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    name: Optional[str] = None
    groups: list[str] = []
    locale: Optional[str] = None
    
    # Raw claims for custom mapping
    raw_claims: dict = {}
    
    @property
    def display_name(self) -> str:
        """Get the best available display name."""
        return self.name or self.preferred_username or self.email or self.sub
    
    def get_claim(self, claim_name: str) -> Optional[str | list[str]]:
        """Get a claim value by name, checking raw_claims as fallback."""
        # Check known fields first
        if hasattr(self, claim_name) and claim_name not in ("raw_claims", "display_name"):
            value = getattr(self, claim_name)
            if value is not None:
                return value
        # Check raw claims
        return self.raw_claims.get(claim_name)


# Cache for OIDC configuration
_oidc_config_cache: Optional[dict] = None
_jwks_cache: Optional[dict] = None


async def get_oidc_config() -> dict:
    """Fetch and cache OIDC discovery document."""
    global _oidc_config_cache
    
    if _oidc_config_cache is not None:
        return _oidc_config_cache
    
    config = get_config()
    issuer = config.oidc.issuer.rstrip("/")
    discovery_url = f"{issuer}/.well-known/openid-configuration"
    
    async with httpx.AsyncClient() as client:
        response = await client.get(discovery_url)
        response.raise_for_status()
        _oidc_config_cache = response.json()
    
    return _oidc_config_cache


async def get_jwks() -> dict:
    """Fetch and cache JWKS (JSON Web Key Set)."""
    global _jwks_cache
    
    if _jwks_cache is not None:
        return _jwks_cache
    
    oidc_config = await get_oidc_config()
    jwks_uri = oidc_config.get("jwks_uri")
    
    if not jwks_uri:
        raise ValueError("JWKS URI not found in OIDC configuration")
    
    async with httpx.AsyncClient() as client:
        response = await client.get(jwks_uri)
        response.raise_for_status()
        _jwks_cache = response.json()
    
    return _jwks_cache


async def get_userinfo(access_token: str) -> dict:
    """Fetch fresh user info from OIDC provider."""
    oidc_config = await get_oidc_config()
    userinfo_endpoint = oidc_config.get("userinfo_endpoint")
    
    if not userinfo_endpoint:
        raise ValueError("Userinfo endpoint not found in OIDC configuration")
    
    async with httpx.AsyncClient() as client:
        response = await client.get(
            userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"}
        )
        response.raise_for_status()
        return response.json()


async def validate_token(token: str) -> UserClaims:
    """
    Validate a token and extract user claims.
    
    Authentik access tokens may be opaque or JWTs without audience.
    We validate by fetching userinfo - if it succeeds, the token is valid.
    
    Retries transient OIDC provider errors (e.g. cold cache after startup)
    to avoid 503s on the first request after login.
    """
    import asyncio
    import logging
    
    config = get_config()
    logger = logging.getLogger(__name__)
    
    max_retries = 2
    retry_delay = 0.5  # seconds
    
    for attempt in range(max_retries + 1):
        try:
            # Try to get userinfo - this validates the token with the OIDC provider
            try:
                userinfo = await get_userinfo(token)
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 401:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid or expired token",
                    )
                raise
            
            # Extract groups - Authentik uses 'groups' claim
            groups = userinfo.get("groups", [])
            if isinstance(groups, str):
                groups = [groups]
            
            return UserClaims(
                sub=userinfo.get("sub"),
                email=userinfo.get("email"),
                email_verified=userinfo.get("email_verified"),
                preferred_username=userinfo.get("preferred_username"),
                given_name=userinfo.get("given_name"),
                family_name=userinfo.get("family_name"),
                name=userinfo.get("name"),
                groups=groups,
                locale=userinfo.get("locale"),
                raw_claims=userinfo,
            )
            
        except HTTPException:
            raise
        except httpx.HTTPError as e:
            if attempt < max_retries:
                logger.warning(
                    f"OIDC provider request failed (attempt {attempt + 1}/{max_retries + 1}), "
                    f"retrying in {retry_delay}s: {e}"
                )
                # Clear caches in case they hold stale/bad data
                global _oidc_config_cache, _jwks_cache
                _oidc_config_cache = None
                _jwks_cache = None
                await asyncio.sleep(retry_delay)
                retry_delay *= 2  # exponential backoff
            else:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=f"OIDC provider unavailable: {str(e)}",
                )


# FastAPI security scheme
bearer_scheme = HTTPBearer(auto_error=True)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> UserClaims:
    """FastAPI dependency to get the current authenticated user."""
    from .audit import audit_logger
    
    try:
        user = await validate_token(credentials.credentials)
        # Note: We don't log every successful auth here to avoid log spam
        # Only log significant events (login, logout, failures)
        return user
    except HTTPException as e:
        # Log authentication failures
        if e.status_code == 401:
            audit_logger.log_auth_failure(
                reason=e.detail,
                ip_address=None,  # IP not available in dependency
            )
        raise


async def require_groups(required_groups: list[str], user: UserClaims) -> bool:
    """Check if user belongs to any of the required groups."""
    if not required_groups:
        return True
    return any(group in user.groups for group in required_groups)


def get_user_matching_rule(user: UserClaims, ca_id: str):
    """
    Find the best matching CA rule for a user.
    Returns the rule and whether the user has access.
    """
    config = get_config()
    
    # Find the CA
    ca = None
    for c in config.x509_cas:
        if c.id == ca_id:
            ca = c
            break
    
    if ca is None:
        return None, False
    
    # Check rules in order - first matching rule wins
    for rule in ca.rules:
        if any(group in user.groups for group in rule.oidc_groups):
            return rule, True
    
    return None, False

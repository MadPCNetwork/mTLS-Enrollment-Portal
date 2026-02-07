"""
Zero-Trust mTLS PKI Portal - FastAPI Application
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from .audit import audit_logger, get_client_ip
from .config import load_config
from .database import init_db
from .routes.requests import router as requests_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    import asyncio
    import logging
    logger = logging.getLogger(__name__)
    
    # Startup - config loads from env + yaml automatically
    load_config()
    await init_db()
    
    # Pre-warm OIDC discovery and JWKS caches so the first user request
    # doesn't trigger a cold fetch (which can fail transiently and cause 503s)
    try:
        from .auth import get_oidc_config, get_jwks
        await get_oidc_config()
        await get_jwks()
        logger.info("OIDC discovery and JWKS caches pre-warmed successfully")
    except Exception as e:
        logger.warning(f"Failed to pre-warm OIDC caches (will retry on first request): {e}")
    
    # Start renewal notification background task if SMTP is enabled
    renewal_task = None
    config = load_config()
    if config.smtp.enabled:
        from .renewal_notifier import renewal_notification_loop
        renewal_task = asyncio.create_task(renewal_notification_loop())
        logger.info("Renewal notification background task scheduled")
    else:
        logger.info("SMTP disabled - renewal notification background task not started")
    
    yield
    
    # Shutdown - cancel background tasks
    if renewal_task is not None:
        renewal_task.cancel()
        try:
            await renewal_task
        except asyncio.CancelledError:
            pass
        logger.info("Renewal notification background task stopped")


# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="mTLS PKI Portal",
    description="Zero-Trust mTLS Certificate Management Portal",
    version="1.0.0",
    lifespan=lifespan,
)

# Attach limiter to app state
app.state.limiter = limiter

# Add rate limit exception handler
@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """Handle rate limit exceeded errors."""
    ip_address = get_client_ip(request)
    endpoint = request.url.path
    
    # Log rate limit violation
    audit_logger.log_rate_limit_exceeded(
        endpoint=endpoint,
        ip_address=ip_address,
    )
    
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={
            "detail": "Rate limit exceeded. Please try again later.",
            "retry_after": exc.detail.split("Retry after ")[1] if "Retry after" in exc.detail else "60 seconds"
        }
    )

# CORS configuration for development
# In production, the SPA is served from the same origin via nginx
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost",
        "http://localhost:3000",
        "http://localhost:8080",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(requests_router, dependencies=[])

# Add security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    
    # Content Security Policy - balanced security without requiring URL whitelisting
    # Allows external resources while still protecting against common attacks
    response.headers["Content-Security-Policy"] = (
        "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    
    # Strict Transport Security - enforce HTTPS (only if behind HTTPS proxy)
    # Note: This should only be enabled in production with HTTPS
    # response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    
    # Permissions Policy - disable unnecessary browser features
    response.headers["Permissions-Policy"] = (
        "geolocation=(), "
        "microphone=(), "
        "camera=(), "
        "payment=(), "
        "usb=(), "
        "magnetometer=(), "
        "gyroscope=(), "
        "accelerometer=()"
    )
    
    # X-Content-Type-Options - prevent MIME sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    
    # X-Frame-Options - prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    
    # Referrer-Policy - control referrer information
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    # X-XSS-Protection - legacy XSS protection (for older browsers)
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    return response


@app.get("/")
async def root():
    """Root endpoint - API info."""
    return {
        "name": "mTLS PKI Portal API",
        "version": "1.0.0",
        "docs": "/docs",
    }

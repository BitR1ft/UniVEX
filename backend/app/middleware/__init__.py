"""
Custom middleware for FastAPI application
Includes error handling, request validation, rate limiting, and request tracking
"""
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.gzip import GZipMiddleware
import time
import uuid
import logging
from typing import Callable
from collections import defaultdict
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Health/noise endpoints to skip logging
_SKIP_LOG_PATHS = frozenset(["/health", "/readiness", "/"])


class CorrelationIDMiddleware(BaseHTTPMiddleware):
    """
    Propagate or generate an X-Request-ID header and store it on request.state.
    """

    def __init__(self, app, header_name: str = "X-Request-ID"):
        super().__init__(app)
        self.header_name = header_name

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        correlation_id = request.headers.get(self.header_name) or str(uuid.uuid4())
        request.state.correlation_id = correlation_id
        # Ensure request_id is also set for compatibility
        if not hasattr(request.state, "request_id"):
            request.state.request_id = correlation_id
        response = await call_next(request)
        response.headers[self.header_name] = correlation_id
        return response


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Add unique request ID to each request for tracking and logging.

    .. deprecated::
        ``CorrelationIDMiddleware`` supersedes this class: it propagates the
        upstream ``X-Request-ID`` header (or generates one) and sets both
        ``request.state.correlation_id`` and ``request.state.request_id``.
        This middleware is kept for backwards compatibility only; when both are
        registered, ``CorrelationIDMiddleware`` must run first so that
        ``request_id`` is already present when this class executes.
    """
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = getattr(request.state, "request_id", None) or str(uuid.uuid4())
        request.state.request_id = request_id

        # Add request ID to response headers
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id

        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Log all incoming requests and responses with timing, correlation ID, and size info.
    Skips health check endpoints to reduce noise.
    """
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip noisy health endpoints
        if request.url.path in _SKIP_LOG_PATHS:
            return await call_next(request)

        start_time = time.time()
        correlation_id = getattr(request.state, "correlation_id", "unknown")
        request_id = getattr(request.state, "request_id", "unknown")

        # Approximate request size from content-length header
        req_size = int(request.headers.get("content-length", 0))

        response = await call_next(request)

        duration_ms = (time.time() - start_time) * 1000
        resp_size = int(response.headers.get("content-length", 0))

        logger.info(
            "HTTP request",
            extra={
                "correlation_id": correlation_id,
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": round(duration_ms, 2),
                "request_size_bytes": req_size,
                "response_size_bytes": resp_size,
            },
        )

        response.headers["X-Process-Time"] = f"{duration_ms / 1000:.3f}"
        return response


class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """
    Global error handling middleware
    Catches and formats all unhandled exceptions
    """
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        try:
            response = await call_next(request)
            return response
        except Exception as exc:
            request_id = getattr(request.state, "request_id", "unknown")
            
            # Log the error
            logger.error(
                f"Unhandled exception in request {request_id}: {exc}",
                exc_info=True
            )
            
            # Return formatted error response
            return JSONResponse(
                status_code=500,
                content={
                    "error": "Internal Server Error",
                    "message": str(exc) if logger.level == logging.DEBUG else "An unexpected error occurred",
                    "request_id": request_id,
                    "timestamp": datetime.utcnow().isoformat()
                }
            )


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Simple rate limiting middleware
    Limits requests per IP address
    """
    def __init__(self, app, calls: int = 100, period: int = 60):
        """
        Initialize rate limiter
        
        Args:
            app: FastAPI application
            calls: Maximum number of calls allowed
            period: Time period in seconds
        """
        super().__init__(app)
        self.calls = calls
        self.period = period
        self.clients = defaultdict(list)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip rate limiting for health checks
        if request.url.path in ["/health", "/", "/docs", "/redoc", "/openapi.json"]:
            return await call_next(request)
        
        # Get client IP
        client_ip = request.client.host
        now = datetime.now()
        
        # Clean old requests
        self.clients[client_ip] = [
            req_time for req_time in self.clients[client_ip]
            if now - req_time < timedelta(seconds=self.period)
        ]
        
        # Check rate limit
        if len(self.clients[client_ip]) >= self.calls:
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too Many Requests",
                    "message": f"Rate limit exceeded. Maximum {self.calls} requests per {self.period} seconds.",
                    "retry_after": self.period
                },
                headers={"Retry-After": str(self.period)}
            )
        
        # Add current request
        self.clients[client_ip].append(now)
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(self.calls)
        response.headers["X-RateLimit-Remaining"] = str(
            self.calls - len(self.clients[client_ip])
        )
        response.headers["X-RateLimit-Reset"] = str(self.period)
        
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Add security headers to all responses
    """
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        return response


class MetricsMiddleware(BaseHTTPMiddleware):
    """
    Record Prometheus HTTP metrics on every request.
    Skips the /metrics endpoint itself to avoid self-referential noise.
    Gracefully degrades if prometheus_client is not installed.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path == "/metrics":
            return await call_next(request)

        start = time.time()
        response = await call_next(request)
        duration = time.time() - start

        try:
            from app.core.metrics import http_requests_total, http_request_duration_seconds
            endpoint = request.url.path
            http_requests_total.labels(
                method=request.method,
                endpoint=endpoint,
                status_code=str(response.status_code),
            ).inc()
            http_request_duration_seconds.labels(
                method=request.method,
                endpoint=endpoint,
            ).observe(duration)
        except Exception:
            pass  # metrics not available – don't crash the request

        return response


class APIVersionMiddleware(BaseHTTPMiddleware):
    """
    Inject API versioning metadata into every HTTP response.

    Adds the following headers:
    - ``X-API-Version``      — canonical integer version of the active API
      (e.g. ``1``).
    - ``X-API-Deprecated``   — present and set to ``true`` only when the
      request targets a legacy unversioned path (``/api/*``).  Clients that
      see this header should migrate to the versioned path (``/v1/api/*``).

    The middleware reads ``settings.API_VERSION`` so the version is controlled
    entirely via the ``API_VERSION`` environment variable without touching
    application code.
    """

    def __init__(self, app, api_version: str = "1"):
        super().__init__(app)
        self.api_version = api_version

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["X-API-Version"] = self.api_version
        # Flag legacy /api/* calls so clients know to migrate
        path = request.url.path
        if path.startswith("/api/") and not path.startswith("/api/health"):
            response.headers["X-API-Deprecated"] = "true"
            response.headers["X-API-Deprecated-Sunset"] = "2027-01-01"
            response.headers["Link"] = (
                f'</v{self.api_version}{path}>; rel="successor-version"'
            )
        return response


def setup_middleware(app):
    """
    Set up all middleware for the FastAPI application

    Args:
        app: FastAPI application instance
    """
    from app.core.config import settings

    # Add middleware in reverse order (last added is executed first)

    # Compression
    app.add_middleware(GZipMiddleware, minimum_size=1000)

    # Security headers
    app.add_middleware(SecurityHeadersMiddleware)

    # Prometheus metrics
    app.add_middleware(MetricsMiddleware)

    # Rate limiting (100 requests per minute by default)
    app.add_middleware(RateLimitMiddleware, calls=100, period=60)

    # Error handling
    app.add_middleware(ErrorHandlingMiddleware)

    # Request logging
    app.add_middleware(RequestLoggingMiddleware)

    # API versioning headers (must run before correlation/request-id so that
    # the version header is always present even if upstream middleware short-circuits)
    app.add_middleware(APIVersionMiddleware, api_version=settings.API_VERSION)

    # Correlation ID propagation
    app.add_middleware(CorrelationIDMiddleware)

    # Request ID tracking
    app.add_middleware(RequestIDMiddleware)

    logger.info("Middleware setup complete")

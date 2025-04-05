"""
UniVex Proxy Engine

Sub-package that provides the core MITM proxy engine for HTTP/HTTPS interception,
request/response storage, and dynamic SSL certificate generation.

Public exports:
  ProxyInterceptor   — mitmproxy-based MITM engine
  RequestStore       — in-memory + Redis-backed request/response storage
  SSLContextManager  — dynamic CA + per-domain certificate factory
"""

from .interceptor import ProxyInterceptor
from .request_store import RequestStore, CapturedRequest, CapturedResponse
from .ssl_context import SSLContextManager

__all__ = [
    "ProxyInterceptor",
    "RequestStore",
    "CapturedRequest",
    "CapturedResponse",
    "SSLContextManager",
]

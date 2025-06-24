"""
Test configuration for search tool tests.

Stubs additional heavy dependencies that the app.agent import chain requires
but are not installed in the test environment.
"""

import sys
import types
from unittest.mock import MagicMock


class _AutoMockModule(types.ModuleType):
    """
    A module stub that returns MagicMock for any attribute access
    and supports submodule-style imports.
    """

    def __init__(self, name: str):
        super().__init__(name)
        self.__path__ = []
        self.__package__ = name
        self.__spec__ = None

    def __getattr__(self, item: str):
        # Return a MagicMock for any unknown attribute (e.g. classes, functions)
        value = MagicMock(name=f"{self.__name__}.{item}")
        object.__setattr__(self, item, value)
        return value


def _stub_module(name: str) -> _AutoMockModule:
    """Insert an auto-mocking module into sys.modules so imports succeed."""
    parts = name.split(".")
    for i in range(1, len(parts) + 1):
        dotted = ".".join(parts[:i])
        if dotted not in sys.modules:
            mod = _AutoMockModule(dotted)
            sys.modules[dotted] = mod
            # Attach as attribute on parent
            if i > 1:
                parent = sys.modules[".".join(parts[:i - 1])]
                setattr(parent, parts[i - 1], mod)
    return sys.modules[name]  # type: ignore[return-value]


# Stub out additional heavy dependencies not covered by the parent conftest
for _pkg in [
    "fastapi",
    "fastapi.responses",
    "fastapi.exceptions",
    "fastapi.routing",
    "fastapi.middleware",
    "fastapi.middleware.cors",
    "fastapi.security",
    "fastapi.staticfiles",
    "fastapi.testclient",
    "starlette",
    "starlette.middleware",
    "starlette.requests",
    "starlette.responses",
    "starlette.routing",
    "starlette.types",
    "starlette.testclient",
    "aiofiles",
    "docker",
    "docker.errors",
    "docker.types",
    "redis",
    "redis.asyncio",
    "asyncpg",
    "psycopg2",
    "psycopg2.extras",
    "prisma",
    "websockets",
    "sse_starlette",
    "sse_starlette.sse",
    "tavily",
    "whois",
    "dns",
    "dns.resolver",
    "mmh3",
    "prometheus_client",
    "opentelemetry",
    "opentelemetry.trace",
    "opentelemetry.sdk",
    "opentelemetry.sdk.trace",
    "opentelemetry.instrumentation",
    "opentelemetry.instrumentation.fastapi",
    "opentelemetry.exporter",
    "opentelemetry.exporter.otlp",
    "opentelemetry.exporter.otlp.proto",
    "opentelemetry.exporter.otlp.proto.grpc",
    "chromadb",
    "chromadb.config",
    "langchain_chroma",
    "matplotlib",
    "matplotlib.pyplot",
    "weasyprint",
    "fakeredis",
    "boto3",
    "botocore",
    "botocore.exceptions",
    "jose",
    "jose.jwt",
    "passlib",
    "passlib.context",
    "pyotp",
    "multipart",
    "aiohttp",
    "sklearn",
    "sklearn.svm",
    "sklearn.feature_extraction",
    "sklearn.feature_extraction.text",
    "sklearn.pipeline",
    "sklearn.model_selection",
    "duckduckgo_search",
    "python_multipart",
    "email_validator",
    "pydantic_extra_types",
    "cryptography",
    "slugify",
]:
    _stub_module(_pkg)

# DuckDuckGo stub — expose DDGS class
_ddgs_mod = sys.modules["duckduckgo_search"]
_ddgs_mod.DDGS = MagicMock(name="DDGS")

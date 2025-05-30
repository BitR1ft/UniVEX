"""
UniVex Observability Package

Provides LLM tracing (Langfuse), structured log aggregation (Loki),
and distributed tracing (Jaeger / OpenTelemetry) for the full agent
execution pipeline.

Public surface
--------------
- ``LangfuseClient``  — trace every LLM call across all 13 agent roles
- ``LokiHandler``     — Python logging handler that ships JSON logs to Loki
- ``get_langfuse``    — module-level singleton accessor
- ``setup_logging``   — configure structured JSON logging with Loki shipping
"""

from .langfuse_client import LangfuseClient, get_langfuse
from .loki_handler import LokiHandler

__all__ = [
    "LangfuseClient",
    "get_langfuse",
    "LokiHandler",
]

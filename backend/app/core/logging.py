"""
Structured logging configuration — Loki + Jaeger integration.

Provides:
- JSONFormatter: single-line JSON log records with OpenTelemetry trace context
- CorrelationFilter: injects correlation_id / trace_id / span_id on every record
- configure_logging(): one-call setup for stdout JSON + optional Loki shipping
- get_logger(): returns a logger pre-configured with UniVex structured fields
"""
from __future__ import annotations

import json
import logging
import logging.config
import os
import sys
from datetime import datetime, timezone
from typing import Any, Optional


# ---------------------------------------------------------------------------
# JSON Formatter with OTEL trace context injection
# ---------------------------------------------------------------------------

class JSONFormatter(logging.Formatter):
    """
    Formats log records as single-line JSON objects.

    Extended fields over the original implementation:
    - ``trace_id`` / ``span_id`` injected from the active OpenTelemetry span
    - ``flow_id``, ``agent_role``, ``session_id`` forwarded from record extras
    - ``service`` tag for Loki / Grafana stream identification
    - ``environment`` tag for multi-environment log filtering
    """

    # Env-level static fields (set once at process start)
    _SERVICE = os.getenv("SERVICE_NAME", "univex-api")
    _ENV = os.getenv("ENVIRONMENT", "development")

    def format(self, record: logging.LogRecord) -> str:
        log_obj: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "service": self._SERVICE,
            "environment": self._ENV,
        }

        # --- OpenTelemetry trace context ---
        trace_id, span_id = _get_otel_ids()
        if trace_id:
            log_obj["trace_id"] = trace_id
        if span_id:
            log_obj["span_id"] = span_id

        # --- Correlation / structured extras ---
        for attr in (
            "correlation_id",
            "request_id",
            "duration_ms",
            "flow_id",
            "agent_role",
            "trace_id",      # explicit override wins over OTEL
            "session_id",
        ):
            val = getattr(record, attr, None)
            if val is not None:
                log_obj[attr] = val

        # --- Exception info ---
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            log_obj["stack_info"] = record.stack_info

        return json.dumps(log_obj, default=str)


# ---------------------------------------------------------------------------
# Correlation filter — injects trace context onto every record
# ---------------------------------------------------------------------------

class CorrelationFilter(logging.Filter):
    """
    Logging filter that injects the current OpenTelemetry trace / span IDs
    onto every ``LogRecord``.  Downstream formatters and Loki label extractors
    can then use these fields for trace → log correlation in Grafana.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        trace_id, span_id = _get_otel_ids()
        if not hasattr(record, "trace_id") or not record.trace_id:  # type: ignore[attr-defined]
            record.trace_id = trace_id or ""  # type: ignore[attr-defined]
        if not hasattr(record, "span_id") or not record.span_id:  # type: ignore[attr-defined]
            record.span_id = span_id or ""  # type: ignore[attr-defined]
        return True


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_otel_ids() -> tuple[str, str]:
    """
    Return (trace_id_hex, span_id_hex) from the active OpenTelemetry span.
    Returns empty strings when OTEL is not configured or no span is active.
    """
    try:
        from opentelemetry import trace  # noqa: PLC0415
        span = trace.get_current_span()
        ctx = span.get_span_context()
        if ctx.is_valid:
            trace_hex = format(ctx.trace_id, "032x")
            span_hex = format(ctx.span_id, "016x")
            return trace_hex, span_hex
    except Exception:  # noqa: BLE001
        pass
    return "", ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def configure_logging(
    log_level: str = "INFO",
    log_format: str = "json",
    loki_url: Optional[str] = None,
    loki_labels: Optional[dict[str, str]] = None,
    enable_loki: Optional[bool] = None,
) -> None:
    """
    Configure application-wide logging.

    Args:
        log_level:    Root log level (DEBUG / INFO / WARNING / ERROR).
        log_format:   ``"json"`` (structured) or ``"text"`` (human-readable).
        loki_url:     Loki push URL.  Falls back to ``LOKI_URL`` env var.
        loki_labels:  Extra static Loki stream labels.
        enable_loki:  Explicitly enable / disable Loki shipping.  Auto-detects
                      from ``LOKI_ENABLED`` env var and URL availability when
                      ``None``.
    """
    root = logging.getLogger()
    root.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Remove existing handlers to avoid duplicate logs on reload
    root.handlers.clear()

    # Correlation filter on root logger
    root.addFilter(CorrelationFilter())

    # --- stdout handler ---
    stdout_handler = logging.StreamHandler(sys.stdout)
    if log_format == "json":
        stdout_handler.setFormatter(JSONFormatter())
    else:
        stdout_handler.setFormatter(
            logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")
        )
    root.addHandler(stdout_handler)

    # --- Loki handler (optional) ---
    resolved_loki_url = loki_url or os.getenv("LOKI_URL", "")
    if enable_loki is None:
        loki_env = os.getenv("LOKI_ENABLED", "").lower()
        if loki_env in ("true", "1", "yes"):
            enable_loki = True
        elif loki_env in ("false", "0", "no"):
            enable_loki = False
        else:
            # Auto-enable when a URL is available
            enable_loki = bool(resolved_loki_url)

    if enable_loki and resolved_loki_url:
        try:
            from app.observability.loki_handler import build_loki_handler  # noqa: PLC0415
            loki_handler = build_loki_handler(
                url=resolved_loki_url,
                labels=loki_labels,
                level=getattr(logging, log_level.upper(), logging.INFO),
            )
            root.addHandler(loki_handler)
            logging.getLogger(__name__).debug(
                "Loki log handler attached — url=%s", resolved_loki_url
            )
        except Exception as exc:  # noqa: BLE001
            logging.getLogger(__name__).warning(
                "Failed to attach Loki handler: %s", exc
            )


def get_logger(
    name: str,
    *,
    flow_id: Optional[str] = None,
    agent_role: Optional[str] = None,
    session_id: Optional[str] = None,
) -> logging.Logger:
    """
    Return a logger pre-configured with UniVex structured fields.

    Extra keyword args are set as default ``LogRecord`` extra fields so every
    message emitted through this logger automatically carries them.

    Usage::

        log = get_logger("app.agent.recon", agent_role="recon", flow_id=fid)
        log.info("Scan complete", extra={"target": "192.168.1.1"})
    """
    log = logging.getLogger(name)

    class _ContextAdapter(logging.LoggerAdapter):
        def process(self, msg: Any, kwargs: Any) -> tuple[Any, Any]:
            extra = kwargs.get("extra") or {}
            if flow_id and "flow_id" not in extra:
                extra["flow_id"] = flow_id
            if agent_role and "agent_role" not in extra:
                extra["agent_role"] = agent_role
            if session_id and "session_id" not in extra:
                extra["session_id"] = session_id
            kwargs["extra"] = extra
            return msg, kwargs

    return _ContextAdapter(log, {})

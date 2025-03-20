"""
Tool Execution Metrics & Structured Logging

Provides:
  - ``ToolMetrics``         – in-process metric aggregator per tool invocation
  - ``StructuredLogger``    – JSON-structured log formatter wrapper
  - ``log_tool_execution``  – convenience decorator that logs + collects metrics
"""
from __future__ import annotations

import functools
import json
import logging
import time
from datetime import datetime
from typing import Any, Callable, Dict, Optional


# ---------------------------------------------------------------------------
# JSON log formatter
# ---------------------------------------------------------------------------

class JSONFormatter(logging.Formatter):
    """
    Emit log records as single-line JSON objects.

    Compatible with most structured-log ingestion pipelines
    (Datadog, ELK, GCP Logging, etc.).
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Attach extra structured fields added by callers
        for key, value in record.__dict__.items():
            if key not in (
                "name", "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "exc_info", "exc_text", "stack_info",
                "lineno", "funcName", "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process", "message",
            ):
                payload[key] = value

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        try:
            return json.dumps(payload, default=str)
        except Exception:
            return json.dumps({"message": str(payload)})


def get_structured_logger(name: str) -> logging.Logger:
    """
    Return a logger pre-configured with ``JSONFormatter``.

    Suitable for production environments where logs are ingested by a
    structured-log pipeline.  Falls back gracefully if the handler already
    exists.
    """
    log = logging.getLogger(name)
    if not any(isinstance(h, logging.StreamHandler) for h in log.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(JSONFormatter())
        log.addHandler(handler)
        log.propagate = False
    return log


# ---------------------------------------------------------------------------
# ToolMetrics – per-invocation accumulator
# ---------------------------------------------------------------------------

class ToolMetrics:
    """
    Collects execution metrics for a single tool invocation.

    Call :meth:`start` at the beginning of an invocation,
    :meth:`stop` at the end, and :meth:`to_dict` to retrieve a snapshot.

    Counters can be incremented at any point during execution::

        metrics = ToolMetrics("nuclei")
        metrics.start()
        ...
        metrics.increment("templates_loaded", 150)
        metrics.increment("findings", 3)
        ...
        metrics.stop(success=True)
        print(metrics.to_dict())
    """

    def __init__(self, tool_name: str) -> None:
        self.tool_name = tool_name
        self._start_time: Optional[float] = None
        self._stop_time: Optional[float] = None
        self._counters: Dict[str, int] = {}
        self._gauges: Dict[str, float] = {}
        self.success: Optional[bool] = None
        self.error: Optional[str] = None

    def start(self) -> "ToolMetrics":
        self._start_time = time.monotonic()
        return self

    def stop(self, success: bool = True, error: Optional[str] = None) -> "ToolMetrics":
        self._stop_time = time.monotonic()
        self.success = success
        self.error = error
        return self

    @property
    def duration_seconds(self) -> Optional[float]:
        if self._start_time is None:
            return None
        end = self._stop_time if self._stop_time is not None else time.monotonic()
        return round(end - self._start_time, 3)

    def increment(self, name: str, amount: int = 1) -> None:
        """Increment integer counter *name* by *amount*."""
        self._counters[name] = self._counters.get(name, 0) + amount

    def gauge(self, name: str, value: float) -> None:
        """Set gauge *name* to *value* (last-write-wins)."""
        self._gauges[name] = value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool_name,
            "duration_seconds": self.duration_seconds,
            "success": self.success,
            "error": self.error,
            "counters": dict(self._counters),
            "gauges": dict(self._gauges),
        }


# ---------------------------------------------------------------------------
# Decorator
# ---------------------------------------------------------------------------

def log_tool_execution(
    tool_name: Optional[str] = None,
    logger_name: Optional[str] = None,
) -> Callable:
    """
    Decorator that:

    1. Starts a ``ToolMetrics`` instance before calling the wrapped function.
    2. Stops metrics (success/failure) after the call.
    3. Emits a structured log record with the full metrics snapshot.

    The ``ToolMetrics`` object is injected as the kwarg ``_metrics``
    so the wrapped function can increment counters::

        @log_tool_execution("nuclei")
        async def run_nuclei(target: str, _metrics: ToolMetrics = None):
            ...
            _metrics.increment("templates_run", 150)
    """

    def decorator(func: Callable) -> Callable:
        _tool = tool_name or func.__name__
        _log = get_structured_logger(logger_name or f"tool.{_tool}")

        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            metrics = ToolMetrics(_tool)
            metrics.start()
            kwargs.setdefault("_metrics", metrics)

            try:
                result = await func(*args, **kwargs)
                metrics.stop(success=True)
                return result
            except Exception as exc:
                metrics.stop(success=False, error=str(exc))
                raise
            finally:
                snapshot = metrics.to_dict()
                log_fn = _log.info if metrics.success else _log.error
                log_fn(
                    "Tool execution complete",
                    extra={"tool_metrics": snapshot},
                )

        return wrapper

    return decorator

"""
Loki Structured Log Handler

A Python ``logging.Handler`` that ships structured JSON log records to a
Grafana Loki instance via its HTTP push API (``/loki/api/v1/push``).

Features
--------
- Batched push with configurable batch size and flush interval
- Background worker thread so logging calls are non-blocking
- Structured JSON payloads with ``flow_id``, ``agent_role``, ``trace_id``
  labels for Loki stream selection and log correlation
- Graceful degradation: drops records silently on connection errors so a
  Loki outage never crashes UniVex
- Compatible with Python's standard ``logging`` module — attach to any logger

Configuration
-------------
Set the following environment variables (or configure programmatically):
    LOKI_URL       — Loki push URL (default: http://loki:3100)
    LOKI_ENABLED   — true / false (default: true when LOKI_URL is set)
    LOKI_BATCH_SIZE  — max log lines per push (default: 100)
    LOKI_FLUSH_INTERVAL — flush interval in seconds (default: 2.0)
    LOKI_TIMEOUT    — HTTP timeout in seconds (default: 5)
    LOKI_LABELS     — extra static labels as JSON string (default: '{}')

Usage
-----
    from app.observability.loki_handler import LokiHandler
    import logging

    handler = LokiHandler(
        url="http://loki:3100",
        labels={"app": "univex", "env": "production"},
    )
    logging.getLogger().addHandler(handler)
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
from typing import Any, Dict, List, Optional, Tuple


# Nanosecond timestamp helper
def _ns_timestamp(ts: float) -> str:
    """Convert a Unix float timestamp to a nanosecond string for Loki."""
    return str(int(ts * 1_000_000_000))


# ---------------------------------------------------------------------------
# LokiHandler
# ---------------------------------------------------------------------------

class LokiHandler(logging.Handler):
    """
    Python ``logging.Handler`` that ships JSON log records to Grafana Loki.

    Records are buffered in a thread-safe queue and flushed in batches by a
    background worker thread.  The handler never blocks the calling thread.

    The Loki stream label set is derived from:
    1. Static labels provided at construction (``labels`` parameter)
    2. Dynamic labels extracted from the ``LogRecord`` extra fields:
       ``flow_id``, ``agent_role``, ``trace_id``, ``request_id``
    """

    DEFAULT_BATCH_SIZE = 100
    DEFAULT_FLUSH_INTERVAL = 2.0  # seconds
    DEFAULT_TIMEOUT = 5           # seconds
    DEFAULT_QUEUE_SIZE = 10_000   # maximum buffered log lines before drops

    def __init__(
        self,
        url: str = "http://loki:3100",
        labels: Optional[Dict[str, str]] = None,
        batch_size: int = DEFAULT_BATCH_SIZE,
        flush_interval: float = DEFAULT_FLUSH_INTERVAL,
        timeout: int = DEFAULT_TIMEOUT,
        enabled: bool = True,
        level: int = logging.DEBUG,
        queue_size: int = DEFAULT_QUEUE_SIZE,
    ) -> None:
        super().__init__(level=level)

        # Normalise URL — strip trailing slash and ensure push endpoint
        base_url = url.rstrip("/")
        self._push_url = f"{base_url}/loki/api/v1/push"
        self._static_labels: Dict[str, str] = {"app": "univex", **(labels or {})}
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._timeout = timeout
        self._enabled = enabled

        # Thread-safe queue for buffering log lines before push
        self._queue: queue.Queue[Optional[Tuple[Dict[str, str], str, str]]] = queue.Queue(
            maxsize=queue_size
        )

        # Background worker thread
        self._worker: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        if self._enabled:
            self._start_worker()

    # ------------------------------------------------------------------
    # logging.Handler interface
    # ------------------------------------------------------------------

    def emit(self, record: logging.LogRecord) -> None:
        """Enqueue a log record for async push to Loki."""
        if not self._enabled:
            return
        try:
            labels = self._extract_labels(record)
            message = self._format_record(record)
            ts = _ns_timestamp(record.created)
            # Non-blocking put; drop silently if queue is full
            self._queue.put_nowait((labels, ts, message))
        except queue.Full:
            pass  # Drop silently — never block the caller
        except Exception:  # noqa: BLE001
            self.handleError(record)

    def close(self) -> None:
        """Flush remaining records and stop the background worker."""
        self._stop_event.set()
        if self._worker is not None and self._worker.is_alive():
            # Signal the worker to stop via sentinel
            try:
                self._queue.put_nowait(None)
            except queue.Full:
                pass
            self._worker.join(timeout=10)
        super().close()

    # ------------------------------------------------------------------
    # Worker thread
    # ------------------------------------------------------------------

    def _start_worker(self) -> None:
        self._worker = threading.Thread(
            target=self._run,
            name="loki-handler-worker",
            daemon=True,
        )
        self._worker.start()

    def _run(self) -> None:
        """Background thread: batch-collect records and push to Loki."""
        batch: List[Tuple[Dict[str, str], str, str]] = []
        last_flush = time.monotonic()

        while not self._stop_event.is_set():
            try:
                timeout = max(0.1, self._flush_interval - (time.monotonic() - last_flush))
                item = self._queue.get(timeout=timeout)
                if item is None:
                    # Sentinel — drain remaining and exit
                    break
                batch.append(item)
                self._queue.task_done()
            except queue.Empty:
                pass

            now = time.monotonic()
            should_flush = (
                len(batch) >= self._batch_size
                or (batch and now - last_flush >= self._flush_interval)
            )
            if should_flush:
                self._push_batch(batch)
                batch = []
                last_flush = now

        # Drain remaining items before exit
        while not self._queue.empty():
            try:
                item = self._queue.get_nowait()
                if item is not None:
                    batch.append(item)
                self._queue.task_done()
            except queue.Empty:
                break

        if batch:
            self._push_batch(batch)

    # ------------------------------------------------------------------
    # Loki push
    # ------------------------------------------------------------------

    def _push_batch(
        self, batch: List[Tuple[Dict[str, str], str, str]]
    ) -> None:
        """
        Group log lines by label set and push to Loki in a single request.

        Loki requires that all lines within a stream share the same label set
        and are ordered by timestamp.
        """
        if not batch:
            return

        # Group by frozen label dict
        streams: Dict[str, Dict[str, Any]] = {}
        for labels, ts, message in batch:
            key = json.dumps(labels, sort_keys=True)
            if key not in streams:
                streams[key] = {"stream": labels, "values": []}
            streams[key]["values"].append([ts, message])

        payload = {"streams": list(streams.values())}
        self._send(payload)

    def _send(self, payload: Dict[str, Any]) -> None:
        """HTTP POST the payload to Loki. Silently ignores connection errors."""
        try:
            import urllib.request  # noqa: PLC0415

            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self._push_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                if resp.status not in (200, 204):
                    pass  # Silently ignore non-2xx responses
        except Exception:  # noqa: BLE001
            pass  # Never crash the caller

    # ------------------------------------------------------------------
    # Label / message extraction
    # ------------------------------------------------------------------

    def _extract_labels(self, record: logging.LogRecord) -> Dict[str, str]:
        """
        Build the Loki stream label set for a log record.

        Static labels are merged with dynamic labels extracted from the
        ``LogRecord``'s extra attributes.
        """
        labels: Dict[str, str] = {**self._static_labels}
        labels["level"] = record.levelname
        labels["logger"] = record.name.split(".")[0]  # top-level module

        # Dynamic labels from structured logging extras
        for attr in ("flow_id", "agent_role", "trace_id", "request_id", "session_id"):
            val = getattr(record, attr, None)
            if val is not None:
                labels[attr] = str(val)

        return labels

    def _format_record(self, record: logging.LogRecord) -> str:
        """
        Serialise a ``LogRecord`` to a structured JSON string.

        The JSON object contains all standard logging fields plus any extra
        attributes attached to the record.
        """
        try:
            message = self.format(record)
        except Exception:  # noqa: BLE001
            message = record.getMessage()

        log_entry: Dict[str, Any] = {
            "timestamp": record.created,
            "level": record.levelname,
            "logger": record.name,
            "message": message,
            "module": record.module,
            "funcName": record.funcName,
            "lineno": record.lineno,
        }

        # Include exception info
        if record.exc_info:
            import traceback  # noqa: PLC0415
            log_entry["exception"] = "".join(traceback.format_exception(*record.exc_info))

        # Include extra structured fields
        _SKIP = frozenset(logging.LogRecord.__dict__.keys()) | {
            "message", "asctime", "exc_text", "stack_info",
        }
        for key, val in record.__dict__.items():
            if not key.startswith("_") and key not in _SKIP:
                try:
                    json.dumps(val)  # test serialisability
                    log_entry[key] = val
                except (TypeError, ValueError):
                    log_entry[key] = str(val)

        return json.dumps(log_entry, default=str)

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def health_check(self) -> Dict[str, Any]:
        """Return handler status information."""
        return {
            "enabled": self._enabled,
            "push_url": self._push_url,
            "queue_size": self._queue.qsize(),
            "worker_alive": self._worker.is_alive() if self._worker else False,
            "static_labels": self._static_labels,
        }


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def build_loki_handler(
    url: Optional[str] = None,
    labels: Optional[Dict[str, str]] = None,
    level: int = logging.INFO,
) -> LokiHandler:
    """
    Build a ``LokiHandler`` from application settings.

    Falls back to ``LOKI_URL`` env var → ``http://loki:3100`` when ``url``
    is not provided explicitly.
    """
    import os  # noqa: PLC0415

    resolved_url = url or os.getenv("LOKI_URL", "http://loki:3100")
    enabled = os.getenv("LOKI_ENABLED", "true").lower() not in ("false", "0", "no")
    batch_size = int(os.getenv("LOKI_BATCH_SIZE", "100"))
    flush_interval = float(os.getenv("LOKI_FLUSH_INTERVAL", "2.0"))
    timeout = int(os.getenv("LOKI_TIMEOUT", "5"))

    extra_labels: Dict[str, str] = {}
    raw_labels = os.getenv("LOKI_LABELS", "{}")
    try:
        extra_labels = json.loads(raw_labels)
    except (json.JSONDecodeError, ValueError):
        pass

    merged_labels = {**(labels or {}), **extra_labels}
    return LokiHandler(
        url=resolved_url,
        labels=merged_labels,
        batch_size=batch_size,
        flush_interval=flush_interval,
        timeout=timeout,
        enabled=enabled,
        level=level,
    )


__all__ = ["LokiHandler", "build_loki_handler"]

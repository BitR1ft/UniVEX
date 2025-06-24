"""
Tests — Loki Log Aggregation & Jaeger Distributed Tracing

Covers:
- LokiHandler initialisation (enabled / disabled)
- emit() queuing flow_id / agent_role / trace_id labels
- _extract_labels(): static + dynamic label merging
- _format_record(): JSON structure, exception serialisation, extra fields
- _push_batch(): stream grouping by label set
- _send(): graceful failure on network errors
- Worker thread lifecycle (start, flush, stop)
- health_check()
- build_loki_handler() factory from environment variables
- configure_logging(): stdout + Loki integration, log_format options
- JSONFormatter: timestamp, OTEL field injection, structured extras
- CorrelationFilter: trace_id / span_id injection
- get_logger(): context adapter with pre-set fields
- Queue overflow handling (drop, never block)
- Batch grouping by label set
- Nanosecond timestamp generation
- Handler close / drain behaviour
"""

from __future__ import annotations

import importlib.util
import json
import logging
import queue
import sys
import threading
import time
import types
import unittest
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch, call

# Resolve paths relative to this test file for cross-environment portability
_BACKEND_DIR = Path(__file__).parent.parent.parent
_LOKI_HANDLER = _BACKEND_DIR / "app" / "observability" / "loki_handler.py"
_CORE_LOGGING = _BACKEND_DIR / "app" / "core" / "logging.py"


# ---------------------------------------------------------------------------
# Module loader helpers
# ---------------------------------------------------------------------------

def _load_loki_handler_module():
    """Load the loki_handler module without real network dependencies."""
    for key in list(sys.modules.keys()):
        if "loki_handler" in key:
            del sys.modules[key]
    # Stub app.observability so the __init__ doesn't cascade
    sys.modules.setdefault("app", types.ModuleType("app"))
    sys.modules.setdefault("app.observability", types.ModuleType("app.observability"))
    spec = importlib.util.spec_from_file_location(
        "app.observability.loki_handler",
        str(_LOKI_HANDLER),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_logging_module():
    """Load core/logging.py with stubs for heavy deps."""
    for key in list(sys.modules.keys()):
        if key == "app.core.logging" or key.endswith(".core.logging"):
            del sys.modules[key]
    sys.modules.setdefault("app", types.ModuleType("app"))
    sys.modules.setdefault("app.core", types.ModuleType("app.core"))

    # Stub opentelemetry
    otel = types.ModuleType("opentelemetry")
    otel_trace = types.ModuleType("opentelemetry.trace")
    class FakeSpanCtx:
        is_valid = False
        trace_id = 0
        span_id = 0
    class FakeSpan:
        def get_span_context(self):
            return FakeSpanCtx()
    otel_trace.get_current_span = lambda: FakeSpan()
    sys.modules["opentelemetry"] = otel
    sys.modules["opentelemetry.trace"] = otel_trace

    # Stub loki_handler
    loki_mod = types.ModuleType("app.observability.loki_handler")
    class FakeLokiHandler(logging.Handler):
        def emit(self, record): pass
    loki_mod.LokiHandler = FakeLokiHandler
    loki_mod.build_loki_handler = lambda **kw: FakeLokiHandler()
    sys.modules["app.observability.loki_handler"] = loki_mod

    spec = importlib.util.spec_from_file_location(
        "app.core.logging",
        str(_CORE_LOGGING),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Loki Handler Tests
# ---------------------------------------------------------------------------

class TestNsTimestamp(unittest.TestCase):
    """Test nanosecond timestamp generation."""

    def setUp(self):
        self._mod = _load_loki_handler_module()

    def test_ns_timestamp_format(self):
        ts = self._mod._ns_timestamp(1700000000.0)
        self.assertIsInstance(ts, str)
        self.assertGreater(int(ts), 0)

    def test_ns_timestamp_precision(self):
        ts_float = 1700000000.123456
        ts_ns = self._mod._ns_timestamp(ts_float)
        self.assertEqual(ts_ns, str(int(ts_float * 1_000_000_000)))

    def test_ns_timestamp_for_current_time(self):
        now = time.time()
        ts = self._mod._ns_timestamp(now)
        # Should be a string of ~19 digits
        self.assertGreaterEqual(len(ts), 18)


class TestLokiHandlerInit(unittest.TestCase):
    """Test LokiHandler initialisation."""

    def setUp(self):
        self._mod = _load_loki_handler_module()

    def tearDown(self):
        # Clean up any background threads
        pass

    def test_default_push_url(self):
        h = self._mod.LokiHandler(url="http://loki:3100", enabled=False)
        self.assertIn("/loki/api/v1/push", h._push_url)

    def test_trailing_slash_stripped(self):
        h = self._mod.LokiHandler(url="http://loki:3100///", enabled=False)
        self.assertFalse(h._push_url.endswith("//"))
        self.assertIn("/loki/api/v1/push", h._push_url)

    def test_static_labels_include_app(self):
        h = self._mod.LokiHandler(url="http://loki:3100", enabled=False)
        self.assertIn("app", h._static_labels)
        self.assertEqual(h._static_labels["app"], "univex")

    def test_custom_labels_merged(self):
        h = self._mod.LokiHandler(
            url="http://loki:3100",
            labels={"env": "staging", "component": "backend"},
            enabled=False,
        )
        self.assertEqual(h._static_labels.get("env"), "staging")
        self.assertEqual(h._static_labels.get("component"), "backend")

    def test_disabled_handler_no_worker(self):
        h = self._mod.LokiHandler(url="http://loki:3100", enabled=False)
        self.assertIsNone(h._worker)

    def test_enabled_handler_starts_worker(self):
        h = self._mod.LokiHandler(url="http://loki:3100", enabled=True)
        # Worker should be started
        self.assertIsNotNone(h._worker)
        self.assertTrue(h._worker.is_alive())
        h.close()

    def test_health_check_shape(self):
        h = self._mod.LokiHandler(url="http://loki:3100", enabled=False)
        hc = h.health_check()
        self.assertIn("enabled", hc)
        self.assertIn("push_url", hc)
        self.assertIn("queue_size", hc)
        self.assertIn("worker_alive", hc)
        self.assertIn("static_labels", hc)

    def test_health_check_disabled(self):
        h = self._mod.LokiHandler(url="http://loki:3100", enabled=False)
        hc = h.health_check()
        self.assertFalse(hc["enabled"])
        self.assertFalse(hc["worker_alive"])


class TestLokiHandlerEmit(unittest.TestCase):
    """Test emit() and label extraction."""

    def setUp(self):
        self._mod = _load_loki_handler_module()
        self._handler = self._mod.LokiHandler(url="http://loki:3100", enabled=False)

    def _make_record(self, msg="test message", level=logging.INFO, **extra) -> logging.LogRecord:
        record = logging.LogRecord(
            name="test.logger",
            level=level,
            pathname="/path/to/file.py",
            lineno=42,
            msg=msg,
            args=(),
            exc_info=None,
        )
        for k, v in extra.items():
            setattr(record, k, v)
        return record

    def test_emit_disabled_drops_silently(self):
        record = self._make_record()
        self._handler.emit(record)
        # Queue should be empty
        self.assertEqual(self._handler._queue.qsize(), 0)

    def test_extract_labels_basic(self):
        record = self._make_record()
        labels = self._handler._extract_labels(record)
        self.assertIn("app", labels)
        self.assertIn("level", labels)
        self.assertIn("logger", labels)
        self.assertEqual(labels["level"], "INFO")

    def test_extract_labels_with_flow_id(self):
        record = self._make_record(flow_id="flow-123")
        labels = self._handler._extract_labels(record)
        self.assertEqual(labels["flow_id"], "flow-123")

    def test_extract_labels_with_agent_role(self):
        record = self._make_record(agent_role="recon")
        labels = self._handler._extract_labels(record)
        self.assertEqual(labels["agent_role"], "recon")

    def test_extract_labels_with_trace_id(self):
        record = self._make_record(trace_id="abc-trace-id")
        labels = self._handler._extract_labels(record)
        self.assertEqual(labels["trace_id"], "abc-trace-id")

    def test_extract_labels_with_session_id(self):
        record = self._make_record(session_id="sess-xyz")
        labels = self._handler._extract_labels(record)
        self.assertEqual(labels["session_id"], "sess-xyz")

    def test_extract_labels_missing_extras_not_included(self):
        record = self._make_record()
        labels = self._handler._extract_labels(record)
        self.assertNotIn("flow_id", labels)
        self.assertNotIn("agent_role", labels)

    def test_format_record_is_valid_json(self):
        record = self._make_record("hello world")
        msg = self._handler._format_record(record)
        parsed = json.loads(msg)
        self.assertIn("message", parsed)
        self.assertIn("level", parsed)
        self.assertIn("timestamp", parsed)

    def test_format_record_contains_logger_name(self):
        record = self._make_record()
        msg = self._handler._format_record(record)
        parsed = json.loads(msg)
        self.assertEqual(parsed["logger"], "test.logger")

    def test_format_record_contains_lineno(self):
        record = self._make_record()
        msg = self._handler._format_record(record)
        parsed = json.loads(msg)
        self.assertEqual(parsed["lineno"], 42)

    def test_format_record_with_exception(self):
        try:
            raise ValueError("test error")
        except ValueError:
            import sys as _sys
            exc_info = _sys.exc_info()
        record = self._make_record()
        record.exc_info = exc_info
        msg = self._handler._format_record(record)
        parsed = json.loads(msg)
        self.assertIn("exception", parsed)
        self.assertIn("ValueError", parsed["exception"])

    def test_format_record_extra_fields_included(self):
        record = self._make_record(flow_id="flow-abc", agent_role="exploit")
        msg = self._handler._format_record(record)
        parsed = json.loads(msg)
        self.assertEqual(parsed["flow_id"], "flow-abc")
        self.assertEqual(parsed["agent_role"], "exploit")

    def test_format_record_debug_level(self):
        record = self._make_record(level=logging.DEBUG)
        msg = self._handler._format_record(record)
        parsed = json.loads(msg)
        self.assertEqual(parsed["level"], "DEBUG")

    def test_format_record_error_level(self):
        record = self._make_record(level=logging.ERROR)
        msg = self._handler._format_record(record)
        parsed = json.loads(msg)
        self.assertEqual(parsed["level"], "ERROR")


class TestLokiHandlerPushBatch(unittest.TestCase):
    """Test batch grouping and HTTP push logic."""

    def setUp(self):
        self._mod = _load_loki_handler_module()
        self._handler = self._mod.LokiHandler(url="http://loki:3100", enabled=False)

    def test_push_batch_empty_is_noop(self):
        # Should not raise
        self._handler._push_batch([])

    def test_push_batch_groups_by_label_set(self):
        """Records with same labels should end up in the same stream."""
        captured_payloads = []

        def fake_send(payload):
            captured_payloads.append(payload)

        self._handler._send = fake_send

        labels_a = {"app": "univex", "level": "INFO", "agent_role": "recon"}
        labels_b = {"app": "univex", "level": "ERROR", "agent_role": "exploit"}
        ts = str(int(time.time() * 1e9))

        batch = [
            (labels_a, ts, '{"msg":"a1"}'),
            (labels_a, ts, '{"msg":"a2"}'),
            (labels_b, ts, '{"msg":"b1"}'),
        ]
        self._handler._push_batch(batch)

        self.assertEqual(len(captured_payloads), 1)
        payload = captured_payloads[0]
        self.assertIn("streams", payload)
        self.assertEqual(len(payload["streams"]), 2)

    def test_push_batch_single_stream(self):
        captured_payloads = []

        def fake_send(payload):
            captured_payloads.append(payload)

        self._handler._send = fake_send
        labels = {"app": "univex", "level": "INFO"}
        ts = str(int(time.time() * 1e9))
        batch = [(labels, ts, '{"msg":"test"}')]
        self._handler._push_batch(batch)

        self.assertEqual(len(captured_payloads), 1)
        streams = captured_payloads[0]["streams"]
        self.assertEqual(len(streams), 1)
        self.assertEqual(len(streams[0]["values"]), 1)

    def test_send_silent_on_connection_error(self):
        """_send() must never raise — connection errors are swallowed."""
        # Point to a non-existent server
        h = self._mod.LokiHandler(url="http://127.0.0.1:19999", enabled=False)
        payload = {"streams": [{"stream": {"app": "univex"}, "values": [[str(int(time.time() * 1e9)), "test"]]}]}
        h._send(payload)  # Should not raise


class TestLokiHandlerWorker(unittest.TestCase):
    """Test background worker thread lifecycle."""

    def setUp(self):
        self._mod = _load_loki_handler_module()

    def test_close_stops_worker(self):
        h = self._mod.LokiHandler(url="http://loki:3100", enabled=True)
        self.assertTrue(h._worker.is_alive())
        h.close()
        # Give thread time to exit
        h._worker.join(timeout=3)
        self.assertFalse(h._worker.is_alive())

    def test_queue_overflow_drops_records(self):
        """When the queue is full, emit() must drop records without raising."""
        h = self._mod.LokiHandler(url="http://loki:3100", enabled=True)
        # Fill the queue
        try:
            for _ in range(h._queue.maxsize + 10):
                try:
                    h._queue.put_nowait(
                        ({"app": "univex"}, str(int(time.time() * 1e9)), '{"msg":"x"}')
                    )
                except queue.Full:
                    break
            # Now emit should not raise
            record = logging.LogRecord(
                name="test", level=logging.INFO,
                pathname="", lineno=0, msg="overflow test",
                args=(), exc_info=None,
            )
            h.emit(record)
        finally:
            h.close()


class TestBuildLokiHandler(unittest.TestCase):
    """Test the build_loki_handler() factory function."""

    def setUp(self):
        self._mod = _load_loki_handler_module()

    def test_factory_creates_handler(self):
        h = self._mod.build_loki_handler(url="http://loki:3100", level=logging.INFO)
        self.assertIsNotNone(h)
        self.assertIsInstance(h, self._mod.LokiHandler)

    def test_factory_uses_env_var(self):
        import os
        with patch.dict(os.environ, {"LOKI_URL": "http://my-loki:9999", "LOKI_ENABLED": "false"}):
            h = self._mod.build_loki_handler()
            self.assertIn("my-loki:9999", h._push_url)
            self.assertFalse(h._enabled)

    def test_factory_disabled_via_env(self):
        import os
        with patch.dict(os.environ, {"LOKI_ENABLED": "false", "LOKI_URL": "http://loki:3100"}):
            h = self._mod.build_loki_handler()
            self.assertFalse(h._enabled)

    def test_factory_respects_batch_size_env(self):
        import os
        with patch.dict(os.environ, {"LOKI_BATCH_SIZE": "50", "LOKI_ENABLED": "false",
                                      "LOKI_URL": "http://loki:3100"}):
            h = self._mod.build_loki_handler()
            self.assertEqual(h._batch_size, 50)

    def test_factory_respects_extra_labels_env(self):
        import os
        with patch.dict(os.environ, {
            "LOKI_LABELS": '{"region": "eu-west-1", "tier": "prod"}',
            "LOKI_ENABLED": "false",
            "LOKI_URL": "http://loki:3100",
        }):
            h = self._mod.build_loki_handler()
            self.assertEqual(h._static_labels.get("region"), "eu-west-1")


# ---------------------------------------------------------------------------
# Core logging module tests
# ---------------------------------------------------------------------------

class TestJSONFormatter(unittest.TestCase):
    """Test the upgraded JSONFormatter with OTEL context."""

    def setUp(self):
        self._mod = _load_logging_module()

    def _make_record(self, **extra) -> logging.LogRecord:
        record = logging.LogRecord(
            name="app.agent.recon",
            level=logging.INFO,
            pathname="/app/agent/recon.py",
            lineno=42,
            msg="Scan complete for target",
            args=(),
            exc_info=None,
        )
        for k, v in extra.items():
            setattr(record, k, v)
        return record

    def test_format_returns_valid_json(self):
        fmt = self._mod.JSONFormatter()
        record = self._make_record()
        output = fmt.format(record)
        parsed = json.loads(output)
        self.assertIn("timestamp", parsed)
        self.assertIn("level", parsed)
        self.assertIn("message", parsed)

    def test_format_includes_service_field(self):
        fmt = self._mod.JSONFormatter()
        record = self._make_record()
        parsed = json.loads(fmt.format(record))
        self.assertIn("service", parsed)

    def test_format_includes_environment(self):
        fmt = self._mod.JSONFormatter()
        record = self._make_record()
        parsed = json.loads(fmt.format(record))
        self.assertIn("environment", parsed)

    def test_format_includes_function_name(self):
        fmt = self._mod.JSONFormatter()
        record = self._make_record()
        parsed = json.loads(fmt.format(record))
        self.assertIn("function", parsed)

    def test_format_extra_flow_id(self):
        fmt = self._mod.JSONFormatter()
        record = self._make_record(flow_id="flow-999")
        parsed = json.loads(fmt.format(record))
        self.assertEqual(parsed["flow_id"], "flow-999")

    def test_format_extra_agent_role(self):
        fmt = self._mod.JSONFormatter()
        record = self._make_record(agent_role="exploit")
        parsed = json.loads(fmt.format(record))
        self.assertEqual(parsed["agent_role"], "exploit")

    def test_format_exception_info(self):
        fmt = self._mod.JSONFormatter()
        try:
            raise RuntimeError("test exception")
        except RuntimeError:
            import sys as _sys
            record = self._make_record()
            record.exc_info = _sys.exc_info()
        parsed = json.loads(fmt.format(record))
        self.assertIn("exception", parsed)
        self.assertIn("RuntimeError", parsed["exception"])


class TestCorrelationFilter(unittest.TestCase):
    """Test CorrelationFilter injects OTEL trace context."""

    def setUp(self):
        self._mod = _load_logging_module()

    def test_filter_returns_true(self):
        f = self._mod.CorrelationFilter()
        record = logging.LogRecord(
            name="test", level=logging.INFO,
            pathname="", lineno=0, msg="test",
            args=(), exc_info=None,
        )
        result = f.filter(record)
        self.assertTrue(result)

    def test_filter_injects_trace_id(self):
        f = self._mod.CorrelationFilter()
        record = logging.LogRecord(
            name="test", level=logging.INFO,
            pathname="", lineno=0, msg="test",
            args=(), exc_info=None,
        )
        f.filter(record)
        # trace_id should be set (empty string when no OTEL span active)
        self.assertTrue(hasattr(record, "trace_id"))
        self.assertIsInstance(record.trace_id, str)  # type: ignore[attr-defined]

    def test_filter_injects_span_id(self):
        f = self._mod.CorrelationFilter()
        record = logging.LogRecord(
            name="test", level=logging.INFO,
            pathname="", lineno=0, msg="test",
            args=(), exc_info=None,
        )
        f.filter(record)
        self.assertTrue(hasattr(record, "span_id"))

    def test_filter_does_not_overwrite_existing_trace_id(self):
        f = self._mod.CorrelationFilter()
        record = logging.LogRecord(
            name="test", level=logging.INFO,
            pathname="", lineno=0, msg="test",
            args=(), exc_info=None,
        )
        record.trace_id = "my-explicit-trace"  # type: ignore[attr-defined]
        f.filter(record)
        self.assertEqual(record.trace_id, "my-explicit-trace")  # type: ignore[attr-defined]


class TestConfigureLogging(unittest.TestCase):
    """Test the configure_logging() function."""

    def setUp(self):
        self._mod = _load_logging_module()

    def _clean_root(self):
        root = logging.getLogger()
        root.handlers.clear()

    def test_configure_json_format(self):
        self._clean_root()
        self._mod.configure_logging(log_level="INFO", log_format="json")
        root = logging.getLogger()
        # Should have at least one handler
        self.assertGreaterEqual(len(root.handlers), 1)

    def test_configure_text_format(self):
        self._clean_root()
        self._mod.configure_logging(log_level="DEBUG", log_format="text")
        root = logging.getLogger()
        self.assertGreaterEqual(len(root.handlers), 1)

    def test_configure_sets_log_level(self):
        self._clean_root()
        self._mod.configure_logging(log_level="WARNING")
        root = logging.getLogger()
        self.assertEqual(root.level, logging.WARNING)

    def test_configure_loki_disabled_by_default(self):
        import os
        self._clean_root()
        with patch.dict(os.environ, {}, clear=False):
            # Should not attach Loki handler when LOKI_URL is empty
            self._mod.configure_logging(
                log_level="INFO",
                loki_url="",
                enable_loki=False,
            )
        root = logging.getLogger()
        loki_handlers = [
            h for h in root.handlers
            if "loki" in type(h).__name__.lower()
        ]
        self.assertEqual(len(loki_handlers), 0)


class TestGetLogger(unittest.TestCase):
    """Test the get_logger() convenience function."""

    def setUp(self):
        self._mod = _load_logging_module()

    def test_get_logger_returns_logger_adapter(self):
        log = self._mod.get_logger("app.test.module")
        self.assertIsNotNone(log)
        # Should be usable like a standard logger
        self.assertTrue(hasattr(log, "info"))
        self.assertTrue(hasattr(log, "error"))
        self.assertTrue(hasattr(log, "debug"))

    def test_get_logger_with_agent_role(self):
        log = self._mod.get_logger("app.agent.recon", agent_role="recon")
        self.assertIsNotNone(log)

    def test_get_logger_with_flow_id(self):
        log = self._mod.get_logger("app.agent", flow_id="flow-abc")
        self.assertIsNotNone(log)

    def test_get_logger_with_session_id(self):
        log = self._mod.get_logger("app.api", session_id="sess-123")
        self.assertIsNotNone(log)

    def test_get_logger_injects_extras_into_records(self):
        """Verify that the adapter injects agent_role into log records."""
        self._mod.configure_logging(log_level="DEBUG", log_format="json")
        stream = StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(self._mod.JSONFormatter())
        log = self._mod.get_logger("test.flow", agent_role="webapp", flow_id="f1")
        log.logger.addHandler(handler)
        log.info("Testing extras injection")
        output = stream.getvalue()
        parsed = json.loads(output.strip())
        self.assertEqual(parsed.get("agent_role"), "webapp")
        self.assertEqual(parsed.get("flow_id"), "f1")


if __name__ == "__main__":
    unittest.main()

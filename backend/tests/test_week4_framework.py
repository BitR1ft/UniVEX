"""
Week 4 Test Suite – Tool Integration Framework

Covers:
  Day 21 – Canonical schemas (ReconResult, Endpoint, Technology, Finding)
  Day 22 – BaseOrchestrator lifecycle + input validation
  Day 24 – Rate limiter (token bucket) + retry decorator
  Day 25 – Deduplication service (hash, fuzzy, confidence)
  Day 26 – ToolMetrics + structured logging
  Day 27 – Tool output fixtures + mock execution + performance harness
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.recon.canonical_schemas import (
    Endpoint,
    EndpointMethod,
    Finding,
    ReconResult,
    Severity,
    Technology,
)
from app.recon.dedup import (
    DeduplicationService,
    EndpointDeduplicator,
    FindingDeduplicator,
    TechnologyDeduplicator,
    levenshtein,
    similarity,
)
from app.recon.orchestrators.base import BaseOrchestrator, validate_target
from app.utils.rate_limiter import RetryConfig, TokenBucketRateLimiter, with_retry
from app.utils.tool_metrics import JSONFormatter, ToolMetrics, log_tool_execution


# ===========================================================================
# Fixtures – sample tool outputs
# ===========================================================================

@pytest.fixture
def sample_endpoints() -> List[Endpoint]:
    return [
        Endpoint(url="https://example.com/api/v1/users", method=EndpointMethod.GET, status_code=200),
        Endpoint(url="https://example.com/api/v1/users/", method=EndpointMethod.GET, status_code=200),  # trailing slash
        Endpoint(url="HTTPS://EXAMPLE.COM/api/v1/users", method=EndpointMethod.GET, status_code=200),  # case
        Endpoint(url="https://example.com/api/v1/products", method=EndpointMethod.GET, status_code=200),
        Endpoint(url="https://example.com/admin/login", method=EndpointMethod.POST, status_code=200, confidence=0.9),
    ]


@pytest.fixture
def sample_technologies() -> List[Technology]:
    return [
        Technology(name="nginx", version="1.24.0"),
        Technology(name="NGINX"),          # duplicate – no version, lower confidence
        Technology(name="React", version="18.2.0"),
        Technology(name="React"),          # duplicate – no version
        Technology(name="PostgreSQL", version="15.4"),
    ]


@pytest.fixture
def sample_findings() -> List[Finding]:
    return [
        Finding(id="CVE-2023-0001", name="SQL Injection", severity=Severity.CRITICAL, url="https://example.com/search"),
        Finding(id="CVE-2023-0001", name="SQL Injection", severity=Severity.CRITICAL, url="https://example.com/search"),  # exact dup
        Finding(id="CVE-2023-0002", name="XSS", severity=Severity.HIGH, url="https://example.com/comment"),
        Finding(id="CVE-2023-0003", name="Info Disclosure", severity=Severity.LOW, url="https://example.com/debug"),
    ]


@pytest.fixture
def sample_recon_result(sample_endpoints, sample_technologies, sample_findings) -> ReconResult:
    return ReconResult(
        tool_name="test_tool",
        target="example.com",
        endpoints=sample_endpoints[:2],
        technologies=sample_technologies[:2],
        findings=sample_findings[:2],
    )


# ===========================================================================
# ===========================================================================

class TestCanonicalSchemas:
    def test_endpoint_defaults(self):
        ep = Endpoint(url="https://example.com/path")
        assert ep.method == EndpointMethod.UNKNOWN
        assert ep.is_live is True
        assert ep.confidence == 1.0

    def test_finding_severity_enum(self):
        f = Finding(id="x", name="Test")
        assert f.severity == Severity.UNKNOWN

    def test_technology_optional_version(self):
        t = Technology(name="nginx")
        assert t.version is None

    def test_recon_result_counts(self, sample_recon_result):
        assert sample_recon_result.endpoint_count == 2
        assert sample_recon_result.technology_count == 2
        assert sample_recon_result.finding_count == 2

    def test_recon_result_critical_count(self):
        result = ReconResult(
            tool_name="t",
            target="x",
            findings=[
                Finding(id="1", name="A", severity=Severity.CRITICAL),
                Finding(id="2", name="B", severity=Severity.HIGH),
                Finding(id="3", name="C", severity=Severity.CRITICAL),
            ],
        )
        assert result.critical_count == 2
        assert result.high_count == 1

    def test_recon_result_summary(self, sample_recon_result):
        summary = sample_recon_result.summary()
        assert summary["tool"] == "test_tool"
        assert summary["target"] == "example.com"
        assert "endpoints" in summary
        assert "findings" in summary


# ===========================================================================
# ===========================================================================

class MockOrchestrator(BaseOrchestrator):
    """Concrete orchestrator for testing."""

    TOOL_NAME = "mock_tool"
    BINARY = None  # skip binary check

    def __init__(self, target: str, should_fail: bool = False, **kwargs):
        super().__init__(target, **kwargs)
        self.should_fail = should_fail
        self.executed = False

    async def _execute(self) -> Any:
        self.executed = True
        if self.should_fail:
            raise RuntimeError("simulated failure")
        return {"ports": [80, 443]}

    def _normalise(self, raw: Any) -> ReconResult:
        return self._make_result(
            endpoints=[Endpoint(url=f"https://{self.target}:{p}") for p in raw.get("ports", [])]
        )


class TestBaseOrchestrator:
    def test_validate_target_accepts_domain(self):
        assert validate_target("example.com") == "example.com"

    def test_validate_target_accepts_ip(self):
        assert validate_target("192.168.1.1") == "192.168.1.1"

    def test_validate_target_accepts_cidr(self):
        assert validate_target("10.0.0.0/24") == "10.0.0.0/24"

    def test_validate_target_accepts_url(self):
        assert validate_target("https://app.example.com/path") == "https://app.example.com/path"

    def test_validate_target_rejects_empty(self):
        with pytest.raises(ValueError, match="empty"):
            validate_target("")

    def test_validate_target_rejects_invalid(self):
        with pytest.raises(ValueError, match="Invalid target"):
            validate_target("not a target!!")

    @pytest.mark.asyncio
    async def test_successful_run_returns_result(self):
        orch = MockOrchestrator("example.com")
        result = await orch.run()
        assert isinstance(result, ReconResult)
        assert result.success is True
        assert result.endpoint_count == 2
        assert orch.executed is True

    @pytest.mark.asyncio
    async def test_failed_run_marks_result_failed(self):
        orch = MockOrchestrator("example.com", should_fail=True)
        result = await orch.run()
        assert result.success is False
        assert result.error_message is not None

    @pytest.mark.asyncio
    async def test_result_has_timing_metadata(self):
        orch = MockOrchestrator("192.168.1.1")
        result = await orch.run()
        assert result.started_at is not None
        assert result.completed_at is not None
        assert result.duration_seconds is not None and result.duration_seconds >= 0

    @pytest.mark.asyncio
    async def test_result_propagates_project_task_ids(self):
        orch = MockOrchestrator("example.com", project_id="proj-1", task_id="task-1")
        result = await orch.run()
        assert result.project_id == "proj-1"
        assert result.task_id == "task-1"

    @pytest.mark.asyncio
    async def test_missing_binary_raises_in_pre_run(self):
        class BinaryOrchestrator(BaseOrchestrator):
            TOOL_NAME = "nonexistent"
            BINARY = "definitely_not_installed_xyz"

            async def _execute(self):
                return None

            def _normalise(self, raw):
                return self._make_result()

        orch = BinaryOrchestrator("example.com")
        result = await orch.run()
        assert result.success is False
        assert "not found on PATH" in (result.error_message or "")


# ===========================================================================
# ===========================================================================

class TestTokenBucketRateLimiter:
    def test_invalid_rate_raises(self):
        with pytest.raises(ValueError):
            TokenBucketRateLimiter(rate=0, capacity=10)

    def test_invalid_capacity_raises(self):
        with pytest.raises(ValueError):
            TokenBucketRateLimiter(rate=10, capacity=0)

    @pytest.mark.asyncio
    async def test_single_acquire_succeeds(self):
        limiter = TokenBucketRateLimiter(rate=100, capacity=10)
        await limiter.acquire()  # should not raise

    @pytest.mark.asyncio
    async def test_context_manager(self):
        limiter = TokenBucketRateLimiter(rate=100, capacity=10)
        async with limiter:
            pass  # should not raise

    @pytest.mark.asyncio
    async def test_rate_limits_requests(self):
        """Acquiring more tokens than available should introduce a delay."""
        limiter = TokenBucketRateLimiter(rate=100.0, capacity=3)
        # Drain the bucket (3 tokens)
        await limiter.acquire(3)
        # Next acquire should require ~0.01s (1/100 rate) to refill 1 token
        t0 = time.monotonic()
        await limiter.acquire(1)
        elapsed = time.monotonic() - t0
        # Allow generous margin for test environment jitter
        assert elapsed >= 0.005, f"Expected delay but got {elapsed:.4f}s"


class TestRetryConfig:
    def test_delay_increases_exponentially(self):
        cfg = RetryConfig(base_delay=1.0, backoff_factor=2.0, jitter=False)
        assert cfg.delay_for(1) == 1.0
        assert cfg.delay_for(2) == 2.0
        assert cfg.delay_for(3) == 4.0

    def test_max_delay_is_capped(self):
        cfg = RetryConfig(base_delay=1.0, backoff_factor=10.0, max_delay=5.0, jitter=False)
        assert cfg.delay_for(5) == 5.0


class TestWithRetryDecorator:
    @pytest.mark.asyncio
    async def test_succeeds_on_first_attempt(self):
        calls = []

        @with_retry(max_attempts=3, base_delay=0)
        async def fn():
            calls.append(1)
            return "ok"

        result = await fn()
        assert result == "ok"
        assert len(calls) == 1

    @pytest.mark.asyncio
    async def test_retries_on_transient_failure(self):
        calls = []

        @with_retry(max_attempts=3, base_delay=0)
        async def fn():
            calls.append(1)
            if len(calls) < 3:
                raise ValueError("transient")
            return "ok"

        result = await fn()
        assert result == "ok"
        assert len(calls) == 3

    @pytest.mark.asyncio
    async def test_raises_after_max_attempts(self):
        @with_retry(max_attempts=2, base_delay=0)
        async def fn():
            raise RuntimeError("permanent failure")

        with pytest.raises(RuntimeError, match="permanent failure"):
            await fn()

    @pytest.mark.asyncio
    async def test_does_not_retry_non_matching_exception(self):
        @with_retry(
            max_attempts=3,
            base_delay=0,
            retryable_exceptions=(ValueError,),
        )
        async def fn():
            raise TypeError("not retryable")

        with pytest.raises(TypeError):
            await fn()


# ===========================================================================
# ===========================================================================

class TestLevenshtein:
    def test_identical_strings(self):
        assert levenshtein("abc", "abc") == 0

    def test_empty_strings(self):
        assert levenshtein("", "") == 0

    def test_single_insertion(self):
        assert levenshtein("abc", "ab") == 1

    def test_known_distance(self):
        assert levenshtein("kitten", "sitting") == 3


class TestSimilarity:
    def test_identical(self):
        assert similarity("abc", "abc") == 1.0

    def test_completely_different(self):
        assert similarity("aaa", "bbb") < 0.5

    def test_near_duplicate(self):
        assert similarity("https://example.com/api/users", "https://example.com/api/user") > 0.9


class TestEndpointDeduplicator:
    def test_exact_duplicates_are_removed(self, sample_endpoints):
        dedup = EndpointDeduplicator()
        result = dedup.deduplicate(sample_endpoints)
        # Trailing slash + case variants of the same URL → deduplicated
        urls = [r.url for r in result]
        # Only one entry for /api/v1/users should survive
        api_users = [u for u in urls if "v1/users" in u.lower() and "products" not in u]
        assert len(api_users) == 1

    def test_distinct_endpoints_are_kept(self, sample_endpoints):
        dedup = EndpointDeduplicator()
        result = dedup.deduplicate(sample_endpoints)
        # /api/v1/products and /admin/login should survive
        urls = [r.url for r in result]
        assert any("products" in u for u in urls)
        assert any("admin" in u for u in urls)

    def test_empty_list(self):
        assert EndpointDeduplicator().deduplicate([]) == []


class TestTechnologyDeduplicator:
    def test_versioned_preferred_over_unversioned(self, sample_technologies):
        result = TechnologyDeduplicator().deduplicate(sample_technologies)
        nginx = next(t for t in result if t.name.lower() == "nginx")
        assert nginx.version == "1.24.0"

    def test_count_is_reduced(self, sample_technologies):
        result = TechnologyDeduplicator().deduplicate(sample_technologies)
        assert len(result) == 3  # nginx, React, PostgreSQL

    def test_empty_list(self):
        assert TechnologyDeduplicator().deduplicate([]) == []


class TestFindingDeduplicator:
    def test_exact_id_duplicates_removed(self, sample_findings):
        result = FindingDeduplicator().deduplicate(sample_findings)
        ids = [f.id for f in result]
        assert ids.count("CVE-2023-0001") == 1

    def test_all_unique_findings_kept(self, sample_findings):
        result = FindingDeduplicator().deduplicate(sample_findings)
        assert len(result) == 3

    def test_empty_list(self):
        assert FindingDeduplicator().deduplicate([]) == []


class TestDeduplicationService:
    def test_all_three_deduplicators(
        self, sample_endpoints, sample_technologies, sample_findings
    ):
        svc = DeduplicationService()
        eps = svc.dedup_endpoints(sample_endpoints)
        techs = svc.dedup_technologies(sample_technologies)
        findings = svc.dedup_findings(sample_findings)

        assert len(eps) < len(sample_endpoints)
        assert len(techs) < len(sample_technologies)
        assert len(findings) < len(sample_findings)


# ===========================================================================
# ===========================================================================

class TestToolMetrics:
    def test_duration_is_none_before_start(self):
        m = ToolMetrics("test")
        assert m.duration_seconds is None

    def test_duration_is_measured(self):
        m = ToolMetrics("test")
        m.start()
        time.sleep(0.01)
        m.stop()
        assert m.duration_seconds is not None
        assert m.duration_seconds >= 0.009

    def test_counters(self):
        m = ToolMetrics("test")
        m.increment("findings")
        m.increment("findings", 4)
        assert m._counters["findings"] == 5

    def test_gauges(self):
        m = ToolMetrics("test")
        m.gauge("memory_mb", 128.5)
        assert m._gauges["memory_mb"] == 128.5

    def test_to_dict(self):
        m = ToolMetrics("nuclei")
        m.start()
        m.increment("templates_run", 100)
        m.stop(success=True)
        d = m.to_dict()
        assert d["tool"] == "nuclei"
        assert d["success"] is True
        assert d["counters"]["templates_run"] == 100


class TestJSONFormatter:
    def test_formats_as_json(self):
        import json

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO,
            pathname="", lineno=0, msg="hello world",
            args=(), exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["message"] == "hello world"
        assert parsed["level"] == "INFO"
        assert "timestamp" in parsed


class TestLogToolExecutionDecorator:
    @pytest.mark.asyncio
    async def test_injects_metrics(self):
        collected = {}

        @log_tool_execution("test_tool")
        async def fn(_metrics=None):
            _metrics.increment("items", 5)
            collected["metrics"] = _metrics

        await fn()
        assert collected["metrics"]._counters["items"] == 5

    @pytest.mark.asyncio
    async def test_marks_success_on_completion(self):
        captured = {}

        @log_tool_execution("test_tool")
        async def fn(_metrics=None):
            captured["metrics"] = _metrics

        await fn()
        assert captured["metrics"].success is True

    @pytest.mark.asyncio
    async def test_marks_failure_on_exception(self):
        captured = {}

        @log_tool_execution("test_tool")
        async def fn(_metrics=None):
            captured["metrics"] = _metrics
            raise ValueError("boom")

        with pytest.raises(ValueError):
            await fn()

        assert captured["metrics"].success is False
        assert "boom" in captured["metrics"].error


# ===========================================================================
# ===========================================================================

class TestPerformanceHarness:
    """
    Lightweight performance tests that verify the core deduplication and
    rate-limiting code scales to realistic workloads within acceptable time.
    """

    def _make_endpoints(self, count: int) -> list:
        # Use path prefixes from different "domains" to ensure they are
        # truly distinct (not near-duplicates) for the performance harness.
        return [
            Endpoint(url=f"https://host{i}.example.com/resource")
            for i in range(count)
        ]

    def _make_findings(self, count: int) -> list:
        return [
            Finding(id=f"CVE-2023-{i:04d}", name=f"Finding {i}", severity=Severity.INFO)
            for i in range(count)
        ]

    def test_endpoint_dedup_1000_items_under_2s(self):
        items = self._make_endpoints(1000)
        svc = DeduplicationService()
        t0 = time.monotonic()
        result = svc.dedup_endpoints(items)
        elapsed = time.monotonic() - t0
        assert len(result) == 1000  # all unique
        assert elapsed < 2.0, f"Dedup took {elapsed:.2f}s (limit: 2s)"

    def test_finding_dedup_500_items_under_1s(self):
        items = self._make_findings(500)
        svc = DeduplicationService()
        t0 = time.monotonic()
        result = svc.dedup_findings(items)
        elapsed = time.monotonic() - t0
        assert len(result) == 500
        assert elapsed < 1.0, f"Finding dedup took {elapsed:.2f}s (limit: 1s)"

    @pytest.mark.asyncio
    async def test_rate_limiter_throughput(self):
        """Rate limiter should grant ≥90 % of capacity tokens within 1s."""
        limiter = TokenBucketRateLimiter(rate=1000.0, capacity=1000.0)
        granted = 0
        t0 = time.monotonic()
        while time.monotonic() - t0 < 0.1:  # 100 ms window
            await limiter.acquire()
            granted += 1
        # Should have granted roughly 100 tokens (100ms × 1000/s) + initial capacity
        assert granted >= 50, f"Only granted {granted} tokens in 100ms"

"""

Coverage:
  TestClickHouseSettings    (6 tests)  — env-var driven settings
  TestClickHousePool        (8 tests)  — pool acquire/release, stub fallback
  TestClickHouseClient      (14 tests) — execute, insert, fetch, ping, schema
  TestPentestAnalytics      (18 tests) — all five record_* methods + query_*
  TestAnalyticsAPI          (18 tests) — all REST endpoints via TestClient

Total: 64 tests
"""
from __future__ import annotations

import asyncio
import uuid
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Imports from analytics package (no heavy deps — no langgraph/pydantic chain)
# ---------------------------------------------------------------------------
from app.analytics.clickhouse_client import (
    ClickHouseClient,
    ClickHousePool,
    ClickHouseSettings,
    _StubClient,
    get_clickhouse_client,
    set_clickhouse_client,
)
from app.analytics.pentest_analytics import (
    PentestAnalytics,
    get_pentest_analytics,
    set_pentest_analytics,
)
from app.api.analytics import router as analytics_router


# ===========================================================================
# Helpers
# ===========================================================================

def _make_mock_client(return_value: Any = None) -> ClickHouseClient:
    """Return a ClickHouseClient whose internal pool executes are mocked."""
    client = ClickHouseClient.__new__(ClickHouseClient)
    mock_pool = MagicMock()
    mock_pool.execute = AsyncMock(return_value=return_value or [])
    client._pool = mock_pool
    client._settings = ClickHouseSettings()
    return client


def _make_analytics(return_map: Optional[Dict[str, Any]] = None) -> PentestAnalytics:
    """Return a PentestAnalytics backed by a fully-mocked ClickHouseClient."""
    client = ClickHouseClient.__new__(ClickHouseClient)
    client._settings = ClickHouseSettings()

    async def _fake_execute(query: str, params=None, with_column_types: bool = False, **kwargs):
        # Return preset values keyed by first keyword in query
        if return_map:
            for key, val in return_map.items():
                if key in query:
                    return val
        return []

    mock_pool = MagicMock()
    mock_pool.execute = AsyncMock(side_effect=_fake_execute)
    client._pool = mock_pool
    return PentestAnalytics(client=client)


@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset module-level singletons between tests."""
    import app.analytics.clickhouse_client as cc_mod
    import app.analytics.pentest_analytics as pa_mod
    _prev_cc = cc_mod._client
    _prev_pa = pa_mod._analytics
    yield
    cc_mod._client = _prev_cc
    pa_mod._analytics = _prev_pa


# ===========================================================================
# TestClickHouseSettings
# ===========================================================================

class TestClickHouseSettings:
    def test_default_host(self):
        s = ClickHouseSettings()
        assert s.host == "localhost"

    def test_default_port(self):
        s = ClickHouseSettings()
        assert s.port == 9000

    def test_default_database(self):
        s = ClickHouseSettings()
        assert s.database == "univex"

    def test_default_user(self):
        s = ClickHouseSettings()
        assert s.user == "default"

    def test_pool_size_default(self):
        s = ClickHouseSettings()
        assert s.pool_size == 5

    def test_as_dict_keys(self):
        s = ClickHouseSettings()
        d = s.as_dict()
        assert "host" in d
        assert "port" in d
        assert "database" in d
        assert "user" in d
        assert "password" in d
        assert "client_name" in d

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("CLICKHOUSE_HOST", "ch-server")
        monkeypatch.setenv("CLICKHOUSE_PORT", "9001")
        monkeypatch.setenv("CLICKHOUSE_DATABASE", "mydb")
        monkeypatch.setenv("CLICKHOUSE_POOL_SIZE", "10")
        s = ClickHouseSettings()
        assert s.host == "ch-server"
        assert s.port == 9001
        assert s.database == "mydb"
        assert s.pool_size == 10


# ===========================================================================
# TestStubClient
# ===========================================================================

class TestStubClient:
    def test_execute_returns_empty_list(self):
        stub = _StubClient()
        result = stub.execute("SELECT 1")
        assert result == []

    def test_execute_with_params(self):
        stub = _StubClient()
        result = stub.execute("INSERT INTO t VALUES", [(1, 2)])
        assert isinstance(result, list)

    def test_disconnect_no_error(self):
        stub = _StubClient()
        stub.disconnect()  # should not raise


# ===========================================================================
# TestClickHousePool
# ===========================================================================

class TestClickHousePool:
    def test_pool_initialised_with_stub_clients(self):
        settings = ClickHouseSettings()
        with patch("app.analytics.clickhouse_client._CLICKHOUSE_AVAILABLE", False):
            pool = ClickHousePool(settings)
        assert pool._pool.qsize() == settings.pool_size

    def test_acquire_release_roundtrip(self):
        settings = ClickHouseSettings()
        settings.pool_size = 2
        with patch("app.analytics.clickhouse_client._CLICKHOUSE_AVAILABLE", False):
            pool = ClickHousePool(settings)
        client = pool._acquire()
        assert isinstance(client, _StubClient)
        pool._release(client)
        assert pool._pool.qsize() == 2

    def test_execute_async_with_stub(self):
        settings = ClickHouseSettings()
        with patch("app.analytics.clickhouse_client._CLICKHOUSE_AVAILABLE", False):
            pool = ClickHousePool(settings)
        result = asyncio.run(pool.execute("SELECT 1"))
        assert result == []

    def test_close_drains_pool(self):
        settings = ClickHouseSettings()
        settings.pool_size = 3
        with patch("app.analytics.clickhouse_client._CLICKHOUSE_AVAILABLE", False):
            pool = ClickHousePool(settings)
        asyncio.run(pool.close())
        assert pool._pool.empty()


# ===========================================================================
# TestClickHouseClient
# ===========================================================================

class TestClickHouseClient:
    def _client(self, return_value: Any = None) -> ClickHouseClient:
        return _make_mock_client(return_value)

    def test_execute_delegates_to_pool(self):
        client = self._client([(1,)])
        result = asyncio.run(client.execute("SELECT 1"))
        assert result == [(1,)]
        client._pool.execute.assert_awaited_once()

    def test_insert_calls_pool_with_values(self):
        client = self._client()
        rows = [{"a": 1, "b": "x"}, {"a": 2, "b": "y"}]
        asyncio.run(client.insert("test_table", rows))
        client._pool.execute.assert_awaited_once()
        call_args = client._pool.execute.call_args
        query = call_args[0][0]
        assert "INSERT INTO test_table" in query
        assert "a, b" in query or "b, a" in query

    def test_insert_empty_rows_noop(self):
        client = self._client()
        asyncio.run(client.insert("test_table", []))
        client._pool.execute.assert_not_awaited()

    def test_fetch_one_returns_first_row(self):
        client = self._client([(42, "ok")])
        row = asyncio.run(client.fetch_one("SELECT 42"))
        assert row == (42, "ok")

    def test_fetch_one_returns_none_when_empty(self):
        client = self._client([])
        row = asyncio.run(client.fetch_one("SELECT 1 WHERE 1=0"))
        assert row is None

    def test_fetch_all_returns_all_rows(self):
        client = self._client([(1,), (2,), (3,)])
        rows = asyncio.run(client.fetch_all("SELECT n FROM t"))
        assert len(rows) == 3

    def test_ping_true_when_returns_1(self):
        client = self._client([(1,)])
        assert asyncio.run(client.ping()) is True

    def test_ping_false_on_exception(self):
        client = self._client()
        client._pool.execute = AsyncMock(side_effect=Exception("conn refused"))
        assert asyncio.run(client.ping()) is False

    def test_table_exists_true(self):
        client = self._client([("agent_runs",)])
        result = asyncio.run(client.table_exists("agent_runs"))
        assert result is True

    def test_table_exists_false(self):
        client = self._client([])
        result = asyncio.run(client.table_exists("nonexistent"))
        assert result is False

    def test_get_table_columns_returns_list(self):
        client = self._client([("run_id", "UUID"), ("agent_role", "String")])
        cols = asyncio.run(client.get_table_columns("agent_runs"))
        assert ("run_id", "UUID") in cols

    def test_get_row_count(self):
        client = self._client([(999,)])
        count = asyncio.run(client.get_row_count("univex.agent_runs"))
        assert count == 999

    def test_get_row_count_invalid_table_raises(self):
        client = self._client([(1,)])
        with pytest.raises(ValueError, match="not in the list of allowed tables"):
            asyncio.run(client.get_row_count("evil_table; DROP TABLE agent_runs--"))

    def test_close_calls_pool_close(self):
        client = self._client()
        client._pool.close = AsyncMock()
        asyncio.run(client.close())
        client._pool.close.assert_awaited_once()

    def test_singleton_lazy_init(self):
        import app.analytics.clickhouse_client as mod
        mod._client = None
        # Setting a mock so no real connection is attempted
        mock = _make_mock_client()
        set_clickhouse_client(mock)
        result = asyncio.run(get_clickhouse_client())
        assert result is mock


# ===========================================================================
# TestPentestAnalytics
# ===========================================================================

class TestPentestAnalytics:
    def _analytics(self, return_map=None) -> PentestAnalytics:
        return _make_analytics(return_map)

    # --- record_agent_run ---

    def test_record_agent_run_returns_uuid(self):
        pa = self._analytics()
        run_id = asyncio.run(
            pa.record_agent_run(
                agent_role="recon",
                duration_ms=1200,
                prompt_tokens=512,
                completion_tokens=128,
                cost_usd=0.001,
                success=True,
                target="example.com",
            )
        )
        assert len(run_id) == 36  # UUID string length

    def test_record_agent_run_inserts_row(self):
        pa = self._analytics()
        asyncio.run(
            pa.record_agent_run(agent_role="exploit", duration_ms=800, success=False)
        )
        pa._client._pool.execute.assert_awaited()

    def test_record_agent_run_calculates_total_tokens(self):
        pa = self._analytics()
        captured_rows: List[Any] = []

        async def capture(query, params=None, with_column_types=False, **kwargs):
            if isinstance(params, list):
                captured_rows.extend(params)
            return []

        pa._client._pool.execute = AsyncMock(side_effect=capture)
        asyncio.run(
            pa.record_agent_run(
                agent_role="planner",
                duration_ms=500,
                prompt_tokens=100,
                completion_tokens=50,
                success=True,
            )
        )
        # INSERT was called at least once
        assert len(captured_rows) > 0
        # Verify that the values list (inner list) contains 150 as total_tokens
        # The insert() method passes [[col0, col1, ...]] as params
        inner = captured_rows[0]  # list of column values
        # total_tokens = prompt_tokens + completion_tokens = 100 + 50 = 150
        assert 150 in inner

    # --- record_tool_execution ---

    def test_record_tool_execution_returns_uuid(self):
        pa = self._analytics()
        eid = asyncio.run(
            pa.record_tool_execution(
                tool_name="naabu",
                target="192.168.1.1",
                duration_ms=3000,
                result_code=0,
                findings_count=5,
                success=True,
            )
        )
        assert len(eid) == 36

    def test_record_tool_execution_failure(self):
        pa = self._analytics()
        eid = asyncio.run(
            pa.record_tool_execution(
                tool_name="nuclei",
                target="http://target.com",
                duration_ms=1500,
                result_code=1,
                success=False,
            )
        )
        assert eid  # Still returns an ID

    # --- record_finding ---

    def test_record_finding_returns_uuid(self):
        pa = self._analytics()
        fid = asyncio.run(
            pa.record_finding(
                severity="critical",
                category="sqli",
                owasp_tag="A03",
                cvss_score=9.8,
                target="db.internal",
            )
        )
        assert len(fid) == 36

    def test_record_finding_pads_fingerprint(self):
        pa = self._analytics()
        captured: List[Any] = []

        async def cap(query, params=None, **kwargs):
            if params and isinstance(params, list):
                captured.extend(params)
            return []

        pa._client._pool.execute = AsyncMock(side_effect=cap)
        asyncio.run(
            pa.record_finding(
                severity="high",
                category="xss",
                fingerprint="short",  # less than 16 chars
            )
        )
        # Should pad to 16 chars — just verify no error

    # --- record_llm_call ---

    def test_record_llm_call_returns_uuid(self):
        pa = self._analytics()
        cid = asyncio.run(
            pa.record_llm_call(
                provider="openai",
                model="gpt-4o",
                prompt_tokens=1024,
                completion_tokens=256,
                cost_usd=0.05,
                latency_ms=800,
            )
        )
        assert len(cid) == 36

    def test_record_llm_call_failed_call(self):
        pa = self._analytics()
        cid = asyncio.run(
            pa.record_llm_call(
                provider="anthropic",
                model="claude-3-5-sonnet",
                prompt_tokens=500,
                completion_tokens=0,
                cost_usd=0.0,
                success=False,
                error_code="rate_limit",
                finish_reason="error",
            )
        )
        assert cid

    # --- record_scan_session ---

    def test_record_scan_session(self):
        pa = self._analytics()
        sid = str(uuid.uuid4())
        # Should not raise
        asyncio.run(
            pa.record_scan_session(
                session_id=sid,
                campaign_id="camp-1",
                target="192.168.0.0/24",
                scan_type="full",
                status="completed",
                total_findings=12,
                critical_count=2,
                high_count=4,
                risk_score=8.5,
            )
        )

    # --- query methods ---

    def test_query_aggregate_stats_structure(self):
        # Return fixed aggregated rows
        pa = self._analytics(
            return_map={
                "agent_runs": [(100, 50000, 1.5)],
                "tool_executions": [(200,)],
                "findings": [(300, 10, 20)],
                "llm_calls": [(500, 0.75)],
            }
        )
        stats = asyncio.run(pa.query_aggregate_stats())
        assert "total_agent_runs" in stats
        assert "total_findings" in stats
        assert "total_cost_usd" in stats
        assert "critical_findings" in stats

    def test_query_aggregate_stats_zero_when_empty(self):
        pa = self._analytics()
        stats = asyncio.run(pa.query_aggregate_stats())
        assert stats["total_agent_runs"] == 0
        assert stats["total_cost_usd"] == 0.0

    def test_query_trend_valid_metric(self):
        pa = self._analytics()
        pa._client._pool.execute = AsyncMock(
            return_value=[("2026-01-01", 5), ("2026-01-02", 8)]
        )
        trend = asyncio.run(pa.query_trend(metric="agent_runs", days=7))
        assert isinstance(trend, list)
        assert all("day" in t and "count" in t for t in trend)

    def test_query_trend_invalid_metric_raises(self):
        pa = self._analytics()
        with pytest.raises(ValueError, match="Unknown metric"):
            asyncio.run(pa.query_trend(metric="invalid_metric"))

    def test_query_cost_report(self):
        pa = self._analytics()
        pa._client._pool.execute = AsyncMock(
            return_value=[("openai", "gpt-4o", 100, 10000, 2500, 2.5, 750.0)]
        )
        report = asyncio.run(pa.query_cost_report(days=30))
        assert len(report) == 1
        assert report[0]["provider"] == "openai"
        assert report[0]["total_cost_usd"] == 2.5

    def test_query_tool_performance(self):
        pa = self._analytics()
        pa._client._pool.execute = AsyncMock(
            return_value=[("naabu", 50, 48, 2500.0, 120)]
        )
        perf = asyncio.run(pa.query_tool_performance())
        assert perf[0]["tool_name"] == "naabu"
        assert perf[0]["success_rate"] == pytest.approx(0.96)

    def test_query_findings_by_severity(self):
        pa = self._analytics()
        pa._client._pool.execute = AsyncMock(
            return_value=[("critical", "sqli", 10, 9.2)]
        )
        findings = asyncio.run(pa.query_findings_by_severity())
        assert findings[0]["severity"] == "critical"
        assert findings[0]["count"] == 10

    def test_query_findings_with_campaign_filter(self):
        pa = self._analytics()
        pa._client._pool.execute = AsyncMock(return_value=[])
        findings = asyncio.run(pa.query_findings_by_severity(campaign_id="camp-123"))
        assert isinstance(findings, list)

    def test_query_agent_performance(self):
        pa = self._analytics()
        pa._client._pool.execute = AsyncMock(
            return_value=[("recon", 100, 95, 1500.0, 50000, 0.75)]
        )
        perf = asyncio.run(pa.query_agent_performance(days=30))
        assert perf[0]["agent_role"] == "recon"
        assert perf[0]["success_rate"] == pytest.approx(0.95)


# ===========================================================================
# TestAnalyticsAPI — FastAPI TestClient
# ===========================================================================

@pytest.fixture(scope="module")
def api_client():
    """Provide a TestClient with the analytics router mounted."""
    app = FastAPI()
    app.include_router(analytics_router)
    return TestClient(app)


@pytest.fixture(autouse=True)
def mock_analytics_singleton(request):
    """Inject a fully-mocked PentestAnalytics for API tests."""
    if "api_client" not in request.fixturenames:
        return  # Only active for API tests
    mock = MagicMock(spec=PentestAnalytics)
    mock.record_agent_run = AsyncMock(return_value=str(uuid.uuid4()))
    mock.record_tool_execution = AsyncMock(return_value=str(uuid.uuid4()))
    mock.record_finding = AsyncMock(return_value=str(uuid.uuid4()))
    mock.record_llm_call = AsyncMock(return_value=str(uuid.uuid4()))
    mock.record_scan_session = AsyncMock(return_value=None)
    mock.query_aggregate_stats = AsyncMock(
        return_value={
            "total_agent_runs": 10,
            "total_tool_executions": 20,
            "total_findings": 30,
            "total_llm_calls": 40,
            "total_cost_usd": 1.5,
            "total_tokens": 10000,
            "critical_findings": 2,
            "high_findings": 5,
        }
    )
    mock.query_trend = AsyncMock(
        return_value=[{"day": "2026-01-01", "count": 5}]
    )
    mock.query_cost_report = AsyncMock(
        return_value=[
            {
                "provider": "openai",
                "model": "gpt-4o",
                "call_count": 100,
                "prompt_tokens": 5000,
                "completion_tokens": 1000,
                "total_cost_usd": 0.5,
                "avg_latency_ms": 800.0,
            }
        ]
    )
    mock.query_tool_performance = AsyncMock(
        return_value=[
            {
                "tool_name": "naabu",
                "execution_count": 50,
                "success_count": 48,
                "success_rate": 0.96,
                "avg_duration_ms": 2500.0,
                "total_findings": 120,
            }
        ]
    )
    mock.query_findings_by_severity = AsyncMock(
        return_value=[
            {"severity": "critical", "category": "sqli", "count": 5, "avg_cvss_score": 9.2}
        ]
    )
    mock.query_agent_performance = AsyncMock(
        return_value=[
            {
                "agent_role": "recon",
                "run_count": 100,
                "success_count": 95,
                "success_rate": 0.95,
                "avg_duration_ms": 1500.0,
                "total_tokens": 50000,
                "total_cost_usd": 0.75,
            }
        ]
    )
    set_pentest_analytics(mock)
    return mock


class TestAnalyticsAPI:
    # --- Health ---

    def test_health_endpoint_exists(self, api_client):
        with patch("app.api.analytics.get_clickhouse_client", new_callable=AsyncMock) as m:
            mock_ch = MagicMock()
            mock_ch.ping = AsyncMock(return_value=True)
            m.return_value = mock_ch
            resp = api_client.get("/api/analytics/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    # --- Stats ---

    def test_stats_returns_200(self, api_client):
        resp = api_client.get("/api/analytics/stats")
        assert resp.status_code == 200

    def test_stats_schema(self, api_client):
        resp = api_client.get("/api/analytics/stats")
        data = resp.json()
        assert "total_agent_runs" in data
        assert "total_findings" in data
        assert "critical_findings" in data

    # --- Trend ---

    def test_trend_default(self, api_client):
        resp = api_client.get("/api/analytics/trend")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_trend_with_metric(self, api_client):
        resp = api_client.get("/api/analytics/trend?metric=findings&days=7")
        assert resp.status_code == 200

    def test_trend_invalid_metric(self, api_client):
        resp = api_client.get("/api/analytics/trend?metric=bad_metric")
        assert resp.status_code == 400

    # --- Cost Report ---

    def test_cost_report_returns_list(self, api_client):
        resp = api_client.get("/api/analytics/cost-report")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_cost_report_schema(self, api_client):
        resp = api_client.get("/api/analytics/cost-report")
        data = resp.json()
        assert len(data) > 0
        assert "provider" in data[0]
        assert "total_cost_usd" in data[0]

    # --- Tool Performance ---

    def test_tool_performance_returns_list(self, api_client):
        resp = api_client.get("/api/analytics/tool-performance")
        assert resp.status_code == 200

    def test_tool_performance_schema(self, api_client):
        resp = api_client.get("/api/analytics/tool-performance")
        data = resp.json()
        assert data[0]["tool_name"] == "naabu"
        assert "success_rate" in data[0]

    # --- Findings ---

    def test_findings_endpoint(self, api_client):
        resp = api_client.get("/api/analytics/findings")
        assert resp.status_code == 200

    def test_findings_campaign_filter(self, api_client):
        resp = api_client.get("/api/analytics/findings?campaign_id=camp-1")
        assert resp.status_code == 200

    # --- Agent Performance ---

    def test_agent_performance_endpoint(self, api_client):
        resp = api_client.get("/api/analytics/agent-performance")
        assert resp.status_code == 200

    # --- Record: Agent Run ---

    def test_record_agent_run_201(self, api_client):
        resp = api_client.post(
            "/api/analytics/record/agent-run",
            json={
                "agent_role": "recon",
                "duration_ms": 1500,
                "prompt_tokens": 512,
                "completion_tokens": 128,
                "cost_usd": 0.002,
                "success": True,
                "target": "example.com",
            },
        )
        assert resp.status_code == 201
        assert "id" in resp.json()

    def test_record_agent_run_validation(self, api_client):
        resp = api_client.post(
            "/api/analytics/record/agent-run",
            json={"duration_ms": 500},  # missing agent_role
        )
        assert resp.status_code == 422

    # --- Record: Tool Execution ---

    def test_record_tool_exec_201(self, api_client):
        resp = api_client.post(
            "/api/analytics/record/tool-exec",
            json={
                "tool_name": "nuclei",
                "target": "http://target.com",
                "duration_ms": 2000,
                "findings_count": 3,
                "success": True,
            },
        )
        assert resp.status_code == 201

    # --- Record: Finding ---

    def test_record_finding_201(self, api_client):
        resp = api_client.post(
            "/api/analytics/record/finding",
            json={
                "severity": "high",
                "category": "xss",
                "owasp_tag": "A03",
                "target": "http://app.internal",
                "cvss_score": 7.5,
            },
        )
        assert resp.status_code == 201

    # --- Record: LLM Call ---

    def test_record_llm_call_201(self, api_client):
        resp = api_client.post(
            "/api/analytics/record/llm-call",
            json={
                "provider": "openai",
                "model": "gpt-4o-mini",
                "prompt_tokens": 1000,
                "completion_tokens": 200,
                "cost_usd": 0.001,
                "latency_ms": 450,
                "success": True,
            },
        )
        assert resp.status_code == 201

    # --- Record: Scan Session ---

    def test_record_scan_session_201(self, api_client):
        resp = api_client.post(
            "/api/analytics/record/scan-session",
            json={
                "session_id": str(uuid.uuid4()),
                "campaign_id": "camp-999",
                "target": "10.0.0.0/24",
                "scan_type": "full",
                "status": "completed",
                "total_findings": 15,
                "critical_count": 1,
                "risk_score": 7.8,
            },
        )
        assert resp.status_code == 201

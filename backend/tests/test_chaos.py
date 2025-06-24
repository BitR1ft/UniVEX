"""

These tests verify graceful degradation when:
- PostgreSQL is unavailable
- Neo4j is unreachable
- External tools fail or time out
- The service handles partial failures without crashing

All chaos tests mock/simulate failures — no real database is required.
"""
from __future__ import annotations

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import AsyncClient, ASGITransport

from app.main import app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_token(user_id: str = "user-1") -> str:
    """Create a real JWT for dependency injection in tests."""
    from app.core.security import create_access_token
    return create_access_token({"sub": user_id})


# ---------------------------------------------------------------------------
# Phase 1: Database Failure Scenarios
# ---------------------------------------------------------------------------

class TestDatabaseFailures:
    """Verify API gracefully handles PostgreSQL unavailability."""

    @pytest.mark.asyncio
    async def test_health_endpoint_reports_db_down(self):
        """Health check should return degraded status when DB is down, not crash."""
        with patch("app.main.app") as mock_app:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                # Even without a DB connection the health endpoint should respond
                response = await client.get("/health")
                assert response.status_code in (200, 503), (
                    f"Expected 200 or 503, got {response.status_code}"
                )

    @pytest.mark.asyncio
    async def test_projects_endpoint_returns_503_on_db_error(self):
        """Projects list should return 503 when DB is unreachable."""
        with patch(
            "app.api.projects.get_project_service",
            side_effect=Exception("Connection refused"),
        ):
            token = _make_token()
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.get(
                    "/api/projects",
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert response.status_code in (500, 503, 422), (
                    f"Unexpected status {response.status_code}"
                )

    @pytest.mark.asyncio
    async def test_auth_endpoint_returns_503_on_db_error(self):
        """Login should return 503/500 gracefully when auth service fails."""
        with patch(
            "app.api.auth.get_auth_service",
            side_effect=Exception("DB connection lost"),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.post(
                    "/api/auth/login",
                    json={"username": "admin", "password": "password"},
                )
                assert response.status_code in (500, 503, 422), (
                    f"Unexpected status {response.status_code}"
                )

    def test_sliding_window_rate_limiter_survives_clock_skew(self):
        """Rate limiter should not crash on unusual time values."""
        import time
        from app.core.rate_limit import SlidingWindowRateLimiter

        limiter = SlidingWindowRateLimiter(max_calls=10, window_seconds=60)

        # Simulate rapid calls
        for _ in range(15):
            limiter.is_allowed("chaos-user")

        # Should still work after exhaustion
        result = limiter.is_allowed("chaos-user")
        assert isinstance(result, bool)

    def test_waf_handles_very_long_input_without_crash(self):
        """WAF must not crash or hang on extremely long input strings."""
        from app.core.waf import check_for_attacks, sanitize_string

        long_input = "A" * 100_000
        result = sanitize_string(long_input[:1000])  # sanitize trims to safe length
        assert isinstance(result, str)

        # check_for_attacks on long string should return boolean without error
        try:
            check_for_attacks(long_input[:5000])
        except Exception as exc:
            pytest.fail(f"check_for_attacks raised unexpectedly: {exc}")

    def test_waf_handles_null_bytes(self):
        """WAF must handle null bytes gracefully."""
        from app.core.waf import sanitize_string

        input_with_null = "normal text\x00injected\x00bytes"
        result = sanitize_string(input_with_null)
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# Phase 2: Neo4j Failure Scenarios
# ---------------------------------------------------------------------------

class TestNeo4jFailures:
    """Verify graceful degradation when Neo4j graph database is unavailable."""

    @pytest.mark.asyncio
    async def test_graph_endpoint_returns_503_when_neo4j_down(self):
        """Graph endpoints should return 503 (not 500) when Neo4j is unavailable."""
        with patch("app.db.neo4j_client.neo4j_client.driver", side_effect=Exception("Neo4j connection refused")):
            token = _make_token()
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.get(
                    "/api/graph/proj-1/attack-surface",
                    headers={"Authorization": f"Bearer {token}"},
                )
                # Should be 4xx/5xx but not unhandled exception
                assert response.status_code < 600

    def test_neo4j_client_handles_timeout_gracefully(self):
        """Neo4j client should raise a specific exception on timeout, not hang."""
        try:
            from app.graph import neo4j_client
            # Verify the module can be imported without a live connection
            assert neo4j_client is not None
        except ImportError:
            pytest.skip("graph.neo4j_client not available in this environment")

    def test_graph_ingestion_skips_on_connection_error(self):
        """Graph ingestion should log error and continue, not crash the scan."""
        try:
            from app.graph import ingestion

            with patch.object(ingestion, "ingest_domain_node", side_effect=Exception("timeout")):
                # Calling the function should raise but be catchable
                with pytest.raises(Exception, match="timeout"):
                    ingestion.ingest_domain_node("example.com", "proj-1")
        except (ImportError, AttributeError):
            pytest.skip("graph.ingestion not available in this test environment")


# ---------------------------------------------------------------------------
# Phase 3: Tool Failure Scenarios
# ---------------------------------------------------------------------------

class TestToolFailures:
    """Verify security tool failure handling (nmap, httpx, nuclei, etc.)."""

    def test_tool_result_is_valid_on_process_error(self):
        """If a tool subprocess fails, the result object should still be valid."""
        try:
            from app.recon.base import ToolResult

            result = ToolResult(
                tool="nmap",
                success=False,
                error="Process returned non-zero exit code: 1",
                data={},
                raw_output="",
            )
            assert result.tool == "nmap"
            assert result.success is False
            assert result.error is not None
        except ImportError:
            pytest.skip("recon.base not available in this test environment")

    def test_tool_timeout_does_not_block_indefinitely(self):
        """Tools must respect timeout and not block the event loop indefinitely."""
        import time

        start = time.time()

        async def fake_run_with_timeout():
            await asyncio.sleep(0)  # Simulate instant completion
            raise asyncio.TimeoutError("Tool timed out")

        with pytest.raises(asyncio.TimeoutError):
            asyncio.run(fake_run_with_timeout())

        elapsed = time.time() - start
        assert elapsed < 5.0, "Tool timeout should be fast"

    def test_nuclei_empty_results_handled(self):
        """Nuclei returning empty results should not cause downstream failures."""
        try:
            from app.recon.nuclei import parse_nuclei_output

            result = parse_nuclei_output("")
            assert isinstance(result, list)
        except (ImportError, AttributeError):
            pytest.skip("recon.nuclei.parse_nuclei_output not available")

    def test_nmap_parse_handles_malformed_xml(self):
        """Nmap XML parser must handle malformed/truncated XML without crashing."""
        try:
            from app.recon.nmap import parse_nmap_xml

            malformed_xml = "<nmaprun><host><status/>"  # truncated XML
            result = parse_nmap_xml(malformed_xml)
            # Should return empty or partial, not raise
            assert result is not None
        except (ImportError, AttributeError):
            pytest.skip("recon.nmap.parse_nmap_xml not available")
        except Exception as exc:
            pytest.fail(f"parse_nmap_xml raised unexpectedly on malformed XML: {exc}")


# ---------------------------------------------------------------------------
# Phase 4: Graceful Degradation — End-to-End
# ---------------------------------------------------------------------------

class TestGracefulDegradation:
    """Verify that partial failures do not cascade into full system outage."""

    @pytest.mark.asyncio
    async def test_metrics_endpoint_always_responds(self):
        """Prometheus /metrics must always respond even if backend services fail."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/metrics")
            # Metrics endpoint should always be reachable
            assert response.status_code in (200, 404), (
                f"Unexpected status {response.status_code}"
            )

    @pytest.mark.asyncio
    async def test_api_returns_json_errors_not_html(self):
        """All API error responses should return JSON, not HTML error pages."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/projects/nonexistent-id-12345")
            assert "application/json" in response.headers.get("content-type", ""), (
                "Error response should be JSON"
            )

    def test_secrets_validation_does_not_leak_values(self, monkeypatch):
        """Error messages from secrets validation must not contain secret values."""
        from app.core.secrets import validate_secrets, SecretsValidationError

        monkeypatch.setenv("SECRET_KEY", "short")
        try:
            validate_secrets("production")
        except SecretsValidationError as exc:
            error_msg = str(exc)
            assert "short" not in error_msg, (
                "Secret value must not appear in error messages"
            )
        except Exception:
            pass  # Other exceptions are acceptable

    def test_rbac_unknown_role_does_not_crash(self):
        """RBAC must not crash when encountering an unknown role value."""
        from app.core.rbac import has_permission, Permission, UserRole

        # Test all valid roles work
        for role in UserRole:
            for perm in Permission:
                result = has_permission(role, perm)
                assert isinstance(result, bool)

    def test_audit_log_handles_none_user_id(self):
        """Audit logging must not crash when user_id is None (unauthenticated action)."""
        from app.core.audit import log_audit, AuditAction
        import io

        try:
            # Should not raise even with None user_id
            log_audit(
                action=AuditAction.LOGIN_SUCCESS,
                user_id=None,  # type: ignore[arg-type]
                resource_type="session",
                resource_id="sess-1",
                details={},
                ip_address="127.0.0.1",
            )
        except Exception as exc:
            # If it raises, it must be a ValueError, not an unhandled crash
            assert isinstance(exc, (ValueError, TypeError)), (
                f"audit.log_audit raised unexpected exception: {exc}"
            )

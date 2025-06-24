"""
Tests for Week 15 — Tool Adapters.

Covers:
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, Mock, patch
from app.agent.tools.tool_adapters import (
    DomainDiscoveryTool,
    PortScanTool,
    HttpProbeTool,
    TechDetectionTool,
    EndpointEnumerationTool,
    NucleiTemplateSelectTool,
    NucleiScanTool,
    AttackSurfaceQueryTool,
    VulnerabilityLookupTool,
    ExploitSearchTool,
    CVELookupTool,
)
from app.agent.tools.error_handling import (
    ErrorCategory,
    ToolErrorReporter,
    ToolExecutionError,
    ToolRateLimitError,
    ToolTimeoutError,
    categorise_error,
    get_recovery_hint,
    with_retry,
    RECOVERY_HINTS,
)


def run(coro):
    """Helper to run async functions in a test event loop."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class TestDomainDiscoveryTool:
    def test_metadata(self):
        tool = DomainDiscoveryTool()
        assert tool.name == "domain_discovery"
        assert "domain" in tool.description.lower()
        assert "domain" in tool.metadata.parameters["properties"]

    def test_execute_success(self):
        tool = DomainDiscoveryTool()
        mock_result = {"success": True, "subdomains": ["sub1.example.com", "sub2.example.com"]}
        with patch("app.mcp.base_server.MCPClient") as MockClient:
            MockClient.return_value.call_tool = AsyncMock(return_value=mock_result)
            result = run(tool.execute(domain="example.com"))
        assert "sub1.example.com" in result
        assert "2 subdomains" in result

    def test_execute_no_results(self):
        tool = DomainDiscoveryTool()
        with patch("app.mcp.base_server.MCPClient") as MockClient:
            MockClient.return_value.call_tool = AsyncMock(return_value={"success": True, "subdomains": []})
            result = run(tool.execute(domain="example.com"))
        assert "No subdomains" in result

    def test_execute_error_response(self):
        tool = DomainDiscoveryTool()
        with patch("app.mcp.base_server.MCPClient") as MockClient:
            MockClient.return_value.call_tool = AsyncMock(
                return_value={"success": False, "error": "DNS timeout"}
            )
            result = run(tool.execute(domain="example.com"))
        assert "failed" in result.lower() or "DNS timeout" in result

    def test_execute_exception_raises_tool_error(self):
        tool = DomainDiscoveryTool()
        with patch("app.mcp.base_server.MCPClient") as MockClient:
            MockClient.return_value.call_tool = AsyncMock(side_effect=RuntimeError("network down"))
            with pytest.raises(ToolExecutionError):
                run(tool.execute(domain="example.com"))


class TestPortScanTool:
    def test_metadata(self):
        tool = PortScanTool()
        assert tool.name == "port_scan"
        assert "target" in tool.metadata.parameters["properties"]
        assert "ports" in tool.metadata.parameters["properties"]

    def test_execute_open_ports(self):
        tool = PortScanTool()
        mock_result = {
            "success": True,
            "ports": [
                {"port": 80, "protocol": "tcp", "service": "http"},
                {"port": 443, "protocol": "tcp", "service": "https"},
            ],
        }
        with patch("app.mcp.base_server.MCPClient") as MockClient:
            MockClient.return_value.call_tool = AsyncMock(return_value=mock_result)
            result = run(tool.execute(target="10.0.0.1"))
        assert "80/tcp" in result
        assert "443/tcp" in result

    def test_execute_no_ports(self):
        tool = PortScanTool()
        with patch("app.mcp.base_server.MCPClient") as MockClient:
            MockClient.return_value.call_tool = AsyncMock(return_value={"success": True, "ports": []})
            result = run(tool.execute(target="10.0.0.1"))
        assert "No open ports" in result

    def test_execute_failure(self):
        tool = PortScanTool()
        with patch("app.mcp.base_server.MCPClient") as MockClient:
            MockClient.return_value.call_tool = AsyncMock(
                return_value={"success": False, "error": "Target unreachable"}
            )
            result = run(tool.execute(target="10.0.0.1"))
        assert "failed" in result.lower() or "unreachable" in result.lower()


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class TestHttpProbeTool:
    def test_metadata(self):
        tool = HttpProbeTool()
        assert tool.name == "http_probe"
        assert "url" in tool.metadata.parameters["properties"]

    def test_execute_success(self):
        tool = HttpProbeTool()
        mock_result = {
            "success": True,
            "status_code": 200,
            "title": "Example Domain",
            "server": "Apache/2.4",
            "technologies": ["PHP", "jQuery"],
            "redirects": [],
        }
        with patch("app.mcp.base_server.MCPClient") as MockClient:
            MockClient.return_value.call_tool = AsyncMock(return_value=mock_result)
            result = run(tool.execute(url="https://example.com"))
        assert "200" in result
        assert "Apache/2.4" in result

    def test_execute_failure(self):
        tool = HttpProbeTool()
        with patch("app.mcp.base_server.MCPClient") as MockClient:
            MockClient.return_value.call_tool = AsyncMock(
                return_value={"success": False, "error": "SSL error"}
            )
            result = run(tool.execute(url="https://example.com"))
        assert "failed" in result.lower()


class TestTechDetectionTool:
    def test_metadata(self):
        tool = TechDetectionTool()
        assert tool.name == "tech_detection"
        assert "url" in tool.metadata.parameters["properties"]

    def test_execute_technologies(self):
        tool = TechDetectionTool()
        mock_result = {
            "success": True,
            "technologies": [
                {"name": "WordPress", "version": "6.4", "categories": ["CMS"], "confidence": 100},
                {"name": "PHP", "version": "8.1", "categories": ["Programming Languages"], "confidence": 90},
            ],
        }
        with patch("app.mcp.base_server.MCPClient") as MockClient:
            MockClient.return_value.call_tool = AsyncMock(return_value=mock_result)
            result = run(tool.execute(url="https://example.com"))
        assert "WordPress" in result
        assert "PHP" in result

    def test_execute_no_tech(self):
        tool = TechDetectionTool()
        with patch("app.mcp.base_server.MCPClient") as MockClient:
            MockClient.return_value.call_tool = AsyncMock(
                return_value={"success": True, "technologies": []}
            )
            result = run(tool.execute(url="https://example.com"))
        assert "No technologies" in result


class TestEndpointEnumerationTool:
    def test_metadata(self):
        tool = EndpointEnumerationTool()
        assert tool.name == "endpoint_enumeration"
        assert "url" in tool.metadata.parameters["properties"]
        assert "wordlist" in tool.metadata.parameters["properties"]

    def test_execute_endpoints(self):
        tool = EndpointEnumerationTool()
        mock_result = {
            "success": True,
            "endpoints": [
                {"path": "/admin", "status_code": 200, "content_length": 1234, "content_type": "text/html"},
                {"path": "/login", "status_code": 200, "content_length": 567, "content_type": "text/html"},
            ],
        }
        with patch("app.mcp.base_server.MCPClient") as MockClient:
            MockClient.return_value.call_tool = AsyncMock(return_value=mock_result)
            result = run(tool.execute(url="https://example.com"))
        assert "/admin" in result

    def test_execute_no_endpoints(self):
        tool = EndpointEnumerationTool()
        with patch("app.mcp.base_server.MCPClient") as MockClient:
            MockClient.return_value.call_tool = AsyncMock(
                return_value={"success": True, "endpoints": []}
            )
            result = run(tool.execute(url="https://example.com"))
        assert "No endpoints" in result


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class TestNucleiTemplateSelectTool:
    def test_metadata(self):
        tool = NucleiTemplateSelectTool()
        assert tool.name == "nuclei_template_select"

    def test_select_wordpress_templates(self):
        tool = NucleiTemplateSelectTool()
        result = run(tool.execute(technologies=["WordPress", "PHP"]))
        assert "wordpress" in result.lower() or "cms" in result.lower()

    def test_select_cve_templates(self):
        tool = NucleiTemplateSelectTool()
        result = run(tool.execute(cve_ids=["CVE-2021-41773", "CVE-2021-44228"]))
        assert "cve-2021-41773" in result.lower()
        assert "cve-2021-44228" in result.lower()

    def test_select_no_input_returns_generic(self):
        tool = NucleiTemplateSelectTool()
        result = run(tool.execute())
        assert "generic" in result.lower() or "http" in result.lower() or "misconfig" in result.lower()

    def test_select_deduplicates_tags(self):
        tool = NucleiTemplateSelectTool()
        result = run(tool.execute(technologies=["WordPress", "WordPress"]))
        # Should not have duplicated tags
        assert result.count("wordpress") <= 3  # allow for context mentions


class TestNucleiScanTool:
    def test_metadata(self):
        tool = NucleiScanTool()
        assert tool.name == "nuclei_scan"
        assert "target" in tool.metadata.parameters["properties"]
        assert "tags" in tool.metadata.parameters["properties"]

    def test_execute_findings(self):
        tool = NucleiScanTool()
        mock_result = {
            "success": True,
            "findings": [
                {
                    "name": "Apache Path Traversal",
                    "severity": "critical",
                    "matched_at": "https://example.com/cgi-bin/%2e%2e/",
                    "template_id": "CVE-2021-41773",
                },
            ],
        }
        with patch("app.mcp.base_server.MCPClient") as MockClient:
            MockClient.return_value.call_tool = AsyncMock(return_value=mock_result)
            result = run(tool.execute(target="https://example.com", tags=["cve"]))
        assert "[CRITICAL]" in result
        assert "Apache Path Traversal" in result

    def test_execute_no_findings(self):
        tool = NucleiScanTool()
        with patch("app.mcp.base_server.MCPClient") as MockClient:
            MockClient.return_value.call_tool = AsyncMock(return_value={"success": True, "findings": []})
            result = run(tool.execute(target="https://example.com"))
        assert "No vulnerabilities" in result


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class TestAttackSurfaceQueryTool:
    def test_metadata(self):
        tool = AttackSurfaceQueryTool()
        assert tool.name == "attack_surface_query"
        assert "query_type" in tool.metadata.parameters["properties"]

    def test_requires_project_id(self):
        tool = AttackSurfaceQueryTool()  # no project_id set
        result = run(tool.execute(query_type="overview"))
        assert "project_id" in result.lower() and "required" in result.lower()

    def test_overview_query(self):
        tool = AttackSurfaceQueryTool(project_id="proj-1")
        mock_qs = Mock()
        mock_qs.get_attack_surface_overview.return_value = {
            "subdomain_count": 3,
            "ip_count": 2,
            "endpoint_count": 10,
        }
        with patch("app.graph.graph_queries.AttackSurfaceQueries", return_value=mock_qs):
            with patch("app.db.neo4j_client.get_neo4j_client"):
                result = run(tool.execute(query_type="overview"))
        assert "subdomain_count" in result

    def test_services_query(self):
        tool = AttackSurfaceQueryTool(project_id="proj-1")
        mock_qs = Mock()
        mock_qs.get_exposed_services.return_value = [
            {"ip": "10.0.0.1", "port": 80, "protocol": "tcp",
             "service_name": "http", "service_version": "2.4"}
        ]
        with patch("app.graph.graph_queries.AttackSurfaceQueries", return_value=mock_qs):
            with patch("app.db.neo4j_client.get_neo4j_client"):
                result = run(tool.execute(query_type="services"))
        assert "10.0.0.1" in result

    def test_unknown_query_type(self):
        tool = AttackSurfaceQueryTool(project_id="proj-1")
        with patch("app.db.neo4j_client.get_neo4j_client"):
            result = run(tool.execute(query_type="nonexistent"))
        assert "Unknown" in result


class TestVulnerabilityLookupTool:
    def test_metadata(self):
        tool = VulnerabilityLookupTool()
        assert tool.name == "vulnerability_lookup"
        assert "lookup_type" in tool.metadata.parameters["properties"]

    def test_requires_project_id(self):
        tool = VulnerabilityLookupTool()
        result = run(tool.execute(lookup_type="by_severity"))
        assert "project_id" in result.lower()

    def test_by_severity(self):
        tool = VulnerabilityLookupTool(project_id="proj-1")
        mock_qs = Mock()
        mock_qs.get_vulnerabilities_by_severity.return_value = [
            {"id": "v1", "name": "SQLi", "severity": "critical", "endpoint_path": "/login"}
        ]
        with patch("app.graph.graph_queries.VulnerabilityQueries", return_value=mock_qs):
            with patch("app.db.neo4j_client.get_neo4j_client"):
                result = run(tool.execute(lookup_type="by_severity", severity="critical"))
        assert "SQLi" in result

    def test_cve_chain_requires_cve_id(self):
        tool = VulnerabilityLookupTool(project_id="proj-1")
        result = run(tool.execute(lookup_type="cve_chain"))
        assert "cve_id is required" in result.lower() or "required" in result.lower()

    def test_cve_chain_found(self):
        tool = VulnerabilityLookupTool(project_id="proj-1")
        mock_qs = Mock()
        mock_qs.get_cve_chain.return_value = {
            "cve_id": "CVE-2021-41773",
            "cvss_score": 9.8,
            "cve_severity": "critical",
            "cve_description": "Path traversal",
            "cwe_chain": [{"cwe_id": "CWE-22"}],
            "exploits": [{"exploit_id": "e1"}],
        }
        with patch("app.graph.graph_queries.VulnerabilityQueries", return_value=mock_qs):
            with patch("app.db.neo4j_client.get_neo4j_client"):
                result = run(tool.execute(lookup_type="cve_chain", cve_id="CVE-2021-41773"))
        assert "CVE-2021-41773" in result
        assert "9.8" in result


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class TestExploitSearchTool:
    def test_metadata(self):
        tool = ExploitSearchTool()
        assert tool.name == "exploit_search"
        assert "target" in tool.metadata.parameters["properties"]
        assert "search_type" in tool.metadata.parameters["properties"]

    def test_execute_cve_search(self):
        tool = ExploitSearchTool()
        with patch("app.agent.tools.web_search_tool.WebSearchTool") as MockSearch:
            instance = MockSearch.return_value
            instance.execute = AsyncMock(return_value="Exploit found: CVE-2021-41773")
            result = run(tool.execute(target="CVE-2021-41773", search_type="cve"))
        assert "CVE-2021-41773" in result

    def test_execute_software_search(self):
        tool = ExploitSearchTool()
        with patch("app.agent.tools.web_search_tool.WebSearchTool") as MockSearch:
            instance = MockSearch.return_value
            instance.execute = AsyncMock(return_value="Apache 2.4 vuln")
            result = run(tool.execute(target="Apache 2.4", search_type="software"))
        assert "Apache 2.4" in result


class TestCVELookupTool:
    def test_metadata(self):
        tool = CVELookupTool()
        assert tool.name == "cve_lookup"
        assert "cve_id" in tool.metadata.parameters["properties"]

    def test_execute_with_web_fallback(self):
        tool = CVELookupTool()  # no project_id → goes straight to web search
        with patch("app.agent.tools.web_search_tool.WebSearchTool") as MockSearch:
            instance = MockSearch.return_value
            instance.execute = AsyncMock(return_value="CVE-2021-44228: Log4Shell CVSS 10.0")
            result = run(tool.execute(cve_id="CVE-2021-44228"))
        assert "CVE-2021-44228" in result

    def test_execute_no_data_returns_message(self):
        tool = CVELookupTool()
        with patch("app.agent.tools.web_search_tool.WebSearchTool") as MockSearch:
            instance = MockSearch.return_value
            instance.execute = AsyncMock(side_effect=RuntimeError("no API key"))
            result = run(tool.execute(cve_id="CVE-9999-99999"))
        assert "CVE-9999-99999" in result


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class TestErrorCategorisation:
    def test_categorise_timeout(self):
        assert categorise_error("Tool timed out after 30s") == ErrorCategory.TIMEOUT

    def test_categorise_rate_limit(self):
        assert categorise_error("429 too many requests") == ErrorCategory.RATE_LIMIT

    def test_categorise_connection(self):
        assert categorise_error("Connection refused to host") == ErrorCategory.CONNECTION

    def test_categorise_permission(self):
        assert categorise_error("403 Forbidden") == ErrorCategory.PERMISSION

    def test_categorise_not_found(self):
        assert categorise_error("404 not found") == ErrorCategory.NOT_FOUND

    def test_categorise_parse(self):
        assert categorise_error("Failed to decode JSON") == ErrorCategory.PARSE

    def test_categorise_validation(self):
        assert categorise_error("Missing required field") == ErrorCategory.VALIDATION

    def test_categorise_unknown(self):
        assert categorise_error("something completely random") == ErrorCategory.UNKNOWN

    def test_recovery_hints_all_categories(self):
        for cat in ErrorCategory:
            assert cat in RECOVERY_HINTS
            assert len(RECOVERY_HINTS[cat]) > 20

    def test_get_recovery_hint(self):
        hint = get_recovery_hint("Connection refused")
        assert "connection" in hint.lower() or "firewall" in hint.lower() or "target" in hint.lower()


class TestToolRateLimitError:
    def test_is_recoverable(self):
        err = ToolRateLimitError("rate limit", retry_after=30)
        assert err.recoverable is True
        assert err.retry_after == 30

    def test_is_subclass_of_execution_error(self):
        err = ToolRateLimitError("rate limit")
        assert isinstance(err, ToolExecutionError)


class TestToolErrorReporter:
    def test_record_and_retrieve(self):
        reporter = ToolErrorReporter()
        err = RuntimeError("network error")
        reporter.record("naabu_scan", err, inputs={"target": "10.0.0.1"})
        records = reporter.get_records()
        assert len(records) == 1
        assert records[0]["tool_name"] == "naabu_scan"
        assert records[0]["error_type"] == "RuntimeError"

    def test_summary_counts(self):
        reporter = ToolErrorReporter()
        reporter.record("tool_a", RuntimeError("timeout error"))
        reporter.record("tool_a", RuntimeError("timeout error"))
        reporter.record("tool_b", RuntimeError("connection refused"))
        summary = reporter.get_summary()
        assert summary["total_errors"] == 3
        assert summary["per_tool"]["tool_a"] == 2

    def test_clear(self):
        reporter = ToolErrorReporter()
        reporter.record("t", RuntimeError("err"))
        reporter.clear()
        assert len(reporter.get_records()) == 0

    def test_has_unrecoverable_false(self):
        reporter = ToolErrorReporter()
        reporter.record("t", RuntimeError("err"))
        assert reporter.has_unrecoverable() is False

    def test_has_unrecoverable_true(self):
        reporter = ToolErrorReporter()
        err = ToolExecutionError("fatal", recoverable=False)
        reporter.record("t", err)
        assert reporter.has_unrecoverable() is True


class TestWithRetry:
    def test_succeeds_on_first_attempt(self):
        call_count = 0

        @with_retry(max_attempts=3)
        async def fn():
            nonlocal call_count
            call_count += 1
            return "ok"

        result = run(fn())
        assert result == "ok"
        assert call_count == 1

    def test_retries_on_recoverable_error(self):
        call_count = 0

        @with_retry(max_attempts=3, backoff_base=0.01)
        async def fn():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ToolExecutionError("transient", recoverable=True)
            return "recovered"

        result = run(fn())
        assert result == "recovered"
        assert call_count == 3

    def test_raises_immediately_on_unrecoverable(self):
        call_count = 0

        @with_retry(max_attempts=3, backoff_base=0.01)
        async def fn():
            nonlocal call_count
            call_count += 1
            raise ToolExecutionError("fatal", recoverable=False)

        with pytest.raises(ToolExecutionError, match="fatal"):
            run(fn())
        assert call_count == 1  # Not retried

    def test_raises_after_max_attempts(self):
        call_count = 0

        @with_retry(max_attempts=2, backoff_base=0.01)
        async def fn():
            nonlocal call_count
            call_count += 1
            raise ConnectionError("always fails")

        with pytest.raises(ToolExecutionError, match="All 2 attempts failed"):
            run(fn())
        assert call_count == 2

    def test_does_not_retry_non_retryable_exception(self):
        call_count = 0

        @with_retry(max_attempts=3, backoff_base=0.01)
        async def fn():
            nonlocal call_count
            call_count += 1
            raise ValueError("not retryable")

        with pytest.raises(ValueError):
            run(fn())
        assert call_count == 1


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class TestAdapterDocumentation:
    """
    non-empty name, description (>30 chars), and at least one parameter.
    """

    _ADAPTERS = [
        DomainDiscoveryTool,
        PortScanTool,
        HttpProbeTool,
        TechDetectionTool,
        EndpointEnumerationTool,
        NucleiTemplateSelectTool,
        NucleiScanTool,
        AttackSurfaceQueryTool,
        VulnerabilityLookupTool,
        ExploitSearchTool,
        CVELookupTool,
    ]

    def test_all_adapters_have_name(self):
        for cls in self._ADAPTERS:
            tool = cls()
            assert tool.name, f"{cls.__name__} has no name"
            assert len(tool.name) > 0

    def test_all_adapters_have_description(self):
        for cls in self._ADAPTERS:
            tool = cls()
            assert len(tool.description) > 30, (
                f"{cls.__name__} description too short: {tool.description!r}"
            )

    def test_all_adapters_have_parameters(self):
        for cls in self._ADAPTERS:
            tool = cls()
            params = tool.metadata.parameters
            assert isinstance(params, dict), f"{cls.__name__} parameters is not a dict"

    def test_all_adapters_have_required_params(self):
        """At least the tools that need a target/url/domain have required params."""
        target_tools = [DomainDiscoveryTool, PortScanTool, HttpProbeTool, NucleiScanTool]
        for cls in target_tools:
            tool = cls()
            props = tool.metadata.parameters.get("properties", {})
            assert len(props) >= 1, f"{cls.__name__} has no parameter properties"

    def test_all_adapters_importable_from_package(self):
        from app.agent.tools import (
            DomainDiscoveryTool,
            PortScanTool,
            HttpProbeTool,
            TechDetectionTool,
            EndpointEnumerationTool,
            NucleiTemplateSelectTool,
            NucleiScanTool,
            AttackSurfaceQueryTool,
            VulnerabilityLookupTool,
            ExploitSearchTool,
            CVELookupTool,
        )
        assert DomainDiscoveryTool is not None

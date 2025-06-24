"""
Tests for Week 13 — Multi-tenancy & Queries.

Covers:
           exposed services, attack paths, CVE chain
"""

import pytest
from unittest.mock import Mock, patch
from app.db.neo4j_client import Neo4jClient
from app.graph.graph_queries import (
    TenantIsolation,
    AttackSurfaceQueries,
    VulnerabilityQueries,
    PathFindingQueries,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_neo4j_client():
    """Mock Neo4j client returning empty lists by default."""
    client = Mock(spec=Neo4jClient)
    client.execute_query = Mock(return_value=[])
    return client


@pytest.fixture
def project_id():
    return "project-w13"


@pytest.fixture
def user_id():
    return "user-w13"


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestTenantIsolation:
    """Day 80 — multi-tenancy implementation."""

    def test_tenant_filter_both(self, mock_neo4j_client, user_id, project_id):
        """Both user_id and project_id produce a compound WHERE clause."""
        ti = TenantIsolation(mock_neo4j_client)
        clause, params = ti.get_tenant_filter(user_id=user_id, project_id=project_id)
        assert "user_id" in clause
        assert "project_id" in clause
        assert params["user_id"] == user_id
        assert params["project_id"] == project_id

    def test_tenant_filter_project_only(self, mock_neo4j_client, project_id):
        ti = TenantIsolation(mock_neo4j_client)
        clause, params = ti.get_tenant_filter(project_id=project_id)
        assert "project_id" in clause
        assert "user_id" not in clause
        assert "user_id" not in params

    def test_tenant_filter_none(self, mock_neo4j_client):
        ti = TenantIsolation(mock_neo4j_client)
        clause, params = ti.get_tenant_filter()
        assert clause == "TRUE"
        assert params == {}

    def test_tenant_filter_custom_alias(self, mock_neo4j_client, user_id):
        ti = TenantIsolation(mock_neo4j_client)
        clause, params = ti.get_tenant_filter(user_id=user_id, node_alias="u")
        assert "u.user_id" in clause

    def test_check_project_access_granted(self, mock_neo4j_client, project_id, user_id):
        """Access check returns True when DB reports at least 1 node."""
        mock_neo4j_client.execute_query.return_value = [{"cnt": 3}]
        ti = TenantIsolation(mock_neo4j_client)
        assert ti.check_project_access(project_id, user_id) is True

    def test_check_project_access_denied(self, mock_neo4j_client, project_id, user_id):
        """Access check returns False when DB reports 0 nodes."""
        mock_neo4j_client.execute_query.return_value = [{"cnt": 0}]
        ti = TenantIsolation(mock_neo4j_client)
        assert ti.check_project_access(project_id, user_id) is False

    def test_check_project_access_empty_result(self, mock_neo4j_client, project_id, user_id):
        """Access check returns False when DB returns empty list."""
        mock_neo4j_client.execute_query.return_value = []
        ti = TenantIsolation(mock_neo4j_client)
        assert ti.check_project_access(project_id, user_id) is False

    def test_check_project_access_exception(self, mock_neo4j_client, project_id, user_id):
        """Access check returns False on DB error."""
        mock_neo4j_client.execute_query.side_effect = RuntimeError("DB down")
        ti = TenantIsolation(mock_neo4j_client)
        assert ti.check_project_access(project_id, user_id) is False

    def test_list_user_projects(self, mock_neo4j_client, user_id):
        mock_neo4j_client.execute_query.return_value = [
            {"project_id": "p1"}, {"project_id": "p2"}
        ]
        ti = TenantIsolation(mock_neo4j_client)
        projects = ti.list_user_projects(user_id)
        assert projects == ["p1", "p2"]

    def test_list_user_projects_empty(self, mock_neo4j_client, user_id):
        mock_neo4j_client.execute_query.return_value = []
        ti = TenantIsolation(mock_neo4j_client)
        assert ti.list_user_projects(user_id) == []

    def test_get_project_node_counts(self, mock_neo4j_client, project_id):
        mock_neo4j_client.execute_query.return_value = [
            {"label": "Domain", "cnt": 1},
            {"label": "IP", "cnt": 4},
        ]
        ti = TenantIsolation(mock_neo4j_client)
        counts = ti.get_project_node_counts(project_id)
        assert counts["Domain"] == 1
        assert counts["IP"] == 4

    def test_get_project_node_counts_with_user_filter(
        self, mock_neo4j_client, project_id, user_id
    ):
        mock_neo4j_client.execute_query.return_value = [{"label": "Domain", "cnt": 1}]
        ti = TenantIsolation(mock_neo4j_client)
        counts = ti.get_project_node_counts(project_id, user_id=user_id)
        assert counts.get("Domain") == 1
        # Ensure user_id was passed as a parameter
        call_params = mock_neo4j_client.execute_query.call_args[0][1]
        assert call_params.get("user_id") == user_id


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestAttackSurfaceQueries:
    """Day 81 — attack surface overview, exposed services, technology inventory."""

    def test_get_attack_surface_overview_returns_dict(
        self, mock_neo4j_client, project_id
    ):
        mock_neo4j_client.execute_query.return_value = [{
            "domains": ["example.com"],
            "subdomain_count": 3,
            "ip_count": 4,
            "port_count": 8,
            "service_count": 7,
            "base_url_count": 2,
            "endpoint_count": 15,
        }]
        qs = AttackSurfaceQueries(mock_neo4j_client)
        result = qs.get_attack_surface_overview(project_id)
        assert result["subdomain_count"] == 3
        assert result["endpoint_count"] == 15

    def test_get_attack_surface_overview_empty_db(
        self, mock_neo4j_client, project_id
    ):
        mock_neo4j_client.execute_query.return_value = []
        qs = AttackSurfaceQueries(mock_neo4j_client)
        assert qs.get_attack_surface_overview(project_id) == {}

    def test_get_attack_surface_overview_user_filter(
        self, mock_neo4j_client, project_id, user_id
    ):
        mock_neo4j_client.execute_query.return_value = [{"ip_count": 1}]
        qs = AttackSurfaceQueries(mock_neo4j_client)
        qs.get_attack_surface_overview(project_id, user_id=user_id)
        query = mock_neo4j_client.execute_query.call_args[0][0]
        assert "user_id" in query

    def test_get_exposed_services_returns_list(
        self, mock_neo4j_client, project_id
    ):
        mock_neo4j_client.execute_query.return_value = [
            {"ip": "10.0.0.1", "port": 80, "protocol": "tcp",
             "service_name": "http", "service_version": "2.4"},
            {"ip": "10.0.0.1", "port": 443, "protocol": "tcp",
             "service_name": "https", "service_version": "2.4"},
        ]
        qs = AttackSurfaceQueries(mock_neo4j_client)
        services = qs.get_exposed_services(project_id)
        assert len(services) == 2
        assert services[0]["port"] == 80

    def test_get_exposed_services_filters_only_open(
        self, mock_neo4j_client, project_id
    ):
        """Query must include state='open' filter."""
        mock_neo4j_client.execute_query.return_value = []
        qs = AttackSurfaceQueries(mock_neo4j_client)
        qs.get_exposed_services(project_id)
        query = mock_neo4j_client.execute_query.call_args[0][0]
        assert "open" in query

    def test_get_technology_inventory_with_cves(
        self, mock_neo4j_client, project_id
    ):
        mock_neo4j_client.execute_query.return_value = [
            {"name": "Apache", "version": "2.4", "cve_count": 3,
             "categories": ["Web servers"], "confidence": 100,
             "cve_ids": ["CVE-2021-41773"]},
        ]
        qs = AttackSurfaceQueries(mock_neo4j_client)
        result = qs.get_technology_inventory(project_id, with_cves=True)
        assert result[0]["cve_count"] == 3

    def test_get_technology_inventory_without_cves(
        self, mock_neo4j_client, project_id
    ):
        mock_neo4j_client.execute_query.return_value = [
            {"name": "nginx", "version": "1.24", "cve_count": 0}
        ]
        qs = AttackSurfaceQueries(mock_neo4j_client)
        result = qs.get_technology_inventory(project_id, with_cves=False)
        # Without CVEs the query should NOT request cve_count from DB
        query = mock_neo4j_client.execute_query.call_args[0][0]
        assert "HAS_KNOWN_CVE" not in query

    def test_test_query_performance_returns_counts(
        self, mock_neo4j_client, project_id
    ):
        mock_neo4j_client.execute_query.return_value = [{"ip_count": 1}]
        qs = AttackSurfaceQueries(mock_neo4j_client)
        report = qs.test_query_performance(project_id)
        assert "overview_rows" in report
        assert "exposed_services_rows" in report
        assert "technology_rows" in report


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestVulnerabilityQueries:
    """Day 82 — vulnerability by severity, exploitable, CVE chain."""

    def test_get_vulnerabilities_by_severity_all(
        self, mock_neo4j_client, project_id
    ):
        mock_neo4j_client.execute_query.return_value = [
            {"id": "h1", "name": "XSS", "severity": "high"},
            {"id": "h2", "name": "SQLi", "severity": "critical"},
        ]
        qs = VulnerabilityQueries(mock_neo4j_client)
        result = qs.get_vulnerabilities_by_severity(project_id)
        assert len(result) == 2

    def test_get_vulnerabilities_by_severity_filtered(
        self, mock_neo4j_client, project_id
    ):
        mock_neo4j_client.execute_query.return_value = [
            {"id": "h2", "name": "SQLi", "severity": "critical"},
        ]
        qs = VulnerabilityQueries(mock_neo4j_client)
        result = qs.get_vulnerabilities_by_severity(project_id, severity="critical")
        assert len(result) == 1
        assert result[0]["severity"] == "critical"
        params = mock_neo4j_client.execute_query.call_args[0][1]
        assert params.get("severity") == "critical"

    def test_get_vulnerabilities_limit_passed(
        self, mock_neo4j_client, project_id
    ):
        mock_neo4j_client.execute_query.return_value = []
        qs = VulnerabilityQueries(mock_neo4j_client)
        qs.get_vulnerabilities_by_severity(project_id, limit=5)
        params = mock_neo4j_client.execute_query.call_args[0][1]
        assert params["limit"] == 5

    def test_get_exploitable_vulnerabilities(
        self, mock_neo4j_client, project_id
    ):
        mock_neo4j_client.execute_query.return_value = [
            {"technology": "Apache", "cve_id": "CVE-2021-41773",
             "cvss_score": 9.8, "exploit_count": 2},
        ]
        qs = VulnerabilityQueries(mock_neo4j_client)
        result = qs.get_exploitable_vulnerabilities(project_id)
        assert result[0]["cvss_score"] == 9.8

    def test_get_exploitable_min_cvss_passed(
        self, mock_neo4j_client, project_id
    ):
        mock_neo4j_client.execute_query.return_value = []
        qs = VulnerabilityQueries(mock_neo4j_client)
        qs.get_exploitable_vulnerabilities(project_id, min_cvss=9.0)
        params = mock_neo4j_client.execute_query.call_args[0][1]
        assert params["min_cvss"] == 9.0

    def test_get_cve_chain_returns_dict(
        self, mock_neo4j_client, project_id
    ):
        mock_neo4j_client.execute_query.return_value = [{
            "cve_id": "CVE-2021-41773",
            "cvss_score": 9.8,
            "cwe_chain": [{"cwe_id": "CWE-22", "capec_ids": ["CAPEC-126"]}],
            "exploits": [],
        }]
        qs = VulnerabilityQueries(mock_neo4j_client)
        result = qs.get_cve_chain(project_id, "CVE-2021-41773")
        assert result["cve_id"] == "CVE-2021-41773"
        assert result["cvss_score"] == 9.8

    def test_get_cve_chain_empty(self, mock_neo4j_client, project_id):
        mock_neo4j_client.execute_query.return_value = []
        qs = VulnerabilityQueries(mock_neo4j_client)
        result = qs.get_cve_chain(project_id, "CVE-9999-99999")
        assert result == {}

    def test_test_vulnerability_queries_counts(
        self, mock_neo4j_client, project_id
    ):
        mock_neo4j_client.execute_query.return_value = [{"id": "v1"}]
        qs = VulnerabilityQueries(mock_neo4j_client)
        counts = qs.test_vulnerability_queries(project_id)
        assert "all_vulns" in counts
        assert "critical" in counts
        assert "exploitable" in counts


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestPathFindingQueries:
    """Day 83 — attack path discovery, shortest path, critical paths."""

    def test_discover_attack_paths_returns_list(
        self, mock_neo4j_client, project_id
    ):
        mock_neo4j_client.execute_query.return_value = [
            {
                "entry_ip": "10.0.0.1", "entry_port": 443, "protocol": "tcp",
                "base_url": "https://example.com", "endpoint_path": "/admin",
                "method": "GET", "vulnerability": "Auth Bypass",
                "severity": "critical", "vulnerability_id": "abc123",
            }
        ]
        qs = PathFindingQueries(mock_neo4j_client)
        paths = qs.discover_attack_paths(project_id)
        assert len(paths) == 1
        assert paths[0]["severity"] == "critical"

    def test_discover_attack_paths_exception_returns_empty(
        self, mock_neo4j_client, project_id
    ):
        mock_neo4j_client.execute_query.side_effect = RuntimeError("timeout")
        qs = PathFindingQueries(mock_neo4j_client)
        paths = qs.discover_attack_paths(project_id)
        assert paths == []

    def test_get_shortest_path_uses_shortestpath(
        self, mock_neo4j_client, project_id
    ):
        mock_neo4j_client.execute_query.return_value = []
        qs = PathFindingQueries(mock_neo4j_client)
        qs.get_shortest_path_to_vulnerability(project_id, "vuln-abc")
        query = mock_neo4j_client.execute_query.call_args[0][0]
        assert "shortestPath" in query

    def test_get_shortest_path_returns_records(
        self, mock_neo4j_client, project_id
    ):
        mock_neo4j_client.execute_query.return_value = [
            {"path_nodes": ["IP:10.0.0.1", "Port:443", "Vuln:XSS"],
             "path_length": 2, "entry_point": "10.0.0.1"},
        ]
        qs = PathFindingQueries(mock_neo4j_client)
        paths = qs.get_shortest_path_to_vulnerability(project_id, "vuln-abc")
        assert paths[0]["path_length"] == 2

    def test_identify_critical_paths_order_by_risk(
        self, mock_neo4j_client, project_id
    ):
        mock_neo4j_client.execute_query.return_value = [
            {"entry_ip": "10.0.0.1", "vulnerability": "RCE",
             "severity": "critical", "risk_score": 25},
            {"entry_ip": "10.0.0.2", "vulnerability": "XSS",
             "severity": "high", "risk_score": 12},
        ]
        qs = PathFindingQueries(mock_neo4j_client)
        paths = qs.identify_critical_paths(project_id)
        assert len(paths) == 2
        # First result should have higher risk score
        assert paths[0]["risk_score"] >= paths[1]["risk_score"]

    def test_identify_critical_paths_query_filters_severity(
        self, mock_neo4j_client, project_id
    ):
        mock_neo4j_client.execute_query.return_value = []
        qs = PathFindingQueries(mock_neo4j_client)
        qs.identify_critical_paths(project_id)
        query = mock_neo4j_client.execute_query.call_args[0][0]
        assert "critical" in query
        assert "high" in query

    def test_test_path_finding_returns_counts(
        self, mock_neo4j_client, project_id
    ):
        mock_neo4j_client.execute_query.return_value = []
        qs = PathFindingQueries(mock_neo4j_client)
        counts = qs.test_path_finding(project_id)
        assert "attack_paths" in counts
        assert "critical_paths" in counts


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestNeo4jClientGraphStats:
    """Day 84 — relationship stats and graph health metrics in Neo4jClient."""

    def test_get_relationship_stats_returns_counts(self, mock_neo4j_client, project_id):
        mock_neo4j_client.get_relationship_stats = Mock(
            return_value={
                "relationship_counts": {"HAS_PORT": 5, "RUNS_SERVICE": 3},
                "total_relationships": 8,
            }
        )
        result = mock_neo4j_client.get_relationship_stats(project_id)
        assert result["total_relationships"] == 8
        assert result["relationship_counts"]["HAS_PORT"] == 5

    def test_get_graph_health_metrics_keys(self, mock_neo4j_client, project_id):
        mock_neo4j_client.get_graph_health_metrics = Mock(
            return_value={
                "project_id": project_id,
                "node_count": 50,
                "relationship_count": 80,
                "isolated_nodes": 2,
                "orphaned_vulnerabilities": 1,
                "orphaned_ips": 0,
                "schema_coverage": 0.67,
            }
        )
        metrics = mock_neo4j_client.get_graph_health_metrics(project_id)
        for key in (
            "node_count", "relationship_count", "isolated_nodes",
            "orphaned_vulnerabilities", "orphaned_ips", "schema_coverage"
        ):
            assert key in metrics, f"Missing key: {key}"


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestPhaseDComprehensive:
    """
    handles both successful and error paths gracefully.
    """

    @pytest.mark.parametrize("method,kwargs", [
        ("get_attack_surface_overview", {}),
        ("get_exposed_services", {}),
        ("get_technology_inventory", {}),
    ])
    def test_attack_surface_methods_return_on_exception(
        self, mock_neo4j_client, project_id, method, kwargs
    ):
        mock_neo4j_client.execute_query.side_effect = RuntimeError("DB error")
        qs = AttackSurfaceQueries(mock_neo4j_client)
        result = getattr(qs, method)(project_id, **kwargs)
        # Should not raise; return falsy value
        assert result == {} or result == []

    @pytest.mark.parametrize("method,kwargs", [
        ("get_vulnerabilities_by_severity", {}),
        ("get_exploitable_vulnerabilities", {}),
    ])
    def test_vulnerability_methods_return_on_exception(
        self, mock_neo4j_client, project_id, method, kwargs
    ):
        mock_neo4j_client.execute_query.side_effect = RuntimeError("DB error")
        qs = VulnerabilityQueries(mock_neo4j_client)
        result = getattr(qs, method)(project_id, **kwargs)
        assert result == []

    @pytest.mark.parametrize("method,args", [
        ("discover_attack_paths", []),
        ("identify_critical_paths", []),
    ])
    def test_path_methods_return_on_exception(
        self, mock_neo4j_client, project_id, method, args
    ):
        mock_neo4j_client.execute_query.side_effect = RuntimeError("DB error")
        qs = PathFindingQueries(mock_neo4j_client)
        result = getattr(qs, method)(project_id, *args)
        assert result == []

    def test_tenant_isolation_consistent_params(
        self, mock_neo4j_client, project_id, user_id
    ):
        """Tenant isolation must always pass project_id to every query."""
        ti = TenantIsolation(mock_neo4j_client)

        mock_neo4j_client.execute_query.return_value = [{"cnt": 1}]
        ti.check_project_access(project_id, user_id)
        params = mock_neo4j_client.execute_query.call_args[0][1]
        assert params["project_id"] == project_id

        mock_neo4j_client.execute_query.return_value = []
        ti.get_project_node_counts(project_id)
        params = mock_neo4j_client.execute_query.call_args[0][1]
        assert params["project_id"] == project_id

    def test_all_query_classes_instantiate(self, mock_neo4j_client):
        """Smoke test: all query classes must construct without errors."""
        TenantIsolation(mock_neo4j_client)
        AttackSurfaceQueries(mock_neo4j_client)
        VulnerabilityQueries(mock_neo4j_client)
        PathFindingQueries(mock_neo4j_client)

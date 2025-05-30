"""
Graph Query Service — Multi-tenancy & Queries.

Provides:
"""

from typing import Any, Dict, List, Optional
from app.db.neo4j_client import Neo4jClient
import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class TenantIsolation:
    """
    Tenant isolation utilities for enforcing per-user/per-project boundaries
    in all Neo4j queries.
    """

    def __init__(self, client: Neo4jClient):
        self.client = client

    # ── Core isolation helpers ──────────────────────────────────────────────

    def get_tenant_filter(
        self,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        node_alias: str = "n",
    ) -> tuple:
        """
        Build a WHERE clause fragment and parameter dict for tenant filtering.

        Returns:
            (where_clause: str, params: dict)
            where_clause uses AND conditions suitable for appending to an
            existing WHERE or as standalone WHERE.
        """
        conditions: List[str] = []
        params: Dict[str, Any] = {}

        if user_id:
            conditions.append(f"{node_alias}.user_id = $user_id")
            params["user_id"] = user_id
        if project_id:
            conditions.append(f"{node_alias}.project_id = $project_id")
            params["project_id"] = project_id

        where_clause = " AND ".join(conditions) if conditions else "TRUE"
        return where_clause, params

    def check_project_access(
        self,
        project_id: str,
        user_id: str,
    ) -> bool:
        """
        Verify that the given user owns at least one node in the project.

        Args:
            project_id: Project identifier
            user_id: User identifier

        Returns:
            True if the user has data in this project, False otherwise.
        """
        query = """
        MATCH (n {project_id: $project_id, user_id: $user_id})
        RETURN count(n) AS cnt
        LIMIT 1
        """
        try:
            result = self.client.execute_query(
                query, {"project_id": project_id, "user_id": user_id}
            )
            return result[0]["cnt"] > 0 if result else False
        except Exception as e:
            logger.error(f"Access check failed: {e}")
            return False

    def list_user_projects(self, user_id: str) -> List[str]:
        """
        Return all distinct project_ids that belong to a user.

        Args:
            user_id: User identifier

        Returns:
            List of project_id strings
        """
        query = """
        MATCH (n {user_id: $user_id})
        WHERE n.project_id IS NOT NULL
        RETURN DISTINCT n.project_id AS project_id
        ORDER BY project_id
        """
        try:
            result = self.client.execute_query(query, {"user_id": user_id})
            return [r["project_id"] for r in result]
        except Exception as e:
            logger.error(f"list_user_projects failed: {e}")
            return []

    def get_project_node_counts(
        self,
        project_id: str,
        user_id: Optional[str] = None,
    ) -> Dict[str, int]:
        """
        Return per-label node counts for a project (and optionally a user).

        Args:
            project_id: Project identifier
            user_id: Optional user identifier for extra isolation

        Returns:
            Dict mapping node label → count
        """
        params: Dict[str, Any] = {"project_id": project_id}
        user_filter = ""
        if user_id:
            user_filter = "AND n.user_id = $user_id"
            params["user_id"] = user_id

        query = f"""
        MATCH (n {{project_id: $project_id}})
        WHERE TRUE {user_filter}
        WITH labels(n) AS lbls
        UNWIND lbls AS lbl
        RETURN lbl AS label, count(*) AS cnt
        ORDER BY cnt DESC
        """
        try:
            result = self.client.execute_query(query, params)
            return {r["label"]: r["cnt"] for r in result}
        except Exception as e:
            logger.error(f"get_project_node_counts failed: {e}")
            return {}


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class AttackSurfaceQueries:
    """
    Queries for building an attack surface overview of a project.
    """

    def __init__(self, client: Neo4jClient):
        self.client = client

    def get_attack_surface_overview(
        self,
        project_id: str,
        user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Return a comprehensive attack surface summary for a project.

        Traverses the full Domain → Subdomain → IP → Port → Service chain
        and collects all relevant statistics.

        Args:
            project_id: Project identifier
            user_id: Optional user filter

        Returns:
            Dictionary with domains, subdomains, ips, ports, services, endpoints
        """
        params: Dict[str, Any] = {"project_id": project_id}
        user_cond = "AND d.user_id = $user_id" if user_id else ""
        if user_id:
            params["user_id"] = user_id

        query = f"""
        MATCH (d:Domain {{project_id: $project_id}}) {user_cond}
        OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
        OPTIONAL MATCH (s)-[:RESOLVES_TO]->(ip:IP)
        OPTIONAL MATCH (ip)-[:HAS_PORT]->(p:Port)
        OPTIONAL MATCH (p)-[:RUNS_SERVICE]->(srv:Service)
        OPTIONAL MATCH (p)-[:SERVES_URL]->(u:BaseURL)
        OPTIONAL MATCH (u)-[:HAS_ENDPOINT]->(e:Endpoint)
        RETURN
            collect(DISTINCT d.name)  AS domains,
            count(DISTINCT s)         AS subdomain_count,
            count(DISTINCT ip)        AS ip_count,
            count(DISTINCT p)         AS port_count,
            count(DISTINCT srv)       AS service_count,
            count(DISTINCT u)         AS base_url_count,
            count(DISTINCT e)         AS endpoint_count
        """
        try:
            result = self.client.execute_query(query, params)
            return result[0] if result else {}
        except Exception as e:
            logger.error(f"get_attack_surface_overview failed: {e}")
            return {}

    def get_exposed_services(
        self,
        project_id: str,
        user_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        List all publicly exposed services with their host and port details.

        Args:
            project_id: Project identifier
            user_id: Optional user filter

        Returns:
            List of dicts with ip, port, protocol, service_name, version
        """
        params: Dict[str, Any] = {"project_id": project_id}
        user_cond = "AND ip.user_id = $user_id" if user_id else ""
        if user_id:
            params["user_id"] = user_id

        query = f"""
        MATCH (ip:IP {{project_id: $project_id}}) {user_cond}
        MATCH (ip)-[:HAS_PORT]->(p:Port {{state: 'open'}})
        OPTIONAL MATCH (p)-[:RUNS_SERVICE]->(srv:Service)
        RETURN
            ip.address       AS ip,
            p.number         AS port,
            p.protocol       AS protocol,
            srv.name         AS service_name,
            srv.version      AS service_version,
            srv.banner       AS banner
        ORDER BY ip.address, p.number
        """
        try:
            return self.client.execute_query(query, params)
        except Exception as e:
            logger.error(f"get_exposed_services failed: {e}")
            return []

    def get_technology_inventory(
        self,
        project_id: str,
        user_id: Optional[str] = None,
        with_cves: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Build a complete technology inventory for a project.

        Args:
            project_id: Project identifier
            user_id: Optional user filter
            with_cves: When True, includes related CVE identifiers

        Returns:
            List of dicts with tech name, version, categories, cve_count
        """
        params: Dict[str, Any] = {"project_id": project_id}
        user_cond = "AND t.user_id = $user_id" if user_id else ""
        if user_id:
            params["user_id"] = user_id

        if with_cves:
            query = f"""
            MATCH (t:Technology {{project_id: $project_id}}) {user_cond}
            OPTIONAL MATCH (t)-[:HAS_KNOWN_CVE]->(cve:CVE)
            RETURN
                t.name                       AS name,
                t.version                    AS version,
                t.categories                 AS categories,
                t.confidence                 AS confidence,
                count(DISTINCT cve)          AS cve_count,
                collect(DISTINCT cve.cve_id) AS cve_ids
            ORDER BY cve_count DESC, t.name
            """
        else:
            query = f"""
            MATCH (t:Technology {{project_id: $project_id}}) {user_cond}
            RETURN
                t.name       AS name,
                t.version    AS version,
                t.categories AS categories,
                t.confidence AS confidence,
                0            AS cve_count
            ORDER BY t.name
            """
        try:
            return self.client.execute_query(query, params)
        except Exception as e:
            logger.error(f"get_technology_inventory failed: {e}")
            return []

    def test_query_performance(
        self,
        project_id: str,
        user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Run a lightweight timing test for the main traversal queries.

        Returns a dict with query name → approximate row count (no wall-clock
        timing since that requires Neo4j Enterprise / PROFILE EXPLAIN support).
        """
        report: Dict[str, Any] = {}
        overview = self.get_attack_surface_overview(project_id, user_id)
        report["overview_rows"] = 1 if overview else 0

        services = self.get_exposed_services(project_id, user_id)
        report["exposed_services_rows"] = len(services)

        tech = self.get_technology_inventory(project_id, user_id, with_cves=False)
        report["technology_rows"] = len(tech)

        return report


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class VulnerabilityQueries:
    """
    Queries for vulnerability analysis across a project.
    """

    def __init__(self, client: Neo4jClient):
        self.client = client

    def get_vulnerabilities_by_severity(
        self,
        project_id: str,
        severity: Optional[str] = None,
        user_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Return vulnerabilities optionally filtered by severity level.

        Args:
            project_id: Project identifier
            severity: One of 'critical', 'high', 'medium', 'low', 'info'
            user_id: Optional user filter
            limit: Maximum rows to return

        Returns:
            List of vulnerability dicts ordered by severity then discovered_at
        """
        params: Dict[str, Any] = {"project_id": project_id, "limit": limit}
        filters = []
        if user_id:
            filters.append("v.user_id = $user_id")
            params["user_id"] = user_id
        if severity:
            filters.append("v.severity = $severity")
            params["severity"] = severity

        where_clause = ("WHERE " + " AND ".join(filters)) if filters else ""

        query = f"""
        MATCH (v:Vulnerability {{project_id: $project_id}})
        {where_clause}
        OPTIONAL MATCH (v)-[:FOUND_AT]->(e:Endpoint)
        OPTIONAL MATCH (v)-[:AFFECTS_PARAMETER]->(pr:Parameter)
        RETURN
            v.id            AS id,
            v.name          AS name,
            v.severity      AS severity,
            v.category      AS category,
            v.source        AS source,
            v.description   AS description,
            v.discovered_at AS discovered_at,
            e.path          AS endpoint_path,
            collect(DISTINCT pr.name) AS affected_params
        ORDER BY
            CASE v.severity
                WHEN 'critical' THEN 1
                WHEN 'high'     THEN 2
                WHEN 'medium'   THEN 3
                WHEN 'low'      THEN 4
                ELSE 5
            END,
            v.discovered_at DESC
        LIMIT $limit
        """
        try:
            return self.client.execute_query(query, params)
        except Exception as e:
            logger.error(f"get_vulnerabilities_by_severity failed: {e}")
            return []

    def get_exploitable_vulnerabilities(
        self,
        project_id: str,
        user_id: Optional[str] = None,
        min_cvss: float = 7.0,
    ) -> List[Dict[str, Any]]:
        """
        Return vulnerabilities that have known CVEs with CVSS ≥ min_cvss
        or known public exploits, sorted by exploitability.

        Args:
            project_id: Project identifier
            user_id: Optional user filter
            min_cvss: Minimum CVSS score threshold (default 7.0)

        Returns:
            List of vulnerability dicts with CVE and exploit details
        """
        params: Dict[str, Any] = {
            "project_id": project_id,
            "min_cvss": min_cvss,
        }
        user_cond = "AND v.user_id = $user_id" if user_id else ""
        if user_id:
            params["user_id"] = user_id

        query = f"""
        MATCH (t:Technology {{project_id: $project_id}})
        {user_cond.replace('v.', 't.')}
        MATCH (t)-[:HAS_KNOWN_CVE]->(cve:CVE)
        WHERE cve.cvss_score >= $min_cvss
        OPTIONAL MATCH (ex:Exploit)-[:EXPLOITED_CVE]->(cve)
        RETURN
            t.name             AS technology,
            t.version          AS tech_version,
            cve.cve_id         AS cve_id,
            cve.cvss_score     AS cvss_score,
            cve.severity       AS severity,
            cve.description    AS description,
            count(DISTINCT ex) AS exploit_count
        ORDER BY cve.cvss_score DESC
        """
        try:
            return self.client.execute_query(query, params)
        except Exception as e:
            logger.error(f"get_exploitable_vulnerabilities failed: {e}")
            return []

    def get_cve_chain(
        self,
        project_id: str,
        cve_id: str,
        user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Return the full CVE → CWE → CAPEC knowledge chain for a single CVE.

        Args:
            project_id: Project identifier
            cve_id: CVE identifier (e.g. 'CVE-2021-41773')
            user_id: Optional user filter

        Returns:
            Dict with cve, cwe, and capec details
        """
        params: Dict[str, Any] = {"project_id": project_id, "cve_id": cve_id}
        if user_id:
            params["user_id"] = user_id

        query = """
        MATCH (cve:CVE {cve_id: $cve_id})
        OPTIONAL MATCH (cve)-[:HAS_CWE]->(cwe:MitreData)
        OPTIONAL MATCH (cwe)-[:HAS_CAPEC]->(capec:Capec)
        OPTIONAL MATCH (ex:Exploit)-[:EXPLOITED_CVE]->(cve)
        RETURN
            cve.cve_id          AS cve_id,
            cve.cvss_score      AS cvss_score,
            cve.severity        AS cve_severity,
            cve.description     AS cve_description,
            collect(DISTINCT {
                cwe_id:          cwe.cwe_id,
                name:            cwe.name,
                description:     cwe.description,
                capec_ids:       [(cwe)-[:HAS_CAPEC]->(c:Capec) | c.capec_id]
            }) AS cwe_chain,
            collect(DISTINCT {
                exploit_id:   ex.id,
                name:         ex.name,
                type:         ex.type,
                platform:     ex.platform,
                published:    ex.published_date
            }) AS exploits
        """
        try:
            result = self.client.execute_query(query, params)
            return result[0] if result else {}
        except Exception as e:
            logger.error(f"get_cve_chain failed: {e}")
            return {}

    def test_vulnerability_queries(
        self, project_id: str, user_id: Optional[str] = None
    ) -> Dict[str, int]:
        """Run all vulnerability queries and return row counts for smoke-testing."""
        return {
            "all_vulns": len(
                self.get_vulnerabilities_by_severity(project_id, user_id=user_id)
            ),
            "critical": len(
                self.get_vulnerabilities_by_severity(
                    project_id, severity="critical", user_id=user_id
                )
            ),
            "exploitable": len(
                self.get_exploitable_vulnerabilities(
                    project_id, user_id=user_id, min_cvss=0.0
                )
            ),
        }


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class PathFindingQueries:
    """
    Graph traversal queries for discovering attack paths.
    """

    def __init__(self, client: Neo4jClient):
        self.client = client

    def discover_attack_paths(
        self,
        project_id: str,
        user_id: Optional[str] = None,
        max_depth: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Discover potential attack paths from entry points (exposed services/
        endpoints) to high-value targets (vulnerabilities, admin endpoints).

        Uses variable-length path traversal from IP nodes through Port,
        Service, BaseURL, and Endpoint to Vulnerability nodes.

        Args:
            project_id: Project identifier
            user_id: Optional user filter
            max_depth: Maximum path length to explore (default 5)

        Returns:
            List of discovered path records
        """
        params: Dict[str, Any] = {
            "project_id": project_id,
            "max_depth": max_depth,
        }
        user_cond = "AND ip.user_id = $user_id" if user_id else ""
        if user_id:
            params["user_id"] = user_id

        query = f"""
        MATCH (ip:IP {{project_id: $project_id}}) {user_cond}
        MATCH (ip)-[:HAS_PORT]->(p:Port {{state: 'open'}})
        MATCH (p)-[:SERVES_URL]->(u:BaseURL)
        MATCH (u)-[:HAS_ENDPOINT]->(e:Endpoint)
        MATCH (v:Vulnerability {{project_id: $project_id}})-[:FOUND_AT]->(e)
        RETURN
            ip.address    AS entry_ip,
            p.number      AS entry_port,
            p.protocol    AS protocol,
            u.url         AS base_url,
            e.path        AS endpoint_path,
            e.method      AS method,
            v.name        AS vulnerability,
            v.severity    AS severity,
            v.id          AS vulnerability_id
        ORDER BY
            CASE v.severity
                WHEN 'critical' THEN 1
                WHEN 'high'     THEN 2
                WHEN 'medium'   THEN 3
                ELSE 4
            END
        """
        try:
            return self.client.execute_query(query, params)
        except Exception as e:
            logger.error(f"discover_attack_paths failed: {e}")
            return []

    def get_shortest_path_to_vulnerability(
        self,
        project_id: str,
        vulnerability_id: str,
        user_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Find the shortest path(s) from any IP node to a specific vulnerability.

        Uses Cypher's shortestPath() to locate the minimum-hop attack route.

        Args:
            project_id: Project identifier
            vulnerability_id: Vulnerability node ID (MD5 hash)
            user_id: Optional user filter

        Returns:
            List of path records (each includes nodes and relationships)
        """
        params: Dict[str, Any] = {
            "project_id": project_id,
            "vuln_id": vulnerability_id,
        }
        user_cond = "AND ip.user_id = $user_id" if user_id else ""
        if user_id:
            params["user_id"] = user_id

        query = f"""
        MATCH (ip:IP {{project_id: $project_id}}) {user_cond}
        MATCH (v:Vulnerability {{id: $vuln_id}})
        MATCH path = shortestPath((ip)-[*1..8]->(v))
        RETURN
            [node IN nodes(path) | labels(node)[0] + ':' +
              COALESCE(node.name, node.address, node.url, node.id, '')
            ]   AS path_nodes,
            length(path) AS path_length,
            ip.address   AS entry_point
        ORDER BY path_length
        LIMIT 5
        """
        try:
            return self.client.execute_query(query, params)
        except Exception as e:
            logger.error(f"get_shortest_path_to_vulnerability failed: {e}")
            return []

    def identify_critical_paths(
        self,
        project_id: str,
        user_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Identify the most critical attack paths — those passing through
        high/critical severity vulnerabilities reachable from external IPs.

        Returns paths scored by:
          - Vulnerability severity (critical > high > …)
          - CVSS score of associated CVEs
          - Number of exploits available

        Args:
            project_id: Project identifier
            user_id: Optional user filter

        Returns:
            List of critical path records with risk scores
        """
        params: Dict[str, Any] = {"project_id": project_id}
        user_cond = "AND ip.user_id = $user_id" if user_id else ""
        if user_id:
            params["user_id"] = user_id

        query = f"""
        MATCH (ip:IP {{project_id: $project_id}}) {user_cond}
        MATCH (ip)-[:HAS_PORT]->(p:Port {{state: 'open'}})
        MATCH (p)-[:SERVES_URL]->(u:BaseURL)
        MATCH (u)-[:HAS_ENDPOINT]->(e:Endpoint)
        MATCH (v:Vulnerability {{project_id: $project_id}})-[:FOUND_AT]->(e)
        WHERE v.severity IN ['critical', 'high']
        OPTIONAL MATCH (tech:Technology)-[:HAS_KNOWN_CVE]->(cve:CVE)
        WHERE cve.cvss_score IS NOT NULL
        OPTIONAL MATCH (ex:Exploit)-[:EXPLOITED_CVE]->(cve)
        RETURN
            ip.address            AS entry_ip,
            p.number              AS port,
            u.url                 AS base_url,
            e.path                AS endpoint,
            v.name                AS vulnerability,
            v.severity            AS severity,
            max(cve.cvss_score)   AS max_cvss,
            count(DISTINCT ex)    AS exploit_count,
            (CASE v.severity WHEN 'critical' THEN 10 ELSE 7 END
             + coalesce(max(cve.cvss_score), 0)
             + count(DISTINCT ex)) AS risk_score
        ORDER BY risk_score DESC
        LIMIT 20
        """
        try:
            return self.client.execute_query(query, params)
        except Exception as e:
            logger.error(f"identify_critical_paths failed: {e}")
            return []

    def test_path_finding(
        self,
        project_id: str,
        user_id: Optional[str] = None,
    ) -> Dict[str, int]:
        """Run all path-finding queries and return row counts for smoke-testing."""
        return {
            "attack_paths": len(
                self.discover_attack_paths(project_id, user_id=user_id)
            ),
            "critical_paths": len(
                self.identify_critical_paths(project_id, user_id=user_id)
            ),
        }

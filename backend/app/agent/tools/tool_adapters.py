"""
Tool Adapters.

Provides thin adapter layer over existing MCP/tool implementations:
"""

from __future__ import annotations

import logging
from typing import Any, List, Optional

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import (
    ToolExecutionError,
    truncate_output,
    with_timeout,
)

logger = logging.getLogger(__name__)


# ===========================================================================
# ===========================================================================


class DomainDiscoveryTool(BaseTool):
    """
    Adapter for domain/subdomain discovery.

    Wraps the Naabu/httpx-based recon pipeline to expose a simple interface:
    given a root domain, return all discovered subdomains.

    In production this would delegate to the MCP recon server; in the current
    codebase it calls through the existing NaabuTool / httpx patterns.
    """

    def __init__(self, server_url: str = "http://kali-tools:8000"):
        self._server_url = server_url
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="domain_discovery",
            description=(
                "Discover subdomains for a root domain using passive and active "
                "enumeration. Returns a list of live subdomains with their resolved IPs."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Root domain to enumerate (e.g. 'example.com')",
                    },
                    "passive_only": {
                        "type": "boolean",
                        "description": "Use only passive sources (no DNS brute-force). Default: true",
                        "default": True,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds per DNS lookup. Default: 5",
                        "default": 5,
                    },
                },
                "required": ["domain"],
            },
        )

    @with_timeout(120)
    async def execute(
        self,
        domain: str,
        passive_only: bool = True,
        timeout: int = 5,
        **kwargs: Any,
    ) -> str:
        """
        Discover subdomains for *domain*.

        Args:
            domain: Root domain to enumerate
            passive_only: Use only passive sources
            timeout: Per-lookup timeout in seconds

        Returns:
            Formatted list of discovered subdomains
        """
        try:
            from app.mcp.base_server import MCPClient

            client = MCPClient(self._server_url)
            result = await client.call_tool(
                "discover_subdomains",
                {"domain": domain, "passive_only": passive_only, "timeout": timeout},
            )

            if not result.get("success"):
                return f"Domain discovery failed: {result.get('error', 'Unknown error')}"

            subdomains: List[str] = result.get("subdomains", [])
            if not subdomains:
                return f"No subdomains found for {domain}"

            output = f"Discovered {len(subdomains)} subdomains for {domain}:\n"
            for sub in subdomains:
                output += f"  - {sub}\n"
            return truncate_output(output)

        except Exception as e:
            logger.error(f"DomainDiscoveryTool error: {e}", exc_info=True)
            raise ToolExecutionError(
                f"Domain discovery failed: {e}", tool_name="domain_discovery"
            ) from e


class PortScanTool(BaseTool):
    """
    Adapter for port scanning.

    Wraps the existing NaabuTool with a richer interface: supports top-N
    port selection, protocol filtering, and returns structured results.
    """

    def __init__(self, server_url: str = "http://kali-tools:8000"):
        self._server_url = server_url
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="port_scan",
            description=(
                "Scan a host for open TCP/UDP ports using Naabu. "
                "Returns open ports with service banners where available."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address, hostname, or CIDR range",
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port spec: 'top-100', '1-65535', '80,443,8080'. Default: 'top-100'",
                        "default": "top-100",
                    },
                    "rate": {
                        "type": "integer",
                        "description": "Packets per second (stealth: 100, fast: 1000). Default: 500",
                        "default": 500,
                    },
                },
                "required": ["target"],
            },
        )

    @with_timeout(180)
    async def execute(
        self,
        target: str,
        ports: str = "top-100",
        rate: int = 500,
        **kwargs: Any,
    ) -> str:
        """
        Scan *target* for open ports.

        Args:
            target: Host, IP, or CIDR to scan
            ports: Port specification
            rate: Scan rate in packets per second

        Returns:
            Formatted list of open ports
        """
        try:
            from app.mcp.base_server import MCPClient

            client = MCPClient(self._server_url)
            result = await client.call_tool(
                "execute_naabu",
                {"target": target, "ports": ports, "rate": rate},
            )

            if not result.get("success"):
                return f"Port scan failed: {result.get('error', 'Unknown error')}"

            open_ports = result.get("ports", [])
            if not open_ports:
                return f"No open ports found on {target}"

            output = f"Port scan results for {target} ({ports}):\n"
            for p in open_ports:
                port_num = p.get("port", "?")
                proto = p.get("protocol", "tcp")
                svc = p.get("service", "")
                banner = p.get("banner", "")
                line = f"  {port_num}/{proto} open"
                if svc:
                    line += f"  {svc}"
                if banner:
                    line += f"  ({banner[:60]})"
                output += line + "\n"
            return truncate_output(output)

        except Exception as e:
            logger.error(f"PortScanTool error: {e}", exc_info=True)
            raise ToolExecutionError(
                f"Port scan failed: {e}", tool_name="port_scan"
            ) from e


# ===========================================================================
# ===========================================================================


class HttpProbeTool(BaseTool):
    """
    Adapter for HTTP/HTTPS probing.

    Sends HTTP requests to a target URL and returns response metadata:
    status code, headers, redirect chain, server information.
    """

    def __init__(self, server_url: str = "http://kali-tools:8001"):
        self._server_url = server_url
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="http_probe",
            description=(
                "Probe an HTTP/HTTPS target. Returns status code, headers, "
                "redirect chain, title, and server info."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL to probe (e.g. 'https://example.com')",
                    },
                    "follow_redirects": {
                        "type": "boolean",
                        "description": "Follow HTTP redirects. Default: true",
                        "default": True,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Request timeout in seconds. Default: 10",
                        "default": 10,
                    },
                    "headers": {
                        "type": "object",
                        "description": "Optional extra request headers",
                    },
                },
                "required": ["url"],
            },
        )

    @with_timeout(30)
    async def execute(
        self,
        url: str,
        follow_redirects: bool = True,
        timeout: int = 10,
        headers: Optional[dict] = None,
        **kwargs: Any,
    ) -> str:
        try:
            from app.mcp.base_server import MCPClient

            client = MCPClient(self._server_url)
            result = await client.call_tool(
                "http_probe",
                {
                    "url": url,
                    "follow_redirects": follow_redirects,
                    "timeout": timeout,
                    "headers": headers or {},
                },
            )

            if not result.get("success"):
                return f"HTTP probe failed: {result.get('error', 'Unknown error')}"

            status = result.get("status_code", "?")
            title = result.get("title", "")
            server = result.get("server", "")
            tech = result.get("technologies", [])
            redirects = result.get("redirects", [])

            output = f"HTTP probe for {url}:\n"
            output += f"  Status: {status}\n"
            if title:
                output += f"  Title: {title}\n"
            if server:
                output += f"  Server: {server}\n"
            if tech:
                output += f"  Technologies: {', '.join(tech)}\n"
            if redirects:
                output += f"  Redirects: {' -> '.join(redirects)}\n"
            return output

        except Exception as e:
            logger.error(f"HttpProbeTool error: {e}", exc_info=True)
            raise ToolExecutionError(
                f"HTTP probe failed: {e}", tool_name="http_probe"
            ) from e


class TechDetectionTool(BaseTool):
    """
    Adapter for web technology detection (Wappalyzer-style fingerprinting).
    """

    def __init__(self, server_url: str = "http://kali-tools:8001"):
        self._server_url = server_url
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="tech_detection",
            description=(
                "Detect web technologies running on a URL using fingerprinting. "
                "Returns CMS, frameworks, libraries, and server software with versions."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL to fingerprint",
                    },
                    "deep_scan": {
                        "type": "boolean",
                        "description": "Fetch multiple pages for deeper fingerprinting. Default: false",
                        "default": False,
                    },
                },
                "required": ["url"],
            },
        )

    @with_timeout(60)
    async def execute(
        self,
        url: str,
        deep_scan: bool = False,
        **kwargs: Any,
    ) -> str:
        try:
            from app.mcp.base_server import MCPClient

            client = MCPClient(self._server_url)
            result = await client.call_tool(
                "detect_technologies",
                {"url": url, "deep_scan": deep_scan},
            )

            if not result.get("success"):
                return f"Technology detection failed: {result.get('error', 'Unknown error')}"

            technologies = result.get("technologies", [])
            if not technologies:
                return f"No technologies detected for {url}"

            output = f"Technologies detected on {url}:\n"
            for tech in technologies:
                name = tech.get("name", "unknown")
                version = tech.get("version", "")
                categories = tech.get("categories", [])
                confidence = tech.get("confidence", 0)
                line = f"  - {name}"
                if version:
                    line += f" v{version}"
                if categories:
                    line += f"  [{', '.join(categories)}]"
                if confidence:
                    line += f"  (confidence: {confidence}%)"
                output += line + "\n"
            return output

        except Exception as e:
            logger.error(f"TechDetectionTool error: {e}", exc_info=True)
            raise ToolExecutionError(
                f"Tech detection failed: {e}", tool_name="tech_detection"
            ) from e


class EndpointEnumerationTool(BaseTool):
    """
    Adapter for web endpoint enumeration (directory/file brute-force + crawl).
    """

    def __init__(self, server_url: str = "http://kali-tools:8001"):
        self._server_url = server_url
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="endpoint_enumeration",
            description=(
                "Enumerate endpoints on a web target using crawling and/or "
                "wordlist-based discovery. Returns path, status, content-type, and size."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Base URL to enumerate (e.g. 'https://example.com')",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Wordlist name: 'small' (1k), 'medium' (10k), 'large' (100k). Default: 'small'",
                        "default": "small",
                    },
                    "crawl": {
                        "type": "boolean",
                        "description": "Also crawl discovered pages. Default: true",
                        "default": True,
                    },
                    "extensions": {
                        "type": "array",
                        "description": "File extensions to probe (e.g. ['php', 'asp', 'txt'])",
                        "items": {"type": "string"},
                    },
                },
                "required": ["url"],
            },
        )

    @with_timeout(300)
    async def execute(
        self,
        url: str,
        wordlist: str = "small",
        crawl: bool = True,
        extensions: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> str:
        try:
            from app.mcp.base_server import MCPClient

            client = MCPClient(self._server_url)
            result = await client.call_tool(
                "enumerate_endpoints",
                {
                    "url": url,
                    "wordlist": wordlist,
                    "crawl": crawl,
                    "extensions": extensions or [],
                },
            )

            if not result.get("success"):
                return f"Endpoint enumeration failed: {result.get('error', 'Unknown error')}"

            endpoints = result.get("endpoints", [])
            if not endpoints:
                return f"No endpoints discovered on {url}"

            output = f"Endpoints discovered on {url} ({len(endpoints)} total):\n"
            for ep in endpoints[:50]:  # show first 50
                path = ep.get("path", "")
                status = ep.get("status_code", "")
                size = ep.get("content_length", "")
                ct = ep.get("content_type", "")
                output += f"  {status}  {path}  [{size}b]  {ct}\n"
            if len(endpoints) > 50:
                output += f"\n  ... and {len(endpoints) - 50} more endpoints\n"
            return truncate_output(output)

        except Exception as e:
            logger.error(f"EndpointEnumerationTool error: {e}", exc_info=True)
            raise ToolExecutionError(
                f"Endpoint enumeration failed: {e}", tool_name="endpoint_enumeration"
            ) from e


# ===========================================================================
# ===========================================================================


class NucleiTemplateSelectTool(BaseTool):
    """
    Selects the most relevant Nuclei templates for a given target context.

    Given technology names, CVE IDs, or tags, returns a curated list of
    Nuclei template paths/IDs ready to feed into NucleiScanTool.
    """

    # Curated template-selection logic (no external call needed)
    _CATEGORY_MAP = {
        "wordpress": ["wordpress", "cms"],
        "apache": ["apache", "http"],
        "nginx": ["nginx", "http"],
        "iis": ["iis", "http"],
        "tomcat": ["tomcat", "java"],
        "jira": ["jira", "atlassian"],
        "confluence": ["confluence", "atlassian"],
        "jenkins": ["jenkins", "ci-cd"],
        "phpmyadmin": ["phpmyadmin", "database"],
        "mysql": ["mysql", "database"],
        "postgres": ["postgresql", "database"],
        "redis": ["redis", "database"],
        "mongodb": ["mongodb", "database"],
        "elasticsearch": ["elasticsearch", "database"],
        "spring": ["spring", "java"],
        "struts": ["struts", "java"],
        "drupal": ["drupal", "cms"],
        "joomla": ["joomla", "cms"],
        "laravel": ["laravel", "php"],
    }

    def __init__(self):
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="nuclei_template_select",
            description=(
                "Select appropriate Nuclei vulnerability templates for a target. "
                "Provide technology names, CVE IDs, or tag keywords. "
                "Returns a list of template tags/paths to use with nuclei_scan."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "technologies": {
                        "type": "array",
                        "description": "Detected technology names (e.g. ['Apache', 'WordPress'])",
                        "items": {"type": "string"},
                    },
                    "cve_ids": {
                        "type": "array",
                        "description": "Specific CVE IDs to find templates for",
                        "items": {"type": "string"},
                    },
                    "tags": {
                        "type": "array",
                        "description": "Additional Nuclei tag filters (e.g. ['sqli', 'xss', 'rce'])",
                        "items": {"type": "string"},
                    },
                    "severity": {
                        "type": "array",
                        "description": "Severity filter: ['critical','high','medium','low','info']",
                        "items": {"type": "string"},
                        "default": ["critical", "high", "medium"],
                    },
                },
                "required": [],
            },
        )

    async def execute(
        self,
        technologies: Optional[List[str]] = None,
        cve_ids: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        severity: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> str:
        """
        Select Nuclei templates based on context.

        Returns a formatted recommendation of template tags/paths.
        """
        selected_tags: list = list(tags or [])
        severity_filter = severity or ["critical", "high", "medium"]

        # Add tags from technology map
        for tech in technologies or []:
            tech_lower = tech.lower()
            for key, mapped_tags in self._CATEGORY_MAP.items():
                if key in tech_lower:
                    selected_tags.extend(mapped_tags)

        # Add CVE-specific templates
        cve_templates: list = []
        for cve in cve_ids or []:
            cve_templates.append(cve.lower())  # nuclei -t cves/YYYY/CVE-YYYY-XXXXX.yaml

        # Deduplicate
        selected_tags = list(dict.fromkeys(selected_tags))

        if not selected_tags and not cve_templates:
            return (
                "No specific templates identified. Recommend running generic scan:\n"
                "  Tags: http, misconfig, exposure\n"
                "  Severity: " + ", ".join(severity_filter)
            )

        output = "Recommended Nuclei templates:\n"
        if cve_templates:
            output += f"  CVE templates: {', '.join(cve_templates)}\n"
        if selected_tags:
            output += f"  Technology tags: {', '.join(selected_tags)}\n"
        output += f"  Severity filter: {', '.join(severity_filter)}\n"
        output += "\nUsage: nuclei_scan with tags=" + str(selected_tags[:10])
        return output


class NucleiScanTool(BaseTool):
    """
    Adapter for Nuclei vulnerability scanning.

    Wraps the existing NucleiTool from mcp_tools.py with a richer interface:
    template selection by tags/severity, output parsing, and summary.
    """

    def __init__(self, server_url: str = "http://kali-tools:8002"):
        self._server_url = server_url
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="nuclei_scan",
            description=(
                "Run Nuclei vulnerability scanner against a target. "
                "Supports template tags, CVE-specific templates, and severity filters."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target URL or host to scan",
                    },
                    "tags": {
                        "type": "array",
                        "description": "Nuclei template tags (e.g. ['cve', 'sqli', 'xss'])",
                        "items": {"type": "string"},
                    },
                    "templates": {
                        "type": "array",
                        "description": "Specific template paths (e.g. ['cves/2021/CVE-2021-41773.yaml'])",
                        "items": {"type": "string"},
                    },
                    "severity": {
                        "type": "array",
                        "description": "Severity filter: critical, high, medium, low, info",
                        "items": {"type": "string"},
                        "default": ["critical", "high"],
                    },
                    "rate_limit": {
                        "type": "integer",
                        "description": "Max requests per second. Default: 150",
                        "default": 150,
                    },
                },
                "required": ["target"],
            },
        )

    @with_timeout(600)
    async def execute(
        self,
        target: str,
        tags: Optional[List[str]] = None,
        templates: Optional[List[str]] = None,
        severity: Optional[List[str]] = None,
        rate_limit: int = 150,
        **kwargs: Any,
    ) -> str:
        try:
            from app.mcp.base_server import MCPClient

            client = MCPClient(self._server_url)
            result = await client.call_tool(
                "execute_nuclei",
                {
                    "target": target,
                    "tags": tags or [],
                    "templates": templates or [],
                    "severity": severity or ["critical", "high"],
                    "rate_limit": rate_limit,
                },
            )

            if not result.get("success"):
                return f"Nuclei scan failed: {result.get('error', 'Unknown error')}"

            findings = result.get("findings", [])
            if not findings:
                return f"No vulnerabilities found on {target} with given templates/tags."

            output = f"Nuclei scan results for {target} — {len(findings)} finding(s):\n\n"
            for finding in findings:
                name = finding.get("name", "Unknown")
                sev = finding.get("severity", "info")
                matched = finding.get("matched_at", "")
                template_id = finding.get("template_id", "")
                output += f"  [{sev.upper()}] {name}\n"
                if template_id:
                    output += f"    Template: {template_id}\n"
                if matched:
                    output += f"    Matched: {matched}\n"
                output += "\n"
            return truncate_output(output)

        except Exception as e:
            logger.error(f"NucleiScanTool error: {e}", exc_info=True)
            raise ToolExecutionError(
                f"Nuclei scan failed: {e}", tool_name="nuclei_scan"
            ) from e


# ===========================================================================
# ===========================================================================


class AttackSurfaceQueryTool(BaseTool):
    """
    High-level adapter for querying the attack surface graph.

    Provides natural-language-to-query shortcuts for the most common
    attack surface analysis questions, backed by graph_queries.AttackSurfaceQueries.
    """

    def __init__(
        self,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
    ):
        self.user_id = user_id
        self.project_id = project_id
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="attack_surface_query",
            description=(
                "Query the attack surface graph for a project. "
                "Supports: 'overview', 'services', 'technologies', 'domains'."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "query_type": {
                        "type": "string",
                        "description": "Query to run: 'overview', 'services', 'technologies', 'domains'",
                        "enum": ["overview", "services", "technologies", "domains"],
                    },
                    "project_id": {
                        "type": "string",
                        "description": "Project ID to query (overrides instance default)",
                    },
                    "with_cves": {
                        "type": "boolean",
                        "description": "Include CVE data in technology results. Default: true",
                        "default": True,
                    },
                },
                "required": ["query_type"],
            },
        )

    async def execute(
        self,
        query_type: str,
        project_id: Optional[str] = None,
        with_cves: bool = True,
        **kwargs: Any,
    ) -> str:
        pid = project_id or self.project_id
        if not pid:
            return "Error: project_id is required. Pass it as a parameter or set it on the tool."

        try:
            from app.db.neo4j_client import get_neo4j_client
            from app.graph.graph_queries import AttackSurfaceQueries

            client = get_neo4j_client()
            qs = AttackSurfaceQueries(client)

            if query_type == "overview":
                data = qs.get_attack_surface_overview(pid, user_id=self.user_id)
                if not data:
                    return f"No attack surface data found for project {pid}."
                output = f"Attack surface overview for {pid}:\n"
                for key, val in data.items():
                    output += f"  {key}: {val}\n"
                return output

            elif query_type == "services":
                services = qs.get_exposed_services(pid, user_id=self.user_id)
                if not services:
                    return f"No exposed services found for project {pid}."
                output = f"Exposed services for {pid} ({len(services)} total):\n"
                for svc in services:
                    output += (
                        f"  {svc.get('ip')}:{svc.get('port')}/{svc.get('protocol')}  "
                        f"{svc.get('service_name', '')}  {svc.get('service_version', '')}\n"
                    )
                return truncate_output(output)

            elif query_type == "technologies":
                techs = qs.get_technology_inventory(pid, user_id=self.user_id, with_cves=with_cves)
                if not techs:
                    return f"No technologies found for project {pid}."
                output = f"Technology inventory for {pid} ({len(techs)} entries):\n"
                for t in techs:
                    cve_info = f"  {t.get('cve_count', 0)} CVEs" if with_cves else ""
                    output += (
                        f"  {t.get('name')} {t.get('version', '')}  "
                        f"[{', '.join(t.get('categories') or [])}]{cve_info}\n"
                    )
                return truncate_output(output)

            elif query_type == "domains":
                # Use raw client query for domain listing
                results = client.execute_query(
                    "MATCH (d:Domain {project_id: $pid}) "
                    "OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain) "
                    "RETURN d.name AS domain, count(s) AS subdomains "
                    "ORDER BY subdomains DESC",
                    {"pid": pid},
                )
                if not results:
                    return f"No domains found for project {pid}."
                output = f"Domains for {pid}:\n"
                for row in results:
                    output += f"  {row['domain']}  ({row['subdomains']} subdomains)\n"
                return output

            else:
                return f"Unknown query_type: {query_type}. Valid: overview, services, technologies, domains"

        except Exception as e:
            logger.error(f"AttackSurfaceQueryTool error: {e}", exc_info=True)
            raise ToolExecutionError(
                f"Attack surface query failed: {e}", tool_name="attack_surface_query"
            ) from e


class VulnerabilityLookupTool(BaseTool):
    """
    Adapter for vulnerability lookups against the project graph.

    Supports looking up by severity, listing exploitable vulnerabilities,
    and fetching the full CVE→CWE→CAPEC chain.
    """

    def __init__(
        self,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
    ):
        self.user_id = user_id
        self.project_id = project_id
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="vulnerability_lookup",
            description=(
                "Look up vulnerabilities in the project graph. "
                "Supports: 'by_severity', 'exploitable', 'cve_chain'."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "lookup_type": {
                        "type": "string",
                        "description": "Lookup to perform: 'by_severity', 'exploitable', 'cve_chain'",
                        "enum": ["by_severity", "exploitable", "cve_chain"],
                    },
                    "project_id": {
                        "type": "string",
                        "description": "Project ID (overrides instance default)",
                    },
                    "severity": {
                        "type": "string",
                        "description": "Severity filter for 'by_severity': critical/high/medium/low/info",
                    },
                    "min_cvss": {
                        "type": "number",
                        "description": "Minimum CVSS score for 'exploitable'. Default: 7.0",
                        "default": 7.0,
                    },
                    "cve_id": {
                        "type": "string",
                        "description": "CVE identifier for 'cve_chain' (e.g. 'CVE-2021-41773')",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max results to return. Default: 20",
                        "default": 20,
                    },
                },
                "required": ["lookup_type"],
            },
        )

    async def execute(
        self,
        lookup_type: str,
        project_id: Optional[str] = None,
        severity: Optional[str] = None,
        min_cvss: float = 7.0,
        cve_id: Optional[str] = None,
        limit: int = 20,
        **kwargs: Any,
    ) -> str:
        pid = project_id or self.project_id
        if not pid:
            return "Error: project_id is required."

        try:
            from app.db.neo4j_client import get_neo4j_client
            from app.graph.graph_queries import VulnerabilityQueries

            client = get_neo4j_client()
            qs = VulnerabilityQueries(client)

            if lookup_type == "by_severity":
                vulns = qs.get_vulnerabilities_by_severity(
                    pid, severity=severity, user_id=self.user_id, limit=limit
                )
                if not vulns:
                    label = f" ({severity})" if severity else ""
                    return f"No vulnerabilities{label} found for project {pid}."
                header = f"Vulnerabilities{' [' + severity + ']' if severity else ''} for {pid}:\n"
                output = header
                for v in vulns:
                    output += (
                        f"  [{v.get('severity', '?').upper()}] {v.get('name', 'Unknown')}  "
                        f"@ {v.get('endpoint_path', 'N/A')}\n"
                    )
                return truncate_output(output)

            elif lookup_type == "exploitable":
                vulns = qs.get_exploitable_vulnerabilities(
                    pid, user_id=self.user_id, min_cvss=min_cvss
                )
                if not vulns:
                    return f"No exploitable vulnerabilities (CVSS≥{min_cvss}) found for project {pid}."
                output = f"Exploitable vulnerabilities (CVSS≥{min_cvss}) for {pid}:\n"
                for v in vulns:
                    output += (
                        f"  {v.get('cve_id', 'N/A')}  CVSS:{v.get('cvss_score', '?')}  "
                        f"{v.get('technology', 'Unknown')} {v.get('tech_version', '')}  "
                        f"exploits:{v.get('exploit_count', 0)}\n"
                    )
                return truncate_output(output)

            elif lookup_type == "cve_chain":
                if not cve_id:
                    return "Error: cve_id is required for 'cve_chain' lookup."
                chain = qs.get_cve_chain(pid, cve_id, user_id=self.user_id)
                if not chain:
                    return f"No CVE chain found for {cve_id}."
                output = f"CVE chain for {cve_id}:\n"
                output += f"  CVSS: {chain.get('cvss_score', 'N/A')}\n"
                output += f"  Severity: {chain.get('cve_severity', 'N/A')}\n"
                output += f"  Description: {str(chain.get('cve_description', ''))[:200]}\n"
                cwe_chain = chain.get("cwe_chain", [])
                if cwe_chain:
                    output += f"  CWEs: {', '.join(c.get('cwe_id', '') for c in cwe_chain if c.get('cwe_id'))}\n"
                exploits = chain.get("exploits", [])
                if exploits:
                    output += f"  Exploits: {len(exploits)} known exploit(s)\n"
                return output

            else:
                return f"Unknown lookup_type: {lookup_type}."

        except Exception as e:
            logger.error(f"VulnerabilityLookupTool error: {e}", exc_info=True)
            raise ToolExecutionError(
                f"Vulnerability lookup failed: {e}", tool_name="vulnerability_lookup"
            ) from e


# ===========================================================================
# ===========================================================================


class ExploitSearchTool(BaseTool):
    """
    Adapter for searching public exploit databases and security advisories.

    Wraps WebSearchTool with exploit-specific query formatting and
    result filtering to surface the most actionable exploit information.
    """

    def __init__(self):
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="exploit_search",
            description=(
                "Search for public exploits for a specific technology, CVE, or vulnerability. "
                "Searches Exploit-DB, GitHub, and security advisories."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "What to search for (CVE ID, software name, or vulnerability type)",
                    },
                    "search_type": {
                        "type": "string",
                        "description": "Type of search: 'cve', 'software', 'technique'. Default: 'cve'",
                        "enum": ["cve", "software", "technique"],
                        "default": "cve",
                    },
                    "include_poc": {
                        "type": "boolean",
                        "description": "Include proof-of-concept code links. Default: true",
                        "default": True,
                    },
                },
                "required": ["target"],
            },
        )

    async def execute(
        self,
        target: str,
        search_type: str = "cve",
        include_poc: bool = True,
        **kwargs: Any,
    ) -> str:
        try:
            from app.agent.tools.web_search_tool import WebSearchTool

            search_tool = WebSearchTool()

            # Build exploit-focused query
            if search_type == "cve":
                query = f"{target} exploit proof of concept PoC Exploit-DB GitHub"
            elif search_type == "software":
                query = f"{target} vulnerability exploit public RCE CVE"
            else:
                query = f"{target} technique exploit MITRE ATT&CK"

            if include_poc:
                query += " site:exploit-db.com OR site:github.com OR site:packetstormsecurity.com"

            result = await search_tool.execute(query=query, max_results=8, search_depth="advanced")
            return f"Exploit search results for '{target}':\n\n{result}"

        except Exception as e:
            logger.error(f"ExploitSearchTool error: {e}", exc_info=True)
            raise ToolExecutionError(
                f"Exploit search failed: {e}", tool_name="exploit_search"
            ) from e


class CVELookupTool(BaseTool):
    """
    Adapter for CVE information lookup.

    Combines NVD/Mitre data from the graph (if available) with a
    web search fallback for enriched CVE details.
    """

    def __init__(
        self,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self.project_id = project_id
        self.user_id = user_id
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="cve_lookup",
            description=(
                "Look up detailed information for a CVE ID. "
                "Returns CVSS score, description, affected software, CWE, CAPEC, and exploits."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "CVE identifier (e.g. 'CVE-2021-44228')",
                    },
                    "include_exploits": {
                        "type": "boolean",
                        "description": "Search for public exploits. Default: true",
                        "default": True,
                    },
                },
                "required": ["cve_id"],
            },
        )

    async def execute(
        self,
        cve_id: str,
        include_exploits: bool = True,
        **kwargs: Any,
    ) -> str:
        output_parts: List[str] = []

        # 1. Try graph first (fast, local data)
        if self.project_id:
            try:
                from app.db.neo4j_client import get_neo4j_client
                from app.graph.graph_queries import VulnerabilityQueries

                client = get_neo4j_client()
                qs = VulnerabilityQueries(client)
                chain = qs.get_cve_chain(self.project_id, cve_id, user_id=self.user_id)
                if chain:
                    block = f"[Graph data for {cve_id}]\n"
                    block += f"  CVSS:        {chain.get('cvss_score', 'N/A')}\n"
                    block += f"  Severity:    {chain.get('cve_severity', 'N/A')}\n"
                    block += f"  Description: {str(chain.get('cve_description', ''))[:300]}\n"
                    cwe_chain = chain.get("cwe_chain", [])
                    if cwe_chain:
                        cwe_ids = [c.get("cwe_id") for c in cwe_chain if c.get("cwe_id")]
                        block += f"  CWE(s):      {', '.join(cwe_ids)}\n"
                    exploits = chain.get("exploits", [])
                    if exploits:
                        block += f"  Exploits:    {len(exploits)} known\n"
                    output_parts.append(block)
            except Exception as e:
                logger.debug(f"Graph CVE lookup skipped: {e}")

        # 2. Web search fallback / enrichment
        try:
            from app.agent.tools.web_search_tool import WebSearchTool

            search_tool = WebSearchTool()
            query = f"{cve_id} CVSS score description affected software patch"
            web_result = await search_tool.execute(
                query=query, max_results=5, search_depth="basic"
            )
            output_parts.append(f"[Web enrichment for {cve_id}]\n{web_result}")
        except Exception as e:
            logger.debug(f"Web CVE search skipped: {e}")

        if not output_parts:
            return f"No information found for {cve_id}."

        return truncate_output("\n\n".join(output_parts))

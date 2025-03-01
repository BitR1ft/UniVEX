"""
OSINT Tools — Internet-Wide Search Integration

Implements six agent tools for passive OSINT reconnaissance using internet-wide
search engines and historical data sources:

  ShodanSearchTool       — Full-text search across Shodan's internet-wide scan
                           database, returning matched hosts with open services,
                           banners, CVEs, and geolocation data.
  ShodanHostTool         — Deep lookup of a single IP address in Shodan, returning
                           all open ports, service fingerprints, CVEs, and optionally
                           historical scan data.
  CensysSearchTool       — Query Censys Search API v2 (hosts or certificates index)
                           for assets matching an arbitrary search expression.
  CensysCertSearchTool   — Discover subdomains by searching Censys certificate
                           transparency data and extracting Subject Alternative Names.
  FOFASearchTool         — Query the FOFA cyberspace search engine for internet-wide
                           asset discovery using FOFA query syntax.
  PassiveDNSTool         — Retrieve historical DNS resolution records from
                           SecurityTrails and/or VirusTotal passive DNS databases.

OWASP Mapping: A05:2021-Security Misconfiguration,
               A01:2021-Broken Access Control
MITRE ATT&CK:  T1596.005 (Search Open Technical Databases),
               T1596.001 (Search Open Technical Databases: DNS/Passive DNS)
"""

from __future__ import annotations

import asyncio
import base64
import datetime
import json
import logging
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import (
    ToolExecutionError,
    ToolRateLimitError,
    truncate_output,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared HTTP helper
# ---------------------------------------------------------------------------


def _make_api_request(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 20,
) -> Dict[str, Any]:
    """
    Perform a synchronous GET request and return the parsed JSON response.

    Args:
        url:     Full URL (with query string) to request.
        headers: Optional dict of HTTP request headers.
        timeout: Socket timeout in seconds.

    Returns:
        Parsed JSON body as a Python dict.

    Raises:
        ToolRateLimitError: When the server returns HTTP 429.
        ToolExecutionError: For HTTP 400, 401, 403, or any other failure.
    """
    req = urllib.request.Request(url, headers=headers or {})  # nosec B310
    req.add_header("User-Agent", "UniVex-OSINTTool/1.0")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            raw = resp.read(16 * 1024 * 1024).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read(2048).decode("utf-8", errors="replace")
        except Exception:
            pass
        if exc.code == 429:
            raise ToolRateLimitError(
                f"Rate limit exceeded (HTTP 429). Retry after 60 seconds. Detail: {body}",
                retry_after=60,
            ) from exc
        if exc.code == 401:
            raise ToolExecutionError(
                f"Unauthorized (HTTP 401): invalid or missing API key. Detail: {body}",
                recoverable=False,
            ) from exc
        if exc.code == 403:
            raise ToolExecutionError(
                f"Forbidden (HTTP 403): insufficient permissions. Detail: {body}",
                recoverable=False,
            ) from exc
        if exc.code == 400:
            raise ToolExecutionError(
                f"Bad request (HTTP 400): invalid query or parameters. Detail: {body}",
                recoverable=False,
            ) from exc
        raise ToolExecutionError(
            f"HTTP {exc.code} error from {url}: {body[:300]}",
        ) from exc
    except urllib.error.URLError as exc:
        raise ToolExecutionError(f"Network error contacting {url}: {exc.reason}") from exc
    except Exception as exc:
        raise ToolExecutionError(f"Unexpected error during API request: {exc}") from exc

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ToolExecutionError(
            f"API returned non-JSON response: {exc}. Preview: {raw[:200]}"
        ) from exc


def _validate_ip(ip: str) -> None:
    """
    Validate that *ip* is a syntactically valid IPv4 or IPv6 address.

    Args:
        ip: The IP address string to validate.

    Raises:
        ToolExecutionError: If the string is not a valid IP address.
    """
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, ip)
            return
        except (socket.error, OSError):
            continue
    raise ToolExecutionError(
        f"Invalid IP address: '{ip}'. Provide a valid IPv4 or IPv6 address.",
        recoverable=False,
    )


# ---------------------------------------------------------------------------
# Tool 1 — ShodanSearchTool
# ---------------------------------------------------------------------------


class ShodanSearchTool(BaseTool):
    """
    Search Shodan's internet-wide scan database.

    Executes a Shodan search query and returns matching hosts with their open
    services, banners, organisation, geolocation, and associated CVEs.  Requires
    a valid ``SHODAN_API_KEY`` environment variable.

    Example queries:
        ``apache country:US port:443``
        ``product:nginx version:1.14``
        ``vuln:CVE-2021-44228``
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="shodan_search",
            description=(
                "Search Shodan's internet-wide scan database for hosts matching a "
                "query. Returns open services, banners, CVEs, geolocation, and "
                "organisation data. Requires SHODAN_API_KEY environment variable."
            ),
            parameters={
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": {
                        "type": "string",
                        "description": (
                            "Shodan search query (e.g. 'apache country:US port:443', "
                            "'vuln:CVE-2021-44228', 'product:nginx version:1.14')."
                        ),
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Number of results to return (default 10, max 100).",
                        "default": 10,
                        "minimum": 1,
                        "maximum": 100,
                    },
                    "facets": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Optional list of facets to include in the response "
                            "(e.g. ['country', 'org', 'port'])."
                        ),
                    },
                },
            },
        )

    async def execute(  # type: ignore[override]
        self,
        query: Optional[str] = None,
        limit: int = 10,
        facets: Optional[List[str]] = None,
        **_: Any,
    ) -> str:
        """
        Execute a Shodan search query.

        Args:
            query:  Shodan search query string.
            limit:  Number of results (1–100, default 10).
            facets: Optional list of facet names.

        Returns:
            JSON string with matching hosts and summary statistics.

        Raises:
            ToolExecutionError: If the API key is missing or the query is invalid.
            ToolRateLimitError: If the Shodan API rate limit is exceeded.
        """
        if not query or not query.strip():
            raise ToolExecutionError(
                "Parameter 'query' is required and must not be empty.",
                tool_name=self.name,
                recoverable=False,
            )

        api_key = os.environ.get("SHODAN_API_KEY", "")
        if not api_key:
            raise ToolExecutionError(
                "Shodan API key not configured. Set the SHODAN_API_KEY environment variable. "
                "Obtain a key at https://account.shodan.io/",
                tool_name=self.name,
                recoverable=False,
            )

        limit = max(1, min(int(limit), 100))

        params: Dict[str, str] = {
            "key": api_key,
            "query": query.strip(),
            "minify": "false",
            "page": "1",
        }
        if facets:
            params["facets"] = ",".join(facets)

        url = f"https://api.shodan.io/shodan/host/search?{urllib.parse.urlencode(params)}"
        logger.debug("[shodan_search] querying: %s", query)

        data = await asyncio.to_thread(_make_api_request, url, {}, 25)

        matches: List[Dict[str, Any]] = data.get("matches", [])[:limit]
        formatted: List[Dict[str, Any]] = []
        for host in matches:
            entry: Dict[str, Any] = {
                "ip": host.get("ip_str", ""),
                "port": host.get("port"),
                "org": host.get("org", ""),
                "country": host.get("location", {}).get("country_name", ""),
                "city": host.get("location", {}).get("city", ""),
                "hostnames": host.get("hostnames", []),
                "domains": host.get("domains", []),
                "os": host.get("os"),
                "product": host.get("product", ""),
                "version": host.get("version", ""),
                "banner": (host.get("data", "") or "")[:500],
                "vulns": list(host.get("vulns", {}).keys()),
                "timestamp": host.get("timestamp", ""),
                "transport": host.get("transport", "tcp"),
                "tags": host.get("tags", []),
            }
            formatted.append(entry)

        result: Dict[str, Any] = {
            "query": query,
            "total_results": data.get("total", 0),
            "returned": len(formatted),
            "hosts": formatted,
        }
        if "facets" in data:
            result["facets"] = data["facets"]

        return truncate_output(json.dumps(result, indent=2))


# ---------------------------------------------------------------------------
# Tool 2 — ShodanHostTool
# ---------------------------------------------------------------------------


class ShodanHostTool(BaseTool):
    """
    Look up a single IP address in Shodan.

    Returns all open ports, detected services, banners, operating system,
    ASN, geolocation, associated CVEs, and optionally historical scan data
    for the provided IP address.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="shodan_host_lookup",
            description=(
                "Retrieve all Shodan information for a specific IP address: open ports, "
                "service banners, CVEs, ASN, geolocation, and optionally historical data. "
                "Requires SHODAN_API_KEY environment variable."
            ),
            parameters={
                "type": "object",
                "required": ["ip"],
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "IPv4 or IPv6 address to look up (e.g. '8.8.8.8').",
                    },
                    "history": {
                        "type": "boolean",
                        "description": "Include historical banners in the response (default False).",
                        "default": False,
                    },
                    "minify": {
                        "type": "boolean",
                        "description": "Return only the list of ports (default False).",
                        "default": False,
                    },
                },
            },
        )

    async def execute(  # type: ignore[override]
        self,
        ip: Optional[str] = None,
        history: bool = False,
        minify: bool = False,
        **_: Any,
    ) -> str:
        """
        Look up a single IP address in Shodan.

        Args:
            ip:      Target IPv4 or IPv6 address.
            history: Include historical banners when True.
            minify:  Return only port list when True.

        Returns:
            JSON string with all Shodan data for the host.

        Raises:
            ToolExecutionError: If the API key is missing or the IP is invalid.
            ToolRateLimitError: If the Shodan API rate limit is exceeded.
        """
        if not ip or not ip.strip():
            raise ToolExecutionError(
                "Parameter 'ip' is required and must not be empty.",
                tool_name=self.name,
                recoverable=False,
            )

        ip = ip.strip()
        _validate_ip(ip)

        api_key = os.environ.get("SHODAN_API_KEY", "")
        if not api_key:
            raise ToolExecutionError(
                "Shodan API key not configured. Set the SHODAN_API_KEY environment variable. "
                "Obtain a key at https://account.shodan.io/",
                tool_name=self.name,
                recoverable=False,
            )

        params: Dict[str, str] = {"key": api_key}
        if history:
            params["history"] = "true"
        if minify:
            params["minify"] = "true"

        url = f"https://api.shodan.io/shodan/host/{ip}?{urllib.parse.urlencode(params)}"
        logger.debug("[shodan_host_lookup] looking up IP: %s", ip)

        data = await asyncio.to_thread(_make_api_request, url, {}, 25)

        ports_summary: List[Dict[str, Any]] = []
        for service in data.get("data", []):
            ports_summary.append(
                {
                    "port": service.get("port"),
                    "transport": service.get("transport", "tcp"),
                    "product": service.get("product", ""),
                    "version": service.get("version", ""),
                    "banner": (service.get("data", "") or "")[:300],
                    "timestamp": service.get("timestamp", ""),
                    "module": service.get("_shodan", {}).get("module", ""),
                    "ssl": service.get("ssl") is not None,
                    "vulns": list(service.get("vulns", {}).keys()),
                }
            )

        result: Dict[str, Any] = {
            "ip": data.get("ip_str", ip),
            "asn": data.get("asn", ""),
            "org": data.get("org", ""),
            "isp": data.get("isp", ""),
            "country": data.get("country_name", ""),
            "city": data.get("city", ""),
            "region": data.get("region_code", ""),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "os": data.get("os"),
            "hostnames": data.get("hostnames", []),
            "domains": data.get("domains", []),
            "tags": data.get("tags", []),
            "ports": data.get("ports", []),
            "last_update": data.get("last_update", ""),
            "total_banners": len(data.get("data", [])),
            "services": ports_summary,
            "vulns": list(data.get("vulns", {}).keys()),
        }

        return truncate_output(json.dumps(result, indent=2))


# ---------------------------------------------------------------------------
# Tool 3 — CensysSearchTool
# ---------------------------------------------------------------------------


class CensysSearchTool(BaseTool):
    """
    Search Censys internet-wide scan data via the Search API v2.

    Supports searching both the ``hosts`` index (IPv4 hosts and their open
    services) and the ``certificates`` index (TLS/SSL certificates observed
    across the internet).  Authentication uses HTTP Basic with the Censys
    API ID and secret from environment variables.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="censys_search",
            description=(
                "Search Censys internet-wide scan data. Use the 'hosts' index for "
                "IPv4 hosts with open services, or 'certificates' index for TLS "
                "certificates. Requires CENSYS_API_ID and CENSYS_API_SECRET env vars."
            ),
            parameters={
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": {
                        "type": "string",
                        "description": (
                            "Censys search query (e.g. 'services.port=443 and "
                            "services.tls.certificate.parsed.subject.organization: Acme')."
                        ),
                    },
                    "index": {
                        "type": "string",
                        "enum": ["hosts", "certificates"],
                        "description": "Censys index to search: 'hosts' (default) or 'certificates'.",
                        "default": "hosts",
                    },
                    "per_page": {
                        "type": "integer",
                        "description": "Results per page (default 25, max 100).",
                        "default": 25,
                        "minimum": 1,
                        "maximum": 100,
                    },
                    "fields": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Optional list of fields to return "
                            "(e.g. ['ip', 'services.port', 'services.transport_protocol'])."
                        ),
                    },
                },
            },
        )

    async def execute(  # type: ignore[override]
        self,
        query: Optional[str] = None,
        index: str = "hosts",
        per_page: int = 25,
        fields: Optional[List[str]] = None,
        **_: Any,
    ) -> str:
        """
        Execute a Censys v2 search query.

        Args:
            query:    Censys search expression.
            index:    Index to search: 'hosts' or 'certificates'.
            per_page: Results per page (1–100, default 25).
            fields:   Optional list of fields to include in results.

        Returns:
            JSON string with matching results and metadata.

        Raises:
            ToolExecutionError: If credentials are missing or the query is invalid.
            ToolRateLimitError: If the Censys API rate limit is exceeded.
        """
        if not query or not query.strip():
            raise ToolExecutionError(
                "Parameter 'query' is required and must not be empty.",
                tool_name=self.name,
                recoverable=False,
            )

        if index not in ("hosts", "certificates"):
            raise ToolExecutionError(
                "Parameter 'index' must be one of: 'hosts', 'certificates'.",
                tool_name=self.name,
                recoverable=False,
            )

        api_id = os.environ.get("CENSYS_API_ID", "")
        api_secret = os.environ.get("CENSYS_API_SECRET", "")
        if not api_id or not api_secret:
            raise ToolExecutionError(
                "Censys credentials not configured. Set CENSYS_API_ID and "
                "CENSYS_API_SECRET environment variables. "
                "Obtain them at https://search.censys.io/account/api",
                tool_name=self.name,
                recoverable=False,
            )

        per_page = max(1, min(int(per_page), 100))
        credentials = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        headers = {
            "Authorization": f"Basic {credentials}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        payload: Dict[str, Any] = {"q": query.strip(), "per_page": per_page}
        if fields:
            payload["fields"] = fields

        url = f"https://search.censys.io/api/v2/{index}/search"
        logger.debug("[censys_search] index=%s query=%s", index, query)

        data = await asyncio.to_thread(
            self._post_json, url, headers, payload, timeout=25
        )

        results = data.get("result", {})
        hits = results.get("hits", [])

        formatted: List[Dict[str, Any]] = []
        for hit in hits:
            if index == "hosts":
                services = [
                    {
                        "port": svc.get("port"),
                        "transport": svc.get("transport_protocol", ""),
                        "service_name": svc.get("service_name", ""),
                        "tls": svc.get("tls") is not None,
                    }
                    for svc in hit.get("services", [])
                ]
                formatted.append(
                    {
                        "ip": hit.get("ip", ""),
                        "asn": hit.get("autonomous_system", {}).get("asn"),
                        "org": hit.get("autonomous_system", {}).get("name", ""),
                        "country": hit.get("location", {}).get("country", ""),
                        "services": services,
                        "labels": hit.get("labels", []),
                    }
                )
            else:
                parsed = hit.get("parsed", {})
                subject = parsed.get("subject", {})
                issuer = parsed.get("issuer", {})
                formatted.append(
                    {
                        "fingerprint_sha256": hit.get("fingerprint_sha256", ""),
                        "subject_cn": subject.get("common_name", []),
                        "subject_org": subject.get("organization", []),
                        "issuer_cn": issuer.get("common_name", []),
                        "issuer_org": issuer.get("organization", []),
                        "names": hit.get("names", []),
                        "not_before": parsed.get("validity", {}).get("start", ""),
                        "not_after": parsed.get("validity", {}).get("end", ""),
                    }
                )

        result: Dict[str, Any] = {
            "query": query,
            "index": index,
            "total": results.get("total", {}).get("value", len(formatted)),
            "returned": len(formatted),
            "results": formatted,
            "next_cursor": results.get("links", {}).get("next", ""),
        }

        return truncate_output(json.dumps(result, indent=2))

    @staticmethod
    def _post_json(
        url: str,
        headers: Dict[str, str],
        payload: Dict[str, Any],
        timeout: int = 20,
    ) -> Dict[str, Any]:
        """POST JSON payload and return parsed response."""
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(  # nosec B310
            url, data=body, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
                raw = resp.read(16 * 1024 * 1024).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            body_text = ""
            try:
                body_text = exc.read(2048).decode("utf-8", errors="replace")
            except Exception:
                pass
            if exc.code == 429:
                raise ToolRateLimitError(
                    f"Censys rate limit (HTTP 429). Retry after 60s. Detail: {body_text}",
                    retry_after=60,
                ) from exc
            if exc.code in (401, 403):
                raise ToolExecutionError(
                    f"Censys authentication failed (HTTP {exc.code}). "
                    "Check CENSYS_API_ID and CENSYS_API_SECRET. Detail: {body_text}",
                    recoverable=False,
                ) from exc
            if exc.code == 400:
                raise ToolExecutionError(
                    f"Censys bad request (HTTP 400). Invalid query syntax. Detail: {body_text}",
                    recoverable=False,
                ) from exc
            raise ToolExecutionError(
                f"Censys API HTTP {exc.code}: {body_text[:300]}"
            ) from exc
        except urllib.error.URLError as exc:
            raise ToolExecutionError(
                f"Network error contacting Censys: {exc.reason}"
            ) from exc

        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ToolExecutionError(
                f"Censys returned non-JSON: {exc}. Preview: {raw[:200]}"
            ) from exc


# ---------------------------------------------------------------------------
# Tool 4 — CensysCertSearchTool
# ---------------------------------------------------------------------------


class CensysCertSearchTool(BaseTool):
    """
    Discover subdomains via Censys certificate transparency data.

    Searches the Censys certificates index for TLS certificates issued for the
    target domain and extracts all Subject Alternative Name (SAN) entries,
    revealing subdomains and related hostnames without active DNS probing.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="censys_cert_search",
            description=(
                "Discover subdomains by searching Censys certificate transparency logs. "
                "Extracts Subject Alternative Names (SANs) from TLS certificates to find "
                "hostnames without active scanning. Requires CENSYS_API_ID and "
                "CENSYS_API_SECRET environment variables."
            ),
            parameters={
                "type": "object",
                "required": ["domain"],
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain to search certificates for (e.g. 'example.com').",
                    },
                    "include_subdomains": {
                        "type": "boolean",
                        "description": "Include wildcard/subdomain certificates in results (default True).",
                        "default": True,
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of certificates to retrieve (default 50, max 100).",
                        "default": 50,
                        "minimum": 1,
                        "maximum": 100,
                    },
                },
            },
        )

    async def execute(  # type: ignore[override]
        self,
        domain: Optional[str] = None,
        include_subdomains: bool = True,
        limit: int = 50,
        **_: Any,
    ) -> str:
        """
        Search Censys certificate data for a domain to find subdomains.

        Args:
            domain:             Target domain name.
            include_subdomains: When True, include *.domain.com certificates.
            limit:              Maximum certificates to retrieve (1–100).

        Returns:
            JSON string with certificate details and discovered hostnames.

        Raises:
            ToolExecutionError: If credentials are missing or the domain is invalid.
            ToolRateLimitError: If the Censys API rate limit is exceeded.
        """
        if not domain or not domain.strip():
            raise ToolExecutionError(
                "Parameter 'domain' is required and must not be empty.",
                tool_name=self.name,
                recoverable=False,
            )

        domain = domain.strip().lower().lstrip("*.")

        api_id = os.environ.get("CENSYS_API_ID", "")
        api_secret = os.environ.get("CENSYS_API_SECRET", "")
        if not api_id or not api_secret:
            raise ToolExecutionError(
                "Censys credentials not configured. Set CENSYS_API_ID and "
                "CENSYS_API_SECRET environment variables. "
                "Obtain them at https://search.censys.io/account/api",
                tool_name=self.name,
                recoverable=False,
            )

        limit = max(1, min(int(limit), 100))

        if include_subdomains:
            query = f"parsed.names: {domain}"
        else:
            query = (
                f"parsed.subject.common_name: {domain} or "
                f"parsed.extensions.subject_alt_name.dns_names: {domain}"
            )

        credentials = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        headers = {
            "Authorization": f"Basic {credentials}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        payload: Dict[str, Any] = {
            "q": query,
            "per_page": limit,
            "fields": [
                "parsed.subject.common_name",
                "parsed.issuer.common_name",
                "parsed.issuer.organization",
                "parsed.extensions.subject_alt_name.dns_names",
                "parsed.validity.start",
                "parsed.validity.end",
                "fingerprint_sha256",
                "parsed.names",
            ],
        }

        logger.debug("[censys_cert_search] domain=%s query=%s", domain, query)

        url = "https://search.censys.io/api/v2/certificates/search"
        data = await asyncio.to_thread(
            CensysSearchTool._post_json, url, headers, payload, 25
        )

        hits = data.get("result", {}).get("hits", [])
        discovered_names: set[str] = set()
        certificates: List[Dict[str, Any]] = []

        for cert in hits:
            parsed = cert.get("parsed", {})
            validity = parsed.get("validity", {})
            issuer = parsed.get("issuer", {})
            subject = parsed.get("subject", {})
            san_names: List[str] = parsed.get("extensions", {}).get(
                "subject_alt_name", {}
            ).get("dns_names", [])
            all_names: List[str] = cert.get("names") or san_names

            # Collect subdomain names relevant to the target domain
            for name in all_names:
                if name.endswith(f".{domain}") or name == domain:
                    discovered_names.add(name.lstrip("*."))

            certificates.append(
                {
                    "fingerprint_sha256": cert.get("fingerprint_sha256", ""),
                    "subject_cn": subject.get("common_name", []),
                    "issuer_cn": issuer.get("common_name", []),
                    "issuer_org": issuer.get("organization", []),
                    "sans": all_names,
                    "not_before": validity.get("start", ""),
                    "not_after": validity.get("end", ""),
                }
            )

        result: Dict[str, Any] = {
            "domain": domain,
            "certificates_found": len(certificates),
            "discovered_subdomains": sorted(discovered_names),
            "total_subdomains": len(discovered_names),
            "certificates": certificates,
        }

        return truncate_output(json.dumps(result, indent=2))


# ---------------------------------------------------------------------------
# Tool 5 — FOFASearchTool
# ---------------------------------------------------------------------------


class FOFASearchTool(BaseTool):
    """
    Query the FOFA cyberspace search engine for internet-wide asset discovery.

    FOFA (Fingerprint of All) is a Chinese internet-wide search engine covering
    billions of assets.  Queries are submitted as base64-encoded FOFA syntax
    expressions.  Requires ``FOFA_API_EMAIL`` and ``FOFA_API_KEY`` environment
    variables.

    Example queries:
        ``app="Apache" && country="US"``
        ``title="Jenkins" && port="8080"``
        ``header="X-Jenkins" && protocol="https"``
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="fofa_search",
            description=(
                "Query the FOFA cyberspace search engine for asset discovery. "
                "Supports FOFA syntax (app, title, header, port, country, etc.). "
                "Requires FOFA_API_EMAIL and FOFA_API_KEY environment variables."
            ),
            parameters={
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": {
                        "type": "string",
                        "description": (
                            "FOFA search query using FOFA syntax "
                            "(e.g. 'app=\"Apache\" && country=\"US\"', "
                            "'title=\"Jenkins\" && port=\"8080\"')."
                        ),
                    },
                    "size": {
                        "type": "integer",
                        "description": "Number of results to return (default 100, max 10000).",
                        "default": 100,
                        "minimum": 1,
                        "maximum": 10000,
                    },
                    "page": {
                        "type": "integer",
                        "description": "Page number for pagination (default 1).",
                        "default": 1,
                        "minimum": 1,
                    },
                    "fields": {
                        "type": "string",
                        "description": (
                            "Comma-separated list of fields to return "
                            "(default 'host,ip,port,title,country,server')."
                        ),
                        "default": "host,ip,port,title,country,server",
                    },
                },
            },
        )

    async def execute(  # type: ignore[override]
        self,
        query: Optional[str] = None,
        size: int = 100,
        page: int = 1,
        fields: str = "host,ip,port,title,country,server",
        **_: Any,
    ) -> str:
        """
        Execute a FOFA search query.

        Args:
            query:  FOFA query expression.
            size:   Number of results (1–10000, default 100).
            page:   Page number (default 1).
            fields: Comma-separated field names to return.

        Returns:
            JSON string with matching assets.

        Raises:
            ToolExecutionError: If credentials are missing or the query is invalid.
            ToolRateLimitError: If the FOFA API rate limit is exceeded.
        """
        if not query or not query.strip():
            raise ToolExecutionError(
                "Parameter 'query' is required and must not be empty.",
                tool_name=self.name,
                recoverable=False,
            )

        email = os.environ.get("FOFA_API_EMAIL", "")
        key = os.environ.get("FOFA_API_KEY", "")
        if not email or not key:
            raise ToolExecutionError(
                "FOFA credentials not configured. Set FOFA_API_EMAIL and "
                "FOFA_API_KEY environment variables. "
                "Obtain them at https://fofa.info/userInfo",
                tool_name=self.name,
                recoverable=False,
            )

        size = max(1, min(int(size), 10000))
        page = max(1, int(page))
        fields = fields.strip() or "host,ip,port,title,country,server"

        q_b64 = base64.b64encode(query.strip().encode("utf-8")).decode("ascii")
        params: Dict[str, str] = {
            "email": email,
            "key": key,
            "qbase64": q_b64,
            "size": str(size),
            "page": str(page),
            "fields": fields,
            "full": "false",
        }
        url = f"https://fofa.info/api/v1/search/all?{urllib.parse.urlencode(params)}"
        logger.debug("[fofa_search] query=%s size=%d page=%d", query, size, page)

        data = await asyncio.to_thread(_make_api_request, url, {}, 30)

        if data.get("error"):
            raise ToolExecutionError(
                f"FOFA API error: {data.get('errmsg', 'unknown error')}",
                tool_name=self.name,
            )

        field_names = [f.strip() for f in fields.split(",") if f.strip()]
        raw_results: List[List[str]] = data.get("results", [])
        formatted: List[Dict[str, str]] = []
        for row in raw_results:
            if isinstance(row, list):
                entry = {
                    field_names[i]: row[i] if i < len(row) else ""
                    for i in range(len(field_names))
                }
                formatted.append(entry)
            elif isinstance(row, dict):
                formatted.append(row)

        result: Dict[str, Any] = {
            "query": query,
            "page": page,
            "size": size,
            "total": data.get("size", len(formatted)),
            "returned": len(formatted),
            "mode": data.get("mode", ""),
            "results": formatted,
        }

        return truncate_output(json.dumps(result, indent=2))


# ---------------------------------------------------------------------------
# Tool 6 — PassiveDNSTool
# ---------------------------------------------------------------------------


class PassiveDNSTool(BaseTool):
    """
    Retrieve historical DNS resolution records from passive DNS databases.

    Aggregates passive DNS data from SecurityTrails and/or VirusTotal to
    reveal historical IP addresses, past infrastructure, and ownership changes
    for a domain — without sending any traffic to the target.

    Supported providers:
        * ``securitytrails`` — Requires ``SECURITYTRAILS_API_KEY``
        * ``virustotal``     — Requires ``VIRUSTOTAL_API_KEY``
        * ``all``            — Queries both providers and merges results
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="passive_dns_lookup",
            description=(
                "Retrieve historical DNS records from SecurityTrails and/or VirusTotal. "
                "Reveals past IP addresses, infrastructure changes, and related domains "
                "without active probing. Requires provider-specific API key env vars."
            ),
            parameters={
                "type": "object",
                "required": ["domain"],
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain to query historical DNS records for (e.g. 'example.com').",
                    },
                    "provider": {
                        "type": "string",
                        "enum": ["securitytrails", "virustotal", "all"],
                        "description": (
                            "Passive DNS provider to query. "
                            "'all' queries both and merges results (default)."
                        ),
                        "default": "all",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum records to return per provider (default 100).",
                        "default": 100,
                        "minimum": 1,
                        "maximum": 1000,
                    },
                },
            },
        )

    async def execute(  # type: ignore[override]
        self,
        domain: Optional[str] = None,
        provider: str = "all",
        limit: int = 100,
        **_: Any,
    ) -> str:
        """
        Query passive DNS providers for historical records of a domain.

        Args:
            domain:   Target domain name.
            provider: Provider(s) to query: 'securitytrails', 'virustotal', or 'all'.
            limit:    Maximum records per provider (1–1000, default 100).

        Returns:
            JSON string with aggregated historical DNS records from all queried providers.

        Raises:
            ToolExecutionError: If required API keys are missing or inputs are invalid.
            ToolRateLimitError: If a provider rate limit is exceeded.
        """
        if not domain or not domain.strip():
            raise ToolExecutionError(
                "Parameter 'domain' is required and must not be empty.",
                tool_name=self.name,
                recoverable=False,
            )

        domain = domain.strip().lower()
        limit = max(1, min(int(limit), 1000))

        if provider not in ("securitytrails", "virustotal", "all"):
            raise ToolExecutionError(
                "Parameter 'provider' must be one of: 'securitytrails', 'virustotal', 'all'.",
                tool_name=self.name,
                recoverable=False,
            )

        tasks: List[Any] = []
        provider_names: List[str] = []

        if provider in ("securitytrails", "all"):
            tasks.append(self._query_securitytrails(domain, limit))
            provider_names.append("securitytrails")

        if provider in ("virustotal", "all"):
            tasks.append(self._query_virustotal(domain, limit))
            provider_names.append("virustotal")

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        all_records: List[Dict[str, Any]] = []
        provider_errors: Dict[str, str] = {}
        provider_counts: Dict[str, int] = {}

        for name, resp in zip(provider_names, responses):
            if isinstance(resp, Exception):
                provider_errors[name] = str(resp)
                logger.warning("[passive_dns] %s failed for %s: %s", name, domain, resp)
            elif isinstance(resp, list):
                provider_counts[name] = len(resp)
                all_records.extend(resp)

        # Sort by first_seen descending (most recent first)
        all_records.sort(key=lambda r: r.get("first_seen", ""), reverse=True)

        result: Dict[str, Any] = {
            "domain": domain,
            "provider": provider,
            "total_records": len(all_records),
            "provider_counts": provider_counts,
            "provider_errors": provider_errors,
            "records": all_records[:limit],
        }

        return truncate_output(json.dumps(result, indent=2))

    # ------------------------------------------------------------------
    # Private provider helpers
    # ------------------------------------------------------------------

    @staticmethod
    async def _query_securitytrails(
        domain: str, limit: int
    ) -> List[Dict[str, Any]]:
        """
        Query SecurityTrails passive DNS API for historical A records.

        Args:
            domain: Target domain.
            limit:  Maximum records to return.

        Returns:
            List of normalised DNS record dicts.

        Raises:
            ToolExecutionError: If the API key is missing or the request fails.
        """
        api_key = os.environ.get("SECURITYTRAILS_API_KEY", "")
        if not api_key:
            raise ToolExecutionError(
                "SecurityTrails API key not configured. Set the "
                "SECURITYTRAILS_API_KEY environment variable. "
                "Obtain a key at https://securitytrails.com/app/account/credentials",
                recoverable=False,
            )

        url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
        headers = {
            "apikey": api_key,
            "Accept": "application/json",
        }

        data = await asyncio.to_thread(_make_api_request, url, headers, 20)

        records: List[Dict[str, Any]] = []
        for record in data.get("records", [])[:limit]:
            for value_obj in record.get("values", []):
                records.append(
                    {
                        "source": "securitytrails",
                        "record_type": "A",
                        "value": value_obj.get("ip", ""),
                        "first_seen": record.get("first_seen", ""),
                        "last_seen": record.get("last_seen", ""),
                        "organizations": value_obj.get("ip_organization", ""),
                    }
                )
        return records

    @staticmethod
    async def _query_virustotal(
        domain: str, limit: int
    ) -> List[Dict[str, Any]]:
        """
        Query VirusTotal passive DNS API for historical resolutions.

        Args:
            domain: Target domain.
            limit:  Maximum records to return.

        Returns:
            List of normalised DNS record dicts.

        Raises:
            ToolExecutionError: If the API key is missing or the request fails.
        """
        api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        if not api_key:
            raise ToolExecutionError(
                "VirusTotal API key not configured. Set the "
                "VIRUSTOTAL_API_KEY environment variable. "
                "Obtain a key at https://www.virustotal.com/gui/user/apikey",
                recoverable=False,
            )

        url = (
            f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions"
            f"?limit={min(limit, 40)}"
        )
        headers = {
            "x-apikey": api_key,
            "Accept": "application/json",
        }

        data = await asyncio.to_thread(_make_api_request, url, headers, 20)

        records: List[Dict[str, Any]] = []
        for item in data.get("data", [])[:limit]:
            attrs = item.get("attributes", {})
            records.append(
                {
                    "source": "virustotal",
                    "record_type": "A",
                    "value": attrs.get("ip_address", ""),
                    "first_seen": _vt_epoch_to_iso(attrs.get("date", 0)),
                    "last_seen": _vt_epoch_to_iso(attrs.get("date", 0)),
                    "resolver": attrs.get("resolver", ""),
                    "hostname": attrs.get("host_name", ""),
                }
            )
        return records


def _vt_epoch_to_iso(epoch: Any) -> str:
    """Convert a VirusTotal Unix epoch timestamp to an ISO-8601 date string."""
    if not epoch:
        return ""
    try:
        return datetime.datetime.fromtimestamp(
            int(epoch), tz=datetime.timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError, OSError):
        return str(epoch)


# ---------------------------------------------------------------------------
# Module-level registry
# ---------------------------------------------------------------------------

OSINT_TOOLS: List[BaseTool] = [
    ShodanSearchTool(),
    ShodanHostTool(),
    CensysSearchTool(),
    CensysCertSearchTool(),
    FOFASearchTool(),
    PassiveDNSTool(),
]

__all__ = [
    "ShodanSearchTool",
    "ShodanHostTool",
    "CensysSearchTool",
    "CensysCertSearchTool",
    "FOFASearchTool",
    "PassiveDNSTool",
    "OSINT_TOOLS",
]

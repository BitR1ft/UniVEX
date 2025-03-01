"""
Extended Recon Tools — Passive URL & Parameter Discovery

Implements five agent tools for historical and passive URL/parameter discovery:

  WaybackUrlsTool        — Enumerate archived URLs from the Wayback Machine CDX API
                           for a target domain, with deduplication and mime-type filtering.
  GAUTool                — Wrapper around the GetAllUrls (gau) CLI tool for aggregating
                           URLs from Common Crawl, Wayback Machine, and OTX.
  ParamSpiderTool        — Extract unique parameter names from archived URLs to guide
                           injection fuzzing (no active probing).
  KatanaCrawlerTool      — Wrapper around the Katana CLI crawler for active JS-aware
                           crawling of a target URL.
  WebArchiveSearchTool   — Search web.archive.org snapshots for specific page keywords
                           or paths, returning timestamped snapshot URLs.

OWASP Mapping: A05:2021-Security Misconfiguration, A06:2021-Vulnerable and Outdated Components
MITRE ATT&CK:  T1595.003 (Active Scanning: Wordlist Scanning),
               T1592 (Gather Victim Host Information)
"""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Set

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import (
    ToolExecutionError,
    truncate_output,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared CDX API helper
# ---------------------------------------------------------------------------

_CDX_API = "https://web.archive.org/cdx/search/cdx"
_CDX_DEFAULT_LIMIT = 500


def _fetch_wayback_urls(
    domain: str,
    limit: int = _CDX_DEFAULT_LIMIT,
    mime_filter: Optional[str] = None,
    timeout: int = 20,
) -> List[str]:
    """
    Query the Wayback Machine CDX API and return a deduplicated list of URLs.

    Parameters
    ----------
    domain:      Target domain (e.g. example.com).  Wildcards are appended automatically.
    limit:       Maximum number of CDX results to request.
    mime_filter: Optional MIME type to include (e.g. "text/html").
    timeout:     Request timeout in seconds.
    """
    params: Dict[str, str] = {
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": str(limit),
    }
    if mime_filter:
        params["filter"] = f"mimetype:{mime_filter}"

    query = urllib.parse.urlencode(params)
    full_url = f"{_CDX_API}?{query}"
    logger.debug("CDX request: %s", full_url)

    req = urllib.request.Request(
        full_url,
        headers={"User-Agent": "UniVex-ReconTool/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            raw = resp.read(8 * 1024 * 1024).decode("utf-8", errors="replace")
    except Exception as exc:
        raise ToolExecutionError(f"CDX API request failed: {exc}") from exc

    try:
        rows = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ToolExecutionError(f"CDX API returned non-JSON: {exc}") from exc

    # rows[0] is the header ["original"], subsequent rows are values
    urls: List[str] = []
    seen: Set[str] = set()
    for row in rows[1:]:
        if isinstance(row, list) and row:
            url = row[0]
            if url not in seen:
                seen.add(url)
                urls.append(url)
    return urls


def _extract_params_from_urls(urls: List[str]) -> Dict[str, int]:
    """Return a frequency map of query parameter names found across *urls*."""
    param_counts: Dict[str, int] = {}
    for url in urls:
        try:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            for name in qs:
                param_counts[name] = param_counts.get(name, 0) + 1
        except Exception:
            continue
    return param_counts


def _run_cli_tool(
    cmd: List[str],
    timeout: int = 120,
) -> str:
    """Run an external CLI tool and return its combined stdout+stderr output."""
    try:
        proc = subprocess.run(  # nosec B603
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = proc.stdout + proc.stderr
        if proc.returncode not in (0, 1):
            raise ToolExecutionError(
                f"Command {cmd[0]} exited with code {proc.returncode}: {output[:500]}"
            )
        return output
    except FileNotFoundError:
        raise ToolExecutionError(
            f"Tool '{cmd[0]}' not found. Install it on the kali-tools container."
        )
    except subprocess.TimeoutExpired:
        raise ToolExecutionError(f"Command {cmd[0]} timed out after {timeout}s.")


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


class WaybackUrlsTool(BaseTool):
    """
    Enumerate archived URLs from the Wayback Machine CDX API.

    Uses the public CDX search endpoint to retrieve all archived URLs for a
    domain, deduplicated by URL key. Optionally filters by MIME type and
    restricts the result count.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="wayback_urls",
            description=(
                "Retrieve historical URLs for a domain from the Wayback Machine "
                "CDX API. Useful for discovering hidden endpoints, old parameters, "
                "and forgotten pages without active scanning."
            ),
            parameters={
                "type": "object",
                "required": ["domain"],
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain (e.g. example.com).",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max URLs to retrieve (default 500, max 5000).",
                        "default": 500,
                    },
                    "mime_filter": {
                        "type": "string",
                        "description": "Filter by MIME type (e.g. 'text/html').",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "CDX API request timeout in seconds (default 20).",
                        "default": 20,
                    },
                },
            },
        )

    async def execute(  # type: ignore[override]
        self,
        domain: Optional[str] = None,
        limit: int = _CDX_DEFAULT_LIMIT,
        mime_filter: Optional[str] = None,
        timeout: int = 20,
        **kwargs: Any,
    ) -> str:
        if not domain:
            raise ToolExecutionError("'domain' parameter is required.")
        domain = domain.strip()
        for _prefix in ("https://", "http://"):
            if domain.startswith(_prefix):
                domain = domain[len(_prefix):]
                break
        domain = domain.split("/")[0]
        limit = min(max(1, limit), 5000)

        urls = await asyncio.to_thread(
            _fetch_wayback_urls, domain, limit, mime_filter, timeout
        )

        result: Dict[str, Any] = {
            "domain": domain,
            "urls_found": len(urls),
            "urls": urls[:2000],
        }
        return truncate_output(json.dumps(result, indent=2))


class GAUTool(BaseTool):
    """
    GetAllUrls (gau) — aggregate archived URLs from multiple sources.

    Runs the ``gau`` CLI tool (https://github.com/lc/gau) which collects URLs
    from Common Crawl, Wayback Machine, and OTX. Falls back gracefully with an
    informative error if ``gau`` is not installed.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="gau",
            description=(
                "Use the gau (GetAllUrls) tool to aggregate archived URLs for a "
                "domain from Common Crawl, Wayback Machine, and OTX Alienvault."
            ),
            parameters={
                "type": "object",
                "required": ["domain"],
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain (e.g. example.com).",
                    },
                    "providers": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Providers to query: wayback, commoncrawl, otx (default all).",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds (default 120).",
                        "default": 120,
                    },
                    "blacklist": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "File extensions to blacklist (e.g. ['png','jpg']).",
                    },
                },
            },
        )

    async def execute(  # type: ignore[override]
        self,
        domain: Optional[str] = None,
        providers: Optional[List[str]] = None,
        timeout: int = 120,
        blacklist: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> str:
        if not domain:
            raise ToolExecutionError("'domain' parameter is required.")

        cmd = ["gau", "--json", domain]

        if providers:
            cmd += ["--providers", ",".join(providers)]
        if blacklist:
            cmd += ["--blacklist", ",".join(blacklist)]

        raw_output = await asyncio.to_thread(_run_cli_tool, cmd, timeout)

        urls: List[str] = []
        seen: Set[str] = set()
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                url = obj.get("url", "")
            except json.JSONDecodeError:
                url = line
            if url and url not in seen:
                seen.add(url)
                urls.append(url)

        result: Dict[str, Any] = {
            "domain": domain,
            "urls_found": len(urls),
            "urls": urls[:2000],
        }
        return truncate_output(json.dumps(result, indent=2))


class ParamSpiderTool(BaseTool):
    """
    Extract unique query parameter names from historical Wayback Machine URLs.

    Uses the CDX API (same as WaybackUrlsTool) to collect URLs and then parses
    all query strings to build a frequency-ranked list of parameter names. This
    list can be used to seed fuzzing wordlists or guide injection testing without
    making any direct requests to the live target.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="param_spider",
            description=(
                "Extract query parameter names from archived Wayback Machine URLs "
                "for a domain. Returns a ranked list of unique parameter names for "
                "use in fuzzing and injection testing."
            ),
            parameters={
                "type": "object",
                "required": ["domain"],
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain (e.g. example.com).",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max CDX URLs to fetch (default 500).",
                        "default": 500,
                    },
                    "min_count": {
                        "type": "integer",
                        "description": "Minimum occurrence count to include a parameter (default 1).",
                        "default": 1,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "CDX API request timeout in seconds (default 20).",
                        "default": 20,
                    },
                },
            },
        )

    async def execute(  # type: ignore[override]
        self,
        domain: Optional[str] = None,
        limit: int = _CDX_DEFAULT_LIMIT,
        min_count: int = 1,
        timeout: int = 20,
        **kwargs: Any,
    ) -> str:
        if not domain:
            raise ToolExecutionError("'domain' parameter is required.")
        domain = domain.strip()
        for _prefix in ("https://", "http://"):
            if domain.startswith(_prefix):
                domain = domain[len(_prefix):]
                break
        domain = domain.split("/")[0]
        limit = min(max(1, limit), 5000)

        urls = await asyncio.to_thread(
            _fetch_wayback_urls, domain, limit, None, timeout
        )

        param_counts = _extract_params_from_urls(urls)
        # Filter and sort descending by count
        filtered = {
            k: v for k, v in param_counts.items() if v >= min_count
        }
        sorted_params = sorted(filtered.items(), key=lambda x: x[1], reverse=True)

        result: Dict[str, Any] = {
            "domain": domain,
            "total_urls_analysed": len(urls),
            "unique_params_found": len(sorted_params),
            "params": [{"name": k, "count": v} for k, v in sorted_params[:500]],
        }
        return truncate_output(json.dumps(result, indent=2))


class KatanaCrawlerTool(BaseTool):
    """
    Katana — fast, JS-aware web crawler for active endpoint discovery.

    Runs the ``katana`` CLI tool (https://github.com/projectdiscovery/katana)
    against a target URL, collecting endpoints including those loaded by JavaScript.
    Falls back gracefully with an informative error if ``katana`` is not installed.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="katana_crawler",
            description=(
                "Actively crawl a web application with the Katana JS-aware crawler "
                "to discover all reachable endpoints, including those rendered by "
                "JavaScript frameworks."
            ),
            parameters={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Starting URL to crawl.",
                    },
                    "depth": {
                        "type": "integer",
                        "description": "Crawl depth (default 3, max 10).",
                        "default": 3,
                    },
                    "js_crawl": {
                        "type": "boolean",
                        "description": "Enable JavaScript parsing (default true).",
                        "default": True,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds (default 120).",
                        "default": 120,
                    },
                    "concurrency": {
                        "type": "integer",
                        "description": "Number of concurrent requests (default 10).",
                        "default": 10,
                    },
                },
            },
        )

    async def execute(  # type: ignore[override]
        self,
        url: Optional[str] = None,
        depth: int = 3,
        js_crawl: bool = True,
        timeout: int = 120,
        concurrency: int = 10,
        **kwargs: Any,
    ) -> str:
        if not url:
            raise ToolExecutionError("'url' parameter is required.")

        depth = min(max(1, depth), 10)
        concurrency = min(max(1, concurrency), 50)

        cmd = [
            "katana",
            "-u", url,
            "-d", str(depth),
            "-c", str(concurrency),
            "-silent",
            "-o", "/dev/stdout",
        ]
        if js_crawl:
            cmd += ["-js-crawl"]

        raw_output = await asyncio.to_thread(_run_cli_tool, cmd, timeout)

        endpoints: List[str] = []
        seen: Set[str] = set()
        for line in raw_output.splitlines():
            ep = line.strip()
            if ep and ep not in seen and (ep.startswith("http://") or ep.startswith("https://")):
                seen.add(ep)
                endpoints.append(ep)

        result: Dict[str, Any] = {
            "url": url,
            "depth": depth,
            "endpoints_found": len(endpoints),
            "endpoints": endpoints[:2000],
        }
        return truncate_output(json.dumps(result, indent=2))


class WebArchiveSearchTool(BaseTool):
    """
    Search web.archive.org snapshots for specific paths or keywords.

    Uses the CDX API with a path filter to find archived snapshots of specific
    URLs, returning timestamped Wayback Machine links. Useful for finding old
    admin pages, debug endpoints, backup files, and config files that may no
    longer exist on the live site.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="web_archive_search",
            description=(
                "Search the Wayback Machine for archived snapshots of specific "
                "paths or keywords on a domain. Returns timestamped Wayback "
                "Machine URLs for historical pages."
            ),
            parameters={
                "type": "object",
                "required": ["domain"],
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain (e.g. example.com).",
                    },
                    "path": {
                        "type": "string",
                        "description": "URL path to search for (e.g. '/admin', '/backup.sql').",
                        "default": "/*",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max snapshots to retrieve (default 100).",
                        "default": 100,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "CDX API request timeout in seconds (default 20).",
                        "default": 20,
                    },
                },
            },
        )

    async def execute(  # type: ignore[override]
        self,
        domain: Optional[str] = None,
        path: str = "/*",
        limit: int = 100,
        timeout: int = 20,
        **kwargs: Any,
    ) -> str:
        if not domain:
            raise ToolExecutionError("'domain' parameter is required.")
        domain = domain.strip()
        for _prefix in ("https://", "http://"):
            if domain.startswith(_prefix):
                domain = domain[len(_prefix):]
                break
        domain = domain.split("/")[0]
        limit = min(max(1, limit), 1000)

        if not path.startswith("/"):
            path = "/" + path

        params: Dict[str, str] = {
            "url": f"{domain}{path}",
            "output": "json",
            "fl": "timestamp,original,statuscode",
            "limit": str(limit),
        }
        query = urllib.parse.urlencode(params)
        full_url = f"{_CDX_API}?{query}"

        req = urllib.request.Request(
            full_url,
            headers={"User-Agent": "UniVex-ReconTool/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
                raw = resp.read(4 * 1024 * 1024).decode("utf-8", errors="replace")
        except Exception as exc:
            raise ToolExecutionError(f"CDX API request failed: {exc}") from exc

        try:
            rows = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ToolExecutionError(f"CDX API returned non-JSON: {exc}") from exc

        snapshots: List[Dict[str, str]] = []
        for row in rows[1:]:
            if isinstance(row, list) and len(row) >= 3:
                ts, orig_url, status = row[0], row[1], row[2]
                wb_url = f"https://web.archive.org/web/{ts}/{orig_url}"
                snapshots.append({
                    "timestamp": ts,
                    "original_url": orig_url,
                    "status_code": status,
                    "wayback_url": wb_url,
                })

        result: Dict[str, Any] = {
            "domain": domain,
            "path_searched": path,
            "snapshots_found": len(snapshots),
            "snapshots": snapshots,
        }
        return truncate_output(json.dumps(result, indent=2))

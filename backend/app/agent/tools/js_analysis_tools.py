"""
JavaScript Analysis Tools

Implements five agent tools for client-side JavaScript security analysis:

  JSEndpointExtractTool  — Extract API endpoints and URLs from JS source code
                           using regex-based heuristics (fetch/axios/XHR/href).
  JSSecretFinderTool     — Detect hard-coded secrets (API keys, tokens, passwords)
                           leaked in JavaScript files using entropy + pattern matching.
  JSLibVulnTool          — Fingerprint JavaScript libraries against the local
                           js_vuln_db.json vulnerability database (Retire.js format).
  SourceMapAnalyzeTool   — Detect exposed source maps (.map files) and extract
                           original file paths / source tree from the JSON payload.
  DOMSinkAnalyzerTool    — Identify dangerous DOM sinks (innerHTML, eval, document.write,
                           etc.) that could lead to client-side XSS.

OWASP Mapping: A06:2021-Vulnerable and Outdated Components,
               A02:2021-Cryptographic Failures, A03:2021-Injection
MITRE ATT&CK:  T1190 (Exploit Public-Facing Application),
               T1552.001 (Credentials In Files)
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import (
    ToolExecutionError,
    truncate_output,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_VULN_DB_PATH = os.path.normpath(
    os.path.join(
        os.path.dirname(__file__),
        "../../../data/js_vuln_db.json",
    )
)

# ---------------------------------------------------------------------------
# Internal helpers — shared utilities
# ---------------------------------------------------------------------------


def _load_vuln_db() -> Dict[str, Any]:
    """Load the JS vulnerability database from JSON."""
    try:
        with open(_VULN_DB_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        logger.warning("JS vuln DB not found at %s", _VULN_DB_PATH)
        return {}
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse JS vuln DB: %s", exc)
        return {}


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy for a string."""
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def _version_tuple(version_str: str) -> Tuple[int, ...]:
    """Parse a semver-ish string into a comparable tuple of ints."""
    parts = re.split(r"[.\-+]", version_str)
    result: List[int] = []
    for part in parts:
        try:
            result.append(int(part))
        except ValueError:
            break
    return tuple(result) if result else (0,)


def _version_in_range(
    version: str,
    at_or_above: Optional[str],
    below: Optional[str],
) -> bool:
    """Return True if *version* falls within [atOrAbove, below)."""
    v = _version_tuple(version)
    if at_or_above:
        if v < _version_tuple(at_or_above):
            return False
    if below:
        if v >= _version_tuple(below):
            return False
    return True


# ---------------------------------------------------------------------------
# Endpoint extraction patterns
# ---------------------------------------------------------------------------

_ENDPOINT_PATTERNS: List[re.Pattern] = [
    # fetch("…"), fetch('…'), axios.get("…"), $.ajax({url:"…"})
    re.compile(
        r"""(?:fetch|axios\.(?:get|post|put|patch|delete|request))\s*\(\s*['"`]([^'"`\s]{3,200})['"`]""",
        re.IGNORECASE,
    ),
    # XMLHttpRequest / XHR open("GET", "…")
    re.compile(
        r"""\.open\s*\(\s*['"`][A-Z]+['"`]\s*,\s*['"`]([^'"`\s]{3,200})['"`]""",
        re.IGNORECASE,
    ),
    # window.location, href = "…"
    re.compile(
        r"""(?:location\.href|window\.location)\s*=\s*['"`]([^'"`\s]{3,200})['"`]""",
        re.IGNORECASE,
    ),
    # Hard-coded URL strings that look like paths or full URLs
    re.compile(
        r"""['"`](/(?:api|v\d|graphql|rest|service|endpoint)[^'"`\s]{0,150})['"`]""",
        re.IGNORECASE,
    ),
]


def _extract_endpoints(js_content: str) -> List[str]:
    """Return deduplicated list of endpoints found in JS source."""
    found: List[str] = []
    seen: set = set()
    for pattern in _ENDPOINT_PATTERNS:
        for match in pattern.finditer(js_content):
            ep = match.group(1).strip()
            if ep and ep not in seen:
                seen.add(ep)
                found.append(ep)
    return found


# ---------------------------------------------------------------------------
# Secret patterns
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("AWS Access Key",   re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key",   re.compile(r"""(?:aws[_\-]?secret|aws[_\-]?key)\s*[=:]\s*['"`]?([A-Za-z0-9/+=]{20,})['"`]?""", re.IGNORECASE)),
    ("GitHub Token",     re.compile(r"gh[pousr]_[A-Za-z0-9]{36}")),
    ("Slack Token",      re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("JWT",              re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),
    ("Google API Key",   re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Stripe Key",       re.compile(r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}")),
    ("SendGrid Key",     re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}")),
    ("Twilio SID",       re.compile(r"AC[a-f0-9]{32}")),
    ("Private Key PEM",  re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("Generic Password", re.compile(
        r"""(?:password|passwd|pwd|secret|api[_\-]?key|auth[_\-]?token|access[_\-]?token)\s*[=:]\s*['"`]([^'"`\s]{8,})['"`]""",
        re.IGNORECASE,
    )),
    ("High-entropy string", None),  # handled separately via entropy
]

_HIGH_ENTROPY_RE = re.compile(r"""['"`]([A-Za-z0-9+/=_\-]{20,100})['"`]""")
_HIGH_ENTROPY_THRESHOLD = 4.5


def _find_secrets(js_content: str) -> List[Dict[str, str]]:
    """Return a list of {type, value, context} dicts for detected secrets."""
    findings: List[Dict[str, str]] = []
    seen_values: set = set()

    for label, pattern in _SECRET_PATTERNS:
        if pattern is None:
            # Entropy-based scan
            for m in _HIGH_ENTROPY_RE.finditer(js_content):
                val = m.group(1)
                if val in seen_values:
                    continue
                if _shannon_entropy(val) >= _HIGH_ENTROPY_THRESHOLD:
                    seen_values.add(val)
                    start = max(0, m.start() - 30)
                    context = js_content[start : m.end() + 30].replace("\n", " ")
                    findings.append({"type": "High-entropy string", "value": val[:40] + "…", "context": context[:120]})
            continue

        for m in pattern.finditer(js_content):
            val = m.group(0)[:80]
            if val in seen_values:
                continue
            seen_values.add(val)
            start = max(0, m.start() - 20)
            context = js_content[start : m.end() + 20].replace("\n", " ")
            findings.append({"type": label, "value": val, "context": context[:120]})

    return findings


# ---------------------------------------------------------------------------
# DOM sink patterns
# ---------------------------------------------------------------------------

_DOM_SINKS: List[Tuple[str, re.Pattern]] = [
    ("innerHTML assignment",      re.compile(r"""\.innerHTML\s*[+]?=""", re.IGNORECASE)),
    ("outerHTML assignment",      re.compile(r"""\.outerHTML\s*[+]?=""", re.IGNORECASE)),
    ("document.write",            re.compile(r"""document\.write\s*\(""", re.IGNORECASE)),
    ("document.writeln",          re.compile(r"""document\.writeln\s*\(""", re.IGNORECASE)),
    ("eval()",                    re.compile(r"""\beval\s*\(""")),
    ("setTimeout(string)",        re.compile(r"""setTimeout\s*\(\s*['"`]""")),
    ("setInterval(string)",       re.compile(r"""setInterval\s*\(\s*['"`]""")),
    ("Function() constructor",    re.compile(r"""\bnew\s+Function\s*\(""")),
    ("insertAdjacentHTML",        re.compile(r"""\.insertAdjacentHTML\s*\(""", re.IGNORECASE)),
    ("jQuery .html()",            re.compile(r"""\$\(.*\)\.html\s*\(""", re.IGNORECASE)),
    ("location.href assignment",  re.compile(r"""location\.href\s*=""", re.IGNORECASE)),
    ("location.replace(var)",     re.compile(r"""location\.replace\s*\(""", re.IGNORECASE)),
    ("src attribute assignment",  re.compile(r"""\.src\s*=\s*(?!['"`]https?://[^`'\"]+['"`])""", re.IGNORECASE)),
    ("postMessage",               re.compile(r"""window\.postMessage\s*\(""", re.IGNORECASE)),
]


def _find_dom_sinks(js_content: str) -> List[Dict[str, Any]]:
    """Return list of {sink, line, snippet} for dangerous DOM sinks."""
    lines = js_content.splitlines()
    findings: List[Dict[str, Any]] = []
    for sink_name, pattern in _DOM_SINKS:
        for m in pattern.finditer(js_content):
            # Calculate line number
            line_no = js_content[: m.start()].count("\n") + 1
            snippet = lines[line_no - 1].strip()[:120] if line_no <= len(lines) else ""
            findings.append({"sink": sink_name, "line": line_no, "snippet": snippet})
    return findings


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


class JSEndpointExtractTool(BaseTool):
    """
    Extract API endpoints and URLs hard-coded in JavaScript source files.

    Accepts either raw JS *content* or a *url* to fetch. Returns a structured
    list of discovered endpoints grouped by extraction pattern.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="js_endpoint_extract",
            description=(
                "Extract API endpoints, URLs and path strings from JavaScript "
                "source code. Accepts raw JS content or a URL to download the file."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "Raw JavaScript source code to analyse.",
                    },
                    "url": {
                        "type": "string",
                        "description": "URL of the JS file to download and analyse.",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Request timeout in seconds (default 15).",
                        "default": 15,
                    },
                },
                "anyOf": [{"required": ["content"]}, {"required": ["url"]}],
            },
        )

    async def execute(  # type: ignore[override]
        self,
        content: Optional[str] = None,
        url: Optional[str] = None,
        timeout: int = 15,
        **kwargs: Any,
    ) -> str:
        if not content and not url:
            raise ToolExecutionError("Either 'content' or 'url' must be provided.")

        js_source = content or ""
        source_label = "<inline>"

        if url and not js_source:
            import urllib.request

            source_label = url
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "UniVex-JSAnalyzer/1.0"},
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
                    js_source = resp.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
            except Exception as exc:
                raise ToolExecutionError(f"Failed to fetch {url}: {exc}") from exc

        endpoints = _extract_endpoints(js_source)

        result: Dict[str, Any] = {
            "source": source_label,
            "endpoints_found": len(endpoints),
            "endpoints": endpoints[:200],  # cap at 200 per file
        }
        return truncate_output(json.dumps(result, indent=2))


class JSSecretFinderTool(BaseTool):
    """
    Detect hard-coded secrets (API keys, tokens, passwords) in JavaScript files.

    Uses both regex pattern matching for known secret formats and
    Shannon entropy analysis for high-entropy strings.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="js_secret_finder",
            description=(
                "Scan JavaScript source code for hard-coded secrets such as API keys, "
                "access tokens, passwords, and high-entropy strings."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "Raw JavaScript source code to scan.",
                    },
                    "url": {
                        "type": "string",
                        "description": "URL of the JS file to download and scan.",
                    },
                    "entropy_threshold": {
                        "type": "number",
                        "description": "Minimum Shannon entropy to flag a string (default 4.5).",
                        "default": 4.5,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Request timeout in seconds (default 15).",
                        "default": 15,
                    },
                },
                "anyOf": [{"required": ["content"]}, {"required": ["url"]}],
            },
        )

    async def execute(  # type: ignore[override]
        self,
        content: Optional[str] = None,
        url: Optional[str] = None,
        entropy_threshold: float = _HIGH_ENTROPY_THRESHOLD,
        timeout: int = 15,
        **kwargs: Any,
    ) -> str:
        if not content and not url:
            raise ToolExecutionError("Either 'content' or 'url' must be provided.")

        js_source = content or ""
        source_label = "<inline>"

        if url and not js_source:
            import urllib.request

            source_label = url
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "UniVex-JSAnalyzer/1.0"},
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
                    js_source = resp.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
            except Exception as exc:
                raise ToolExecutionError(f"Failed to fetch {url}: {exc}") from exc

        secrets = _find_secrets(js_source)

        severity_map = {
            "AWS Access Key": "critical",
            "AWS Secret Key": "critical",
            "GitHub Token": "high",
            "Slack Token": "high",
            "JWT": "high",
            "Google API Key": "high",
            "Stripe Key": "critical",
            "SendGrid Key": "high",
            "Twilio SID": "medium",
            "Private Key PEM": "critical",
            "Generic Password": "medium",
            "High-entropy string": "info",
        }
        for s in secrets:
            s["severity"] = severity_map.get(s["type"], "info")

        result: Dict[str, Any] = {
            "source": source_label,
            "secrets_found": len(secrets),
            "findings": secrets[:100],
        }
        return truncate_output(json.dumps(result, indent=2))


class JSLibVulnTool(BaseTool):
    """
    Fingerprint JavaScript libraries detected in source/URL against the local
    vulnerability database (Retire.js format: backend/data/js_vuln_db.json).
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="js_lib_vuln",
            description=(
                "Identify vulnerable JavaScript libraries in source code by "
                "matching filenames, content patterns, and version strings against "
                "the built-in CVE vulnerability database."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "Raw JavaScript source code to fingerprint.",
                    },
                    "filename": {
                        "type": "string",
                        "description": "Optional filename hint (e.g. 'jquery-3.4.1.min.js').",
                    },
                    "url": {
                        "type": "string",
                        "description": "URL of the JS file; filename is inferred from the URL.",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Request timeout in seconds when fetching via URL (default 15).",
                        "default": 15,
                    },
                },
                "anyOf": [
                    {"required": ["content"]},
                    {"required": ["url"]},
                    {"required": ["filename"]},
                ],
            },
        )

    async def execute(  # type: ignore[override]
        self,
        content: Optional[str] = None,
        filename: Optional[str] = None,
        url: Optional[str] = None,
        timeout: int = 15,
        **kwargs: Any,
    ) -> str:
        if not content and not url and not filename:
            raise ToolExecutionError("Provide 'content', 'url', or 'filename'.")

        js_source = content or ""
        source_label = filename or url or "<inline>"

        if url and not js_source:
            import urllib.request

            parsed = urllib.parse.urlparse(url)
            filename = filename or os.path.basename(parsed.path) or "unknown.js"
            source_label = url
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "UniVex-JSAnalyzer/1.0"},
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
                    js_source = resp.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
            except Exception as exc:
                raise ToolExecutionError(f"Failed to fetch {url}: {exc}") from exc

        vuln_db = _load_vuln_db()
        matches: List[Dict[str, Any]] = []

        for lib_name, lib_data in vuln_db.items():
            extractors = lib_data.get("extractors", {})
            version: Optional[str] = None

            # 1. Try filename extractor
            if filename:
                for fn_pattern in extractors.get("filename", []):
                    if re.search(fn_pattern, filename, re.IGNORECASE):
                        # Try to pull version from filename
                        ver_m = re.search(r"(\d+\.\d+[\d.]*)", filename)
                        if ver_m:
                            version = ver_m.group(1)
                        break

            # 2. Try filecontent extractor
            if js_source:
                for fc_pattern in extractors.get("filecontent", []):
                    fc_m = re.search(fc_pattern, js_source)
                    if fc_m:
                        try:
                            version = fc_m.group(1)
                        except IndexError:
                            version = version or "unknown"
                        break

            if version is None:
                continue  # Library not detected

            # Check vulnerabilities
            for vuln in lib_data.get("vulnerabilities", []):
                at_or_above = vuln.get("atOrAbove")
                below = vuln.get("below")
                if version == "unknown" or _version_in_range(version, at_or_above, below):
                    cves = vuln.get("identifiers", {}).get("CVE", [])
                    matches.append({
                        "library": lib_name,
                        "detected_version": version,
                        "severity": vuln.get("severity", "unknown"),
                        "cve": cves,
                        "affected_range": f">={at_or_above or '0'} <{below or '∞'}",
                        "info": vuln.get("info", []),
                    })

        result: Dict[str, Any] = {
            "source": source_label,
            "vulnerable_libraries": len(matches),
            "findings": matches,
        }
        return truncate_output(json.dumps(result, indent=2))


class SourceMapAnalyzeTool(BaseTool):
    """
    Detect exposed source maps and extract original source tree metadata.

    Checks for .map files by appending '.map' to JS URLs, and parses the JSON
    source map to enumerate original source file paths.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="source_map_analyze",
            description=(
                "Detect exposed JavaScript source maps (.map files) and extract "
                "original source file paths from the source map JSON. Exposed source "
                "maps can reveal full application source code structure."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL of the JS file (the .map URL will be probed automatically).",
                    },
                    "map_content": {
                        "type": "string",
                        "description": "Raw source map JSON content to analyse directly.",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Request timeout in seconds (default 10).",
                        "default": 10,
                    },
                },
                "anyOf": [{"required": ["url"]}, {"required": ["map_content"]}],
            },
        )

    async def execute(  # type: ignore[override]
        self,
        url: Optional[str] = None,
        map_content: Optional[str] = None,
        timeout: int = 10,
        **kwargs: Any,
    ) -> str:
        if not url and not map_content:
            raise ToolExecutionError("Either 'url' or 'map_content' must be provided.")

        findings: List[Dict[str, Any]] = []

        if map_content:
            parsed = self._parse_source_map(map_content, "<inline>")
            if parsed:
                findings.append(parsed)

        if url:
            map_urls = self._candidate_map_urls(url)
            import urllib.request

            for map_url in map_urls:
                try:
                    req = urllib.request.Request(
                        map_url,
                        headers={"User-Agent": "UniVex-SourceMapAnalyzer/1.0"},
                    )
                    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
                        if resp.status == 200:
                            raw = resp.read(4 * 1024 * 1024).decode("utf-8", errors="replace")
                            parsed = self._parse_source_map(raw, map_url)
                            if parsed:
                                findings.append(parsed)
                                break  # first hit is enough
                except Exception:
                    continue

        result: Dict[str, Any] = {
            "source_maps_found": len(findings),
            "findings": findings,
        }
        if findings:
            result["severity"] = "high"
            result["owasp"] = "A02:2021-Cryptographic Failures"
        return truncate_output(json.dumps(result, indent=2))

    @staticmethod
    def _candidate_map_urls(js_url: str) -> List[str]:
        """Return candidate source map URLs for a given JS file URL."""
        candidates = [js_url + ".map"]
        # Also try replacing .js with .js.map and .min.js with .js.map
        if js_url.endswith(".min.js"):
            candidates.append(js_url[: -len(".min.js")] + ".js.map")
        elif js_url.endswith(".js"):
            candidates.append(js_url[: -len(".js")] + ".js.map")
        return candidates

    @staticmethod
    def _parse_source_map(raw: str, map_url: str) -> Optional[Dict[str, Any]]:
        """Parse a source map JSON and return a summary dict, or None if invalid."""
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        if "sources" not in data and "sourceRoot" not in data:
            return None

        sources: List[str] = data.get("sources", [])
        return {
            "map_url": map_url,
            "version": data.get("version"),
            "source_count": len(sources),
            "sources_preview": sources[:50],
            "source_root": data.get("sourceRoot", ""),
        }


class DOMSinkAnalyzerTool(BaseTool):
    """
    Identify dangerous DOM sinks in JavaScript source that may lead to
    client-side XSS (Cross-Site Scripting).

    Sinks include: innerHTML, eval, document.write, setTimeout(string), etc.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="dom_sink_analyzer",
            description=(
                "Scan JavaScript source code for dangerous DOM sinks that could "
                "enable client-side XSS, such as innerHTML, eval(), document.write(), "
                "and insertAdjacentHTML()."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "Raw JavaScript source code to analyse.",
                    },
                    "url": {
                        "type": "string",
                        "description": "URL of the JS file to download and analyse.",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Request timeout in seconds (default 15).",
                        "default": 15,
                    },
                },
                "anyOf": [{"required": ["content"]}, {"required": ["url"]}],
            },
        )

    async def execute(  # type: ignore[override]
        self,
        content: Optional[str] = None,
        url: Optional[str] = None,
        timeout: int = 15,
        **kwargs: Any,
    ) -> str:
        if not content and not url:
            raise ToolExecutionError("Either 'content' or 'url' must be provided.")

        js_source = content or ""
        source_label = "<inline>"

        if url and not js_source:
            import urllib.request

            source_label = url
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "UniVex-DOMAnalyzer/1.0"},
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
                    js_source = resp.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
            except Exception as exc:
                raise ToolExecutionError(f"Failed to fetch {url}: {exc}") from exc

        sinks = _find_dom_sinks(js_source)

        # Aggregate by sink type
        sink_summary: Dict[str, int] = {}
        for s in sinks:
            sink_summary[s["sink"]] = sink_summary.get(s["sink"], 0) + 1

        result: Dict[str, Any] = {
            "source": source_label,
            "total_sink_occurrences": len(sinks),
            "sink_types_found": len(sink_summary),
            "sink_summary": sink_summary,
            "findings": sinks[:150],  # cap detail to 150 occurrences
        }
        if sinks:
            result["owasp"] = "A03:2021-Injection"
            result["severity"] = "medium"
        return truncate_output(json.dumps(result, indent=2))

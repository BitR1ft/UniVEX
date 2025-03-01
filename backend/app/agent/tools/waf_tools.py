"""
WAF Detection & Bypass Engine

Implements four agent tools for detecting and bypassing Web Application Firewalls:

  WAFDetectTool           — Probe a URL and match responses against 55+ WAF
                            fingerprints (headers, cookies, status codes, body
                            patterns). Returns detected WAF name and confidence.
  WAFBypassTool           — Automatically select and fire WAF bypass payloads
                            from the payload database, classifying each response
                            as BYPASSED, BLOCKED, or ERROR.
  PayloadEncoderTool      — Encode / obfuscate attack payloads using base64, URL,
                            double-URL, Unicode, HTML entities, hex, null-byte,
                            SQL comment, case variation, or all-at-once modes.
  WAFFingerprintTool      — Passive-only WAF fingerprinting via response timing
                            analysis and header/cookie inspection — no attack
                            payloads sent. Safe for stealth reconnaissance.

OWASP Mapping: A05:2021-Security Misconfiguration, A03:2021-Injection
MITRE ATT&CK:  T1595 (Active Scanning), T1027 (Obfuscated Files or Information)
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import math
import os
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from http.client import HTTPMessage
from typing import Any, Dict, List, Optional, Tuple

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import (
    truncate_output,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data file paths
# ---------------------------------------------------------------------------

_WAF_FINGERPRINTS_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "../../../data/waf_fingerprints.json")
)
_WAF_BYPASS_PAYLOADS_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "../../../data/waf_bypass_payloads.json")
)

# Module-level cache so JSON is loaded only once per process lifetime
_FINGERPRINTS_CACHE: Optional[List[Dict[str, Any]]] = None
_BYPASS_PAYLOADS_CACHE: Optional[Dict[str, Any]] = None

_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# ---------------------------------------------------------------------------
# Shared loader helpers
# ---------------------------------------------------------------------------


def _load_waf_fingerprints() -> List[Dict[str, Any]]:
    """Load and cache WAF fingerprints from JSON file."""
    global _FINGERPRINTS_CACHE
    if _FINGERPRINTS_CACHE is not None:
        return _FINGERPRINTS_CACHE
    try:
        with open(_WAF_FINGERPRINTS_PATH, "r", encoding="utf-8") as fh:
            _FINGERPRINTS_CACHE = json.load(fh)
            return _FINGERPRINTS_CACHE
    except FileNotFoundError:
        logger.warning("WAF fingerprints file not found: %s", _WAF_FINGERPRINTS_PATH)
        _FINGERPRINTS_CACHE = []
        return _FINGERPRINTS_CACHE
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse WAF fingerprints JSON: %s", exc)
        _FINGERPRINTS_CACHE = []
        return _FINGERPRINTS_CACHE


def _load_bypass_payloads() -> Dict[str, Any]:
    """Load and cache WAF bypass payloads from JSON file."""
    global _BYPASS_PAYLOADS_CACHE
    if _BYPASS_PAYLOADS_CACHE is not None:
        return _BYPASS_PAYLOADS_CACHE
    try:
        with open(_WAF_BYPASS_PAYLOADS_PATH, "r", encoding="utf-8") as fh:
            _BYPASS_PAYLOADS_CACHE = json.load(fh)
            return _BYPASS_PAYLOADS_CACHE
    except FileNotFoundError:
        logger.warning("WAF bypass payloads file not found: %s", _WAF_BYPASS_PAYLOADS_PATH)
        _BYPASS_PAYLOADS_CACHE = {}
        return _BYPASS_PAYLOADS_CACHE
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse WAF bypass payloads JSON: %s", exc)
        _BYPASS_PAYLOADS_CACHE = {}
        return _BYPASS_PAYLOADS_CACHE


# ---------------------------------------------------------------------------
# HTTP probe helper (sync, wrapped with asyncio.to_thread at call sites)
# ---------------------------------------------------------------------------


def _send_probe(
    url: str,
    payload: Optional[str] = None,
    timeout: int = 10,
    method: str = "GET",
    extra_headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Send an HTTP probe request and return a normalised response dict.

    Parameters
    ----------
    url:           Base URL (query string may already contain a payload).
    payload:       If provided, append as ``?x=<payload>`` (url-encoded) unless
                   the URL already contains ``?``.
    timeout:       Socket timeout in seconds.
    method:        HTTP verb (GET, HEAD, POST).
    extra_headers: Additional request headers merged on top of defaults.

    Returns
    -------
    dict with keys: status_code, headers (dict), cookies (list[str]),
                    body_snippet (str, first 2 000 chars), elapsed_ms (float),
                    error (str | None).
    """
    parsed_scheme = urllib.parse.urlparse(url).scheme.lower()
    if parsed_scheme not in ("http", "https"):
        return {
            "status_code": 0,
            "headers": {},
            "cookies": [],
            "body_snippet": "",
            "elapsed_ms": 0.0,
            "error": f"Unsafe URL scheme '{parsed_scheme}': only http and https are permitted.",
        }

    if payload is not None:
        separator = "&" if "?" in url else "?"
        url = f"{url}{separator}x={urllib.parse.quote(payload, safe='')}"

    headers: Dict[str, str] = {"User-Agent": _BROWSER_UA}
    if extra_headers:
        headers.update(extra_headers)

    req = urllib.request.Request(url, headers=headers, method=method)
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            elapsed_ms = (time.monotonic() - t0) * 1000.0
            body_raw = resp.read(4096)
            body_snippet = body_raw.decode("utf-8", errors="replace")[:2000]
            raw_headers: HTTPMessage = resp.info()
            header_dict: Dict[str, str] = {
                k.lower(): v for k, v in raw_headers.items()
            }
            cookies: List[str] = []
            for val in raw_headers.get_all("set-cookie") or []:
                # Extract just the cookie name=value portion
                name_val = val.split(";")[0].strip()
                cookies.append(name_val)
            return {
                "status_code": resp.status,
                "headers": header_dict,
                "cookies": cookies,
                "body_snippet": body_snippet,
                "elapsed_ms": round(elapsed_ms, 2),
                "error": None,
            }
    except urllib.error.HTTPError as exc:
        elapsed_ms = (time.monotonic() - t0) * 1000.0
        body_snippet = ""
        try:
            body_snippet = exc.read(2048).decode("utf-8", errors="replace")[:2000]
        except Exception:
            pass
        raw_headers_exc: HTTPMessage = exc.headers
        header_dict_exc: Dict[str, str] = (
            {k.lower(): v for k, v in raw_headers_exc.items()}
            if raw_headers_exc
            else {}
        )
        cookies_exc: List[str] = []
        if raw_headers_exc:
            for val in raw_headers_exc.get_all("set-cookie") or []:
                cookies_exc.append(val.split(";")[0].strip())
        return {
            "status_code": exc.code,
            "headers": header_dict_exc,
            "cookies": cookies_exc,
            "body_snippet": body_snippet,
            "elapsed_ms": round(elapsed_ms, 2),
            "error": None,
        }
    except Exception as exc:
        elapsed_ms = (time.monotonic() - t0) * 1000.0
        return {
            "status_code": 0,
            "headers": {},
            "cookies": [],
            "body_snippet": "",
            "elapsed_ms": round(elapsed_ms, 2),
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# WAF fingerprint matching helpers
# ---------------------------------------------------------------------------


def _score_match(response: Dict[str, Any], fingerprint: Dict[str, Any]) -> float:
    """
    Compute a confidence score (0.0–1.0) for a single fingerprint against a probe.

    Scoring breakdown:
    - Each matched header key       → +0.15 (max 0.30 total from headers)
    - Header value substring match  → +0.05 bonus per value match
    - Each matched cookie prefix     → +0.20
    - Status code match              → +0.15
    - Each body pattern match        → +0.10 (max 0.30 total from body)
    - Each error page pattern match  → +0.10 (max 0.20 total from error patterns)

    The final score is clamped to [0.0, 1.0].
    """
    score = 0.0
    resp_headers: Dict[str, str] = response.get("headers", {})
    resp_cookies_raw: List[str] = response.get("cookies", [])
    resp_status: int = response.get("status_code", 0)
    resp_body: str = response.get("body_snippet", "").lower()

    # --- Headers ---
    fp_headers: Dict[str, Optional[str]] = fingerprint.get("headers", {})
    header_hits = 0
    for hdr_name, hdr_val in fp_headers.items():
        if hdr_name.lower() in resp_headers:
            if header_hits < 2:
                score += 0.15
                header_hits += 1
            # Bonus: header value contains expected substring
            if hdr_val and hdr_val.lower() in resp_headers[hdr_name.lower()].lower():
                score += 0.05

    # --- Cookies ---
    fp_cookies: List[str] = fingerprint.get("cookies", [])
    cookie_names_in_resp = [c.split("=")[0].lower() for c in resp_cookies_raw]
    for ck in fp_cookies:
        if ck.lower() in cookie_names_in_resp:
            score += 0.20
            break  # One cookie hit is enough evidence

    # --- Status codes ---
    fp_statuses: List[int] = fingerprint.get("status_codes", [])
    if resp_status in fp_statuses:
        score += 0.15

    # --- Body patterns ---
    fp_body_patterns: List[str] = fingerprint.get("body_patterns", [])
    body_hits = 0
    for pat in fp_body_patterns:
        if pat.lower() in resp_body:
            if body_hits < 3:
                score += 0.10
                body_hits += 1

    # --- Error page patterns ---
    fp_error_patterns: List[str] = fingerprint.get("error_page_patterns", [])
    error_hits = 0
    for pat in fp_error_patterns:
        if pat.lower() in resp_body:
            if error_hits < 2:
                score += 0.10
                error_hits += 1

    return min(score, 1.0)


def _match_waf_fingerprints(
    responses: List[Dict[str, Any]], fingerprints: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Match a list of probe responses against all fingerprints.

    Scores are accumulated across all probe responses (a multi-probe hit
    increases confidence). Returns matches sorted descending by score, only
    including fingerprints whose cumulative score exceeds 0.10.
    """
    scores: Dict[str, float] = {}
    for response in responses:
        for fp in fingerprints:
            fid = fp["id"]
            scores[fid] = scores.get(fid, 0.0) + _score_match(response, fp)

    matches = []
    for fp in fingerprints:
        fid = fp["id"]
        cumulative = scores.get(fid, 0.0)
        # Normalise: multiple probes can push score > 1.0; re-clamp
        normalised = min(cumulative, 1.0)
        if normalised > 0.10:
            matches.append(
                {
                    "waf_id": fid,
                    "waf_name": fp.get("name", fid),
                    "vendor": fp.get("vendor", "Unknown"),
                    "confidence": round(normalised, 3),
                    "description": fp.get("description", ""),
                }
            )

    matches.sort(key=lambda m: m["confidence"], reverse=True)
    return matches


# ---------------------------------------------------------------------------
# WAF bypass response classifier
# ---------------------------------------------------------------------------

# Patterns in response body that indicate a WAF block page
_BLOCK_BODY_PATTERNS = [
    "access denied",
    "forbidden",
    "request blocked",
    "blocked by",
    "security policy",
    "firewall",
    "your ip",
    "attention required",
    "ddos protection",
    "bot protection",
    "challenge",
    "captcha",
    "suspicious activity",
    "malicious",
    "illegal request",
    "web application firewall",
]


def _classify_response(response: Dict[str, Any], waf_name: Optional[str] = None) -> str:
    """
    Classify a WAF bypass probe response.

    Returns
    -------
    "bypassed"  — HTTP 2xx with no obvious WAF block signals.
    "blocked"   — HTTP 4xx/5xx WAF block codes or body contains WAF error page.
    "error"     — Network/protocol error (status_code == 0 or non-nil error field).
    """
    if response.get("error") or response.get("status_code", 0) == 0:
        return "error"

    status = response["status_code"]
    body_lower = response.get("body_snippet", "").lower()

    # Classic WAF block status codes
    if status in (403, 406, 412, 429, 501, 503):
        return "blocked"

    # Scan body for WAF-specific block patterns
    for pat in _BLOCK_BODY_PATTERNS:
        if pat in body_lower:
            return "blocked"

    if 200 <= status < 300:
        return "bypassed"

    return "blocked"


# ---------------------------------------------------------------------------
# Payload encoding helpers
# ---------------------------------------------------------------------------


def _encode_base64(payload: str) -> str:
    """Base64-encode the payload."""
    return base64.b64encode(payload.encode("utf-8")).decode("ascii")


def _encode_url(payload: str) -> str:
    """URL-encode special characters (safe chars left unchanged)."""
    return urllib.parse.quote(payload, safe="")


def _encode_double_url(payload: str) -> str:
    """Double URL-encode (encode the percent signs from first encoding)."""
    first = urllib.parse.quote(payload, safe="")
    return urllib.parse.quote(first, safe="")


def _encode_unicode(payload: str) -> str:
    """Convert each non-ASCII character to \\uXXXX escape; ASCII left intact."""
    result = []
    for ch in payload:
        if ord(ch) > 127:
            result.append(f"\\u{ord(ch):04x}")
        else:
            result.append(ch)
    return "".join(result)


def _encode_html_entity(payload: str) -> str:
    """Convert every character to decimal HTML entity (&amp;#XX;)."""
    return "".join(f"&#{ord(ch)};" for ch in payload)


def _encode_hex(payload: str) -> str:
    """Hex-encode every character as \\xXX."""
    return "".join(f"\\x{ord(ch):02x}" for ch in payload)


def _encode_null_byte(payload: str) -> str:
    """Insert a null byte (%00) between every character."""
    return "%00".join(payload)


_SQL_KEYWORDS_RE = re.compile(
    r"\b(SELECT|UNION|FROM|WHERE|INSERT|UPDATE|DROP|TABLE)\b", re.IGNORECASE
)


def _encode_comment_sql(payload: str) -> str:
    """Insert SQL inline comments /**/ between SQL keywords and spaces."""
    # Replace spaces with /**/
    result = re.sub(r"\s+", "/**/", payload)
    # Fragment recognised SQL keywords by inserting /**/ at mid-point in a single pass
    def _fragment(m: re.Match) -> str:  # type: ignore[type-arg]
        kw = m.group(0)
        mid = len(kw) // 2
        return kw[:mid] + "/**/" + kw[mid:]

    return _SQL_KEYWORDS_RE.sub(_fragment, result)


def _encode_case_variation(payload: str) -> str:
    """
    Randomly vary the case of alphabetic characters.

    Output is intentionally non-deterministic — each call may return a
    different casing variant. This is by design: WAF bypass relies on
    producing varied requests to avoid pattern matching.
    """
    result = []
    for ch in payload:
        if ch.isalpha():
            result.append(ch.upper() if random.random() > 0.5 else ch.lower())
        else:
            result.append(ch)
    return "".join(result)


_ENCODING_FUNCTIONS = {
    "base64": _encode_base64,
    "url": _encode_url,
    "double_url": _encode_double_url,
    "unicode": _encode_unicode,
    "html_entity": _encode_html_entity,
    "hex": _encode_hex,
    "null_byte": _encode_null_byte,
    "comment_sql": _encode_comment_sql,
    "case_variation": _encode_case_variation,
}

_REVERSIBILITY: Dict[str, bool] = {
    "base64": True,
    "url": True,
    "double_url": True,
    "unicode": True,
    "html_entity": True,
    "hex": True,
    "null_byte": False,
    "comment_sql": False,
    "case_variation": False,
}


# ---------------------------------------------------------------------------
# WAFDetectTool
# ---------------------------------------------------------------------------


class WAFDetectTool(BaseTool):
    """
    Detect WAF/IDS presence via HTTP probe analysis.

    Sends normal and probe requests to the target URL, then matches response
    headers, cookies, status codes, and body content against 55+ WAF signatures.
    Returns detection results with a confidence score (0.0–1.0).

    OWASP: A05:2021-Security Misconfiguration
    MITRE: T1595 (Active Scanning)
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="waf_detect",
            description=(
                "Detect WAF/IDS presence by sending probe HTTP requests and analyzing "
                "response headers, cookies, status codes, and body content against 55+ "
                "WAF signatures. Returns detected WAF name and confidence score (0.0–1.0). "
                "OWASP: A05:2021-Security Misconfiguration | MITRE: T1595"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL to probe (e.g. https://example.com/page)",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "HTTP request timeout in seconds (default: 10)",
                        "default": 10,
                    },
                    "aggressive": {
                        "type": "boolean",
                        "description": (
                            "If true, send additional probe payloads (SQLi probe) "
                            "to trigger WAF blocking responses (default: false)"
                        ),
                        "default": False,
                    },
                },
                "required": ["url"],
            },
        )

    async def execute(self, **kwargs: Any) -> str:  # noqa: C901
        url: str = kwargs.get("url", "").strip()
        timeout: int = int(kwargs.get("timeout", 10))
        aggressive: bool = bool(kwargs.get("aggressive", False))

        if not url:
            return "Error: 'url' parameter is required."
        if not url.startswith(("http://", "https://")):
            return "Error: 'url' must start with http:// or https://"

        fingerprints = _load_waf_fingerprints()
        if not fingerprints:
            return "Error: Could not load WAF fingerprint database."

        # Build list of probes: (url, payload)
        probes: List[Tuple[str, Optional[str]]] = [
            (url, None),  # baseline — no payload
            (url, "<script>alert(1)</script>"),  # mild XSS probe
        ]
        if aggressive:
            probes.append((url, "1 OR 1=1--"))  # SQLi probe

        probe_results: List[Dict[str, Any]] = []
        for probe_url, payload in probes:
            result = await asyncio.to_thread(_send_probe, probe_url, payload, timeout)
            probe_results.append(result)

        # Check for network-level errors on baseline
        if probe_results[0].get("error"):
            return json.dumps(
                {
                    "error": f"Failed to reach {url}: {probe_results[0]['error']}",
                    "waf_detected": False,
                },
                indent=2,
            )

        matches = _match_waf_fingerprints(probe_results, fingerprints)

        # Build matched_signals list for the top match
        top_match = matches[0] if matches else None
        matched_signals: List[str] = []
        if top_match:
            fp = next((f for f in fingerprints if f["id"] == top_match["waf_id"]), None)
            if fp:
                resp_headers = probe_results[0].get("headers", {})
                resp_body = " ".join(
                    r.get("body_snippet", "") for r in probe_results
                ).lower()
                resp_cookies_raw = probe_results[0].get("cookies", [])
                cookie_names = [c.split("=")[0].lower() for c in resp_cookies_raw]

                for hdr in fp.get("headers", {}):
                    if hdr.lower() in resp_headers:
                        matched_signals.append(f"header:{hdr}")
                for ck in fp.get("cookies", []):
                    if ck.lower() in cookie_names:
                        matched_signals.append(f"cookie:{ck}")
                for pat in fp.get("body_patterns", []):
                    if pat.lower() in resp_body:
                        matched_signals.append(f"body:{pat}")
                for pat in fp.get("error_page_patterns", []):
                    if pat.lower() in resp_body:
                        matched_signals.append(f"error_page:{pat}")
                if probe_results[0]["status_code"] in fp.get("status_codes", []):
                    matched_signals.append(f"status_code:{probe_results[0]['status_code']}")

        result_data: Dict[str, Any]
        if top_match and top_match["confidence"] >= 0.15:
            result_data = {
                "waf_detected": True,
                "waf_name": top_match["waf_name"],
                "waf_id": top_match["waf_id"],
                "vendor": top_match["vendor"],
                "confidence": top_match["confidence"],
                "matched_signals": matched_signals,
                "all_matches": matches,
                "probe_summary": {
                    "num_probes": len(probe_results),
                    "aggressive_mode": aggressive,
                    "baseline_status": probe_results[0]["status_code"],
                },
            }
        else:
            result_data = {
                "waf_detected": False,
                "waf_name": None,
                "confidence": 0.0,
                "matched_signals": [],
                "message": (
                    "No WAF detected above confidence threshold. "
                    "The target may be unprotected or using a custom/unknown WAF."
                ),
                "probe_summary": {
                    "num_probes": len(probe_results),
                    "aggressive_mode": aggressive,
                    "baseline_status": probe_results[0]["status_code"],
                },
            }

        return truncate_output(json.dumps(result_data, indent=2))


# ---------------------------------------------------------------------------
# WAFBypassTool
# ---------------------------------------------------------------------------


class WAFBypassTool(BaseTool):
    """
    Automatically apply WAF bypass techniques from the payload database.

    Selects payloads by attack type and, if provided, by WAF-specific variants.
    Classifies each response as BYPASSED, BLOCKED, or ERROR.

    OWASP: A03:2021-Injection, A05:2021-Security Misconfiguration
    MITRE: T1027 (Obfuscated Files or Information)
    """

    _VALID_ATTACK_TYPES = frozenset(["sqli", "xss", "rce", "lfi", "xxe", "ssti"])

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="waf_bypass",
            description=(
                "Automatically select and apply WAF bypass techniques based on detected "
                "WAF type and target attack category. Fires payloads from the database, "
                "classifying each response as BYPASSED, BLOCKED, or ERROR. "
                "OWASP: A03:2021-Injection | MITRE: T1027"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL to test bypass payloads against",
                    },
                    "waf_name": {
                        "type": "string",
                        "description": (
                            "Name of detected WAF (e.g. 'cloudflare', 'akamai'). "
                            "If provided, WAF-specific payloads are preferred."
                        ),
                    },
                    "attack_type": {
                        "type": "string",
                        "enum": ["sqli", "xss", "rce", "lfi", "xxe", "ssti"],
                        "description": "Attack category to test bypass payloads for",
                    },
                    "parameter": {
                        "type": "string",
                        "description": "Query parameter name to inject payload into (e.g. 'id')",
                    },
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST", "PUT"],
                        "description": "HTTP method (default: GET)",
                        "default": "GET",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of payloads to try (default: 20)",
                        "default": 20,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Request timeout in seconds (default: 10)",
                        "default": 10,
                    },
                },
                "required": ["url", "attack_type", "parameter"],
            },
        )

    async def execute(self, **kwargs: Any) -> str:  # noqa: C901
        url: str = kwargs.get("url", "").strip()
        waf_name: Optional[str] = kwargs.get("waf_name", "").strip().lower() or None
        attack_type: str = kwargs.get("attack_type", "").strip().lower()
        parameter: str = kwargs.get("parameter", "").strip()
        method: str = kwargs.get("method", "GET").upper()
        limit: int = int(kwargs.get("limit", 20))
        timeout: int = int(kwargs.get("timeout", 10))

        if not url:
            return "Error: 'url' parameter is required."
        if not url.startswith(("http://", "https://")):
            return "Error: 'url' must start with http:// or https://"
        if attack_type not in self._VALID_ATTACK_TYPES:
            return (
                f"Error: 'attack_type' must be one of {sorted(self._VALID_ATTACK_TYPES)}. "
                f"Got: '{attack_type}'"
            )
        if not parameter:
            return "Error: 'parameter' is required."

        payload_db = _load_bypass_payloads()
        payloads: List[Dict[str, Any]] = []

        # Prefer WAF-specific payloads for the requested attack type
        if waf_name:
            waf_specific = payload_db.get("waf_specific", {})
            for key in waf_specific:
                if key.lower() == waf_name or waf_name in key.lower():
                    type_payloads = waf_specific[key]
                    if isinstance(type_payloads, dict):
                        payloads.extend(type_payloads.get(attack_type, []))
                    elif isinstance(type_payloads, list):
                        payloads.extend(type_payloads)
                    break

        # Fall back to / supplement with general category payloads
        categories = payload_db.get("categories", {})
        cat_data = categories.get(attack_type, {})
        general_payloads: List[Dict[str, Any]] = []
        if isinstance(cat_data, dict):
            general_payloads = cat_data.get("payloads", [])
        elif isinstance(cat_data, list):
            general_payloads = cat_data

        # Merge: WAF-specific first, then general (deduplicated by payload string)
        seen_payloads: set = {p.get("payload", "") for p in payloads}
        for gp in general_payloads:
            if gp.get("payload", "") not in seen_payloads:
                payloads.append(gp)
                seen_payloads.add(gp.get("payload", ""))

        if not payloads:
            return json.dumps(
                {
                    "error": (
                        f"No payloads found for attack_type='{attack_type}'"
                        + (f", waf='{waf_name}'" if waf_name else "")
                    )
                },
                indent=2,
            )

        payloads = payloads[:limit]

        total_tested = 0
        bypassed_count = 0
        blocked_count = 0
        error_count = 0
        bypassed_payloads: List[Dict[str, Any]] = []

        for entry in payloads:
            raw_payload: str = entry.get("payload", "")
            if not raw_payload:
                continue

            # Construct target URL with injected parameter
            sep = "&" if "?" in url else "?"
            probe_url = f"{url}{sep}{urllib.parse.quote(parameter, safe='')}={urllib.parse.quote(raw_payload, safe='')}"

            response = await asyncio.to_thread(_send_probe, probe_url, None, timeout, method)
            classification = _classify_response(response, waf_name)

            total_tested += 1
            if classification == "bypassed":
                bypassed_count += 1
                bypassed_payloads.append(
                    {
                        "payload": raw_payload,
                        "description": entry.get("description", ""),
                        "technique": entry.get("technique", ""),
                        "severity": entry.get("severity", ""),
                        "status_code": response["status_code"],
                        "elapsed_ms": response["elapsed_ms"],
                    }
                )
            elif classification == "blocked":
                blocked_count += 1
            else:
                error_count += 1

        result: Dict[str, Any] = {
            "url": url,
            "waf_name": waf_name,
            "attack_type": attack_type,
            "parameter": parameter,
            "total_tested": total_tested,
            "bypassed_count": bypassed_count,
            "blocked_count": blocked_count,
            "error_count": error_count,
            "bypass_rate": (
                round(bypassed_count / total_tested, 3) if total_tested > 0 else 0.0
            ),
            "bypassed_payloads": bypassed_payloads,
        }

        return truncate_output(json.dumps(result, indent=2))


# ---------------------------------------------------------------------------
# PayloadEncoderTool
# ---------------------------------------------------------------------------


class PayloadEncoderTool(BaseTool):
    """
    Encode and obfuscate attack payloads to evade WAF detection.

    Supports base64, URL, double-URL, Unicode, HTML entity, hex, null-byte,
    SQL comment insertion, case variation, and an "all" mode that returns every
    variant at once.

    OWASP: A03:2021-Injection
    MITRE: T1027 (Obfuscated Files or Information)
    """

    _VALID_ENCODINGS = frozenset(
        [
            "base64",
            "url",
            "double_url",
            "unicode",
            "html_entity",
            "hex",
            "null_byte",
            "comment_sql",
            "case_variation",
            "all",
        ]
    )

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="payload_encoder",
            description=(
                "Encode and obfuscate attack payloads to evade WAF detection. "
                "Supports base64, url, double_url, unicode, html_entity, hex, "
                "null_byte, comment_sql, case_variation, and 'all' (returns all variants). "
                "OWASP: A03:2021-Injection | MITRE: T1027"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "payload": {
                        "type": "string",
                        "description": "Original attack payload to encode/obfuscate",
                    },
                    "encoding": {
                        "type": "string",
                        "enum": [
                            "base64",
                            "url",
                            "double_url",
                            "unicode",
                            "html_entity",
                            "hex",
                            "null_byte",
                            "comment_sql",
                            "case_variation",
                            "all",
                        ],
                        "description": "Encoding technique to apply",
                    },
                    "context": {
                        "type": "string",
                        "enum": ["url", "html", "sql", "js", "header"],
                        "description": (
                            "Optional target context hint for smart encoding selection "
                            "(url → prefer url/double_url, html → prefer html_entity, "
                            "sql → prefer comment_sql, js → prefer unicode/hex)."
                        ),
                    },
                },
                "required": ["payload", "encoding"],
            },
        )

    async def execute(self, **kwargs: Any) -> str:
        payload: str = kwargs.get("payload", "")
        encoding: str = kwargs.get("encoding", "").strip().lower()
        context: Optional[str] = kwargs.get("context", "").strip().lower() or None

        if not payload:
            return "Error: 'payload' parameter is required."
        if encoding not in self._VALID_ENCODINGS:
            return (
                f"Error: 'encoding' must be one of {sorted(self._VALID_ENCODINGS)}. "
                f"Got: '{encoding}'"
            )

        if encoding == "all":
            variants: Dict[str, Any] = {}
            for enc_name, enc_fn in _ENCODING_FUNCTIONS.items():
                try:
                    variants[enc_name] = {
                        "encoded": enc_fn(payload),
                        "reversible": _REVERSIBILITY.get(enc_name, False),
                    }
                except Exception as exc:
                    variants[enc_name] = {"error": str(exc)}

            result: Dict[str, Any] = {
                "original": payload,
                "encoding": "all",
                "context": context,
                "variants": variants,
                "recommended": self._recommend_encoding(context),
            }
            return truncate_output(json.dumps(result, indent=2))

        enc_fn = _ENCODING_FUNCTIONS.get(encoding)
        if enc_fn is None:
            return f"Error: Encoding '{encoding}' is not implemented."

        try:
            encoded = enc_fn(payload)
        except Exception as exc:
            return json.dumps({"error": f"Encoding failed: {exc}"}, indent=2)

        result = {
            "original": payload,
            "encoding": encoding,
            "encoded": encoded,
            "reversible": _REVERSIBILITY.get(encoding, False),
            "context": context,
            "length_original": len(payload),
            "length_encoded": len(encoded),
            "expansion_ratio": round(len(encoded) / max(len(payload), 1), 2),
        }
        return truncate_output(json.dumps(result, indent=2))

    @staticmethod
    def _recommend_encoding(context: Optional[str]) -> str:
        """Return a recommended encoding name for a given context hint."""
        mapping = {
            "url": "double_url",
            "html": "html_entity",
            "sql": "comment_sql",
            "js": "unicode",
            "header": "url",
        }
        return mapping.get(context or "", "url")


# ---------------------------------------------------------------------------
# WAFFingerprintTool
# ---------------------------------------------------------------------------


class WAFFingerprintTool(BaseTool):
    """
    Passive WAF fingerprinting via timing analysis and response header/cookie inspection.

    No attack payloads are sent. Safe for stealth reconnaissance. Collects
    timing samples to detect WAF inspection overhead and checks passive signals
    (headers, cookies, server banner) against the fingerprint database.

    OWASP: A05:2021-Security Misconfiguration
    MITRE: T1595 (Active Scanning — passive variant)
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="waf_fingerprint_passive",
            description=(
                "Passive WAF fingerprinting via response timing analysis and "
                "header/cookie inspection — no attack probes sent. Safe for stealth "
                "reconnaissance. Returns detected WAF, confidence, timing statistics, "
                "and passive signals list. Results are marked stealth_safe: true. "
                "OWASP: A05:2021-Security Misconfiguration | MITRE: T1595"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL to passively fingerprint",
                    },
                    "num_requests": {
                        "type": "integer",
                        "description": "Number of timing samples to collect (default: 3)",
                        "default": 3,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Request timeout in seconds (default: 15)",
                        "default": 15,
                    },
                },
                "required": ["url"],
            },
        )

    async def execute(self, **kwargs: Any) -> str:  # noqa: C901
        url: str = kwargs.get("url", "").strip()
        num_requests: int = max(1, int(kwargs.get("num_requests", 3)))
        timeout: int = int(kwargs.get("timeout", 15))

        if not url:
            return "Error: 'url' parameter is required."
        if not url.startswith(("http://", "https://")):
            return "Error: 'url' must start with http:// or https://"

        fingerprints = _load_waf_fingerprints()
        if not fingerprints:
            return "Error: Could not load WAF fingerprint database."

        # Send HEAD requests for timing (smaller payload = faster round trip)
        timing_samples: List[float] = []
        latest_response: Optional[Dict[str, Any]] = None

        for i in range(num_requests):
            # Use HEAD first; fall back to GET if HEAD returns 405
            response = await asyncio.to_thread(_send_probe, url, None, timeout, "HEAD")
            if response.get("status_code") == 405:
                response = await asyncio.to_thread(_send_probe, url, None, timeout, "GET")
            if response.get("error"):
                if i == 0:
                    return json.dumps(
                        {"error": f"Failed to reach {url}: {response['error']}"},
                        indent=2,
                    )
                continue
            timing_samples.append(response["elapsed_ms"])
            latest_response = response
            # Small delay between samples to get realistic timings
            if i < num_requests - 1:
                await asyncio.sleep(0.3)

        if not timing_samples or latest_response is None:
            return json.dumps(
                {"error": "All probe requests failed — could not collect timing data."},
                indent=2,
            )

        # Timing statistics
        mean_ms = sum(timing_samples) / len(timing_samples)
        variance = (
            sum((t - mean_ms) ** 2 for t in timing_samples) / len(timing_samples)
            if len(timing_samples) > 1
            else 0.0
        )
        stddev_ms = math.sqrt(variance)
        timing_stats: Dict[str, float] = {
            "mean_ms": round(mean_ms, 2),
            "stddev_ms": round(stddev_ms, 2),
            "min_ms": round(min(timing_samples), 2),
            "max_ms": round(max(timing_samples), 2),
            "samples": timing_samples,
        }

        # Passive signal collection (headers + cookies only — no body patterns)
        passive_signals: List[str] = []
        resp_headers: Dict[str, str] = latest_response.get("headers", {})
        resp_cookies_raw: List[str] = latest_response.get("cookies", [])
        cookie_names = [c.split("=")[0].lower() for c in resp_cookies_raw]

        # Server header hint
        server_header = resp_headers.get("server", "")
        if server_header:
            passive_signals.append(f"server_header:{server_header}")

        # Via / x-forwarded-by
        via = resp_headers.get("via", "")
        if via:
            passive_signals.append(f"via_header:{via}")

        # Match fingerprints using passive signals only (headers + cookies)
        passive_matches: List[Dict[str, Any]] = []
        for fp in fingerprints:
            score = 0.0
            fp_headers: Dict[str, Optional[str]] = fp.get("headers", {})
            header_hits = 0
            for hdr_name, hdr_val in fp_headers.items():
                if hdr_name.lower() in resp_headers:
                    if header_hits < 2:
                        score += 0.20
                        header_hits += 1
                        passive_signals.append(f"header:{hdr_name}")
                    if hdr_val and hdr_val.lower() in resp_headers[hdr_name.lower()].lower():
                        score += 0.05

            for ck in fp.get("cookies", []):
                if ck.lower() in cookie_names:
                    score += 0.25
                    passive_signals.append(f"cookie:{ck}")
                    break

            if score > 0.10:
                passive_matches.append(
                    {
                        "waf_id": fp["id"],
                        "waf_name": fp.get("name", fp["id"]),
                        "vendor": fp.get("vendor", "Unknown"),
                        "confidence": round(min(score, 1.0), 3),
                    }
                )

        passive_matches.sort(key=lambda m: m["confidence"], reverse=True)
        top = passive_matches[0] if passive_matches else None

        # Deduplicate signals
        passive_signals = list(dict.fromkeys(passive_signals))

        result: Dict[str, Any] = {
            "stealth_safe": True,
            "url": url,
            "detected_waf": top["waf_name"] if top else None,
            "waf_id": top["waf_id"] if top else None,
            "vendor": top["vendor"] if top else None,
            "confidence": top["confidence"] if top else 0.0,
            "timing_stats": timing_stats,
            "passive_signals": passive_signals,
            "all_matches": passive_matches,
            "note": (
                "Passive fingerprinting only — no attack payloads sent. "
                "Run waf_detect with aggressive=true for higher confidence."
            ),
        }

        return truncate_output(json.dumps(result, indent=2))

"""
IDOR & Access Control Testing Suite

Implements three agent tools for Insecure Direct Object Reference (IDOR)
and privilege escalation testing:

  IDORDetectTool              — enumerate object references (sequential IDs,
                                UUIDs) to discover access-control gaps.
  IDORExploitTool             — cross-user resource access verification and
                                automated exploitation with evidence capture.
  PrivilegeEscalationWebTool  — horizontal / vertical privilege escalation
                                via role manipulation and parameter tampering.

OWASP Mapping: A01:2021-Broken Access Control
"""

from __future__ import annotations

import logging
import re
import urllib.parse
from enum import Enum
from typing import Any, Dict, List, Optional

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import truncate_output
from app.mcp.base_server import MCPClient

logger = logging.getLogger(__name__)

DEFAULT_CURL_SERVER_URL = "http://kali-tools:8001"

OWASP_IDOR_TAG = "A01:2021-Broken Access Control (IDOR)"
OWASP_PRIVESC_TAG = "A01:2021-Broken Access Control (Privilege Escalation)"


# ---------------------------------------------------------------------------
# Risk / severity enumerations
# ---------------------------------------------------------------------------


class IDORRisk(str, Enum):
    """Risk level of an IDOR finding."""
    CRITICAL = "critical"  # Cross-account data access or modification confirmed
    HIGH = "high"          # Confirmed read access to another user's resource
    MEDIUM = "medium"      # Potential IDOR — response differs but not definitively
    LOW = "low"            # Sequential IDs found but no cross-user access verified
    NONE = "none"          # No IDOR indicators


class PrivEscRisk(str, Enum):
    """Risk level of a privilege escalation finding."""
    CRITICAL = "critical"  # Full admin / superuser access obtained
    HIGH = "high"          # Elevated role confirmed
    MEDIUM = "medium"      # Role parameter accepted but effect unverified
    LOW = "low"            # Role field visible but change rejected
    NONE = "none"          # No privilege escalation vector detected


# ---------------------------------------------------------------------------
# ID generators and helpers
# ---------------------------------------------------------------------------

_SEQUENTIAL_ID_RANGE = 5   # Number of sequential IDs to probe around base


def _generate_sequential_ids(base_id: int, count: int = _SEQUENTIAL_ID_RANGE) -> List[int]:
    """Generate sequential integer IDs around a base ID."""
    ids: List[int] = []
    start = max(1, base_id - count)
    end = base_id + count + 1
    for i in range(start, end):
        if i != base_id:
            ids.append(i)
    return ids[:count * 2]


def _generate_uuid_variants(base_uuid: str) -> List[str]:
    """Generate known UUIDs that differ from the base for probing."""
    variants = [
        "00000000-0000-0000-0000-000000000001",
        "00000000-0000-0000-0000-000000000002",
        "11111111-1111-1111-1111-111111111111",
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    ]
    return [v for v in variants if v != base_uuid]


def _looks_like_uuid(value: str) -> bool:
    """Return True if value matches UUID v4 format."""
    _UUID_RE = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        re.IGNORECASE,
    )
    return bool(_UUID_RE.match(value.strip()))


def _extract_id_from_url(url: str) -> Optional[str]:
    """Extract the last path segment that looks like an ID (int or UUID)."""
    parsed = urllib.parse.urlparse(url)
    segments = [s for s in parsed.path.split("/") if s]
    if not segments:
        return None
    last = segments[-1]
    if last.isdigit() or _looks_like_uuid(last):
        return last
    # Try second-to-last for patterns like /users/{id}/profile
    if len(segments) >= 2:
        penultimate = segments[-2]
        if penultimate.isdigit() or _looks_like_uuid(penultimate):
            return penultimate
    return None


def _substitute_id_in_url(url: str, original_id: str, new_id: Any) -> str:
    """Replace the first occurrence of original_id in the URL path with new_id."""
    parsed = urllib.parse.urlparse(url)
    new_path = parsed.path.replace(str(original_id), str(new_id), 1)
    return urllib.parse.urlunparse(parsed._replace(path=new_path))


def _response_differs(body1: str, body2: str, threshold: float = 0.9) -> bool:
    """Heuristic: return True if responses appear to contain different data.

    We compare length and a simple content hash to detect meaningful difference
    (rather than minor whitespace changes).
    """
    if not body1 and not body2:
        return False
    if not body1 or not body2:
        return True
    # Check for common 403/401/404 markers in body2 FIRST (before length check),
    # so a short "Access Denied" body is correctly classified as not different.
    for marker in ("access denied", "forbidden", "not found", "unauthorized", "403", "404", "401"):
        if marker in body2.lower() and marker not in body1.lower():
            return False  # Access was denied for probed ID — not vulnerable
    ratio = len(body2) / max(len(body1), 1)
    if ratio < 0.5 or ratio > 2.0:
        return True
    return body1[:200] != body2[:200]


def _is_access_denied(status: int, body: str) -> bool:
    """Return True if the response indicates an access denial."""
    if status in (401, 403, 404):
        return True
    denial_markers = (
        "access denied", "forbidden", "unauthorized", "not found",
        "not allowed", "not authorized", "permission denied",
    )
    return any(m in body.lower() for m in denial_markers)


# ---------------------------------------------------------------------------
# Role manipulation helpers
# ---------------------------------------------------------------------------

_ADMIN_ROLE_VALUES: List[str] = [
    "admin", "administrator", "superuser", "root", "super_admin",
    "ADMIN", "ADMINISTRATOR", "SUPERUSER",
    "1", "true", "yes",
]

_ROLE_PARAMETERS: List[str] = [
    "role", "user_role", "userRole", "privilege", "level",
    "is_admin", "isAdmin", "admin", "group", "permissions",
    "account_type", "accountType", "type", "user_type", "userType",
]


# ---------------------------------------------------------------------------
# IDORDetectTool
# ---------------------------------------------------------------------------


class IDORDetectTool(BaseTool):
    """Detect Insecure Direct Object References by parameter enumeration.

    Probes sequential integer IDs and UUID variants around the user-supplied
    base ID to discover whether the server returns data for other identifiers
    without enforcing ownership checks.

    OWASP A01:2021-Broken Access Control
    """

    def __init__(
        self,
        server_url: str = DEFAULT_CURL_SERVER_URL,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self._server_url = server_url
        self._project_id = project_id
        self._user_id = user_id
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="idor_detect",
            description=(
                "Detect Insecure Direct Object Reference (IDOR) vulnerabilities by "
                "enumerating sequential IDs and UUID variants in URL paths or query "
                "parameters. Reports whether other users' resources are accessible. "
                "OWASP A01:2021-Broken Access Control."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": (
                            "Target URL containing an object ID. The tool will auto-detect "
                            "the ID in the path (e.g. /api/users/42 or /docs/uuid)."
                        ),
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method to use for probing.",
                        "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"],
                        "default": "GET",
                    },
                    "cookies": {
                        "type": "string",
                        "description": "Session cookies for the authenticated user (name=value; ...).",
                        "default": "",
                    },
                    "headers": {
                        "type": "object",
                        "description": "Additional HTTP headers to include.",
                        "default": {},
                    },
                    "base_id": {
                        "type": "string",
                        "description": (
                            "Override the auto-detected ID. Use when the ID is in a query "
                            "parameter rather than the URL path."
                        ),
                        "default": "",
                    },
                    "param_name": {
                        "type": "string",
                        "description": (
                            "Query parameter name containing the ID (e.g. 'id', 'user_id'). "
                            "Required if ID is a query parameter, not a path segment."
                        ),
                        "default": "",
                    },
                    "probe_count": {
                        "type": "integer",
                        "description": "Number of alternative IDs to probe (default 4).",
                        "default": 4,
                    },
                },
                "required": ["url"],
            },
        )

    async def execute(  # type: ignore[override]
        self,
        url: str,
        method: str = "GET",
        cookies: str = "",
        headers: Optional[Dict[str, str]] = None,
        base_id: str = "",
        param_name: str = "",
        probe_count: int = 4,
        **kwargs: Any,
    ) -> str:
        req_headers: Dict[str, str] = dict(headers or {})
        if cookies:
            req_headers["Cookie"] = cookies

        # Resolve the ID to probe
        detected_id = base_id or _extract_id_from_url(url)
        if not detected_id:
            return (
                "[idor_detect] Could not detect an object ID in the URL. "
                "Supply base_id or param_name for query-parameter IDs."
            )

        # Fetch the legitimate baseline
        baseline = await self._fetch(url, method, req_headers)
        if not baseline.get("success"):
            return (
                f"[idor_detect] Failed to fetch baseline {url}: "
                f"{baseline.get('error', 'unknown error')}"
            )
        baseline_body = _get_body(baseline)
        baseline_status = baseline.get("status_code", 200)

        if _is_access_denied(baseline_status, baseline_body):
            return (
                f"[idor_detect] Baseline request returned {baseline_status} — "
                "you may not have access to this resource. Try with valid session cookies."
            )

        # Generate probe IDs
        if _looks_like_uuid(detected_id):
            probe_ids: List[Any] = _generate_uuid_variants(detected_id)[:probe_count]
        else:
            try:
                probe_ids = _generate_sequential_ids(int(detected_id), count=probe_count // 2)
            except ValueError:
                probe_ids = ["1", "2", "3", "4"][:probe_count]

        # Probe each ID
        findings: List[Dict[str, Any]] = []
        for probe in probe_ids:
            if param_name:
                probe_url = _inject_query_param(url, param_name, str(probe))
            else:
                probe_url = _substitute_id_in_url(url, detected_id, probe)

            resp = await self._fetch(probe_url, method, req_headers)
            probe_status = resp.get("status_code", 0)
            probe_body = _get_body(resp)

            if resp.get("success") and not _is_access_denied(probe_status, probe_body):
                if _response_differs(baseline_body, probe_body):
                    findings.append({
                        "probe_id": probe,
                        "probe_url": probe_url,
                        "status": probe_status,
                        "evidence": probe_body[:300],
                    })

        return self._format(url, detected_id, findings)

    async def _fetch(
        self, url: str, method: str, headers: Dict[str, str]
    ) -> Dict[str, Any]:
        try:
            return await self._client.call_tool(
                "execute_curl",
                {"url": url, "method": method, "headers": headers, "follow_redirects": True},
            )
        except Exception as exc:
            logger.debug("IDOR detect fetch failed: %s", exc)
            return {"success": False, "error": str(exc)}

    def _format(
        self,
        url: str,
        base_id: Any,
        findings: List[Dict[str, Any]],
    ) -> str:
        lines = [
            f"[idor_detect] IDOR Analysis: {url}",
            f"  Base ID detected:  {base_id}",
            f"  Probes with data:  {len(findings)}",
            "",
        ]
        if findings:
            risk = IDORRisk.HIGH if len(findings) >= 2 else IDORRisk.MEDIUM
            lines += [
                f"  ⚠ POTENTIAL IDOR FOUND — Risk: {risk.value.upper()}",
                f"  OWASP: {OWASP_IDOR_TAG}",
                "",
                "── Accessible Resources ───────────────────",
            ]
            for f in findings:
                lines += [
                    f"  ID {f['probe_id']}: {f['probe_url']} [{f['status']}]",
                    f"    Evidence: {f['evidence'][:120]}",
                    "",
                ]
            lines += [
                "── Remediation ────────────────────────────",
                "  1. Implement server-side ownership checks before returning resources",
                "  2. Use non-sequential, cryptographically random identifiers (UUIDs v4)",
                "  3. Apply ABAC (Attribute-Based Access Control) — not just RBAC",
                "  4. Log all direct object reference accesses for anomaly detection",
            ]
        else:
            lines += [
                "  ✓ No IDOR detected — access control appears to be enforced.",
                f"  OWASP: {OWASP_IDOR_TAG}",
            ]
        return truncate_output("\n".join(lines))


# ---------------------------------------------------------------------------
# IDORExploitTool
# ---------------------------------------------------------------------------


class IDORExploitTool(BaseTool):
    """Confirm and exploit IDOR by performing cross-user resource access.

    Requires two sets of credentials (victim and attacker). Verifies that the
    attacker's session can read or modify the victim's resource. Captures
    evidence for the pentest report.

    OWASP A01:2021-Broken Access Control
    """

    def __init__(
        self,
        server_url: str = DEFAULT_CURL_SERVER_URL,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self._server_url = server_url
        self._project_id = project_id
        self._user_id = user_id
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="idor_exploit",
            description=(
                "Confirm IDOR exploitation: use attacker session cookies to access "
                "a victim's resource URL. Compares attacker-session response against "
                "a no-auth baseline to produce cross-user access evidence. "
                "OWASP A01:2021-Broken Access Control."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "victim_url": {
                        "type": "string",
                        "description": "URL of the victim's resource (e.g. /api/users/victim_id/profile).",
                    },
                    "victim_cookies": {
                        "type": "string",
                        "description": "Victim's authenticated session cookies.",
                        "default": "",
                    },
                    "attacker_cookies": {
                        "type": "string",
                        "description": "Attacker's authenticated session cookies.",
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method to use.",
                        "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"],
                        "default": "GET",
                    },
                    "body": {
                        "type": "string",
                        "description": "Request body for POST/PUT/PATCH requests.",
                        "default": "",
                    },
                    "content_type": {
                        "type": "string",
                        "description": "Content-Type header for request body.",
                        "default": "application/json",
                    },
                },
                "required": ["victim_url", "attacker_cookies"],
            },
        )

    async def execute(  # type: ignore[override]
        self,
        victim_url: str,
        attacker_cookies: str,
        victim_cookies: str = "",
        method: str = "GET",
        body: str = "",
        content_type: str = "application/json",
        **kwargs: Any,
    ) -> str:
        # Fetch with victim creds for baseline
        victim_headers: Dict[str, str] = {}
        if victim_cookies:
            victim_headers["Cookie"] = victim_cookies

        # Fetch with attacker creds
        attacker_headers: Dict[str, str] = {"Cookie": attacker_cookies}
        if body:
            attacker_headers["Content-Type"] = content_type

        victim_resp = await self._fetch(victim_url, method, victim_headers, body)
        attacker_resp = await self._fetch(victim_url, method, attacker_headers, body)

        return self._format(victim_url, method, victim_resp, attacker_resp)

    async def _fetch(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: str = "",
    ) -> Dict[str, Any]:
        try:
            params: Dict[str, Any] = {
                "url": url,
                "method": method,
                "headers": headers,
                "follow_redirects": True,
            }
            if body:
                params["body"] = body
            return await self._client.call_tool("execute_curl", params)
        except Exception as exc:
            logger.debug("IDOR exploit fetch failed: %s", exc)
            return {"success": False, "error": str(exc)}

    def _format(
        self,
        url: str,
        method: str,
        victim_resp: Dict[str, Any],
        attacker_resp: Dict[str, Any],
    ) -> str:
        victim_status = victim_resp.get("status_code", 0)
        attacker_status = attacker_resp.get("status_code", 0)
        victim_body = _get_body(victim_resp)
        attacker_body = _get_body(attacker_resp)

        victim_denied = _is_access_denied(victim_status, victim_body)
        attacker_denied = _is_access_denied(attacker_status, attacker_body)

        lines = [
            f"[idor_exploit] IDOR Exploitation: {method} {url}",
            "",
            "── Response Comparison ────────────────────",
            f"  Victim session:   HTTP {victim_status} {'✓ (authorized)' if not victim_denied else '✗ (denied)'}",
            f"  Attacker session: HTTP {attacker_status} {'⚠ (accessible!)' if not attacker_denied else '✓ (properly denied)'}",
            "",
        ]

        if not victim_denied and not attacker_denied:
            # Both got access — cross-user access confirmed
            risk = IDORRisk.CRITICAL if victim_body[:200] == attacker_body[:200] else IDORRisk.HIGH
            lines += [
                f"  ⚠ IDOR CONFIRMED — Risk: {risk.value.upper()}",
                f"  OWASP: {OWASP_IDOR_TAG}",
                "",
                "── Victim Response (truncated) ────────────",
                f"  {victim_body[:400]}",
                "",
                "── Attacker Response (truncated) ──────────",
                f"  {attacker_body[:400]}",
                "",
                "── Remediation ────────────────────────────",
                "  1. Validate object ownership on every request using server-side session data",
                "  2. Never rely on client-supplied IDs alone for authorization",
                "  3. Return 403 Forbidden (not 404) for ownership violations to avoid oracle",
                "  4. Implement audit logging for cross-user access attempts",
            ]
        elif victim_denied and not attacker_denied:
            lines += [
                "  ⚠ ANOMALOUS: Victim denied but attacker succeeded — investigate!",
                f"  OWASP: {OWASP_IDOR_TAG}",
            ]
        else:
            lines += [
                "  ✓ Access control enforced — attacker session was denied.",
                f"  OWASP: {OWASP_IDOR_TAG}",
            ]

        return truncate_output("\n".join(lines))


# ---------------------------------------------------------------------------
# PrivilegeEscalationWebTool
# ---------------------------------------------------------------------------


class PrivilegeEscalationWebTool(BaseTool):
    """Test horizontal and vertical privilege escalation via role manipulation.

    Injects elevated role / privilege values into request parameters and
    headers. Tests both horizontal (same-level user access to others' data)
    and vertical (escalating to admin) escalation vectors.

    OWASP A01:2021-Broken Access Control
    """

    def __init__(
        self,
        server_url: str = DEFAULT_CURL_SERVER_URL,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self._server_url = server_url
        self._project_id = project_id
        self._user_id = user_id
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="privilege_escalation_web",
            description=(
                "Test horizontal and vertical web privilege escalation: inject elevated "
                "role values (admin, superuser) into JSON body, form fields, query params, "
                "and HTTP headers. Detects responses that indicate role acceptance. "
                "OWASP A01:2021-Broken Access Control."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target endpoint (e.g. /api/users/profile or /api/account/update).",
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method for the test request.",
                        "enum": ["GET", "POST", "PUT", "PATCH"],
                        "default": "POST",
                    },
                    "cookies": {
                        "type": "string",
                        "description": "Session cookies for the authenticated user.",
                        "default": "",
                    },
                    "body": {
                        "type": "string",
                        "description": "Original request body (JSON). Role fields will be injected.",
                        "default": "{}",
                    },
                    "admin_endpoint": {
                        "type": "string",
                        "description": "Admin-only endpoint to test access after role manipulation.",
                        "default": "",
                    },
                    "escalation_type": {
                        "type": "string",
                        "description": "Type of escalation to test: 'vertical' (to admin) or 'horizontal' (to other user).",
                        "enum": ["vertical", "horizontal", "both"],
                        "default": "both",
                    },
                },
                "required": ["url"],
            },
        )

    async def execute(  # type: ignore[override]
        self,
        url: str,
        method: str = "POST",
        cookies: str = "",
        body: str = "{}",
        admin_endpoint: str = "",
        escalation_type: str = "both",
        **kwargs: Any,
    ) -> str:
        import json

        req_headers: Dict[str, str] = {"Content-Type": "application/json"}
        if cookies:
            req_headers["Cookie"] = cookies

        # Parse original body
        try:
            body_data: Dict[str, Any] = json.loads(body) if body else {}
        except (json.JSONDecodeError, ValueError):
            body_data = {}

        results: List[Dict[str, Any]] = []

        if escalation_type in ("vertical", "both"):
            # Test vertical privilege escalation via body injection
            for role_field in _ROLE_PARAMETERS[:6]:
                for role_val in _ADMIN_ROLE_VALUES[:4]:
                    injected = dict(body_data)
                    injected[role_field] = role_val
                    resp = await self._fetch_json(url, method, req_headers, injected)
                    if _role_accepted(resp):
                        results.append({
                            "vector": "body_injection",
                            "field": role_field,
                            "value": role_val,
                            "status": resp.get("status_code", 0),
                            "evidence": _get_body(resp)[:200],
                        })
                        break  # Found one — move to next field

        if escalation_type in ("vertical", "both") and admin_endpoint:
            # Test admin endpoint access with current session
            resp = await self._fetch(admin_endpoint, "GET", req_headers)
            admin_status = resp.get("status_code", 0)
            if admin_status not in (401, 403, 404):
                results.append({
                    "vector": "admin_endpoint_access",
                    "field": "N/A",
                    "value": "N/A",
                    "status": admin_status,
                    "evidence": f"Admin endpoint {admin_endpoint} returned {admin_status}",
                })

        return self._format(url, escalation_type, results)

    async def _fetch_json(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: Dict[str, Any],
    ) -> Dict[str, Any]:
        import json
        return await self._fetch(url, method, headers, json.dumps(body))

    async def _fetch(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: str = "",
    ) -> Dict[str, Any]:
        try:
            params: Dict[str, Any] = {
                "url": url,
                "method": method,
                "headers": headers,
                "follow_redirects": True,
            }
            if body:
                params["body"] = body
            return await self._client.call_tool("execute_curl", params)
        except Exception as exc:
            logger.debug("PrivEsc web fetch failed: %s", exc)
            return {"success": False, "error": str(exc)}

    def _format(
        self,
        url: str,
        escalation_type: str,
        results: List[Dict[str, Any]],
    ) -> str:
        lines = [
            f"[privilege_escalation_web] Privilege Escalation Test: {url}",
            f"  Type:    {escalation_type}",
            f"  Vectors: {len(results)} potentially vulnerable",
            "",
        ]
        if results:
            risk = PrivEscRisk.CRITICAL if any(r["vector"] == "admin_endpoint_access" for r in results) else PrivEscRisk.HIGH
            lines += [
                f"  ⚠ PRIVILEGE ESCALATION POSSIBLE — Risk: {risk.value.upper()}",
                f"  OWASP: {OWASP_PRIVESC_TAG}",
                "",
                "── Vulnerable Vectors ─────────────────────",
            ]
            for r in results:
                lines += [
                    f"  Vector:  {r['vector']}",
                    f"  Field:   {r['field']}  Value: {r['value']}",
                    f"  Status:  {r['status']}",
                    f"  Evidence: {r['evidence'][:120]}",
                    "",
                ]
            lines += [
                "── Remediation ────────────────────────────",
                "  1. Server must determine role from authenticated session — never from client input",
                "  2. Implement strict RBAC/ABAC with deny-by-default for privileged operations",
                "  3. Audit all role-changing operations with immutable logs",
                "  4. Conduct regular access control reviews and least-privilege audits",
            ]
        else:
            lines += [
                "  ✓ No privilege escalation vectors detected.",
                f"  OWASP: {OWASP_PRIVESC_TAG}",
            ]
        return truncate_output("\n".join(lines))


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _get_body(result: Dict[str, Any]) -> str:
    """Safely extract body string from a curl result dict."""
    body = result.get("body", "")
    if isinstance(body, dict):
        import json
        return json.dumps(body)
    return str(body) if body else ""


def _inject_query_param(url: str, param: str, value: str) -> str:
    """Replace or add a query parameter in a URL."""
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def _role_accepted(resp: Dict[str, Any]) -> bool:
    """Return True if the response suggests the role injection was accepted."""
    status = resp.get("status_code", 0)
    body = _get_body(resp).lower()
    # 200/201/204 with no denial markers
    if status in (200, 201, 204):
        denial = ("access denied", "forbidden", "unauthorized", "not allowed", "invalid role")
        return not any(d in body for d in denial)
    return False


__all__ = [
    "IDORDetectTool",
    "IDORExploitTool",
    "PrivilegeEscalationWebTool",
    "IDORRisk",
    "PrivEscRisk",
    "OWASP_IDOR_TAG",
    "OWASP_PRIVESC_TAG",
    "_generate_sequential_ids",
    "_generate_uuid_variants",
    "_looks_like_uuid",
    "_extract_id_from_url",
    "_substitute_id_in_url",
    "_response_differs",
    "_is_access_denied",
    "_inject_query_param",
    "_get_body",
]

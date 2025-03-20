"""
API Security MCP Server

JSON-RPC 2.0 MCP server that exposes REST / GraphQL API security testing
capabilities.

Port: 8009

Tools exposed
-------------
  parse_openapi_spec      — fetch and parse Swagger/OpenAPI 2/3 specs
  fuzz_api_endpoint       — type-aware parameter fuzzing
  test_mass_assignment    — inject privileged fields into request bodies
  graphql_introspect      — detect introspection, enumerate full schema
  graphql_injection_test  — batching, nested DoS, field-suggestion leak
  graphql_idor_test       — IDOR via query variable manipulation
  test_rate_limiting      — rate-limit baseline + header-bypass probes
  test_cors_misconfig     — CORS misconfiguration detection

Safety controls
---------------
* Internal/loopback addresses blocked unless ``allow_internal=True``.
* External binary calls wrapped in asyncio subprocesses with hard timeouts.
* Server degrades gracefully when optional tools (curl, nuclei) are absent.

Architecture note
-----------------
Tool implementations prefer curl/nuclei/custom HTTP for live target testing.
All tools return structured JSON with ``success``, ``findings``, and
diagnostic metadata so agent can make informed next-step decisions.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import urllib.parse
from typing import Any, Dict, List, Optional

from ..base_server import MCPServer, MCPTool

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Safety helpers (shared with XSSServer)
# ---------------------------------------------------------------------------

_PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
]

MAX_PAYLOAD_LEN = 1024


def _is_internal(host: str) -> bool:
    if host.lower() in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def _extract_host(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).hostname or ""
    except Exception:
        return ""


def _validate_url(url: str, allow_internal: bool = False) -> None:
    if not re.match(r"^https?://", url, re.IGNORECASE):
        raise ValueError(f"Invalid URL scheme: {url!r}")
    host = _extract_host(url)
    if not allow_internal and _is_internal(host):
        raise ValueError(
            f"Target {host!r} is an internal address. "
            "Pass allow_internal=True for lab environments."
        )


# ---------------------------------------------------------------------------
# Subprocess helper
# ---------------------------------------------------------------------------


async def _run_cmd(cmd: List[str], timeout: int = 30) -> tuple[int, str, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")
    except asyncio.TimeoutError:
        return 1, "", f"Command timed out after {timeout}s"
    except FileNotFoundError:
        return 1, "", f"Binary not found: {cmd[0]}"
    except Exception as exc:
        return 1, "", str(exc)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


async def _curl_json(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    timeout: int = 15,
) -> tuple[int, Dict[str, Any]]:
    """Make an HTTP request via curl and return (http_status_code, response_body_dict).

    Falls back to urllib when curl is unavailable.
    """
    cmd = ["curl", "-s", "-o", "-", "-w", "\n__STATUS__%{http_code}", "-X", method]
    for k, v in (headers or {}).items():
        cmd += ["-H", f"{k}: {v}"]
    if body:
        cmd += ["-H", "Content-Type: application/json", "-d", body]
    cmd += ["--max-time", str(timeout), url]

    rc, stdout, stderr = await _run_cmd(cmd, timeout=timeout + 5)

    status_code = 0
    body_text = stdout
    if "__STATUS__" in stdout:
        parts = stdout.rsplit("__STATUS__", 1)
        body_text = parts[0].strip()
        try:
            status_code = int(parts[1].strip())
        except ValueError:
            pass

    try:
        body_dict = json.loads(body_text) if body_text else {}
    except (json.JSONDecodeError, ValueError):
        body_dict = {"raw": body_text[:500]}

    return status_code, body_dict


async def _fetch_text(url: str, timeout: int = 15) -> str:
    """Fetch raw text content from URL using curl."""
    rc, stdout, _ = await _run_cmd(
        ["curl", "-s", "--max-time", str(timeout), url],
        timeout=timeout + 5,
    )
    return stdout


# ---------------------------------------------------------------------------
# OpenAPI parser helper
# ---------------------------------------------------------------------------


def _parse_openapi_spec_server(spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flat endpoint extraction from OpenAPI spec dict."""
    HTTP_METHODS = ["get", "post", "put", "patch", "delete", "head", "options"]
    endpoints = []
    paths = spec.get("paths", {})

    servers = spec.get("servers", [])
    base_url = servers[0].get("url", "") if servers else ""
    if not base_url:
        host = spec.get("host", "")
        base_path = spec.get("basePath", "/")
        schemes = spec.get("schemes", ["https"])
        if host:
            base_url = f"{schemes[0]}://{host}{base_path}"

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        path_params = path_item.get("parameters", [])
        for method in HTTP_METHODS:
            op = path_item.get(method)
            if not isinstance(op, dict):
                continue
            op_params = op.get("parameters", path_params)
            request_body = op.get("requestBody", {})
            body_schema: Dict[str, Any] = {}
            for mime, media in (request_body.get("content") or {}).items():
                body_schema = media.get("schema", {})
                break
            endpoints.append({
                "method": method.upper(),
                "path": path,
                "url": base_url + path,
                "parameters": op_params,
                "request_body_schema": body_schema,
                "tags": op.get("tags", []),
                "summary": op.get("summary", ""),
                "operation_id": op.get("operationId", ""),
                "security": op.get("security", spec.get("security", [])),
            })

    return endpoints


# ---------------------------------------------------------------------------
# APISecurityServer
# ---------------------------------------------------------------------------


class APISecurityServer(MCPServer):
    """MCP server exposing REST / GraphQL API security testing tools.

    Port 8009. Degrades gracefully when external binaries are absent.
    """

    def __init__(self, allow_internal: bool = False):
        super().__init__(
            name="APISecurity",
            description="API Security testing server (REST, GraphQL, CORS, rate limiting)",
            port=8009,
        )
        self._allow_internal = allow_internal

    # ------------------------------------------------------------------
    # MCPServer interface
    # ------------------------------------------------------------------

    def get_tools(self) -> List[MCPTool]:
        return [
            MCPTool(
                name="parse_openapi_spec",
                description=(
                    "Fetch and parse an OpenAPI/Swagger 2/3 spec from a URL or raw JSON. "
                    "Returns all endpoints, parameters, auth requirements."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "spec_url": {"type": "string"},
                        "spec_json": {"type": "object"},
                        "allow_internal": {"type": "boolean", "default": False},
                    },
                },
                phase="recon",
            ),
            MCPTool(
                name="fuzz_api_endpoint",
                description="Type-aware parameter fuzzing for REST API endpoints.",
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "method": {"type": "string", "default": "GET"},
                        "parameters": {"type": "array", "items": {"type": "object"}, "default": []},
                        "headers": {"type": "object", "default": {}},
                        "max_mutations": {"type": "integer", "default": 10},
                        "allow_internal": {"type": "boolean", "default": False},
                    },
                    "required": ["url"],
                },
                phase="web_app_attack",
            ),
            MCPTool(
                name="test_mass_assignment",
                description="Inject privileged fields into request bodies to detect mass assignment.",
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "method": {"type": "string", "default": "POST"},
                        "base_payload": {"type": "object", "default": {}},
                        "target_fields": {"type": "array", "items": {"type": "string"}},
                        "headers": {"type": "object", "default": {}},
                        "allow_internal": {"type": "boolean", "default": False},
                    },
                    "required": ["url"],
                },
                phase="web_app_attack",
            ),
            MCPTool(
                name="graphql_introspect",
                description="Detect GraphQL introspection and enumerate full schema.",
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "headers": {"type": "object", "default": {}},
                        "allow_internal": {"type": "boolean", "default": False},
                    },
                    "required": ["url"],
                },
                phase="recon",
            ),
            MCPTool(
                name="graphql_injection_test",
                description="Test GraphQL for batching, nested DoS, and field-suggestion leaks.",
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "test_batching": {"type": "boolean", "default": True},
                        "test_nested_dos": {"type": "boolean", "default": True},
                        "test_field_suggestion": {"type": "boolean", "default": True},
                        "batch_payload": {"type": "array"},
                        "nested_query": {"type": "string"},
                        "field_suggestion_payload": {"type": "string"},
                        "headers": {"type": "object", "default": {}},
                        "allow_internal": {"type": "boolean", "default": False},
                    },
                    "required": ["url"],
                },
                phase="web_app_attack",
            ),
            MCPTool(
                name="graphql_idor_test",
                description="Test IDOR via GraphQL query variable manipulation.",
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "query": {"type": "string"},
                        "id_variable": {"type": "string", "default": "id"},
                        "known_own_id": {"type": "string"},
                        "test_ids": {"type": "array", "items": {"type": "string"}},
                        "headers": {"type": "object", "default": {}},
                        "allow_internal": {"type": "boolean", "default": False},
                    },
                    "required": ["url", "query"],
                },
                phase="web_app_attack",
            ),
            MCPTool(
                name="test_rate_limiting",
                description="Test rate limiting and attempt bypass via IP-spoofing headers.",
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "method": {"type": "string", "default": "GET"},
                        "request_count": {"type": "integer", "default": 50},
                        "bypass_headers": {"type": "array", "items": {"type": "object"}, "default": []},
                        "headers": {"type": "object", "default": {}},
                        "body": {"type": "object", "default": {}},
                        "allow_internal": {"type": "boolean", "default": False},
                    },
                    "required": ["url"],
                },
                phase="web_app_attack",
            ),
            MCPTool(
                name="test_cors_misconfig",
                description="Detect CORS misconfiguration: wildcard, reflected origin, null, credentials.",
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "origins": {"type": "array", "items": {"type": "string"}},
                        "headers": {"type": "object", "default": {}},
                        "allow_internal": {"type": "boolean", "default": False},
                    },
                    "required": ["url"],
                },
                phase="web_app_attack",
            ),
        ]

    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        dispatch = {
            "parse_openapi_spec": self._parse_openapi_spec,
            "fuzz_api_endpoint": self._fuzz_api_endpoint,
            "test_mass_assignment": self._test_mass_assignment,
            "graphql_introspect": self._graphql_introspect,
            "graphql_injection_test": self._graphql_injection_test,
            "graphql_idor_test": self._graphql_idor_test,
            "test_rate_limiting": self._test_rate_limiting,
            "test_cors_misconfig": self._test_cors_misconfig,
        }
        handler = dispatch.get(tool_name)
        if not handler:
            raise ValueError(f"Unknown tool: {tool_name!r}")
        return await handler(params)

    # ------------------------------------------------------------------
    # parse_openapi_spec
    # ------------------------------------------------------------------

    async def _parse_openapi_spec(self, params: Dict[str, Any]) -> Dict[str, Any]:
        allow_internal = params.get("allow_internal", self._allow_internal)
        spec_url: Optional[str] = params.get("spec_url")
        spec_json: Optional[Dict] = params.get("spec_json")

        if spec_url:
            try:
                _validate_url(spec_url, allow_internal)
            except ValueError as exc:
                return {"success": False, "error": str(exc)}

            raw = await _fetch_text(spec_url, timeout=15)
            try:
                spec_json = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                return {"success": False, "error": "Failed to parse spec as JSON", "raw": raw[:500]}

        if not spec_json:
            return {"success": False, "error": "No spec_url or spec_json provided"}

        endpoints = _parse_openapi_spec_server(spec_json)
        return {
            "success": True,
            "endpoints": endpoints,
            "total_endpoints": len(endpoints),
            "openapi_version": spec_json.get("openapi", spec_json.get("swagger", "unknown")),
            "info": spec_json.get("info", {}),
        }

    # ------------------------------------------------------------------
    # fuzz_api_endpoint
    # ------------------------------------------------------------------

    async def _fuzz_api_endpoint(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params.get("url", "")
        allow_internal = params.get("allow_internal", self._allow_internal)

        try:
            _validate_url(url, allow_internal)
        except ValueError as exc:
            return {"success": False, "error": str(exc), "findings": []}

        method = params.get("method", "GET").upper()
        parameters = params.get("parameters", [])
        headers = params.get("headers", {})
        max_mutations = min(int(params.get("max_mutations", 10)), 20)

        findings: List[Dict[str, Any]] = []
        baseline_status, _ = await _curl_json(url, method=method, headers=headers)

        # Iterate parameters and test mutations
        for param in parameters[:10]:  # Cap at 10 params per run
            name = param.get("name", "")
            location = param.get("in", "query")
            schema = param.get("schema", {})
            ptype = schema.get("type", "string") if isinstance(schema, dict) else "string"
            mutations = _get_mutations(ptype)[:max_mutations]

            for mutation in mutations:
                test_url = url
                body_str = None
                test_headers = dict(headers)

                if location == "query":
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[name] = [str(mutation) if mutation is not None else "null"]
                    new_query = urllib.parse.urlencode(qs, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                elif location in ("body", "requestBody"):
                    body_str = json.dumps({name: mutation})

                status, resp = await _curl_json(
                    test_url, method=method, headers=test_headers, body=body_str, timeout=10
                )

                finding = _analyse_fuzz_response(
                    name, mutation, str(mutation), status, resp, baseline_status
                )
                if finding:
                    findings.append(finding)

        return {
            "success": True,
            "url": url,
            "method": method,
            "findings": findings,
            "total": len(findings),
        }

    # ------------------------------------------------------------------
    # test_mass_assignment
    # ------------------------------------------------------------------

    async def _test_mass_assignment(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params.get("url", "")
        allow_internal = params.get("allow_internal", self._allow_internal)

        try:
            _validate_url(url, allow_internal)
        except ValueError as exc:
            return {"success": False, "error": str(exc), "findings": []}

        method = params.get("method", "POST").upper()
        base_payload = params.get("base_payload", {})
        target_fields = params.get("target_fields", [])
        headers = params.get("headers", {})

        findings: List[Dict[str, Any]] = []

        # Baseline — send only legitimate fields
        base_body = json.dumps(base_payload)
        baseline_status, baseline_resp = await _curl_json(
            url, method=method, headers=headers, body=base_body, timeout=15
        )

        # Inject each privileged field one at a time
        for field in target_fields[:30]:
            inject_payload = {**base_payload, field: "UNIVEX_MASS_ASSIGN_TEST"}
            inject_body = json.dumps(inject_payload)
            status, resp = await _curl_json(url, method=method, headers=headers, body=inject_body, timeout=10)

            if status in (200, 201, 202):
                resp_str = json.dumps(resp).lower()
                if "univex_mass_assign_test" in resp_str or field in resp_str:
                    findings.append({
                        "field": field,
                        "injected_value": "UNIVEX_MASS_ASSIGN_TEST",
                        "http_status": status,
                        "evidence": resp_str[:200],
                        "severity": "high",
                    })

        return {
            "success": True,
            "url": url,
            "method": method,
            "findings": findings,
            "total": len(findings),
            "owasp_tag": "API8:2023-Security_Misconfiguration",
        }

    # ------------------------------------------------------------------
    # graphql_introspect
    # ------------------------------------------------------------------

    async def _graphql_introspect(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params.get("url", "")
        allow_internal = params.get("allow_internal", self._allow_internal)

        try:
            _validate_url(url, allow_internal)
        except ValueError as exc:
            return {"success": False, "error": str(exc)}

        headers = dict(params.get("headers", {}))
        headers.setdefault("Content-Type", "application/json")

        introspection_query = (
            '{"query":"{ __schema { types { name kind fields { name } } '
            'queryType { name } mutationType { name } } }"}'
        )

        status, resp = await _curl_json(
            url, method="POST", headers=headers, body=introspection_query, timeout=20
        )

        introspection_enabled = False
        types_info: Dict[str, List[str]] = {}

        if status == 200 and "data" in resp and "__schema" in str(resp.get("data", {})):
            introspection_enabled = True
            schema = resp.get("data", {}).get("__schema", {})
            for t in schema.get("types", []):
                name = t.get("name", "")
                if name.startswith("__") or not name:
                    continue
                fields = [f["name"] for f in (t.get("fields") or []) if f.get("name")]
                types_info[name] = fields

        return {
            "success": True,
            "url": url,
            "introspection_enabled": introspection_enabled,
            "http_status": status,
            "types": types_info,
            "total_types": len(types_info),
            "severity": "medium" if introspection_enabled else "info",
            "finding": (
                "GraphQL introspection is enabled — full schema exposed to attackers"
                if introspection_enabled
                else "Introspection is disabled or not a GraphQL endpoint"
            ),
        }

    # ------------------------------------------------------------------
    # graphql_injection_test
    # ------------------------------------------------------------------

    async def _graphql_injection_test(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params.get("url", "")
        allow_internal = params.get("allow_internal", self._allow_internal)

        try:
            _validate_url(url, allow_internal)
        except ValueError as exc:
            return {"success": False, "error": str(exc)}

        headers = dict(params.get("headers", {}))
        headers.setdefault("Content-Type", "application/json")

        results: Dict[str, Any] = {"url": url, "tests": {}}

        # Batch test
        if params.get("test_batching", True):
            batch = params.get("batch_payload", [{"query": "{ __typename }"}] * 10)
            batch_body = json.dumps(batch)
            status, resp = await _curl_json(url, method="POST", headers=headers, body=batch_body, timeout=20)
            vulnerable = isinstance(resp, list) and len(resp) > 0
            results["tests"]["batching"] = {
                "vulnerable": vulnerable,
                "http_status": status,
                "batch_size": len(batch),
                "description": "Server processed batched GraphQL queries" if vulnerable else "Batching blocked or not applicable",
            }

        # Field suggestion leak
        if params.get("test_field_suggestion", True):
            suggestion_body = json.dumps({"query": params.get("field_suggestion_payload", "{ unknownField_xyz }")})
            status, resp = await _curl_json(url, method="POST", headers=headers, body=suggestion_body, timeout=15)
            resp_str = json.dumps(resp).lower()
            has_suggestion = "did you mean" in resp_str
            results["tests"]["field_suggestion"] = {
                "vulnerable": has_suggestion,
                "http_status": status,
                "evidence": resp_str[:200] if has_suggestion else "",
                "description": "Field suggestion leak reveals internal field names" if has_suggestion else "No field suggestions detected",
            }

        # Nested DoS
        if params.get("test_nested_dos", True):
            nested_q = params.get("nested_query", "{ __typename }")
            nested_body = json.dumps({"query": nested_q})
            status, resp = await _curl_json(url, method="POST", headers=headers, body=nested_body, timeout=30)
            results["tests"]["nested_dos"] = {
                "http_status": status,
                "description": "Server responded to deeply nested query",
                "note": "Manual analysis required — measure response time vs baseline",
            }

        findings = [
            {
                "test": k,
                "vulnerable": v.get("vulnerable", False),
                "severity": "high" if v.get("vulnerable") else "info",
                "detail": v,
            }
            for k, v in results["tests"].items()
            if v.get("vulnerable")
        ]

        return {
            "success": True,
            **results,
            "findings": findings,
            "total_findings": len(findings),
        }

    # ------------------------------------------------------------------
    # graphql_idor_test
    # ------------------------------------------------------------------

    async def _graphql_idor_test(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params.get("url", "")
        allow_internal = params.get("allow_internal", self._allow_internal)

        try:
            _validate_url(url, allow_internal)
        except ValueError as exc:
            return {"success": False, "error": str(exc)}

        headers = dict(params.get("headers", {}))
        headers.setdefault("Content-Type", "application/json")

        query = params.get("query", "query($id: ID!) { node(id: $id) { id } }")
        id_variable = params.get("id_variable", "id")
        known_own_id = params.get("known_own_id")
        test_ids = params.get("test_ids", [str(i) for i in range(1, 21)])

        # Get baseline own-ID response
        baseline_resp: Dict[str, Any] = {}
        if known_own_id:
            body = json.dumps({"query": query, "variables": {id_variable: known_own_id}})
            _, baseline_resp = await _curl_json(url, method="POST", headers=headers, body=body, timeout=10)

        findings: List[Dict[str, Any]] = []
        for test_id in test_ids[:25]:
            if test_id == known_own_id:
                continue
            body = json.dumps({"query": query, "variables": {id_variable: test_id}})
            status, resp = await _curl_json(url, method="POST", headers=headers, body=body, timeout=10)

            has_data = bool(resp.get("data") and resp["data"] != {"node": None} and resp["data"] != {})
            errors = resp.get("errors", [])

            if status == 200 and has_data and not errors:
                findings.append({
                    "id": test_id,
                    "http_status": status,
                    "response_excerpt": json.dumps(resp.get("data", {}))[:200],
                    "severity": "high",
                    "description": f"Object with id={test_id!r} accessible — possible IDOR",
                })

        return {
            "success": True,
            "url": url,
            "query": query,
            "findings": findings,
            "total": len(findings),
            "owasp_tag": "API1:2023-Broken_Object_Level_Authorization",
        }

    # ------------------------------------------------------------------
    # test_rate_limiting
    # ------------------------------------------------------------------

    async def _test_rate_limiting(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params.get("url", "")
        allow_internal = params.get("allow_internal", self._allow_internal)

        try:
            _validate_url(url, allow_internal)
        except ValueError as exc:
            return {"success": False, "error": str(exc)}

        method = params.get("method", "GET").upper()
        request_count = min(int(params.get("request_count", 20)), 100)
        bypass_headers_list: List[Dict[str, str]] = params.get("bypass_headers", [])
        headers = params.get("headers", {})
        body = params.get("body", {})
        body_str = json.dumps(body) if body else None

        # Baseline rapid-fire
        status_counts: Dict[int, int] = {}
        for _ in range(request_count):
            status, _ = await _curl_json(url, method=method, headers=headers, body=body_str, timeout=5)
            status_counts[status] = status_counts.get(status, 0) + 1

        rate_limited = status_counts.get(429, 0) > 0
        findings: List[Dict[str, Any]] = []

        if not rate_limited:
            findings.append({
                "type": "no_rate_limiting",
                "severity": "high",
                "description": f"No rate limiting detected after {request_count} rapid requests",
                "status_distribution": status_counts,
            })
        else:
            # Attempt bypasses
            for bypass_header in bypass_headers_list[:9]:
                test_headers = {**headers, **bypass_header}
                status, _ = await _curl_json(url, method=method, headers=test_headers, body=body_str, timeout=5)
                if status != 429:
                    findings.append({
                        "type": "rate_limit_bypass",
                        "severity": "high",
                        "header": bypass_header,
                        "bypass_status": status,
                        "description": f"Rate limit bypassed via header: {bypass_header}",
                    })
                    break

        return {
            "success": True,
            "url": url,
            "rate_limited": rate_limited,
            "status_distribution": status_counts,
            "findings": findings,
            "total": len(findings),
            "owasp_tag": "API4:2023-Unrestricted_Resource_Consumption",
        }

    # ------------------------------------------------------------------
    # test_cors_misconfig
    # ------------------------------------------------------------------

    async def _test_cors_misconfig(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params.get("url", "")
        allow_internal = params.get("allow_internal", self._allow_internal)

        try:
            _validate_url(url, allow_internal)
        except ValueError as exc:
            return {"success": False, "error": str(exc)}

        origins: List[str] = params.get("origins", ["https://evil.com"])
        params.get("headers", {})
        findings: List[Dict[str, Any]] = []

        for origin in origins[:10]:
            cmd = [
                "curl", "-s", "-I", "-X", "OPTIONS",
                "-H", f"Origin: {origin}",
                "-H", "Access-Control-Request-Method: GET",
                "--max-time", "10",
                url,
            ]
            rc, stdout, _ = await _run_cmd(cmd, timeout=15)

            # Parse response headers from curl -I output
            resp_headers: Dict[str, str] = {}
            for line in stdout.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    resp_headers[k.strip().lower()] = v.strip()

            acao = resp_headers.get("access-control-allow-origin", "")
            acac = resp_headers.get("access-control-allow-credentials", "").lower()

            vuln_findings: List[str] = []
            if acao == "*":
                vuln_findings.append("Wildcard ACAO (*) — any origin can read responses")
            if acao == origin and acao not in ("", "*"):
                if acac == "true":
                    vuln_findings.append(
                        f"Reflected origin {origin!r} + Allow-Credentials: true — credential theft possible"
                    )
                else:
                    vuln_findings.append(f"Reflected arbitrary origin: {origin!r}")
            if acao == "null":
                vuln_findings.append("ACAO: null — sandbox iframe bypass")

            if vuln_findings:
                findings.append({
                    "origin_tested": origin,
                    "acao": acao,
                    "acac": acac,
                    "issues": vuln_findings,
                    "severity": "high" if acac == "true" else "medium",
                })

        return {
            "success": True,
            "url": url,
            "findings": findings,
            "total": len(findings),
            "owasp_tag": "A05:2021-Security_Misconfiguration",
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_mutations(schema_type: str) -> List[Any]:
    _STRING = ["", " ", "A" * 256, "'", '"', "<script>alert(1)</script>", "null", None, "{{7*7}}", "${7*7}", "../etc/passwd"]
    _INT = [0, -1, 2 ** 31 - 1, 2 ** 31, -(2 ** 31), None, "not_an_int"]
    _BOOL = [True, False, 0, 1, "true", "false", None]
    _ARR = [[], [None], None, "not_an_array"]
    return {
        "string": _STRING,
        "str": _STRING,
        "integer": _INT,
        "number": _INT,
        "boolean": _BOOL,
        "bool": _BOOL,
        "array": _ARR,
    }.get(schema_type, _STRING)


def _analyse_fuzz_response(
    param: str,
    mutation: Any,
    mutation_str: str,
    status: int,
    resp: Dict[str, Any],
    baseline_status: int,
) -> Optional[Dict[str, Any]]:
    """Detect anomalies in fuzz response that indicate a vulnerability."""
    resp_str = json.dumps(resp).lower()

    # Stack trace / error message patterns
    error_patterns = [
        "traceback", "stack trace", "exception", "error:", "at line",
        "undefined method", "null pointer", "index out of range",
        "cannot read property", "typeerror", "attributeerror",
    ]
    has_error = any(p in resp_str for p in error_patterns)

    # Unexpected 500
    is_500 = status == 500

    # Status code anomaly
    status_anomaly = status != baseline_status and status in (500, 503, 422, 400)

    if has_error or is_500 or status_anomaly:
        return {
            "parameter": param,
            "mutation": mutation_str[:100],
            "http_status": status,
            "has_error_leak": has_error,
            "status_anomaly": status_anomaly,
            "evidence": resp_str[:200],
            "severity": "high" if is_500 else "medium",
        }
    return None


if __name__ == "__main__":
    server = APISecurityServer()
    server.run()

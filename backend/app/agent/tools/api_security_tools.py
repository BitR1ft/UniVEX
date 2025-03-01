"""
API Security Testing Engine

Implements eight agent tools for REST, GraphQL and general API security:

  OpenAPIParserTool       — parse Swagger/OpenAPI specs, enumerate all endpoints automatically
  APIFuzzTool             — fuzz API parameters with type-aware mutations
  MassAssignmentTool      — detect mass assignment by injecting unexpected fields
  GraphQLIntrospectionTool— detect enabled GraphQL introspection, enumerate schema
  GraphQLInjectionTool    — GraphQL query batching, nested-query DoS, field-suggestion leak
  GraphQLIDORTool         — IDOR via GraphQL query variable manipulation
  APIRateLimitTool        — test API rate limiting and bypass techniques
  CORSMisconfigTool       — detect permissive CORS configurations

All tools connect to the APISecurityMCPServer (:8009) with pure-Python fallback.
"""

from __future__ import annotations

import json
import logging
from enum import Enum
from typing import Any, Dict, List, Optional

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import (
    truncate_output,
    with_timeout,
)
from app.mcp.base_server import MCPClient

logger = logging.getLogger(__name__)

DEFAULT_API_SERVER_URL = "http://kali-tools:8009"

# ---------------------------------------------------------------------------
# OWASP tags
# ---------------------------------------------------------------------------
OWASP_API_TAG = "A04:2023-Insecure_Direct_Object_References"
OWASP_MASS_ASSIGN_TAG = "A08:2023-Software_and_Data_Integrity_Failures"
OWASP_CORS_TAG = "A05:2021-Security_Misconfiguration"
OWASP_GRAPHQL_TAG = "A03:2023-Injection"

# ---------------------------------------------------------------------------
# Severity levels
# ---------------------------------------------------------------------------


class APISeverity(str, Enum):
    """API finding severity."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ---------------------------------------------------------------------------
# HTTP method / content-type constants
# ---------------------------------------------------------------------------
_HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

# ---------------------------------------------------------------------------
# Type-aware mutation helpers
# ---------------------------------------------------------------------------

_STRING_MUTATIONS: List[str] = [
    "",                     # empty string
    " ",                    # whitespace
    "A" * 256,              # long string
    "A" * 4096,             # very long string (overflow attempt)
    "'",                    # SQL-injection probe
    '"',                    # SQL-injection probe
    "<script>alert(1)</script>",  # XSS probe
    "null",
    "undefined",
    "true",
    "false",
    "0",
    "-1",
    "../../../etc/passwd",  # path traversal
    "\x00",                 # null byte
    "%00",                  # null byte url-encoded
    "{{7*7}}",              # SSTI probe
    "${7*7}",               # SSTI probe
]

_INT_MUTATIONS: List[Any] = [
    0,
    -1,
    2 ** 31 - 1,    # INT_MAX
    2 ** 31,        # INT_MAX + 1
    -(2 ** 31),     # INT_MIN
    2 ** 63,        # overflow
    None,
    "not_an_int",
]

_BOOL_MUTATIONS: List[Any] = [True, False, 0, 1, "true", "false", "yes", "no", None]

_ARRAY_MUTATIONS: List[Any] = [
    [],
    [None],
    ["A" * 100] * 1000,  # Large array
    None,
    "not_an_array",
]


def _mutate_value(value: Any, schema_type: str) -> List[Any]:
    """Return a list of type-aware mutations for a field value."""
    if schema_type in ("string", "str"):
        return _STRING_MUTATIONS
    if schema_type in ("integer", "number", "int", "float"):
        return _INT_MUTATIONS
    if schema_type in ("boolean", "bool"):
        return _BOOL_MUTATIONS
    if schema_type == "array":
        return _ARRAY_MUTATIONS
    # Unknown — try all
    return _STRING_MUTATIONS[:5] + [None, 0, -1]


# ---------------------------------------------------------------------------
# OpenAPI / Swagger parsing helpers
# ---------------------------------------------------------------------------


def _parse_openapi_spec(spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract a flat list of endpoints from an OpenAPI 2/3 spec dict.

    Returns list of dicts: {method, path, parameters, request_body_schema, tags}
    """
    endpoints: List[Dict[str, Any]] = []
    paths = spec.get("paths", {})
    base_url = ""

    # OpenAPI 3.x — servers array
    servers = spec.get("servers", [])
    if servers and isinstance(servers, list):
        base_url = servers[0].get("url", "")

    # Swagger 2.0 — host + basePath + schemes
    if not base_url:
        host = spec.get("host", "")
        base_path = spec.get("basePath", "/")
        schemes = spec.get("schemes", ["https"])
        if host:
            base_url = f"{schemes[0]}://{host}{base_path}"

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        # Path-level parameters (inherited by all operations)
        path_params = path_item.get("parameters", [])
        for method in _HTTP_METHODS:
            operation = path_item.get(method.lower())
            if not isinstance(operation, dict):
                continue
            op_params = operation.get("parameters", path_params)
            request_body = operation.get("requestBody", {})
            body_schema: Dict[str, Any] = {}
            if request_body:
                content = request_body.get("content", {})
                for mime, media in content.items():
                    body_schema = media.get("schema", {})
                    break  # take first content type

            endpoints.append({
                "method": method,
                "path": path,
                "url": base_url + path,
                "parameters": op_params,
                "request_body_schema": body_schema,
                "tags": operation.get("tags", []),
                "summary": operation.get("summary", ""),
                "operation_id": operation.get("operationId", ""),
                "security": operation.get("security", spec.get("security", [])),
            })

    return endpoints


# ---------------------------------------------------------------------------
# CORS detection helpers
# ---------------------------------------------------------------------------


def _check_cors_headers(response_headers: Dict[str, str], origin_sent: str) -> Dict[str, Any]:
    """Analyse CORS response headers for misconfigurations."""
    findings: List[str] = []
    acao = response_headers.get("access-control-allow-origin", "")
    acac = response_headers.get("access-control-allow-credentials", "").lower()

    if acao == "*":
        findings.append("Wildcard Access-Control-Allow-Origin (*) — any origin can read responses")
    if acao and acao.lower() not in ("", "*"):
        if acao == origin_sent:
            if acac == "true":
                findings.append(
                    f"Reflected origin ({origin_sent}) + Access-Control-Allow-Credentials: true — "
                    "credentials leak to attacker-controlled origin"
                )
            else:
                findings.append(f"Reflected arbitrary origin: {origin_sent}")
    if acao == "null":
        findings.append("Access-Control-Allow-Origin: null — sandbox iframe bypass possible")

    acam = response_headers.get("access-control-allow-methods", "")
    if acam:
        dangerous = [m for m in ["DELETE", "PUT", "PATCH"] if m in acam.upper()]
        if dangerous:
            findings.append(
                f"Dangerous HTTP methods exposed via CORS: {', '.join(dangerous)}"
            )

    return {
        "acao": acao,
        "acac": acac,
        "findings": findings,
        "vulnerable": bool(findings),
    }


# ---------------------------------------------------------------------------
# GraphQL helpers
# ---------------------------------------------------------------------------

_GRAPHQL_INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
        args { name type { name kind } }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
""".strip()

_GRAPHQL_TYPE_NAMES_QUERY = "{ __schema { types { name } } }"

_GRAPHQL_FIELD_SUGGESTION_PAYLOAD = "{ unknownField_do_not_exist }"

_GRAPHQL_BATCH_PAYLOAD = json.dumps(
    [{"query": "{ __typename }"} for _ in range(100)]
)

_GRAPHQL_NESTED_QUERY = (
    "{ user { friends { friends { friends { friends { id name } } } } } }"
)


def _parse_graphql_types(introspection_result: Dict[str, Any]) -> Dict[str, List[str]]:
    """Extract type->fields mapping from a GraphQL introspection result."""
    schema = introspection_result.get("data", {}).get("__schema", {})
    types_info: Dict[str, List[str]] = {}
    for t in schema.get("types", []):
        name = t.get("name", "")
        if name.startswith("__") or not name:
            continue
        fields = [f["name"] for f in (t.get("fields") or []) if f.get("name")]
        types_info[name] = fields
    return types_info


# ---------------------------------------------------------------------------
# Rate-limit bypass techniques
# ---------------------------------------------------------------------------

_RATE_LIMIT_BYPASS_HEADERS: List[Dict[str, str]] = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
]


# ===========================================================================
# OpenAPIParserTool
# ===========================================================================


class OpenAPIParserTool(BaseTool):
    """Parse Swagger/OpenAPI specs and enumerate all endpoints automatically.

    Fetches the spec from a URL or accepts a raw JSON dict, then returns a
    structured list of every endpoint, its HTTP method, parameters, request
    body schema, required auth, and OWASP tags.

    Connects to APISecurityMCPServer (:8009) for remote spec fetching.
    """

    def __init__(
        self,
        server_url: str = DEFAULT_API_SERVER_URL,
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
            name="openapi_parse",
            description=(
                "Fetch and parse an OpenAPI/Swagger specification (v2 or v3) from a URL or raw "
                "JSON. Returns a structured list of every endpoint, HTTP method, parameters, "
                "request body schema, authentication requirements, and OWASP tags. Use before "
                "API fuzzing to enumerate all attack surface."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "spec_url": {
                        "type": "string",
                        "description": "URL to the OpenAPI spec (e.g. http://10.10.10.1/api/swagger.json)",
                    },
                    "spec_json": {
                        "type": "object",
                        "description": "Raw OpenAPI spec as a JSON object (alternative to spec_url)",
                    },
                    "allow_internal": {
                        "type": "boolean",
                        "description": "Allow fetching specs from internal/lab addresses",
                        "default": False,
                    },
                },
            },
        )

    @with_timeout(60)
    async def execute(self, **kwargs) -> str:
        spec_url: Optional[str] = kwargs.get("spec_url")
        spec_json: Optional[Dict[str, Any]] = kwargs.get("spec_json")
        allow_internal: bool = kwargs.get("allow_internal", False)

        try:
            result = await self._client.call_tool(
                "parse_openapi_spec",
                {"spec_url": spec_url, "spec_json": spec_json, "allow_internal": allow_internal},
            )
            if result.get("success"):
                return truncate_output(json.dumps(result, indent=2))
        except Exception:
            pass  # fallback below

        # Pure-Python fallback: parse spec_json if provided
        if spec_json and isinstance(spec_json, dict):
            endpoints = _parse_openapi_spec(spec_json)
            result = {
                "success": True,
                "source": "local_parse",
                "endpoints": endpoints,
                "total_endpoints": len(endpoints),
                "owasp_tags": [OWASP_API_TAG],
            }
            return truncate_output(json.dumps(result, indent=2))

        return json.dumps({
            "success": False,
            "error": "No spec_json provided and MCP server unreachable",
            "endpoints": [],
        })


# ===========================================================================
# APIFuzzTool
# ===========================================================================


class APIFuzzTool(BaseTool):
    """Fuzz API endpoints with type-aware mutations.

    Sends mutated values for every parameter of an endpoint, detecting
    unusual HTTP status codes, verbose error messages, stack traces, or
    response size anomalies that indicate a vulnerability.
    """

    def __init__(
        self,
        server_url: str = DEFAULT_API_SERVER_URL,
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
            name="api_fuzz",
            description=(
                "Fuzz REST API parameters with type-aware mutations: string overflows, negative "
                "integers, null injections, SQL/SSTI probes, and boundary values. Detects "
                "unhandled exceptions, stack traces, abnormal response sizes, and error leakage. "
                "Provide an endpoint dict from openapi_parse or specify manually."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target API endpoint URL"},
                    "method": {
                        "type": "string",
                        "enum": _HTTP_METHODS,
                        "default": "GET",
                    },
                    "parameters": {
                        "type": "array",
                        "description": "List of {name, in, schema} parameter objects from OpenAPI",
                        "items": {"type": "object"},
                        "default": [],
                    },
                    "headers": {
                        "type": "object",
                        "description": "HTTP headers to include (e.g. auth token)",
                        "default": {},
                    },
                    "max_mutations": {
                        "type": "integer",
                        "description": "Max mutations per parameter (default: 10)",
                        "default": 10,
                    },
                    "allow_internal": {"type": "boolean", "default": False},
                },
                "required": ["url"],
            },
        )

    @with_timeout(120)
    async def execute(self, **kwargs) -> str:
        url: str = kwargs.get("url", "")
        method: str = kwargs.get("method", "GET").upper()
        parameters: List[Dict] = kwargs.get("parameters", [])
        headers: Dict[str, str] = kwargs.get("headers", {})
        max_mutations: int = kwargs.get("max_mutations", 10)
        allow_internal: bool = kwargs.get("allow_internal", False)

        try:
            result = await self._client.call_tool(
                "fuzz_api_endpoint",
                {
                    "url": url,
                    "method": method,
                    "parameters": parameters,
                    "headers": headers,
                    "max_mutations": max_mutations,
                    "allow_internal": allow_internal,
                },
            )
            if result.get("success"):
                return truncate_output(json.dumps(result, indent=2))
        except Exception:
            pass

        # Fallback: return mutation plan
        mutations: List[Dict[str, Any]] = []
        for param in parameters[:20]:
            name = param.get("name", "unknown")
            schema_type = param.get("schema", {}).get("type", "string") if isinstance(param.get("schema"), dict) else "string"
            values = _mutate_value(None, schema_type)[:max_mutations]
            mutations.append({"parameter": name, "location": param.get("in", "query"), "mutations": values})

        result = {
            "success": True,
            "source": "mutation_plan",
            "url": url,
            "method": method,
            "mutation_plan": mutations,
            "note": "Connect to APISecurityMCPServer (:8009) to execute mutations against live targets",
        }
        return truncate_output(json.dumps(result, indent=2))


# ===========================================================================
# MassAssignmentTool
# ===========================================================================


_MASS_ASSIGN_FIELDS: List[str] = [
    "role",
    "is_admin",
    "isAdmin",
    "admin",
    "is_superuser",
    "isSuperuser",
    "permissions",
    "privilege",
    "account_type",
    "accountType",
    "user_type",
    "userType",
    "is_staff",
    "isStaff",
    "is_active",
    "verified",
    "email_verified",
    "password",
    "password_hash",
    "credit",
    "balance",
    "credits",
    "price",
    "discount",
    "internal",
    "debug",
    "bypass_limit",
    "api_key",
]


class MassAssignmentTool(BaseTool):
    """Detect mass assignment vulnerabilities by injecting unexpected fields.

    Sends POST/PUT/PATCH requests that include privileged or hidden fields
    alongside legitimate data, then checks whether the server accepted and
    applied the injected values.
    """

    def __init__(
        self,
        server_url: str = DEFAULT_API_SERVER_URL,
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
            name="mass_assignment_test",
            description=(
                "Test for mass assignment vulnerabilities (API3:2023) by injecting privileged "
                "hidden fields (role, is_admin, credits, etc.) into POST/PUT/PATCH request bodies "
                "alongside legitimate user-supplied data. Compares response to detect accepted "
                "injected values. OWASP API3:2023 — Excessive Data Exposure."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target API endpoint"},
                    "method": {
                        "type": "string",
                        "enum": ["POST", "PUT", "PATCH"],
                        "default": "POST",
                    },
                    "base_payload": {
                        "type": "object",
                        "description": "Legitimate request body to include alongside injected fields",
                        "default": {},
                    },
                    "extra_fields": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Additional field names to inject beyond the built-in list",
                        "default": [],
                    },
                    "headers": {"type": "object", "default": {}},
                    "allow_internal": {"type": "boolean", "default": False},
                },
                "required": ["url"],
            },
        )

    @with_timeout(60)
    async def execute(self, **kwargs) -> str:
        url: str = kwargs.get("url", "")
        method: str = kwargs.get("method", "POST").upper()
        base_payload: Dict[str, Any] = kwargs.get("base_payload", {})
        extra_fields: List[str] = kwargs.get("extra_fields", [])
        headers: Dict[str, str] = kwargs.get("headers", {})
        allow_internal: bool = kwargs.get("allow_internal", False)

        target_fields = _MASS_ASSIGN_FIELDS + [f for f in extra_fields if f not in _MASS_ASSIGN_FIELDS]

        try:
            result = await self._client.call_tool(
                "test_mass_assignment",
                {
                    "url": url,
                    "method": method,
                    "base_payload": base_payload,
                    "target_fields": target_fields,
                    "headers": headers,
                    "allow_internal": allow_internal,
                },
            )
            if result.get("success"):
                return truncate_output(json.dumps(result, indent=2))
        except Exception:
            pass

        result = {
            "success": True,
            "source": "field_enumeration",
            "url": url,
            "method": method,
            "fields_to_inject": target_fields,
            "total_fields": len(target_fields),
            "owasp_tag": OWASP_MASS_ASSIGN_TAG,
            "note": "Connect to APISecurityMCPServer (:8009) to execute injection against live targets",
        }
        return truncate_output(json.dumps(result, indent=2))


# ===========================================================================
# GraphQLIntrospectionTool
# ===========================================================================


class GraphQLIntrospectionTool(BaseTool):
    """Detect enabled GraphQL introspection and enumerate the full schema.

    Queries __schema to map all types, queries, mutations and subscriptions.
    Flags enabled introspection as a medium-severity finding (exposes full
    attack surface to an attacker).
    """

    def __init__(
        self,
        server_url: str = DEFAULT_API_SERVER_URL,
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
            name="graphql_introspection",
            description=(
                "Detect whether GraphQL introspection is enabled on an endpoint. If enabled, "
                "queries the full __schema to enumerate all types, queries, mutations and "
                "subscriptions — providing the complete API attack surface. Enabled introspection "
                "on production is a medium-severity misconfiguration."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "GraphQL endpoint URL"},
                    "headers": {"type": "object", "default": {}},
                    "allow_internal": {"type": "boolean", "default": False},
                },
                "required": ["url"],
            },
        )

    @with_timeout(60)
    async def execute(self, **kwargs) -> str:
        url: str = kwargs.get("url", "")
        headers: Dict[str, str] = kwargs.get("headers", {})
        allow_internal: bool = kwargs.get("allow_internal", False)

        try:
            result = await self._client.call_tool(
                "graphql_introspect",
                {"url": url, "headers": headers, "allow_internal": allow_internal},
            )
            if result.get("success"):
                return truncate_output(json.dumps(result, indent=2))
        except Exception:
            pass

        result = {
            "success": True,
            "source": "fallback_schema",
            "url": url,
            "introspection_query": _GRAPHQL_INTROSPECTION_QUERY,
            "owasp_tag": OWASP_GRAPHQL_TAG,
            "severity": APISeverity.MEDIUM,
            "note": (
                "Connect to APISecurityMCPServer (:8009) to query the live GraphQL endpoint. "
                "Introspection enabled in production is MEDIUM severity."
            ),
        }
        return truncate_output(json.dumps(result, indent=2))


# ===========================================================================
# GraphQLInjectionTool
# ===========================================================================


class GraphQLInjectionTool(BaseTool):
    """Test for GraphQL-specific injection vulnerabilities.

    Covers:
    - Query batching attacks (100 queries in one request)
    - Deeply nested query DoS (alias-based recursion)
    - Field suggestion leak (did-you-mean information disclosure)
    - Introspection-based enumeration
    """

    def __init__(
        self,
        server_url: str = DEFAULT_API_SERVER_URL,
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
            name="graphql_injection",
            description=(
                "Test GraphQL endpoint for injection-class vulnerabilities: query batching "
                "(sends 100 queries in one HTTP request to bypass rate limiting), nested query "
                "DoS (deep field recursion to exhaust server), and field-suggestion information "
                "leak (did-you-mean messages that reveal internal field names). OWASP API8:2023."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "GraphQL endpoint URL"},
                    "test_batching": {
                        "type": "boolean",
                        "description": "Test query batching",
                        "default": True,
                    },
                    "test_nested_dos": {
                        "type": "boolean",
                        "description": "Test nested query DoS",
                        "default": True,
                    },
                    "test_field_suggestion": {
                        "type": "boolean",
                        "description": "Test field suggestion leak",
                        "default": True,
                    },
                    "batch_size": {
                        "type": "integer",
                        "description": "Number of queries in batch test (default: 100)",
                        "default": 100,
                    },
                    "nest_depth": {
                        "type": "integer",
                        "description": "Depth of nested query in DoS test (default: 10)",
                        "default": 10,
                    },
                    "headers": {"type": "object", "default": {}},
                    "allow_internal": {"type": "boolean", "default": False},
                },
                "required": ["url"],
            },
        )

    @with_timeout(90)
    async def execute(self, **kwargs) -> str:
        url: str = kwargs.get("url", "")
        test_batching: bool = kwargs.get("test_batching", True)
        test_nested_dos: bool = kwargs.get("test_nested_dos", True)
        test_field_suggestion: bool = kwargs.get("test_field_suggestion", True)
        batch_size: int = kwargs.get("batch_size", 100)
        nest_depth: int = kwargs.get("nest_depth", 10)
        headers: Dict[str, str] = kwargs.get("headers", {})
        allow_internal: bool = kwargs.get("allow_internal", False)

        # Build nested query string
        nested_query = _build_nested_graphql_query(nest_depth)
        # Build batch payload
        batch_payload = [{"query": "{ __typename }"} for _ in range(batch_size)]

        try:
            result = await self._client.call_tool(
                "graphql_injection_test",
                {
                    "url": url,
                    "test_batching": test_batching,
                    "test_nested_dos": test_nested_dos,
                    "test_field_suggestion": test_field_suggestion,
                    "batch_payload": batch_payload,
                    "nested_query": nested_query,
                    "field_suggestion_payload": _GRAPHQL_FIELD_SUGGESTION_PAYLOAD,
                    "headers": headers,
                    "allow_internal": allow_internal,
                },
            )
            if result.get("success"):
                return truncate_output(json.dumps(result, indent=2))
        except Exception:
            pass

        tests = {}
        if test_batching:
            tests["batch_test"] = {
                "payload": batch_payload[:3],
                "description": f"Send {batch_size} queries in a single HTTP request to bypass rate limiting",
            }
        if test_nested_dos:
            tests["nested_dos"] = {
                "payload": nested_query,
                "description": f"Send a {nest_depth}-level deep nested query to exhaust server resources",
            }
        if test_field_suggestion:
            tests["field_suggestion"] = {
                "payload": _GRAPHQL_FIELD_SUGGESTION_PAYLOAD,
                "description": "Send an invalid field name to trigger 'did you mean X?' suggestions",
            }

        result = {
            "success": True,
            "source": "test_plan",
            "url": url,
            "tests": tests,
            "owasp_tag": OWASP_GRAPHQL_TAG,
            "note": "Connect to APISecurityMCPServer (:8009) to execute against live GraphQL targets",
        }
        return truncate_output(json.dumps(result, indent=2))


def _build_nested_graphql_query(depth: int) -> str:
    """Build a deeply nested GraphQL query for DoS testing."""
    # Use __typename which every type supports
    query = "__typename"
    for _ in range(depth):
        query = f"... on Object {{ {query} }}"
    return "{ " + query + " }"


# ===========================================================================
# GraphQLIDORTool
# ===========================================================================


class GraphQLIDORTool(BaseTool):
    """Test for IDOR via GraphQL query variable manipulation.

    Enumerates object IDs in GraphQL query variables, accessing objects
    that should be restricted to other users. Detects missing authorization
    checks on object-level operations.
    """

    def __init__(
        self,
        server_url: str = DEFAULT_API_SERVER_URL,
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
            name="graphql_idor",
            description=(
                "Test for Insecure Direct Object Reference (IDOR) vulnerabilities in GraphQL "
                "queries by manipulating query variables (id, userId, objectId) to access objects "
                "belonging to other users. Cycles through integer and UUID-style IDs. "
                "OWASP API1:2023 — Broken Object Level Authorization."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "GraphQL endpoint URL"},
                    "query": {
                        "type": "string",
                        "description": "GraphQL query template with $id variable (e.g. 'query($id: ID!) { user(id: $id) { id email } }')",
                    },
                    "id_variable": {
                        "type": "string",
                        "description": "Variable name holding the object ID (default: id)",
                        "default": "id",
                    },
                    "known_own_id": {
                        "type": "string",
                        "description": "Current user's own object ID (baseline for comparison)",
                    },
                    "test_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "IDs to test (defaults to 1–20 and common values)",
                        "default": [],
                    },
                    "headers": {"type": "object", "default": {}},
                    "allow_internal": {"type": "boolean", "default": False},
                },
                "required": ["url", "query"],
            },
        )

    @with_timeout(90)
    async def execute(self, **kwargs) -> str:
        url: str = kwargs.get("url", "")
        query: str = kwargs.get("query", "")
        id_variable: str = kwargs.get("id_variable", "id")
        known_own_id: Optional[str] = kwargs.get("known_own_id")
        test_ids: List[str] = kwargs.get("test_ids", [])
        headers: Dict[str, str] = kwargs.get("headers", {})
        allow_internal: bool = kwargs.get("allow_internal", False)

        if not test_ids:
            test_ids = [str(i) for i in range(1, 21)] + ["0", "-1", "admin", "null", "undefined"]

        try:
            result = await self._client.call_tool(
                "graphql_idor_test",
                {
                    "url": url,
                    "query": query,
                    "id_variable": id_variable,
                    "known_own_id": known_own_id,
                    "test_ids": test_ids,
                    "headers": headers,
                    "allow_internal": allow_internal,
                },
            )
            if result.get("success"):
                return truncate_output(json.dumps(result, indent=2))
        except Exception:
            pass

        result = {
            "success": True,
            "source": "idor_test_plan",
            "url": url,
            "query": query,
            "id_variable": id_variable,
            "test_ids": test_ids,
            "owasp_tag": OWASP_API_TAG,
            "severity": APISeverity.HIGH,
            "note": "Connect to APISecurityMCPServer (:8009) to execute IDOR tests against live GraphQL endpoints",
        }
        return truncate_output(json.dumps(result, indent=2))


# ===========================================================================
# APIRateLimitTool
# ===========================================================================


class APIRateLimitTool(BaseTool):
    """Test API rate limiting effectiveness and bypass techniques.

    Sends rapid-fire requests to detect whether rate limiting is applied,
    then attempts bypass via IP spoofing headers, endpoint variation,
    and request parameter permutation.
    """

    def __init__(
        self,
        server_url: str = DEFAULT_API_SERVER_URL,
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
            name="api_rate_limit_test",
            description=(
                "Test API rate limiting by sending rapid-fire requests and checking for 429 "
                "responses. Then attempts rate-limit bypass via: IP spoofing headers "
                "(X-Forwarded-For, X-Real-IP), endpoint path variation, HTTP method switching, "
                "and case-modification of parameters. OWASP API4:2023 — Unrestricted Resource Consumption."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target API endpoint"},
                    "method": {"type": "string", "default": "GET"},
                    "request_count": {
                        "type": "integer",
                        "description": "Number of rapid requests for baseline test (default: 50)",
                        "default": 50,
                    },
                    "test_bypass_headers": {
                        "type": "boolean",
                        "description": "Test IP spoofing header bypasses",
                        "default": True,
                    },
                    "headers": {"type": "object", "default": {}},
                    "body": {"type": "object", "description": "Request body for POST/PUT", "default": {}},
                    "allow_internal": {"type": "boolean", "default": False},
                },
                "required": ["url"],
            },
        )

    @with_timeout(120)
    async def execute(self, **kwargs) -> str:
        url: str = kwargs.get("url", "")
        method: str = kwargs.get("method", "GET").upper()
        request_count: int = kwargs.get("request_count", 50)
        test_bypass_headers: bool = kwargs.get("test_bypass_headers", True)
        headers: Dict[str, str] = kwargs.get("headers", {})
        body: Dict[str, Any] = kwargs.get("body", {})
        allow_internal: bool = kwargs.get("allow_internal", False)

        bypass_headers = _RATE_LIMIT_BYPASS_HEADERS if test_bypass_headers else []

        try:
            result = await self._client.call_tool(
                "test_rate_limiting",
                {
                    "url": url,
                    "method": method,
                    "request_count": request_count,
                    "bypass_headers": bypass_headers,
                    "headers": headers,
                    "body": body,
                    "allow_internal": allow_internal,
                },
            )
            if result.get("success"):
                return truncate_output(json.dumps(result, indent=2))
        except Exception:
            pass

        result = {
            "success": True,
            "source": "rate_limit_test_plan",
            "url": url,
            "method": method,
            "plan": {
                "baseline_requests": request_count,
                "bypass_headers_to_test": bypass_headers,
                "description": (
                    f"Send {request_count} rapid requests to detect rate limiting. "
                    "If 429 is returned, attempt bypass via each IP spoofing header variant."
                ),
            },
            "owasp_tag": "API4:2023-Unrestricted_Resource_Consumption",
            "note": "Connect to APISecurityMCPServer (:8009) to execute against live targets",
        }
        return truncate_output(json.dumps(result, indent=2))


# ===========================================================================
# CORSMisconfigTool
# ===========================================================================


_CORS_TEST_ORIGINS: List[str] = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://legitimate.com.evil.com",  # suffix bypass
    "http://localhost",
    "https://localhost",
    "https://subdomain.target.com.evil.com",
]


class CORSMisconfigTool(BaseTool):
    """Detect permissive CORS configurations.

    Tests each API endpoint with a set of attacker-controlled origins,
    checking for wildcard ACAO, reflected origins, null origin, and
    ACAO + credentials combinations that enable cross-origin credential theft.
    """

    def __init__(
        self,
        server_url: str = DEFAULT_API_SERVER_URL,
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
            name="cors_misconfig_test",
            description=(
                "Detect CORS misconfiguration vulnerabilities by sending requests with attacker-"
                "controlled Origin headers and analysing Access-Control-Allow-Origin responses. "
                "Detects: wildcard ACAO, reflected arbitrary origin, null origin bypass, "
                "ACAO+credentials (credential theft risk). OWASP A05:2021 — Security Misconfiguration."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL or API endpoint"},
                    "extra_origins": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Additional origin values to test",
                        "default": [],
                    },
                    "headers": {"type": "object", "default": {}},
                    "allow_internal": {"type": "boolean", "default": False},
                },
                "required": ["url"],
            },
        )

    @with_timeout(60)
    async def execute(self, **kwargs) -> str:
        url: str = kwargs.get("url", "")
        extra_origins: List[str] = kwargs.get("extra_origins", [])
        headers: Dict[str, str] = kwargs.get("headers", {})
        allow_internal: bool = kwargs.get("allow_internal", False)

        all_origins = _CORS_TEST_ORIGINS + [o for o in extra_origins if o not in _CORS_TEST_ORIGINS]

        try:
            result = await self._client.call_tool(
                "test_cors_misconfig",
                {
                    "url": url,
                    "origins": all_origins,
                    "headers": headers,
                    "allow_internal": allow_internal,
                },
            )
            if result.get("success"):
                return truncate_output(json.dumps(result, indent=2))
        except Exception:
            pass

        result = {
            "success": True,
            "source": "cors_test_plan",
            "url": url,
            "origins_to_test": all_origins,
            "detection_criteria": {
                "wildcard_acao": "Access-Control-Allow-Origin: * — any origin can read responses",
                "reflected_origin": "ACAO matches Origin header value — reflected arbitrary origin",
                "null_origin": "ACAO: null — sandbox iframe bypass",
                "acao_plus_credentials": "ACAO (non-wildcard) + Allow-Credentials: true — credential theft",
                "dangerous_methods": "Dangerous HTTP methods exposed via CORS (DELETE, PUT, PATCH)",
            },
            "owasp_tag": OWASP_CORS_TAG,
            "note": "Connect to APISecurityMCPServer (:8009) to probe live targets",
        }
        return truncate_output(json.dumps(result, indent=2))


# ---------------------------------------------------------------------------
# Public helpers re-exported for tests
# ---------------------------------------------------------------------------
__all__ = [
    "OpenAPIParserTool",
    "APIFuzzTool",
    "MassAssignmentTool",
    "GraphQLIntrospectionTool",
    "GraphQLInjectionTool",
    "GraphQLIDORTool",
    "APIRateLimitTool",
    "CORSMisconfigTool",
    # helpers
    "_parse_openapi_spec",
    "_mutate_value",
    "_check_cors_headers",
    "_parse_graphql_types",
    "_build_nested_graphql_query",
    "_MASS_ASSIGN_FIELDS",
    "_CORS_TEST_ORIGINS",
    "_RATE_LIMIT_BYPASS_HEADERS",
    "_GRAPHQL_INTROSPECTION_QUERY",
    "APISeverity",
    "OWASP_API_TAG",
    "OWASP_MASS_ASSIGN_TAG",
    "OWASP_CORS_TAG",
    "OWASP_GRAPHQL_TAG",
]

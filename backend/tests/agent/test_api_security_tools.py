"""
Tests for PLAN.md Day 5 — API Security Testing Engine

Coverage:
  - _mutate_value(): type-aware mutation generation
  - _parse_openapi_spec(): OpenAPI 2/3 endpoint extraction
  - _check_cors_headers(): CORS misconfiguration detection
  - _parse_graphql_types(): GraphQL introspection result parsing
  - _build_nested_graphql_query(): nested query builder
  - OpenAPIParserTool: metadata, MCP interaction, offline fallback
  - APIFuzzTool: metadata, MCP interaction, mutation plan fallback
  - MassAssignmentTool: metadata, MCP interaction, offline fallback
  - GraphQLIntrospectionTool: metadata, MCP interaction, offline fallback
  - GraphQLInjectionTool: metadata, MCP interaction, offline fallback
  - GraphQLIDORTool: metadata, MCP interaction, offline fallback
  - APIRateLimitTool: metadata, MCP interaction, offline fallback
  - CORSMisconfigTool: metadata, MCP interaction, offline fallback
  - graphql_tools re-exports: alias correctness, OWASP tag
  - APISecurityServer: get_tools() count, execute_tool() dispatch
  - _is_internal(): private IP ranges, hostnames
  - _validate_url(): scheme enforcement, internal address blocking
  - _extract_host(): URL parsing
  - _parse_openapi_spec_server(): server-side spec parsing
  - ToolRegistry: all 8 Day 5 tools registered in correct phases
  - AttackPathRouter: API/GraphQL/CORS keywords → WEB_APP_ATTACK
"""

from __future__ import annotations

import asyncio
import json
import urllib.parse
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.agent.attack_path_router import AttackCategory, AttackPathRouter
from app.agent.state.agent_state import Phase
from app.agent.tools.api_security_tools import (
    APISeverity,
    APIFuzzTool,
    APIRateLimitTool,
    CORSMisconfigTool,
    GraphQLIDORTool,
    GraphQLInjectionTool,
    GraphQLIntrospectionTool,
    MassAssignmentTool,
    OWASP_API_TAG,
    OWASP_CORS_TAG,
    OWASP_GRAPHQL_TAG,
    OWASP_MASS_ASSIGN_TAG,
    OpenAPIParserTool,
    _build_nested_graphql_query,
    _check_cors_headers,
    _mutate_value,
    _parse_graphql_types,
    _parse_openapi_spec,
)
from app.agent.tools.graphql_tools import (
    OWASP_GRAPHQL_TAG as GQL_TAG,
    GraphQLIDORTool as GQLIDORAlias,
    GraphQLInjectionTool as GQLInjectionAlias,
    GraphQLIntrospectionTool as GQLIntrospectionAlias,
)
from app.mcp.servers.api_security_server import (
    APISecurityServer,
    _extract_host,
    _is_internal,
    _validate_url,
)


# ===========================================================================
# Helpers
# ===========================================================================


def _make_mcp_client(result: Dict[str, Any] | None = None, raise_exc: bool = False) -> MagicMock:
    """Return a mock MCP client whose call_tool returns *result* or raises."""
    if result is None:
        result = {"success": True}

    async def call_tool(name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if raise_exc:
            raise ConnectionError("MCP server unreachable")
        return result

    client = MagicMock()
    client.call_tool = AsyncMock(side_effect=call_tool)
    return client


def _run(coro):
    """Execute a coroutine synchronously."""
    return asyncio.run(coro)


# ===========================================================================
# _mutate_value
# ===========================================================================


class TestMutateValue:
    def test_string_returns_list(self):
        result = _mutate_value("hello", "string")
        assert isinstance(result, list)
        assert len(result) > 0

    def test_string_contains_empty_string(self):
        result = _mutate_value("x", "string")
        assert "" in result

    def test_string_contains_sql_probe(self):
        result = _mutate_value("x", "str")
        assert "'" in result or '"' in result

    def test_string_contains_path_traversal(self):
        result = _mutate_value("x", "string")
        assert any("etc/passwd" in str(v) for v in result)

    def test_integer_returns_list(self):
        result = _mutate_value(1, "integer")
        assert isinstance(result, list)
        assert len(result) > 0

    def test_integer_contains_zero(self):
        result = _mutate_value(1, "integer")
        assert 0 in result

    def test_integer_contains_negative(self):
        result = _mutate_value(1, "integer")
        assert -1 in result

    def test_integer_contains_overflow(self):
        result = _mutate_value(1, "number")
        assert any(v is None or (isinstance(v, int) and v > 2**30) for v in result)

    def test_boolean_returns_list(self):
        result = _mutate_value(True, "boolean")
        assert isinstance(result, list)

    def test_boolean_contains_true_false(self):
        result = _mutate_value(False, "bool")
        assert True in result
        assert False in result

    def test_array_type(self):
        result = _mutate_value([], "array")
        assert [] in result or any(v is None for v in result)

    def test_unknown_type_fallback(self):
        result = _mutate_value("x", "object")
        assert isinstance(result, list)
        assert len(result) > 0

    def test_float_treated_as_number(self):
        result = _mutate_value(1.5, "float")
        assert isinstance(result, list)
        assert 0 in result or -1 in result

    def test_ssti_probe_in_string(self):
        result = _mutate_value("x", "string")
        probes = [v for v in result if isinstance(v, str) and "7*7" in v]
        assert len(probes) >= 1


# ===========================================================================
# _parse_openapi_spec
# ===========================================================================


class TestParseOpenAPISpec:
    def _openapi3_spec(self) -> Dict[str, Any]:
        return {
            "openapi": "3.0.0",
            "servers": [{"url": "https://api.example.com/v1"}],
            "paths": {
                "/users": {
                    "get": {
                        "operationId": "listUsers",
                        "tags": ["users"],
                        "summary": "List all users",
                        "parameters": [{"name": "limit", "in": "query", "schema": {"type": "integer"}}],
                    },
                    "post": {
                        "operationId": "createUser",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object", "properties": {"name": {"type": "string"}}}
                                }
                            }
                        },
                    },
                },
                "/users/{id}": {
                    "get": {
                        "operationId": "getUser",
                        "parameters": [{"name": "id", "in": "path", "schema": {"type": "integer"}}],
                    },
                    "delete": {"operationId": "deleteUser"},
                },
            },
        }

    def _swagger2_spec(self) -> Dict[str, Any]:
        return {
            "swagger": "2.0",
            "host": "api.example.com",
            "basePath": "/api",
            "schemes": ["https"],
            "paths": {
                "/items": {
                    "get": {"operationId": "listItems", "parameters": []},
                    "post": {"operationId": "createItem"},
                }
            },
        }

    def test_returns_list(self):
        endpoints = _parse_openapi_spec(self._openapi3_spec())
        assert isinstance(endpoints, list)

    def test_correct_endpoint_count_openapi3(self):
        endpoints = _parse_openapi_spec(self._openapi3_spec())
        # /users GET, /users POST, /users/{id} GET, /users/{id} DELETE
        assert len(endpoints) == 4

    def test_endpoint_has_required_keys(self):
        endpoints = _parse_openapi_spec(self._openapi3_spec())
        for ep in endpoints:
            assert "method" in ep
            assert "path" in ep
            assert "url" in ep

    def test_base_url_from_servers(self):
        endpoints = _parse_openapi_spec(self._openapi3_spec())
        for ep in endpoints:
            assert ep["url"].startswith("https://api.example.com/v1")

    def test_swagger2_base_url(self):
        endpoints = _parse_openapi_spec(self._swagger2_spec())
        assert len(endpoints) == 2
        for ep in endpoints:
            parsed = urllib.parse.urlparse(ep["url"])
            assert parsed.hostname == "api.example.com"

    def test_methods_uppercased(self):
        endpoints = _parse_openapi_spec(self._openapi3_spec())
        methods = {ep["method"] for ep in endpoints}
        assert methods.issubset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})

    def test_parameters_extracted(self):
        endpoints = _parse_openapi_spec(self._openapi3_spec())
        get_users = next(e for e in endpoints if e["path"] == "/users" and e["method"] == "GET")
        assert len(get_users["parameters"]) == 1
        assert get_users["parameters"][0]["name"] == "limit"

    def test_request_body_schema_extracted(self):
        endpoints = _parse_openapi_spec(self._openapi3_spec())
        post_users = next(e for e in endpoints if e["path"] == "/users" and e["method"] == "POST")
        assert isinstance(post_users["request_body_schema"], dict)

    def test_operation_id_present(self):
        endpoints = _parse_openapi_spec(self._openapi3_spec())
        get_users = next(e for e in endpoints if e["path"] == "/users" and e["method"] == "GET")
        assert get_users["operation_id"] == "listUsers"

    def test_tags_present(self):
        endpoints = _parse_openapi_spec(self._openapi3_spec())
        get_users = next(e for e in endpoints if e["path"] == "/users" and e["method"] == "GET")
        assert "users" in get_users["tags"]

    def test_empty_spec(self):
        endpoints = _parse_openapi_spec({})
        assert endpoints == []

    def test_no_paths_key(self):
        endpoints = _parse_openapi_spec({"openapi": "3.0.0"})
        assert endpoints == []


# ===========================================================================
# _check_cors_headers
# ===========================================================================


class TestCheckCorsHeaders:
    def test_wildcard_acao_flagged(self):
        result = _check_cors_headers({"access-control-allow-origin": "*"}, "https://evil.com")
        assert result["vulnerable"] is True
        assert any("wildcard" in f.lower() or "*" in f for f in result["findings"])

    def test_reflected_origin_with_credentials_flagged(self):
        headers = {
            "access-control-allow-origin": "https://evil.com",
            "access-control-allow-credentials": "true",
        }
        result = _check_cors_headers(headers, "https://evil.com")
        assert result["vulnerable"] is True
        assert any("credential" in f.lower() for f in result["findings"])

    def test_reflected_origin_no_credentials_still_flagged(self):
        headers = {"access-control-allow-origin": "https://evil.com"}
        result = _check_cors_headers(headers, "https://evil.com")
        assert result["vulnerable"] is True

    def test_null_origin_bypass_flagged(self):
        result = _check_cors_headers({"access-control-allow-origin": "null"}, "null")
        assert result["vulnerable"] is True
        assert any("null" in f.lower() for f in result["findings"])

    def test_no_cors_headers_not_vulnerable(self):
        result = _check_cors_headers({}, "https://evil.com")
        assert result["vulnerable"] is False
        assert result["findings"] == []

    def test_dangerous_methods_flagged(self):
        headers = {
            "access-control-allow-origin": "*",
            "access-control-allow-methods": "GET, DELETE, PUT",
        }
        result = _check_cors_headers(headers, "https://evil.com")
        assert any("DELETE" in f or "PUT" in f for f in result["findings"])

    def test_acao_field_returned(self):
        headers = {"access-control-allow-origin": "https://trusted.com"}
        result = _check_cors_headers(headers, "https://evil.com")
        assert result["acao"] == "https://trusted.com"

    def test_non_matching_origin_not_flagged_as_reflected(self):
        headers = {"access-control-allow-origin": "https://trusted.com"}
        result = _check_cors_headers(headers, "https://evil.com")
        # trusted.com != evil.com → no reflected origin finding for evil.com
        # A non-matching origin should not produce reflected-origin findings
        assert result["vulnerable"] is False

    def test_patch_in_methods_flagged(self):
        headers = {
            "access-control-allow-origin": "*",
            "access-control-allow-methods": "GET, PATCH",
        }
        result = _check_cors_headers(headers, "https://evil.com")
        assert any("PATCH" in f for f in result["findings"])


# ===========================================================================
# _parse_graphql_types
# ===========================================================================


class TestParseGraphQLTypes:
    def _introspection_result(self) -> Dict[str, Any]:
        return {
            "data": {
                "__schema": {
                    "types": [
                        {
                            "name": "User",
                            "kind": "OBJECT",
                            "fields": [
                                {"name": "id"},
                                {"name": "email"},
                                {"name": "role"},
                            ],
                        },
                        {
                            "name": "Post",
                            "kind": "OBJECT",
                            "fields": [{"name": "title"}, {"name": "body"}],
                        },
                        {
                            "name": "__Schema",
                            "kind": "OBJECT",
                            "fields": [{"name": "types"}],
                        },
                        {
                            "name": "Query",
                            "kind": "OBJECT",
                            "fields": [{"name": "user"}, {"name": "posts"}],
                        },
                    ]
                }
            }
        }

    def test_returns_dict(self):
        result = _parse_graphql_types(self._introspection_result())
        assert isinstance(result, dict)

    def test_user_type_has_fields(self):
        result = _parse_graphql_types(self._introspection_result())
        assert "User" in result
        assert "email" in result["User"]
        assert "role" in result["User"]

    def test_internal_types_excluded(self):
        result = _parse_graphql_types(self._introspection_result())
        assert "__Schema" not in result

    def test_post_type_has_fields(self):
        result = _parse_graphql_types(self._introspection_result())
        assert "Post" in result
        assert "title" in result["Post"]

    def test_empty_introspection(self):
        result = _parse_graphql_types({})
        assert result == {}

    def test_type_with_no_fields(self):
        data = {
            "data": {
                "__schema": {
                    "types": [
                        {"name": "EmptyType", "kind": "SCALAR", "fields": None}
                    ]
                }
            }
        }
        result = _parse_graphql_types(data)
        assert result.get("EmptyType") == []

    def test_query_type_present(self):
        result = _parse_graphql_types(self._introspection_result())
        assert "Query" in result


# ===========================================================================
# _build_nested_graphql_query
# ===========================================================================


class TestBuildNestedGraphQLQuery:
    def test_returns_string(self):
        q = _build_nested_graphql_query(3)
        assert isinstance(q, str)

    def test_starts_with_brace(self):
        q = _build_nested_graphql_query(1)
        assert q.startswith("{")

    def test_ends_with_brace(self):
        q = _build_nested_graphql_query(1)
        assert q.endswith("}")

    def test_zero_depth(self):
        q = _build_nested_graphql_query(0)
        assert "__typename" in q

    def test_depth_increases_nesting(self):
        q1 = _build_nested_graphql_query(2)
        q2 = _build_nested_graphql_query(5)
        # Deeper query should be longer
        assert len(q2) > len(q1)

    def test_contains_typename(self):
        q = _build_nested_graphql_query(4)
        assert "__typename" in q


# ===========================================================================
# OpenAPIParserTool
# ===========================================================================


class TestOpenAPIParserTool:
    def test_name(self):
        assert OpenAPIParserTool().name == "openapi_parse"

    def test_description_mentions_openapi(self):
        tool = OpenAPIParserTool()
        assert "openapi" in tool.description.lower() or "swagger" in tool.description.lower()

    def test_parameters_schema_has_spec_url(self):
        tool = OpenAPIParserTool()
        assert "spec_url" in tool.metadata.parameters["properties"]

    def test_parameters_schema_has_spec_json(self):
        tool = OpenAPIParserTool()
        assert "spec_json" in tool.metadata.parameters["properties"]

    def test_mcp_success_returns_json(self):
        tool = OpenAPIParserTool()
        mcp_result = {"success": True, "endpoints": [], "total_endpoints": 0}
        tool._client = _make_mcp_client(mcp_result)
        result = _run(tool.execute(spec_url="http://target/api/swagger.json", allow_internal=True))
        data = json.loads(result)
        assert data["success"] is True

    def test_offline_fallback_with_spec_json(self):
        spec_json = {
            "openapi": "3.0.0",
            "servers": [{"url": "https://api.example.com"}],
            "paths": {"/items": {"get": {"operationId": "list"}}},
        }
        tool = OpenAPIParserTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute(spec_json=spec_json))
        data = json.loads(result)
        assert data["success"] is True
        assert data["source"] == "local_parse"
        assert len(data["endpoints"]) == 1

    def test_offline_no_spec_returns_error(self):
        tool = OpenAPIParserTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute())
        data = json.loads(result)
        assert data["success"] is False

    def test_mcp_failure_falls_back_to_local(self):
        spec_json = {"paths": {"/a": {"get": {}}}}
        tool = OpenAPIParserTool()
        tool._client = _make_mcp_client({"success": False})
        result = _run(tool.execute(spec_json=spec_json))
        data = json.loads(result)
        assert data["source"] == "local_parse"

    def test_owasp_tag_in_fallback(self):
        tool = OpenAPIParserTool()
        tool._client = _make_mcp_client(raise_exc=True)
        spec_json = {"paths": {"/a": {"get": {}}}}
        result = _run(tool.execute(spec_json=spec_json))
        assert OWASP_API_TAG in result

    def test_total_endpoints_correct_in_fallback(self):
        spec_json = {
            "paths": {
                "/a": {"get": {}, "post": {}},
                "/b": {"delete": {}},
            }
        }
        tool = OpenAPIParserTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute(spec_json=spec_json))
        data = json.loads(result)
        assert data["total_endpoints"] == 3


# ===========================================================================
# APIFuzzTool
# ===========================================================================


class TestAPIFuzzTool:
    def test_name(self):
        assert APIFuzzTool().name == "api_fuzz"

    def test_description_mentions_fuzz(self):
        assert "fuzz" in APIFuzzTool().description.lower()

    def test_url_required(self):
        tool = APIFuzzTool()
        assert "url" in tool.metadata.parameters["required"]

    def test_mcp_success_returns_json(self):
        tool = APIFuzzTool()
        mcp_result = {"success": True, "findings": [], "total_requests": 20}
        tool._client = _make_mcp_client(mcp_result)
        result = _run(tool.execute(url="http://target/api/v1/users", allow_internal=True))
        data = json.loads(result)
        assert data["success"] is True

    def test_offline_fallback_returns_mutation_plan(self):
        # Use a single short-type param to avoid truncation issues with long string mutations
        params = [
            {"name": "user_id", "in": "query", "schema": {"type": "integer"}},
            {"name": "active", "in": "query", "schema": {"type": "boolean"}},
        ]
        tool = APIFuzzTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute(url="http://target/api/users", parameters=params, max_mutations=3))
        # Result may be truncated, so just check it contains key markers
        assert "mutation_plan" in result
        assert "user_id" in result

    def test_fallback_respects_max_mutations(self):
        params = [{"name": "q", "in": "query", "schema": {"type": "string"}}]
        tool = APIFuzzTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute(url="http://target/", parameters=params, max_mutations=3))
        data = json.loads(result)
        assert len(data["mutation_plan"][0]["mutations"]) <= 3

    def test_fallback_includes_url(self):
        tool = APIFuzzTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute(url="http://target/api/endpoint"))
        data = json.loads(result)
        assert data["url"] == "http://target/api/endpoint"

    def test_parameters_schema_has_method_enum(self):
        tool = APIFuzzTool()
        props = tool.metadata.parameters["properties"]
        assert "method" in props

    def test_mcp_failure_falls_back_gracefully(self):
        tool = APIFuzzTool()
        tool._client = _make_mcp_client({"success": False})
        result = _run(tool.execute(url="http://target/api"))
        data = json.loads(result)
        assert data["success"] is True
        assert data["source"] == "mutation_plan"


# ===========================================================================
# MassAssignmentTool
# ===========================================================================


class TestMassAssignmentTool:
    def test_name(self):
        assert MassAssignmentTool().name == "mass_assignment_test"

    def test_description_mentions_mass_assignment(self):
        desc = MassAssignmentTool().description.lower()
        assert "mass assignment" in desc or "mass_assignment" in desc or "privilege" in desc

    def test_url_required(self):
        assert "url" in MassAssignmentTool().metadata.parameters["required"]

    def test_owasp_tag_is_mass_assign(self):
        assert OWASP_MASS_ASSIGN_TAG.startswith("A08")

    def test_mcp_success_returns_json(self):
        tool = MassAssignmentTool()
        mcp_result = {"success": True, "findings": ["role field accepted"], "vulnerable": True}
        tool._client = _make_mcp_client(mcp_result)
        result = _run(tool.execute(url="http://target/api/users", allow_internal=True))
        data = json.loads(result)
        assert data["success"] is True

    def test_offline_fallback_returns_plan(self):
        tool = MassAssignmentTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute(url="http://target/api/users"))
        data = json.loads(result)
        assert data["success"] is True
        assert "fields_to_inject" in data or "target_fields" in data or "owasp_tag" in data

    def test_extra_fields_merged(self):
        tool = MassAssignmentTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute(url="http://target/", extra_fields=["custom_priv_field"]))
        data = json.loads(result)
        fields = data.get("fields_to_inject") or data.get("target_fields") or []
        assert "custom_priv_field" in fields or "custom_priv_field" in result

    def test_owasp_tag_in_fallback_output(self):
        tool = MassAssignmentTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute(url="http://target/api/users"))
        assert OWASP_MASS_ASSIGN_TAG in result

    def test_base_payload_passed_to_mcp(self):
        tool = MassAssignmentTool()
        captured = {}

        async def call_tool(name, params):
            captured.update(params)
            return {"success": True}

        tool._client = MagicMock()
        tool._client.call_tool = AsyncMock(side_effect=call_tool)
        _run(tool.execute(url="http://target/", base_payload={"name": "alice"}, allow_internal=True))
        assert captured.get("base_payload") == {"name": "alice"}


# ===========================================================================
# GraphQLIntrospectionTool
# ===========================================================================


class TestGraphQLIntrospectionTool:
    def test_name(self):
        assert GraphQLIntrospectionTool().name == "graphql_introspection"

    def test_description_mentions_introspection(self):
        assert "introspect" in GraphQLIntrospectionTool().description.lower()

    def test_url_required(self):
        assert "url" in GraphQLIntrospectionTool().metadata.parameters["required"]

    def test_mcp_success_returns_json(self):
        tool = GraphQLIntrospectionTool()
        mcp_result = {
            "success": True,
            "introspection_enabled": True,
            "types": {"User": ["id", "email"]},
        }
        tool._client = _make_mcp_client(mcp_result)
        result = _run(tool.execute(url="http://target/graphql", allow_internal=True))
        data = json.loads(result)
        assert data["success"] is True

    def test_offline_fallback_contains_query(self):
        tool = GraphQLIntrospectionTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute(url="http://target/graphql"))
        data = json.loads(result)
        assert "introspection_query" in data
        assert "__schema" in data["introspection_query"]

    def test_offline_fallback_severity(self):
        tool = GraphQLIntrospectionTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute(url="http://target/graphql"))
        data = json.loads(result)
        assert data["severity"] == APISeverity.MEDIUM

    def test_owasp_graphql_tag_in_fallback(self):
        tool = GraphQLIntrospectionTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute(url="http://target/graphql"))
        assert OWASP_GRAPHQL_TAG in result

    def test_mcp_failure_falls_back_gracefully(self):
        tool = GraphQLIntrospectionTool()
        tool._client = _make_mcp_client({"success": False})
        result = _run(tool.execute(url="http://target/graphql"))
        data = json.loads(result)
        assert data["source"] == "fallback_schema"


# ===========================================================================
# GraphQLInjectionTool
# ===========================================================================


class TestGraphQLInjectionTool:
    def test_name(self):
        assert GraphQLInjectionTool().name == "graphql_injection"

    def test_description_mentions_batching(self):
        desc = GraphQLInjectionTool().description.lower()
        assert "batch" in desc or "injection" in desc

    def test_url_required(self):
        assert "url" in GraphQLInjectionTool().metadata.parameters["required"]

    def test_mcp_success_returns_json(self):
        tool = GraphQLInjectionTool()
        mcp_result = {"success": True, "findings": ["batching allowed"], "tests": {}}
        tool._client = _make_mcp_client(mcp_result)
        result = _run(tool.execute(url="http://target/graphql", allow_internal=True))
        data = json.loads(result)
        assert data["success"] is True

    def test_offline_fallback_batching_test(self):
        tool = GraphQLInjectionTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute(url="http://target/graphql", test_batching=True))
        data = json.loads(result)
        assert "batch_test" in data.get("tests", {})

    def test_offline_fallback_nested_dos(self):
        tool = GraphQLInjectionTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute(url="http://target/graphql", test_nested_dos=True))
        data = json.loads(result)
        assert "nested_dos" in data.get("tests", {})

    def test_offline_fallback_field_suggestion(self):
        tool = GraphQLInjectionTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute(url="http://target/graphql", test_field_suggestion=True))
        data = json.loads(result)
        assert "field_suggestion" in data.get("tests", {})

    def test_disabled_test_not_in_plan(self):
        tool = GraphQLInjectionTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(
            tool.execute(
                url="http://target/graphql",
                test_batching=False,
                test_nested_dos=False,
                test_field_suggestion=True,
            )
        )
        data = json.loads(result)
        tests = data.get("tests", {})
        assert "batch_test" not in tests
        assert "nested_dos" not in tests

    def test_owasp_tag_in_fallback(self):
        tool = GraphQLInjectionTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute(url="http://target/graphql"))
        assert OWASP_GRAPHQL_TAG in result

    def test_nest_depth_respected(self):
        tool = GraphQLInjectionTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute(url="http://target/graphql", nest_depth=5, test_nested_dos=True))
        data = json.loads(result)
        nested = data["tests"]["nested_dos"]["payload"]
        # _build_nested_graphql_query wraps __typename in 5 "... on Object" levels
        assert "__typename" in nested
        assert nested.count("Object") == 5


# ===========================================================================
# GraphQLIDORTool
# ===========================================================================


class TestGraphQLIDORTool:
    def test_name(self):
        assert GraphQLIDORTool().name == "graphql_idor"

    def test_description_mentions_idor(self):
        assert "idor" in GraphQLIDORTool().description.lower() or "object reference" in GraphQLIDORTool().description.lower()

    def test_url_and_query_required(self):
        required = GraphQLIDORTool().metadata.parameters["required"]
        assert "url" in required
        assert "query" in required

    def test_mcp_success_returns_json(self):
        tool = GraphQLIDORTool()
        mcp_result = {"success": True, "vulnerable_ids": ["2", "3"], "findings": []}
        tool._client = _make_mcp_client(mcp_result)
        result = _run(
            tool.execute(
                url="http://target/graphql",
                query="query($id:ID!){user(id:$id){email}}",
                allow_internal=True,
            )
        )
        data = json.loads(result)
        assert data["success"] is True

    def test_offline_fallback_includes_test_ids(self):
        tool = GraphQLIDORTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(
            tool.execute(url="http://target/graphql", query="query($id:ID!){user(id:$id){email}}")
        )
        data = json.loads(result)
        assert "test_ids" in data
        assert len(data["test_ids"]) > 0

    def test_custom_test_ids_used(self):
        tool = GraphQLIDORTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(
            tool.execute(
                url="http://target/graphql",
                query="query($id:ID!){user(id:$id){email}}",
                test_ids=["99", "100"],
            )
        )
        data = json.loads(result)
        assert "99" in data["test_ids"]
        assert "100" in data["test_ids"]

    def test_default_ids_include_sentinel_values(self):
        tool = GraphQLIDORTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(
            tool.execute(url="http://target/graphql", query="query($id:ID!){user(id:$id){email}}")
        )
        data = json.loads(result)
        assert "0" in data["test_ids"] or "-1" in data["test_ids"]

    def test_severity_high_in_fallback(self):
        tool = GraphQLIDORTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(
            tool.execute(url="http://target/graphql", query="query($id:ID!){user(id:$id){email}}")
        )
        data = json.loads(result)
        assert data["severity"] == APISeverity.HIGH

    def test_owasp_api_tag_in_fallback(self):
        tool = GraphQLIDORTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(
            tool.execute(url="http://target/graphql", query="query($id:ID!){user(id:$id){email}}")
        )
        assert OWASP_API_TAG in result


# ===========================================================================
# APIRateLimitTool
# ===========================================================================


class TestAPIRateLimitTool:
    def test_name(self):
        assert APIRateLimitTool().name == "api_rate_limit_test"

    def test_description_mentions_rate_limit(self):
        desc = APIRateLimitTool().description.lower()
        assert "rate" in desc and "limit" in desc

    def test_url_required(self):
        assert "url" in APIRateLimitTool().metadata.parameters["required"]

    def test_mcp_success_returns_json(self):
        tool = APIRateLimitTool()
        mcp_result = {"success": True, "rate_limited": True, "bypass_succeeded": False}
        tool._client = _make_mcp_client(mcp_result)
        result = _run(tool.execute(url="http://target/api/login", allow_internal=True))
        data = json.loads(result)
        assert data["success"] is True

    def test_offline_fallback_includes_plan(self):
        tool = APIRateLimitTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute(url="http://target/api/login"))
        data = json.loads(result)
        assert "plan" in data
        assert data["source"] == "rate_limit_test_plan"

    def test_offline_fallback_includes_bypass_headers(self):
        tool = APIRateLimitTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute(url="http://target/api/login", test_bypass_headers=True))
        data = json.loads(result)
        bypass_headers = data["plan"].get("bypass_headers_to_test", [])
        assert len(bypass_headers) > 0

    def test_bypass_headers_disabled(self):
        tool = APIRateLimitTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute(url="http://target/api", test_bypass_headers=False))
        data = json.loads(result)
        bypass_headers = data["plan"].get("bypass_headers_to_test", [])
        assert bypass_headers == []

    def test_request_count_in_plan(self):
        tool = APIRateLimitTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute(url="http://target/api", request_count=25))
        data = json.loads(result)
        assert data["plan"]["baseline_requests"] == 25

    def test_owasp_rate_limit_tag_in_fallback(self):
        tool = APIRateLimitTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute(url="http://target/api"))
        assert "API4" in result or "Resource" in result


# ===========================================================================
# CORSMisconfigTool
# ===========================================================================


class TestCORSMisconfigTool:
    def test_name(self):
        assert CORSMisconfigTool().name == "cors_misconfig_test"

    def test_description_mentions_cors(self):
        assert "cors" in CORSMisconfigTool().description.lower()

    def test_url_required(self):
        assert "url" in CORSMisconfigTool().metadata.parameters["required"]

    def test_mcp_success_returns_json(self):
        tool = CORSMisconfigTool()
        mcp_result = {
            "success": True,
            "vulnerable": True,
            "findings": ["Wildcard ACAO"],
        }
        tool._client = _make_mcp_client(mcp_result)
        result = _run(tool.execute(url="http://target/api", allow_internal=True))
        data = json.loads(result)
        assert data["success"] is True

    def test_offline_fallback_includes_origins(self):
        tool = CORSMisconfigTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute(url="http://target/api"))
        data = json.loads(result)
        assert "origins_to_test" in data
        assert len(data["origins_to_test"]) > 0

    def test_extra_origins_merged(self):
        tool = CORSMisconfigTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute(url="http://target/api", extra_origins=["https://custom.evil.com"]))
        data = json.loads(result)
        origins_list: list = data["origins_to_test"]
        assert origins_list.count("https://custom.evil.com") == 1

    def test_no_duplicate_origins(self):
        tool = CORSMisconfigTool()
        tool._client = _make_mcp_client(raise_exc=True)
        # Pass an origin that is already in _CORS_TEST_ORIGINS
        result = _run(tool.execute(url="http://target/api", extra_origins=["https://evil.com"]))
        data = json.loads(result)
        origins = data["origins_to_test"]
        assert origins.count("https://evil.com") == 1

    def test_owasp_cors_tag_in_fallback(self):
        tool = CORSMisconfigTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute(url="http://target/api"))
        assert OWASP_CORS_TAG in result

    def test_detection_criteria_present(self):
        tool = CORSMisconfigTool()
        tool._client = _make_mcp_client(raise_exc=True)
        result = _run(tool.execute(url="http://target/api"))
        data = json.loads(result)
        assert "detection_criteria" in data

    def test_mcp_failure_falls_back_to_plan(self):
        tool = CORSMisconfigTool()
        tool._client = _make_mcp_client({"success": False})
        result = _run(tool.execute(url="http://target/api"))
        data = json.loads(result)
        assert data["source"] == "cors_test_plan"


# ===========================================================================
# graphql_tools re-exports
# ===========================================================================


class TestGraphQLToolsReExports:
    def test_introspection_alias_is_same_class(self):
        assert GQLIntrospectionAlias is GraphQLIntrospectionTool

    def test_injection_alias_is_same_class(self):
        assert GQLInjectionAlias is GraphQLInjectionTool

    def test_idor_alias_is_same_class(self):
        assert GQLIDORAlias is GraphQLIDORTool

    def test_gql_tag_matches_main(self):
        assert GQL_TAG == OWASP_GRAPHQL_TAG

    def test_introspection_alias_instantiable(self):
        tool = GQLIntrospectionAlias()
        assert tool.name == "graphql_introspection"

    def test_injection_alias_instantiable(self):
        tool = GQLInjectionAlias()
        assert tool.name == "graphql_injection"

    def test_idor_alias_instantiable(self):
        tool = GQLIDORAlias()
        assert tool.name == "graphql_idor"


# ===========================================================================
# APISeverity enum
# ===========================================================================


class TestAPISeverityEnum:
    def test_critical(self):
        assert APISeverity.CRITICAL == "critical"

    def test_high(self):
        assert APISeverity.HIGH == "high"

    def test_medium(self):
        assert APISeverity.MEDIUM == "medium"

    def test_low(self):
        assert APISeverity.LOW == "low"

    def test_info(self):
        assert APISeverity.INFO == "info"


# ===========================================================================
# OWASP tags
# ===========================================================================


class TestOWASPTags:
    def test_api_tag_has_a04(self):
        assert "A04" in OWASP_API_TAG

    def test_mass_assign_tag_has_a08(self):
        assert "A08" in OWASP_MASS_ASSIGN_TAG

    def test_cors_tag_has_a05(self):
        assert "A05" in OWASP_CORS_TAG

    def test_graphql_tag_has_a03(self):
        assert "A03" in OWASP_GRAPHQL_TAG


# ===========================================================================
# _is_internal
# ===========================================================================


class TestIsInternal:
    def test_localhost_string(self):
        assert _is_internal("localhost") is True

    def test_127_0_0_1(self):
        assert _is_internal("127.0.0.1") is True

    def test_ipv6_loopback(self):
        assert _is_internal("::1") is True

    def test_10_0_0_1_private(self):
        assert _is_internal("10.0.0.1") is True

    def test_10_subnet(self):
        assert _is_internal("10.255.255.255") is True

    def test_172_16_private(self):
        assert _is_internal("172.16.0.1") is True

    def test_172_31_private(self):
        assert _is_internal("172.31.255.255") is True

    def test_192_168_private(self):
        assert _is_internal("192.168.1.100") is True

    def test_public_ip_not_internal(self):
        assert _is_internal("8.8.8.8") is False

    def test_external_hostname_not_internal(self):
        assert _is_internal("example.com") is False

    def test_172_32_not_private(self):
        assert _is_internal("172.32.0.1") is False

    def test_empty_string_not_internal(self):
        assert _is_internal("") is False

    def test_invalid_ip_not_internal(self):
        assert _is_internal("not.an.ip.address") is False


# ===========================================================================
# _extract_host
# ===========================================================================


class TestExtractHost:
    def test_simple_url(self):
        assert _extract_host("http://example.com/path") == "example.com"

    def test_url_with_port(self):
        assert _extract_host("http://example.com:8080/api") == "example.com"

    def test_ip_url(self):
        assert _extract_host("https://10.10.10.1/api") == "10.10.10.1"

    def test_empty_url(self):
        assert _extract_host("") == ""

    def test_invalid_url(self):
        result = _extract_host("not_a_url")
        assert isinstance(result, str)

    def test_localhost_url(self):
        assert _extract_host("http://localhost:8009/graphql") == "localhost"


# ===========================================================================
# _validate_url
# ===========================================================================


class TestValidateUrl:
    def test_valid_https_url_passes(self):
        _validate_url("https://example.com/api", allow_internal=False)

    def test_valid_http_url_passes(self):
        _validate_url("http://example.com/api", allow_internal=False)

    def test_ftp_scheme_raises(self):
        with pytest.raises(ValueError, match="Invalid URL scheme"):
            _validate_url("ftp://example.com/api")

    def test_no_scheme_raises(self):
        with pytest.raises(ValueError):
            _validate_url("example.com/api")

    def test_internal_ip_raises_by_default(self):
        with pytest.raises(ValueError, match="internal"):
            _validate_url("http://192.168.1.1/api")

    def test_localhost_raises_by_default(self):
        with pytest.raises(ValueError, match="internal"):
            _validate_url("http://localhost/api")

    def test_internal_allowed_when_flag_set(self):
        _validate_url("http://192.168.1.1/api", allow_internal=True)

    def test_loopback_allowed_when_flag_set(self):
        _validate_url("http://127.0.0.1/api", allow_internal=True)

    def test_10_subnet_blocked_by_default(self):
        with pytest.raises(ValueError):
            _validate_url("http://10.10.10.1/api")


# ===========================================================================
# APISecurityServer
# ===========================================================================


class TestAPISecurityServer:
    def test_get_tools_returns_8_tools(self):
        server = APISecurityServer()
        tools = server.get_tools()
        assert len(tools) == 8

    def test_tool_names(self):
        server = APISecurityServer()
        names = {t.name for t in server.get_tools()}
        expected = {
            "parse_openapi_spec",
            "fuzz_api_endpoint",
            "test_mass_assignment",
            "graphql_introspect",
            "graphql_injection_test",
            "graphql_idor_test",
            "test_rate_limiting",
            "test_cors_misconfig",
        }
        assert names == expected

    def test_all_tools_have_descriptions(self):
        server = APISecurityServer()
        for tool in server.get_tools():
            assert tool.description.strip() != ""

    def test_server_name(self):
        server = APISecurityServer()
        assert server.name == "APISecurity"

    def test_server_port(self):
        server = APISecurityServer()
        assert server.port == 8009

    def test_allow_internal_default_false(self):
        server = APISecurityServer()
        assert server._allow_internal is False

    def test_allow_internal_can_be_enabled(self):
        server = APISecurityServer(allow_internal=True)
        assert server._allow_internal is True

    def test_recon_phase_tools_present(self):
        server = APISecurityServer()
        recon_tools = [t for t in server.get_tools() if t.phase == "recon"]
        assert len(recon_tools) >= 2

    def test_attack_phase_tools_present(self):
        server = APISecurityServer()
        attack_tools = [t for t in server.get_tools() if t.phase == "web_app_attack"]
        assert len(attack_tools) >= 2


# ===========================================================================
# _parse_openapi_spec_server (server-side helper)
# ===========================================================================


class TestParseOpenAPISpecServer:
    """Test the server-side _parse_openapi_spec_server helper."""

    def test_import(self):
        from app.mcp.servers.api_security_server import _parse_openapi_spec_server
        assert callable(_parse_openapi_spec_server)

    def test_parses_openapi3(self):
        from app.mcp.servers.api_security_server import _parse_openapi_spec_server
        spec = {
            "openapi": "3.0.0",
            "servers": [{"url": "https://api.example.com"}],
            "paths": {"/users": {"get": {"operationId": "listUsers"}}},
        }
        endpoints = _parse_openapi_spec_server(spec)
        assert len(endpoints) == 1
        assert endpoints[0]["method"] == "GET"

    def test_parses_swagger2(self):
        from app.mcp.servers.api_security_server import _parse_openapi_spec_server
        spec = {
            "swagger": "2.0",
            "host": "api.example.com",
            "basePath": "/v1",
            "schemes": ["https"],
            "paths": {"/items": {"post": {"operationId": "createItem"}}},
        }
        endpoints = _parse_openapi_spec_server(spec)
        assert len(endpoints) == 1
        assert endpoints[0]["method"] == "POST"
        parsed = urllib.parse.urlparse(endpoints[0]["url"])
        assert parsed.hostname == "api.example.com"

    def test_empty_spec_returns_empty(self):
        from app.mcp.servers.api_security_server import _parse_openapi_spec_server
        assert _parse_openapi_spec_server({}) == []


# ===========================================================================
# ToolRegistry.# ===========================================================================


class TestToolRegistryDay5:
    def _registry(self):
        from app.agent.tools.tool_registry import create_default_registry
        return create_default_registry()

    def test_openapi_parse_registered(self):
        assert self._registry().get_tool("openapi_parse") is not None

    def test_api_fuzz_registered(self):
        assert self._registry().get_tool("api_fuzz") is not None

    def test_mass_assignment_registered(self):
        assert self._registry().get_tool("mass_assignment_test") is not None

    def test_graphql_introspect_registered(self):
        assert self._registry().get_tool("graphql_introspection") is not None

    def test_graphql_injection_registered(self):
        assert self._registry().get_tool("graphql_injection") is not None

    def test_graphql_idor_registered(self):
        assert self._registry().get_tool("graphql_idor") is not None

    def test_api_rate_limit_registered(self):
        assert self._registry().get_tool("api_rate_limit_test") is not None

    def test_cors_misconfig_registered(self):
        assert self._registry().get_tool("cors_misconfig_test") is not None

    # Phase checks — INFORMATIONAL
    def test_openapi_parse_informational(self):
        assert self._registry().is_tool_allowed("openapi_parse", Phase.INFORMATIONAL)

    def test_openapi_parse_exploitation(self):
        assert self._registry().is_tool_allowed("openapi_parse", Phase.EXPLOITATION)

    def test_api_fuzz_exploitation_only(self):
        r = self._registry()
        assert r.is_tool_allowed("api_fuzz", Phase.EXPLOITATION)
        assert not r.is_tool_allowed("api_fuzz", Phase.INFORMATIONAL)

    def test_mass_assignment_exploitation_only(self):
        r = self._registry()
        assert r.is_tool_allowed("mass_assignment_test", Phase.EXPLOITATION)
        assert not r.is_tool_allowed("mass_assignment_test", Phase.INFORMATIONAL)

    def test_graphql_introspect_informational(self):
        assert self._registry().is_tool_allowed("graphql_introspection", Phase.INFORMATIONAL)

    def test_graphql_introspect_exploitation(self):
        assert self._registry().is_tool_allowed("graphql_introspection", Phase.EXPLOITATION)

    def test_graphql_injection_exploitation_only(self):
        r = self._registry()
        assert r.is_tool_allowed("graphql_injection", Phase.EXPLOITATION)
        assert not r.is_tool_allowed("graphql_injection", Phase.INFORMATIONAL)

    def test_graphql_idor_exploitation_only(self):
        r = self._registry()
        assert r.is_tool_allowed("graphql_idor", Phase.EXPLOITATION)
        assert not r.is_tool_allowed("graphql_idor", Phase.INFORMATIONAL)

    def test_api_rate_limit_informational(self):
        assert self._registry().is_tool_allowed("api_rate_limit_test", Phase.INFORMATIONAL)

    def test_api_rate_limit_exploitation(self):
        assert self._registry().is_tool_allowed("api_rate_limit_test", Phase.EXPLOITATION)

    def test_cors_misconfig_informational(self):
        assert self._registry().is_tool_allowed("cors_misconfig_test", Phase.INFORMATIONAL)

    def test_cors_misconfig_exploitation(self):
        assert self._registry().is_tool_allowed("cors_misconfig_test", Phase.EXPLOITATION)


# ===========================================================================
# AttackPathRouter — API / GraphQL / CORS keywords
# ===========================================================================


class TestAttackPathRouterAPIKeywords:
    def _router(self) -> AttackPathRouter:
        with patch.dict("os.environ", {"CLASSIFIER_MODE": "keyword"}):
            return AttackPathRouter()

    def test_api_fuzzing_keyword(self):
        cat = self._router().classify_intent("api fuzzing on the user registration endpoint")
        assert cat == AttackCategory.WEB_APP_ATTACK

    def test_graphql_injection_keyword(self):
        cat = self._router().classify_intent("test graphql injection vulnerabilities")
        assert cat == AttackCategory.WEB_APP_ATTACK

    def test_cors_misconfiguration_keyword(self):
        cat = self._router().classify_intent("check for cors misconfiguration on the api")
        assert cat == AttackCategory.WEB_APP_ATTACK

    def test_mass_assignment_keyword(self):
        cat = self._router().classify_intent("attempt mass assignment attack on the profile update endpoint")
        assert cat == AttackCategory.WEB_APP_ATTACK

    def test_graphql_introspection_keyword(self):
        cat = self._router().classify_intent("enumerate graphql schema via introspection")
        assert cat == AttackCategory.WEB_APP_ATTACK

    def test_rate_limit_keyword(self):
        cat = self._router().classify_intent("test rate limiting bypass with x-forwarded-for")
        assert cat == AttackCategory.WEB_APP_ATTACK

    def test_openapi_keyword(self):
        cat = self._router().classify_intent("parse the openapi swagger spec for attack surface")
        assert cat == AttackCategory.WEB_APP_ATTACK

    def test_web_app_attack_plan_structure(self):
        router = self._router()
        plan = router.get_attack_plan(AttackCategory.WEB_APP_ATTACK, {"host": "10.10.10.1"})
        assert plan["risk_level"] == "high"
        assert "steps" in plan

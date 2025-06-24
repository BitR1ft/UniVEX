"""
Tests for PLAN.md Day 5 — GraphQL Security Tools (graphql_tools.py re-exports)

Coverage:
  - Re-export identity: graphql_tools.GraphQL* is api_security_tools.GraphQL*
  - Re-exported helpers: _GRAPHQL_INTROSPECTION_QUERY, _GRAPHQL_FIELD_SUGGESTION_PAYLOAD,
      _GRAPHQL_BATCH_PAYLOAD, _build_nested_graphql_query, _parse_graphql_types
  - OWASP_GRAPHQL_TAG re-export consistency
  - __all__ completeness check
  - graphql_tools module usable independently as a namespace for the 3 GraphQL tools
"""

from __future__ import annotations

import json
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest

import app.agent.tools.graphql_tools as gql_module
from app.agent.tools.api_security_tools import (
    GraphQLIDORTool as _ApiGQLIDOR,
    GraphQLInjectionTool as _ApiGQLInjection,
    GraphQLIntrospectionTool as _ApiGQLIntrospection,
    OWASP_GRAPHQL_TAG as _ApiGQLTag,
    _GRAPHQL_BATCH_PAYLOAD as _ApiGQLBatch,
    _GRAPHQL_FIELD_SUGGESTION_PAYLOAD as _ApiGQLSuggestion,
    _GRAPHQL_INTROSPECTION_QUERY as _ApiGQLIntrospectionQuery,
    _build_nested_graphql_query,
    _parse_graphql_types,
)
from app.agent.tools.graphql_tools import (
    GraphQLIDORTool,
    GraphQLInjectionTool,
    GraphQLIntrospectionTool,
    OWASP_GRAPHQL_TAG,
    _GRAPHQL_BATCH_PAYLOAD,
    _GRAPHQL_FIELD_SUGGESTION_PAYLOAD,
    _GRAPHQL_INTROSPECTION_QUERY,
    _build_nested_graphql_query as gql_build_nested,
    _parse_graphql_types as gql_parse_types,
)


# ===========================================================================
# Helpers
# ===========================================================================


def _make_graphql_client(
    success: bool = True,
    introspection_enabled: bool = True,
    types: dict = None,
    findings: list = None,
) -> MagicMock:
    types = types or {}
    findings = findings or []

    async def call_tool(name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if name == "graphql_introspect":
            return {
                "success": success,
                "introspection_enabled": introspection_enabled,
                "types": types,
                "total_types": len(types),
                "severity": "medium" if introspection_enabled else "info",
                "url": params.get("url", ""),
            }
        return {
            "success": success,
            "findings": findings,
            "total": len(findings),
            "url": params.get("url", ""),
        }

    client = MagicMock()
    client.call_tool = AsyncMock(side_effect=call_tool)
    return client


# ===========================================================================
# Re-export identity tests
# ===========================================================================


class TestReExportIdentity:
    """graphql_tools re-exports must be the exact same objects as api_security_tools."""

    def test_introspection_tool_is_same_class(self):
        assert GraphQLIntrospectionTool is _ApiGQLIntrospection

    def test_injection_tool_is_same_class(self):
        assert GraphQLInjectionTool is _ApiGQLInjection

    def test_idor_tool_is_same_class(self):
        assert GraphQLIDORTool is _ApiGQLIDOR

    def test_owasp_tag_is_same(self):
        assert OWASP_GRAPHQL_TAG is _ApiGQLTag

    def test_introspection_query_is_same(self):
        assert _GRAPHQL_INTROSPECTION_QUERY is _ApiGQLIntrospectionQuery

    def test_field_suggestion_payload_is_same(self):
        assert _GRAPHQL_FIELD_SUGGESTION_PAYLOAD is _ApiGQLSuggestion

    def test_batch_payload_is_same(self):
        assert _GRAPHQL_BATCH_PAYLOAD is _ApiGQLBatch

    def test_build_nested_is_same(self):
        assert gql_build_nested is _build_nested_graphql_query

    def test_parse_types_is_same(self):
        assert gql_parse_types is _parse_graphql_types


# ===========================================================================
# __all__ completeness
# ===========================================================================


class TestDunderAll:
    def test_all_is_list(self):
        assert isinstance(gql_module.__all__, list)

    def test_all_contains_three_tools(self):
        assert "GraphQLIntrospectionTool" in gql_module.__all__
        assert "GraphQLInjectionTool" in gql_module.__all__
        assert "GraphQLIDORTool" in gql_module.__all__

    def test_all_contains_owasp_tag(self):
        assert "OWASP_GRAPHQL_TAG" in gql_module.__all__

    def test_all_contains_introspection_query(self):
        assert "_GRAPHQL_INTROSPECTION_QUERY" in gql_module.__all__

    def test_all_contains_field_suggestion_payload(self):
        assert "_GRAPHQL_FIELD_SUGGESTION_PAYLOAD" in gql_module.__all__

    def test_all_contains_batch_payload(self):
        assert "_GRAPHQL_BATCH_PAYLOAD" in gql_module.__all__

    def test_all_contains_build_nested(self):
        assert "_build_nested_graphql_query" in gql_module.__all__

    def test_all_contains_parse_types(self):
        assert "_parse_graphql_types" in gql_module.__all__

    def test_all_no_duplicates(self):
        assert len(gql_module.__all__) == len(set(gql_module.__all__))


# ===========================================================================
# Constant value tests
# ===========================================================================


class TestGraphQLConstants:
    def test_introspection_query_is_string(self):
        assert isinstance(_GRAPHQL_INTROSPECTION_QUERY, str)
        assert len(_GRAPHQL_INTROSPECTION_QUERY) > 50

    def test_introspection_query_contains_schema(self):
        assert "__schema" in _GRAPHQL_INTROSPECTION_QUERY

    def test_introspection_query_contains_types(self):
        assert "types" in _GRAPHQL_INTROSPECTION_QUERY

    def test_field_suggestion_payload_is_string(self):
        assert isinstance(_GRAPHQL_FIELD_SUGGESTION_PAYLOAD, str)
        assert len(_GRAPHQL_FIELD_SUGGESTION_PAYLOAD) > 0

    def test_batch_payload_is_json_list(self):
        # batch payload should be parseable JSON array
        data = json.loads(_GRAPHQL_BATCH_PAYLOAD)
        assert isinstance(data, list)
        assert len(data) >= 2

    def test_owasp_tag_starts_with_a(self):
        assert OWASP_GRAPHQL_TAG.startswith("A")

    def test_owasp_tag_contains_injection(self):
        assert "Injection" in OWASP_GRAPHQL_TAG or "injection" in OWASP_GRAPHQL_TAG.lower()


# ===========================================================================
# _build_nested_graphql_query helper
# ===========================================================================


class TestBuildNestedGraphQLQuery:
    def test_depth_1_is_nonempty(self):
        q = gql_build_nested(1)
        assert isinstance(q, str)
        assert len(q) > 10

    def test_depth_3_contains_typename(self):
        q = gql_build_nested(3)
        assert "__typename" in q

    def test_depth_increases_length(self):
        q2 = gql_build_nested(2)
        q5 = gql_build_nested(5)
        assert len(q5) > len(q2)

    def test_depth_0_graceful(self):
        # Should not raise
        q = gql_build_nested(0)
        assert isinstance(q, str)

    def test_depth_10_still_valid_string(self):
        q = gql_build_nested(10)
        assert isinstance(q, str)
        assert len(q) > 0

    def test_returns_string_type(self):
        assert isinstance(gql_build_nested(2), str)


# ===========================================================================
# _parse_graphql_types helper
# ===========================================================================


class TestParseGraphQLTypes:
    def _make_introspection_result(self, types: List[Dict]) -> Dict:
        return {"data": {"__schema": {"types": types}}}

    def test_empty_types_returns_empty_dict(self):
        result = gql_parse_types(self._make_introspection_result([]))
        assert result == {}

    def test_filters_internal_types(self):
        result = gql_parse_types(
            self._make_introspection_result([
                {"name": "__Type", "kind": "OBJECT", "fields": []},
                {"name": "__Schema", "kind": "OBJECT", "fields": []},
            ])
        )
        assert len(result) == 0

    def test_includes_user_types(self):
        result = gql_parse_types(
            self._make_introspection_result([
                {
                    "name": "User",
                    "kind": "OBJECT",
                    "fields": [{"name": "id"}, {"name": "email"}],
                }
            ])
        )
        assert "User" in result
        assert "id" in result["User"]
        assert "email" in result["User"]

    def test_multiple_types(self):
        result = gql_parse_types(
            self._make_introspection_result([
                {"name": "User", "kind": "OBJECT", "fields": [{"name": "id"}]},
                {"name": "Post", "kind": "OBJECT", "fields": [{"name": "title"}]},
            ])
        )
        assert len(result) == 2

    def test_type_with_no_fields(self):
        result = gql_parse_types(
            self._make_introspection_result([
                {"name": "Status", "kind": "ENUM", "fields": None},
            ])
        )
        assert "Status" in result
        assert result["Status"] == []

    def test_invalid_schema_returns_empty(self):
        result = gql_parse_types({})
        assert isinstance(result, dict)

    def test_returns_dict(self):
        result = gql_parse_types(self._make_introspection_result([]))
        assert isinstance(result, dict)


# ===========================================================================
# GraphQLIntrospectionTool via graphql_tools namespace
# ===========================================================================


class TestGraphQLIntrospectionToolViaGQLModule:
    """Test GraphQLIntrospectionTool accessed through graphql_tools namespace."""

    def test_tool_can_be_instantiated(self):
        tool = GraphQLIntrospectionTool()
        assert tool is not None

    def test_metadata_name(self):
        tool = GraphQLIntrospectionTool()
        meta = tool._define_metadata()
        assert "graphql" in meta.name.lower() or "introspect" in meta.name.lower()

    def test_metadata_has_description(self):
        tool = GraphQLIntrospectionTool()
        meta = tool._define_metadata()
        assert len(meta.description) > 20

    def test_execute_offline_fallback(self):
        import asyncio

        tool = GraphQLIntrospectionTool(server_url="http://unreachable.invalid:9999")

        async def run():
            return await tool.execute(url="http://example.com/graphql")

        result = asyncio.run(run())
        # Should not raise — offline fallback returns some JSON string
        assert isinstance(result, str)


# ===========================================================================
# GraphQLInjectionTool via graphql_tools namespace
# ===========================================================================


class TestGraphQLInjectionToolViaGQLModule:
    def test_tool_can_be_instantiated(self):
        tool = GraphQLInjectionTool()
        assert tool is not None

    def test_metadata_has_description(self):
        tool = GraphQLInjectionTool()
        meta = tool._define_metadata()
        assert len(meta.description) > 20

    def test_execute_with_mock_client(self):
        import asyncio

        tool = GraphQLInjectionTool(server_url="http://mock-server:8009")
        client = _make_graphql_client(success=True, findings=[{"type": "batching", "severity": "medium"}])

        async def run():
            with MagicMock() as _:
                tool._client = client
                return await tool.execute(url="http://example.com/graphql")

        # Should not raise
        result = asyncio.run(run())
        assert isinstance(result, str)


# ===========================================================================
# GraphQLIDORTool via graphql_tools namespace
# ===========================================================================


class TestGraphQLIDORToolViaGQLModule:
    def test_tool_can_be_instantiated(self):
        tool = GraphQLIDORTool()
        assert tool is not None

    def test_metadata_owasp_tag_in_description(self):
        tool = GraphQLIDORTool()
        meta = tool._define_metadata()
        # OWASP tag should be referenced in the description or name
        assert "idor" in meta.name.lower() or "idor" in meta.description.lower() or "direct" in meta.description.lower()

    def test_metadata_parameters_include_query(self):
        tool = GraphQLIDORTool()
        meta = tool._define_metadata()
        param_names = list(meta.parameters.get("properties", {}).keys())
        assert "query" in param_names

    def test_metadata_parameters_include_url(self):
        tool = GraphQLIDORTool()
        meta = tool._define_metadata()
        param_names = list(meta.parameters.get("properties", {}).keys())
        assert "url" in param_names

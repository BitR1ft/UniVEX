"""
GraphQL Security Tools (graphql_tools.py)

Re-exports the GraphQL-specific tools from api_security_tools 
file-layout compliance. All implementations live in api_security_tools.py.

Exposed tools:
  GraphQLIntrospectionTool — detect introspection, enumerate full schema
  GraphQLInjectionTool     — batch attacks, nested DoS, field-suggestion leak
  GraphQLIDORTool          — IDOR via variable manipulation

Public helpers:
  _build_nested_graphql_query()
  _parse_graphql_types()
  _GRAPHQL_INTROSPECTION_QUERY
  _GRAPHQL_FIELD_SUGGESTION_PAYLOAD
  _GRAPHQL_BATCH_PAYLOAD
"""

from __future__ import annotations

from app.agent.tools.api_security_tools import (  # noqa: F401  re-export
    GraphQLIDORTool,
    GraphQLInjectionTool,
    GraphQLIntrospectionTool,
    OWASP_GRAPHQL_TAG,
    _GRAPHQL_BATCH_PAYLOAD,
    _GRAPHQL_FIELD_SUGGESTION_PAYLOAD,
    _GRAPHQL_INTROSPECTION_QUERY,
    _build_nested_graphql_query,
    _parse_graphql_types,
)

__all__ = [
    "GraphQLIntrospectionTool",
    "GraphQLInjectionTool",
    "GraphQLIDORTool",
    "OWASP_GRAPHQL_TAG",
    "_GRAPHQL_INTROSPECTION_QUERY",
    "_GRAPHQL_FIELD_SUGGESTION_PAYLOAD",
    "_GRAPHQL_BATCH_PAYLOAD",
    "_build_nested_graphql_query",
    "_parse_graphql_types",
]

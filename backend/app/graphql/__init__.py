"""
UniVex GraphQL API

GraphQL layer built with Strawberry, mounted at /graphql.
Provides queries, mutations, and WebSocket subscriptions as a complement
to the existing REST API surface.
"""

from .schema import schema
from .router import graphql_router

__all__ = ["schema", "graphql_router"]

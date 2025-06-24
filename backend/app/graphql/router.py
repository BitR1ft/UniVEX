"""
FastAPI router that mounts the Strawberry GraphQL endpoint.

Routes:
  POST/GET  /graphql          — main GraphQL endpoint (JSON + multipart)
  GET       /graphql          — GraphQL Playground (dev only, via HTTP GET)
  WS        /graphql          — WebSocket subscriptions

The playground is only enabled when ENVIRONMENT != "production".
"""

import os
from typing import Any

from fastapi import APIRouter, Request
from strawberry.fastapi import GraphQLRouter
from strawberry.subscriptions import GRAPHQL_TRANSPORT_WS_PROTOCOL, GRAPHQL_WS_PROTOCOL

from app.graphql.schema import schema

# ---------------------------------------------------------------------------
# Build context
# ---------------------------------------------------------------------------


async def get_graphql_context(request: Request) -> dict[str, Any]:
    """Inject FastAPI request into GraphQL resolver context."""
    return {"request": request}


# ---------------------------------------------------------------------------
# Determine if playground should be enabled
# ---------------------------------------------------------------------------

_env = os.getenv("ENVIRONMENT", "development").lower()
_graphql_playground = _env not in ("production", "prod")

# ---------------------------------------------------------------------------
# Strawberry GraphQL router
# ---------------------------------------------------------------------------

_graphql_app = GraphQLRouter(
    schema,
    context_getter=get_graphql_context,
    graphql_ide="graphiql" if _graphql_playground else None,
    subscription_protocols=[
        GRAPHQL_TRANSPORT_WS_PROTOCOL,     # graphql-transport-ws (recommended)
        GRAPHQL_WS_PROTOCOL,               # legacy graphql-ws (backward compat)
    ],
)

# ---------------------------------------------------------------------------
# APIRouter wrapper so main.py can include_router as usual
# ---------------------------------------------------------------------------

graphql_router = APIRouter()
graphql_router.include_router(_graphql_app, prefix="/graphql", tags=["GraphQL"])

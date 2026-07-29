"""
Proxy REST API

Endpoints:
  POST   /api/proxy/start                  — start proxy with config
  POST   /api/proxy/stop                   — stop proxy
  GET    /api/proxy/status                 — proxy status + metrics
  GET    /api/proxy/requests               — list captured requests (paginated, filterable)
  GET    /api/proxy/requests/{id}          — get full request/response detail
  DELETE /api/proxy/requests               — clear captured history
  POST   /api/proxy/replay/{id}            — replay a captured request
  GET    /api/proxy/websocket-sessions     — list captured WebSocket sessions
  GET    /api/proxy/websocket-frames       — list captured WebSocket frames
  GET    /api/proxy/websocket-frames/{id}  — get single frame detail
  POST   /api/proxy/websocket-frames/{id}/replay — replay a WebSocket frame
  GET    /api/proxy/ca-cert               — download the proxy CA certificate (PEM)
  GET    /api/proxy/browser-config         — download browser proxy configuration
  GET    /api/proxy.pac                    — PAC file
  POST   /api/proxy/scope                  — update in-scope / out-of-scope patterns
  GET    /api/proxy/scope                  — get current scope configuration
  POST   /api/proxy/highlight-rules        — add a request highlighting rule
  DELETE /api/proxy/highlight-rules/{index} — remove a highlighting rule

Security: ALL endpoints require a valid JWT bearer token.
Per-user isolation: RequestStore instances are namespaced by user_id so
  users cannot see each other's captured traffic.
"""
from __future__ import annotations

import logging
import re
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from app.api.auth import get_current_user_id
from app.proxy.browser_bridge import BrowserBridge
from app.proxy.interceptor import ProxyInterceptor, ScopeFilter
from app.proxy.request_store import RequestStore
from app.proxy.websocket_interceptor import (
    FrameDirection,
    FrameType,
    WebSocketInterceptor,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/proxy", tags=["Proxy"])

# ---------------------------------------------------------------------------
# Per-user store registry
# Each user gets their own isolated RequestStore and WebSocketInterceptor so
# captured traffic is not visible across accounts.
# ---------------------------------------------------------------------------

_user_stores: Dict[str, RequestStore] = {}
_user_ws_interceptors: Dict[str, WebSocketInterceptor] = {}
_user_highlight_rules: Dict[str, List[Dict[str, Any]]] = {}

# Single proxy interceptor per process (the actual MITM daemon)
# Scope configuration is per-user but the proxy port is shared.
_interceptor: ProxyInterceptor = ProxyInterceptor(store=RequestStore())
_bridge = BrowserBridge()


def _get_store(user_id: str) -> RequestStore:
    if user_id not in _user_stores:
        _user_stores[user_id] = RequestStore()
    return _user_stores[user_id]


def _get_ws_interceptor(user_id: str) -> WebSocketInterceptor:
    if user_id not in _user_ws_interceptors:
        _user_ws_interceptors[user_id] = WebSocketInterceptor()
    return _user_ws_interceptors[user_id]


def _get_highlight_rules(user_id: str) -> List[Dict[str, Any]]:
    if user_id not in _user_highlight_rules:
        _user_highlight_rules[user_id] = []
    return _user_highlight_rules[user_id]


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class StartProxyRequest(BaseModel):
    port: int = Field(8080, ge=1, le=65535)
    upstream: Optional[str] = Field(None, description="Upstream proxy URL (http://host:port)")
    ssl_verify: bool = False
    scope_include: List[str] = Field(default_factory=list)
    scope_exclude: List[str] = Field(default_factory=list)


class ReplayRequestBody(BaseModel):
    method: Optional[str] = None
    url: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = None


class ScopeUpdateRequest(BaseModel):
    include_patterns: List[str] = Field(default_factory=list)
    exclude_patterns: List[str] = Field(default_factory=list)


class HighlightRuleRequest(BaseModel):
    pattern: str = Field(..., description="Regex matched against the full URL")
    color: str = Field("yellow", description="CSS colour name or hex code")
    label: str = Field("", description="Human-readable label shown in the UI")


class WSReplayRequest(BaseModel):
    new_payload: Optional[str] = Field(None, description="If provided, send this instead of the stored payload")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _request_summary(req, highlight_rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Return a concise dict for list views."""
    resp = req.response
    color = _highlight_color(req.url, resp.status_code if resp else 0, highlight_rules)
    return {
        "id": req.id,
        "timestamp": req.timestamp,
        "method": req.method,
        "url": req.url,
        "status_code": resp.status_code if resp else None,
        "content_type": resp.content_type if resp else None,
        "length": len((resp.body or "").encode("utf-8")) if resp else 0,
        "elapsed_ms": resp.elapsed_ms if resp else None,
        "tags": req.tags,
        "notes": req.notes,
        "highlight_color": color,
    }


def _highlight_color(url: str, status_code: int, rules: List[Dict[str, Any]]) -> str:
    """Return a colour for the request row based on custom rules then status code."""
    for rule in rules:
        try:
            if re.search(rule["pattern"], url, re.IGNORECASE):
                return rule["color"]
        except re.error:
            pass

    if status_code == 0:
        return "gray"
    if status_code < 300:
        return "green"
    if status_code < 400:
        return "blue"
    if status_code < 500:
        return "orange"
    return "red"


# ---------------------------------------------------------------------------
# Proxy lifecycle
# ---------------------------------------------------------------------------


@router.post("/start", summary="Start the proxy")
async def start_proxy(
    body: StartProxyRequest,
    current_user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    """Start the MITM proxy on the specified port. Requires authentication."""
    global _interceptor

    if _interceptor.running:
        raise HTTPException(status_code=409, detail="Proxy is already running")

    # Apply scope if provided
    if body.scope_include or body.scope_exclude:
        scope = ScopeFilter()
        for pat in body.scope_include:
            scope.add_in_scope(pat)
        for pat in body.scope_exclude:
            scope.add_out_scope(pat)
        _interceptor._scope = scope

    try:
        await _interceptor.start(port=body.port)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    logger.info("Proxy started by user=%s on port=%d", current_user_id, body.port)
    return {
        "status": "started",
        "port": body.port,
        "timestamp": time.time(),
    }


@router.post("/stop", summary="Stop the proxy")
async def stop_proxy(
    current_user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    """Stop the running MITM proxy. Requires authentication."""
    if not _interceptor.running:
        raise HTTPException(status_code=409, detail="Proxy is not running")

    await _interceptor.stop()
    logger.info("Proxy stopped by user=%s", current_user_id)
    return {"status": "stopped", "timestamp": time.time()}


@router.get("/status", summary="Proxy status and metrics")
async def proxy_status(
    current_user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    """Return proxy status and per-user request capture metrics."""
    stats = _interceptor.get_stats()
    store = _get_store(current_user_id)
    ws_interceptor = _get_ws_interceptor(current_user_id)

    all_requests = await store.list_all()
    total_requests = len(all_requests)
    bandwidth = sum(
        len((r.response.body or "").encode("utf-8"))
        for r in all_requests
        if r.response
    )
    ws_stats = ws_interceptor.get_stats()
    highlight_rules = _get_highlight_rules(current_user_id)

    return {
        **stats,
        "total_requests_captured": total_requests,
        "total_bandwidth_bytes": bandwidth,
        "websocket": ws_stats,
        "highlight_rules": len(highlight_rules),
        "timestamp": time.time(),
    }


# ---------------------------------------------------------------------------
# Captured HTTP Requests
# ---------------------------------------------------------------------------


@router.get("/requests", summary="List captured requests")
async def list_requests(
    url: Optional[str] = Query(None, description="URL substring filter"),
    method: Optional[str] = Query(None),
    status_code: Optional[int] = Query(None),
    content_type: Optional[str] = Query(None),
    tag: Optional[str] = Query(None),
    body_regex: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    """Return paginated list of captured HTTP requests for the authenticated user."""
    store = _get_store(current_user_id)
    highlight_rules = _get_highlight_rules(current_user_id)

    all_reqs = await store.search(
        url_contains=url,
        method=method,
        status_code=status_code,
        content_type_contains=content_type,
        tag=tag,
        body_regex=body_regex,
    )
    total = len(all_reqs)
    page = all_reqs[offset : offset + limit]
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "requests": [_request_summary(r, highlight_rules) for r in page],
    }


@router.get("/requests/{request_id}", summary="Get full request detail")
async def get_request(
    request_id: str,
    current_user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    """Return the full request and response detail for a captured request owned by the caller."""
    store = _get_store(current_user_id)
    req = await store.get(request_id)
    if req is None:
        raise HTTPException(status_code=404, detail=f"Request {request_id!r} not found")
    return req.to_dict()


@router.delete("/requests", summary="Clear captured history", response_model=None)
async def clear_requests(
    session_id: Optional[str] = Query(None),
    current_user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    """Delete all captured HTTP requests for the authenticated user."""
    store = _get_store(current_user_id)
    count = await store.clear()
    return {"deleted": count, "timestamp": time.time()}


# ---------------------------------------------------------------------------
# Request Replay
# ---------------------------------------------------------------------------


@router.post("/replay/{request_id}", summary="Replay a captured request")
async def replay_request(
    request_id: str,
    body: ReplayRequestBody,
    current_user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    """
    Replay a previously captured request belonging to the authenticated user,
    optionally overriding fields.

    When all override fields are *None* the original request is replayed
    verbatim. The response is captured in a new store entry and returned.
    """
    store = _get_store(current_user_id)
    original = await store.get(request_id)
    if original is None:
        raise HTTPException(status_code=404, detail=f"Request {request_id!r} not found")

    import httpx

    method = body.method if body.method is not None else original.method
    url = body.url if body.url is not None else original.url
    headers = body.headers if body.headers is not None else dict(original.headers)
    request_body = body.body if body.body is not None else original.body

    # Strip hop-by-hop headers
    for hop in ("host", "transfer-encoding", "connection", "keep-alive", "te", "trailer", "upgrade"):
        headers.pop(hop, None)
        headers.pop(hop.title(), None)

    start = time.time()
    try:
        # SSL verification disabled by design — the proxy connects to arbitrary
        # targets including those with self-signed or invalid certificates.
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:  # nosec B501
            resp = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=request_body.encode("utf-8") if request_body else None,
            )
        elapsed_ms = (time.time() - start) * 1000

        return {
            "original_id": request_id,
            "method": method,
            "url": url,
            "response": {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text,
                "elapsed_ms": elapsed_ms,
            },
        }
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Replay failed: {exc}")


# ---------------------------------------------------------------------------
# WebSocket Sessions & Frames
# ---------------------------------------------------------------------------


@router.get("/websocket-sessions", summary="List captured WebSocket sessions")
async def list_ws_sessions(
    current_user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    ws_interceptor = _get_ws_interceptor(current_user_id)
    sessions = ws_interceptor.list_sessions()
    return {
        "total": len(sessions),
        "sessions": [s.to_dict() for s in sessions],
    }


@router.get("/websocket-frames", summary="List captured WebSocket frames")
async def list_ws_frames(
    session_id: Optional[str] = Query(None),
    direction: Optional[str] = Query(None),
    frame_type: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    current_user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    """Return WebSocket frames for the authenticated user, optionally filtered."""
    ws_interceptor = _get_ws_interceptor(current_user_id)
    direction_enum = FrameDirection(direction) if direction else None
    frame_type_enum = FrameType(frame_type) if frame_type else None

    if session_id:
        frames = ws_interceptor.get_session_frames(
            session_id,
            direction=direction_enum,
            frame_type=frame_type_enum,
            limit=limit,
            offset=offset,
        )
        total = len(ws_interceptor.get_session_frames(session_id, limit=9999))
    else:
        all_frames = ws_interceptor.list_all_frames(limit=limit + offset, offset=0)
        total = len(all_frames)
        frames = all_frames[offset : offset + limit]

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "frames": [f.to_dict() for f in frames],
    }


@router.get("/websocket-frames/{frame_id}", summary="Get single WebSocket frame")
async def get_ws_frame(
    frame_id: str,
    current_user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    ws_interceptor = _get_ws_interceptor(current_user_id)
    frame = ws_interceptor.get_frame(frame_id)
    if frame is None:
        raise HTTPException(status_code=404, detail=f"Frame {frame_id!r} not found")
    return frame.to_dict()


@router.post("/websocket-frames/{frame_id}/replay", summary="Replay a WebSocket frame")
async def replay_ws_frame(
    frame_id: str,
    body: WSReplayRequest,
    current_user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    """
    Replay a captured WebSocket frame belonging to the authenticated user.
    Pass ``new_payload`` to send a different payload than was originally captured.
    """
    ws_interceptor = _get_ws_interceptor(current_user_id)
    result = await ws_interceptor.replay_frame(frame_id, new_payload=body.new_payload)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error", "Replay failed"))
    return result


# ---------------------------------------------------------------------------
# Browser Configuration & PAC File
# ---------------------------------------------------------------------------


@router.get("/browser-config", summary="Browser proxy configuration")
async def browser_config(
    current_user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    """Return complete browser proxy configuration for Chrome, Firefox, and generic tools."""
    return _bridge.json_config()


@router.get("/proxy.pac", summary="PAC file", response_class=PlainTextResponse)
async def pac_file(
    current_user_id: str = Depends(get_current_user_id),
) -> str:
    """Return a Proxy Auto-Configuration (PAC) file."""
    return _bridge.generate_pac()


@router.get("/ca-cert", summary="Download proxy CA certificate")
async def ca_cert(
    response: Response,
    current_user_id: str = Depends(get_current_user_id),
):
    """Download the proxy CA certificate in PEM format for browser trust-store import."""
    cert_bytes = BrowserBridge.read_ca_cert()
    if cert_bytes is None:
        raise HTTPException(
            status_code=404,
            detail="CA certificate not found. Start the proxy first to generate it.",
        )
    response.headers["Content-Disposition"] = "attachment; filename=univex-ca.pem"
    return Response(content=cert_bytes, media_type="application/x-pem-file")


# ---------------------------------------------------------------------------
# Scope Management
# ---------------------------------------------------------------------------


@router.get("/scope", summary="Get current scope configuration")
async def get_scope(
    current_user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    scope = _interceptor.scope
    return {
        "include_patterns": [p.pattern for p in scope._in_scope],
        "exclude_patterns": [p.pattern for p in scope._out_scope],
    }


@router.post("/scope", summary="Update scope patterns")
async def update_scope(
    body: ScopeUpdateRequest,
    current_user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    """Replace the proxy scope patterns."""
    scope = ScopeFilter()
    for pat in body.include_patterns:
        scope.add_in_scope(pat)
    for pat in body.exclude_patterns:
        scope.add_out_scope(pat)
    _interceptor._scope = scope
    logger.info("Proxy scope updated by user=%s", current_user_id)
    return {
        "status": "updated",
        "include_patterns": body.include_patterns,
        "exclude_patterns": body.exclude_patterns,
    }


# ---------------------------------------------------------------------------
# Highlight Rules (per-user)
# ---------------------------------------------------------------------------


@router.get("/highlight-rules", summary="List highlight rules")
async def list_highlight_rules(
    current_user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    return {"rules": _get_highlight_rules(current_user_id)}


@router.post("/highlight-rules", summary="Add a highlight rule")
async def add_highlight_rule(
    body: HighlightRuleRequest,
    current_user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    try:
        re.compile(body.pattern)
    except re.error as exc:
        raise HTTPException(status_code=422, detail=f"Invalid regex: {exc}")

    rules = _get_highlight_rules(current_user_id)
    rule = {"pattern": body.pattern, "color": body.color, "label": body.label}
    rules.append(rule)
    return {"status": "added", "index": len(rules) - 1, "rule": rule}


@router.delete("/highlight-rules/{index}", summary="Remove a highlight rule", response_model=None)
async def delete_highlight_rule(
    index: int,
    current_user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    rules = _get_highlight_rules(current_user_id)
    if index < 0 or index >= len(rules):
        raise HTTPException(status_code=404, detail=f"Rule index {index} out of range")
    removed = rules.pop(index)
    return {"status": "removed", "rule": removed}

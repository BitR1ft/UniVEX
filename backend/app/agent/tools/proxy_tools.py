"""
Proxy Agent Tools — Replay, Intruder, Comparer, Logger, Scope Manager

Implements six agent tools that wrap the UniVex proxy engine, giving the
AI agent fine-grained control over intercepted HTTP traffic:

  HttpInterceptTool     — start/stop/configure the proxy, manage intercept rules
  RequestReplayTool     — replay a captured request with arbitrary modifications
  RequestIntruderTool   — Burp-style parameter injection (Sniper / Battering Ram /
                           Pitchfork / Cluster Bomb attack types)
  RequestComparerTool   — side-by-side diff of two captured requests/responses
  TrafficLoggerTool     — passive traffic logging + export (HAR/JSON/CSV)
  ScopeManagerTool      — define in-scope / out-of-scope URL patterns

OWASP: A01:2021-Broken Access Control, A03:2021-Injection
MITRE: T1557 (MITM), T1110 (Brute Force), T1185 (Browser Session Hijacking)
"""

from __future__ import annotations

import asyncio
import difflib
import itertools
import json
import logging
import re
import time
import urllib.parse
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Tuple

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import ToolExecutionError, truncate_output
from app.proxy.interceptor import InterceptRule, ProxyInterceptor, ScopeFilter
from app.proxy.request_store import (
    CapturedRequest,
    CapturedResponse,
    RequestStore,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared proxy engine instances (module-level singletons so all tools share state)
# ---------------------------------------------------------------------------

_shared_store = RequestStore()
_shared_scope = ScopeFilter()
_shared_proxy = ProxyInterceptor(store=_shared_store, scope=_shared_scope)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


def _http_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    timeout: int = 15,
) -> Tuple[int, str, Dict[str, str], str, float]:
    """
    Perform a synchronous HTTP request and return
    (status_code, reason, response_headers, body, elapsed_ms).

    Raises urllib.error.URLError on network error.
    """
    data: Optional[bytes] = body.encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", _BROWSER_UA)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    t0 = time.monotonic()
    try:
        ctx = __import__("ssl").create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = __import__("ssl").CERT_NONE
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        raw = resp.read()
        elapsed = (time.monotonic() - t0) * 1000.0
        resp_headers = dict(resp.headers)
        try:
            resp_body = raw.decode("utf-8", errors="replace")
        except Exception:
            import base64
            resp_body = base64.b64encode(raw).decode()
        return resp.status, resp.reason, resp_headers, resp_body, elapsed
    except urllib.error.HTTPError as exc:
        elapsed = (time.monotonic() - t0) * 1000.0
        raw = exc.read() or b""
        try:
            resp_body = raw.decode("utf-8", errors="replace")
        except Exception:
            resp_body = ""
        return exc.code, exc.reason or "", dict(exc.headers), resp_body, elapsed


# ---------------------------------------------------------------------------
# HttpInterceptTool
# ---------------------------------------------------------------------------


class HttpInterceptTool(BaseTool):
    """
    Start, stop, and configure the UniVex proxy interceptor.

    Actions:
      start    — launch the proxy on the given port
      stop     — shut down the proxy
      status   — return running state and capture counts
      add_rule — add a URL/method/content-type intercept rule with optional tag
      list_rules — list all active rules
      remove_rule — remove a rule by index
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="http_intercept",
            description=(
                "Control the HTTP/HTTPS intercepting proxy. "
                "Actions: start, stop, status, add_rule, list_rules, remove_rule."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["start", "stop", "status", "add_rule", "list_rules", "remove_rule"],
                        "description": "Action to perform.",
                    },
                    "port": {
                        "type": "integer",
                        "description": "Proxy listen port (used with 'start').",
                        "default": 8080,
                    },
                    "url_pattern": {
                        "type": "string",
                        "description": "Regex pattern for URL intercept rule.",
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method filter for intercept rule.",
                    },
                    "content_type": {
                        "type": "string",
                        "description": "Content-Type substring for intercept rule.",
                    },
                    "tag": {
                        "type": "string",
                        "description": "Tag to apply to matching captured requests.",
                        "default": "",
                    },
                    "rule_index": {
                        "type": "integer",
                        "description": "Index of rule to remove (used with 'remove_rule').",
                    },
                },
                "required": ["action"],
            },
        )

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action", "").lower()
        proxy = _shared_proxy

        if action == "start":
            if proxy.running:
                return json.dumps({"status": "already_running", "port": proxy.port})
            port = int(kwargs.get("port", 8080))
            try:
                await proxy.start(port=port)
                return json.dumps({"status": "started", "port": proxy.port})
            except RuntimeError as exc:
                # mitmproxy not installed — return informative error rather than crash
                return json.dumps({"status": "error", "error": str(exc)})

        elif action == "stop":
            if not proxy.running:
                return json.dumps({"status": "not_running"})
            await proxy.stop()
            return json.dumps({"status": "stopped"})

        elif action == "status":
            stats = proxy.get_stats()
            stats["captured_requests"] = await _shared_store.count()
            return json.dumps({"status": "ok", **stats})

        elif action == "add_rule":
            try:
                rule = InterceptRule(
                    url_pattern=kwargs.get("url_pattern") or None,
                    method=kwargs.get("method") or None,
                    content_type=kwargs.get("content_type") or None,
                    tag=kwargs.get("tag", ""),
                )
                proxy.add_rule(rule)
                return json.dumps({"status": "rule_added", "rule_count": len(proxy.rules)})
            except ValueError as exc:
                raise ToolExecutionError(str(exc), tool_name="http_intercept")

        elif action == "list_rules":
            rules = [
                {
                    "index": i,
                    "url_pattern": r.url_pattern,
                    "method": r.method,
                    "content_type": r.content_type,
                    "tag": r.tag,
                }
                for i, r in enumerate(proxy.rules)
            ]
            return json.dumps({"rules": rules})

        elif action == "remove_rule":
            idx = kwargs.get("rule_index")
            if idx is None:
                raise ToolExecutionError("rule_index is required for remove_rule.", tool_name="http_intercept")
            idx = int(idx)
            if idx < 0 or idx >= len(proxy.rules):
                raise ToolExecutionError(f"Rule index {idx} out of range.", tool_name="http_intercept")
            proxy.remove_rule(idx)
            return json.dumps({"status": "rule_removed", "rule_count": len(proxy.rules)})

        else:
            raise ToolExecutionError(f"Unknown action: {action}", tool_name="http_intercept")


# ---------------------------------------------------------------------------
# RequestReplayTool
# ---------------------------------------------------------------------------


class RequestReplayTool(BaseTool):
    """
    Replay a captured request with optional modifications.

    Supports overriding any combination of: URL, method, headers, body,
    cookies.  Returns both the original response (from the store) and the
    new response side-by-side for comparison.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="request_replay",
            description=(
                "Replay a captured HTTP request with optional modifications. "
                "Specify request_id to replay from store, or provide full request details."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "request_id": {
                        "type": "string",
                        "description": "ID of the captured request to replay.",
                    },
                    "url": {"type": "string", "description": "Override URL."},
                    "method": {"type": "string", "description": "Override HTTP method."},
                    "headers": {
                        "type": "object",
                        "additionalProperties": {"type": "string"},
                        "description": "Headers to add/override.",
                    },
                    "body": {"type": "string", "description": "Override request body."},
                    "cookies": {
                        "type": "object",
                        "additionalProperties": {"type": "string"},
                        "description": "Cookies to add/override (merged into Cookie header).",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Request timeout in seconds.",
                        "default": 15,
                    },
                    "store_result": {
                        "type": "boolean",
                        "description": "Store the replayed request in the capture store.",
                        "default": True,
                    },
                },
                "required": ["request_id"],
            },
        )

    async def execute(self, **kwargs: Any) -> str:
        request_id: str = kwargs["request_id"]
        original = await _shared_store.get(request_id)
        if original is None:
            raise ToolExecutionError(
                f"Request {request_id} not found in capture store.",
                tool_name="request_replay",
            )

        # Build modified request
        url = kwargs.get("url") or original.url
        method = kwargs.get("method") or original.method
        headers: Dict[str, str] = dict(original.headers)
        headers.update(kwargs.get("headers") or {})

        # Merge cookies
        cookies = kwargs.get("cookies")
        if cookies:
            existing = headers.get("Cookie", "")
            parts = [existing] if existing else []
            parts.extend(f"{k}={v}" for k, v in cookies.items())
            headers["Cookie"] = "; ".join(parts)

        body = kwargs.get("body") if "body" in kwargs else original.body
        timeout = int(kwargs.get("timeout", 15))

        # Execute synchronously in thread so we don't block the event loop
        try:
            status, reason, resp_headers, resp_body, elapsed = await asyncio.to_thread(
                _http_request, url, method, headers, body, timeout
            )
        except Exception as exc:
            raise ToolExecutionError(str(exc), tool_name="request_replay")

        replayed = CapturedRequest(
            id="",
            timestamp=time.time(),
            method=method,
            url=url,
            headers=headers,
            body=body or "",
            response=CapturedResponse(
                status_code=status,
                reason=reason,
                headers=resp_headers,
                body=resp_body,
                content_type=resp_headers.get("Content-Type", ""),
                elapsed_ms=elapsed,
            ),
            tags=["replayed"],
        )

        if kwargs.get("store_result", True):
            await _shared_store.store(replayed)

        result = {
            "original": {
                "url": original.url,
                "method": original.method,
                "status": original.response.status_code if original.response else None,
                "elapsed_ms": original.response.elapsed_ms if original.response else None,
            },
            "replayed": {
                "id": replayed.id,
                "url": url,
                "method": method,
                "status": status,
                "reason": reason,
                "elapsed_ms": elapsed,
                "body_length": len(resp_body),
                "body_preview": resp_body[:500],
            },
        }
        return truncate_output(json.dumps(result, indent=2))


# ---------------------------------------------------------------------------
# RequestIntruderTool — Burp-style automated parameter injection
# ---------------------------------------------------------------------------

_ATTACK_TYPES = ("sniper", "battering_ram", "pitchfork", "cluster_bomb")


class RequestIntruderTool(BaseTool):
    """
    Automated parameter injection across marked positions — Burp Intruder style.

    Attack types:
      sniper        — single payload position, iterate through wordlist
      battering_ram — same payload inserted at ALL positions simultaneously
      pitchfork     — different wordlists per position, iterate in parallel
      cluster_bomb  — cartesian product of all wordlists across all positions

    Positions are marked in the URL/body/headers with §marker§ syntax.

    Example::

        body   = "username=§USER§&password=§PASS§"
        attack = "cluster_bomb"
        payloads = [["admin", "root"], ["password", "123456"]]
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="request_intruder",
            description=(
                "Automated HTTP parameter injection engine. "
                "Marks positions with §placeholder§ and iterates through wordlists. "
                "Attack types: sniper, battering_ram, pitchfork, cluster_bomb."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL (may contain §markers§)."},
                    "method": {"type": "string", "default": "GET"},
                    "headers": {
                        "type": "object",
                        "additionalProperties": {"type": "string"},
                    },
                    "body": {
                        "type": "string",
                        "description": "Request body template (may contain §markers§).",
                        "default": "",
                    },
                    "attack_type": {
                        "type": "string",
                        "enum": list(_ATTACK_TYPES),
                        "default": "sniper",
                    },
                    "payloads": {
                        "type": "array",
                        "items": {"type": "array", "items": {"type": "string"}},
                        "description": (
                            "List of wordlists. For sniper/battering_ram: first list is used. "
                            "For pitchfork/cluster_bomb: one list per position."
                        ),
                    },
                    "timeout": {"type": "integer", "default": 10},
                    "max_requests": {
                        "type": "integer",
                        "description": "Maximum number of requests to fire (safety cap).",
                        "default": 500,
                    },
                    "store_results": {
                        "type": "boolean",
                        "description": "Store each result in the capture store.",
                        "default": False,
                    },
                },
                "required": ["url", "payloads"],
            },
        )

    async def execute(self, **kwargs: Any) -> str:
        url_tpl: str = kwargs["url"]
        method: str = kwargs.get("method", "GET").upper()
        headers: Dict[str, str] = kwargs.get("headers") or {}
        body_tpl: str = kwargs.get("body") or ""
        attack_type: str = kwargs.get("attack_type", "sniper").lower()
        payloads: List[List[str]] = kwargs["payloads"]
        timeout: int = int(kwargs.get("timeout", 10))
        max_requests: int = int(kwargs.get("max_requests", 500))
        store_results: bool = kwargs.get("store_results", False)

        if attack_type not in _ATTACK_TYPES:
            raise ToolExecutionError(
                f"Unknown attack_type: {attack_type!r}. Choose from {_ATTACK_TYPES}.",
                tool_name="request_intruder",
            )
        if not payloads or not isinstance(payloads, list):
            raise ToolExecutionError("payloads must be a non-empty list of wordlists.", tool_name="request_intruder")

        # Enumerate positions
        positions = re.findall(r"§([^§]+)§", url_tpl + body_tpl)
        n_positions = len(positions)

        # Build payload sequences based on attack type
        payload_sequences = self._build_sequences(attack_type, payloads, n_positions)

        results: List[Dict[str, Any]] = []
        fired = 0

        for combo in payload_sequences:
            if fired >= max_requests:
                break

            injected_url = url_tpl
            injected_body = body_tpl
            for i, pos in enumerate(positions):
                payload_value = str(combo[i]) if i < len(combo) else ""
                injected_url = injected_url.replace(f"§{pos}§", urllib.parse.quote(payload_value, safe=""), 1)
                injected_body = injected_body.replace(f"§{pos}§", payload_value, 1)

            try:
                status, reason, resp_headers, resp_body, elapsed = await asyncio.to_thread(
                    _http_request, injected_url, method, headers, injected_body or None, timeout
                )
            except Exception as exc:
                results.append({
                    "payloads": combo,
                    "url": injected_url,
                    "error": str(exc),
                })
                fired += 1
                continue

            entry: Dict[str, Any] = {
                "request_number": fired + 1,
                "payloads": combo,
                "url": injected_url,
                "status": status,
                "reason": reason,
                "elapsed_ms": round(elapsed, 1),
                "body_length": len(resp_body),
            }
            results.append(entry)

            if store_results:
                captured = CapturedRequest(
                    id="",
                    timestamp=time.time(),
                    method=method,
                    url=injected_url,
                    headers=headers,
                    body=injected_body,
                    response=CapturedResponse(
                        status_code=status,
                        reason=reason,
                        headers=resp_headers,
                        body=resp_body,
                        content_type=resp_headers.get("Content-Type", ""),
                        elapsed_ms=elapsed,
                    ),
                    tags=["intruder", attack_type],
                )
                await _shared_store.store(captured)

            fired += 1

        summary = {
            "attack_type": attack_type,
            "positions": positions,
            "total_requests": fired,
            "results": results,
        }
        return truncate_output(json.dumps(summary, indent=2))

    # ------------------------------------------------------------------
    # Payload sequence generators
    # ------------------------------------------------------------------

    def _build_sequences(
        self, attack_type: str, payloads: List[List[str]], n_positions: int
    ) -> List[List[str]]:
        if attack_type == "sniper":
            # Iterate one position at a time through the first wordlist
            wordlist = payloads[0] if payloads else []
            seqs: List[List[str]] = []
            for pos_idx in range(n_positions):
                for word in wordlist:
                    combo = [""] * n_positions
                    combo[pos_idx] = word
                    seqs.append(combo)
            return seqs

        elif attack_type == "battering_ram":
            # Same payload in all positions
            wordlist = payloads[0] if payloads else []
            return [[word] * n_positions for word in wordlist]

        elif attack_type == "pitchfork":
            # Parallel iteration — zip wordlists, padding shorter ones
            max_len = max((len(p) for p in payloads), default=0)
            padded = [list(p) + [""] * (max_len - len(p)) for p in payloads]
            return [list(combo) for combo in zip(*padded)]

        elif attack_type == "cluster_bomb":
            # Cartesian product
            return [list(combo) for combo in itertools.product(*payloads)]

        return []


# ---------------------------------------------------------------------------
# RequestComparerTool
# ---------------------------------------------------------------------------


class RequestComparerTool(BaseTool):
    """
    Compare two captured requests/responses side-by-side.

    Highlights differences in status codes, headers, body, and timing.
    Useful for detecting IDOR, privilege escalation, or subtle response
    differences in blind injection scenarios.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="request_comparer",
            description=(
                "Compare two captured HTTP requests/responses side-by-side. "
                "Highlights status, header, body, and timing differences."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "request_id_a": {"type": "string", "description": "First request ID."},
                    "request_id_b": {"type": "string", "description": "Second request ID."},
                    "diff_format": {
                        "type": "string",
                        "enum": ["unified", "side_by_side", "summary"],
                        "default": "summary",
                        "description": "Format for body diff output.",
                    },
                },
                "required": ["request_id_a", "request_id_b"],
            },
        )

    async def execute(self, **kwargs: Any) -> str:
        id_a: str = kwargs["request_id_a"]
        id_b: str = kwargs["request_id_b"]
        diff_format: str = kwargs.get("diff_format", "summary")

        req_a = await _shared_store.get(id_a)
        req_b = await _shared_store.get(id_b)

        missing = []
        if req_a is None:
            missing.append(id_a)
        if req_b is None:
            missing.append(id_b)
        if missing:
            raise ToolExecutionError(
                f"Request(s) not found in store: {missing}",
                tool_name="request_comparer",
            )

        result: Dict[str, Any] = {
            "request_a": {"id": id_a, "url": req_a.url, "method": req_a.method},
            "request_b": {"id": id_b, "url": req_b.url, "method": req_b.method},
            "differences": {},
        }

        diffs: Dict[str, Any] = {}

        # URL
        if req_a.url != req_b.url:
            diffs["url"] = {"a": req_a.url, "b": req_b.url}

        # Method
        if req_a.method != req_b.method:
            diffs["method"] = {"a": req_a.method, "b": req_b.method}

        # Response status
        status_a = req_a.response.status_code if req_a.response else None
        status_b = req_b.response.status_code if req_b.response else None
        if status_a != status_b:
            diffs["status_code"] = {"a": status_a, "b": status_b}

        # Response timing — only report when meaningfully different
        elapsed_a = req_a.response.elapsed_ms if req_a.response else None
        elapsed_b = req_b.response.elapsed_ms if req_b.response else None
        if elapsed_a is not None and elapsed_b is not None and elapsed_a != elapsed_b:
            delta = abs(elapsed_a - elapsed_b)
            diffs["elapsed_ms"] = {"a": round(elapsed_a, 1), "b": round(elapsed_b, 1), "delta": round(delta, 1)}

        # Response body length
        body_a = req_a.response.body if req_a.response else ""
        body_b = req_b.response.body if req_b.response else ""
        if len(body_a) != len(body_b):
            diffs["body_length"] = {"a": len(body_a), "b": len(body_b)}

        # Header differences
        headers_a = dict(req_a.response.headers) if req_a.response else {}
        headers_b = dict(req_b.response.headers) if req_b.response else {}
        header_diff: Dict[str, Any] = {}
        all_keys = set(headers_a) | set(headers_b)
        for key in all_keys:
            va = headers_a.get(key)
            vb = headers_b.get(key)
            if va != vb:
                header_diff[key] = {"a": va, "b": vb}
        if header_diff:
            diffs["headers"] = header_diff

        # Body diff
        if body_a != body_b:
            if diff_format == "unified":
                diff_lines = list(
                    difflib.unified_diff(
                        body_a.splitlines(keepends=True),
                        body_b.splitlines(keepends=True),
                        fromfile="request_a",
                        tofile="request_b",
                        n=3,
                    )
                )
                diffs["body_diff"] = "".join(diff_lines[:200])  # cap size
            elif diff_format == "side_by_side":
                differ = difflib.Differ()
                diff_lines = list(differ.compare(body_a.splitlines(), body_b.splitlines()))
                diffs["body_diff"] = "\n".join(diff_lines[:200])
            else:
                # Summary: just note whether bodies differ
                diffs["body_diff"] = f"Bodies differ: {len(body_a)} bytes vs {len(body_b)} bytes"

        result["differences"] = diffs
        result["has_differences"] = bool(diffs)
        return truncate_output(json.dumps(result, indent=2))


# ---------------------------------------------------------------------------
# TrafficLoggerTool
# ---------------------------------------------------------------------------


class TrafficLoggerTool(BaseTool):
    """
    Passive traffic logging with search and export.

    Searches the capture store with rich filters and exports the matching
    traffic as HAR, JSON, or CSV.  Does not make any active network requests.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="traffic_logger",
            description=(
                "Query and export captured proxy traffic. "
                "Filter by URL, method, status code, content type, body regex, or tag. "
                "Export as HAR, JSON, or CSV."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["search", "export", "count", "clear"],
                        "default": "search",
                    },
                    "url_contains": {"type": "string"},
                    "method": {"type": "string"},
                    "status_code": {"type": "integer"},
                    "content_type_contains": {"type": "string"},
                    "body_regex": {"type": "string"},
                    "tag": {"type": "string"},
                    "format": {
                        "type": "string",
                        "enum": ["har", "json", "csv"],
                        "default": "json",
                        "description": "Export format (used with 'export' action).",
                    },
                    "page": {"type": "integer", "default": 1},
                    "page_size": {"type": "integer", "default": 50},
                },
                "required": [],
            },
        )

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action", "search").lower()
        store = _shared_store

        if action == "count":
            total = await store.count()
            return json.dumps({"total_captured": total})

        elif action == "clear":
            count = await store.clear()
            return json.dumps({"cleared": count})

        elif action in ("search", "export"):
            try:
                results = await store.search(
                    url_contains=kwargs.get("url_contains"),
                    method=kwargs.get("method"),
                    status_code=kwargs.get("status_code"),
                    content_type_contains=kwargs.get("content_type_contains"),
                    body_regex=kwargs.get("body_regex"),
                    tag=kwargs.get("tag"),
                )
            except ValueError as exc:
                raise ToolExecutionError(str(exc), tool_name="traffic_logger")

            if action == "search":
                page = int(kwargs.get("page", 1))
                page_size = int(kwargs.get("page_size", 50))
                offset = (page - 1) * page_size
                page_results = results[offset : offset + page_size]
                out = {
                    "total_matching": len(results),
                    "page": page,
                    "page_size": page_size,
                    "requests": [r.to_dict() for r in page_results],
                }
                return truncate_output(json.dumps(out, indent=2))
            else:
                fmt = kwargs.get("format", "json").lower()
                if fmt == "har":
                    data = store.export_har(results)
                elif fmt == "csv":
                    data = store.export_csv(results)
                else:
                    data = store.export_json(results)
                return truncate_output(data)

        else:
            raise ToolExecutionError(f"Unknown action: {action}", tool_name="traffic_logger")


# ---------------------------------------------------------------------------
# ScopeManagerTool
# ---------------------------------------------------------------------------


class ScopeManagerTool(BaseTool):
    """
    Define in-scope and out-of-scope URL patterns for the proxy.

    The proxy automatically drops (does not capture) traffic that is
    out-of-scope.  This keeps the capture store focused on the target
    application and avoids noise from third-party CDNs, analytics, etc.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="scope_manager",
            description=(
                "Manage proxy capture scope. "
                "Add in-scope / out-of-scope URL regex patterns. "
                "Actions: set, add_in, add_out, list, clear."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["set", "add_in", "add_out", "list", "clear"],
                        "default": "list",
                    },
                    "in_scope": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Regex patterns for in-scope URLs (used with 'set' and 'add_in').",
                        "default": [],
                    },
                    "out_scope": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Regex patterns for out-of-scope URLs (used with 'set' and 'add_out').",
                        "default": [],
                    },
                },
                "required": [],
            },
        )

    async def execute(self, **kwargs: Any) -> str:
        action = kwargs.get("action", "list").lower()
        scope = _shared_scope

        if action == "clear":
            scope.clear()
            return json.dumps({"status": "scope_cleared"})

        elif action == "list":
            return json.dumps({
                "in_scope": [p.pattern for p in scope._in_scope],
                "out_scope": [p.pattern for p in scope._out_scope],
            })

        elif action == "set":
            scope.clear()
            errors: List[str] = []
            for pat in kwargs.get("in_scope", []):
                try:
                    scope.add_in_scope(pat)
                except re.error as exc:
                    errors.append(f"in_scope {pat!r}: {exc}")
            for pat in kwargs.get("out_scope", []):
                try:
                    scope.add_out_scope(pat)
                except re.error as exc:
                    errors.append(f"out_scope {pat!r}: {exc}")
            result: Dict[str, Any] = {
                "status": "scope_set",
                "in_scope_count": len(scope._in_scope),
                "out_scope_count": len(scope._out_scope),
            }
            if errors:
                result["errors"] = errors
            return json.dumps(result)

        elif action == "add_in":
            added = []
            errors = []
            for pat in kwargs.get("in_scope", []):
                try:
                    scope.add_in_scope(pat)
                    added.append(pat)
                except re.error as exc:
                    errors.append(f"{pat!r}: {exc}")
            result = {"status": "added_in_scope", "added": added}
            if errors:
                result["errors"] = errors
            return json.dumps(result)

        elif action == "add_out":
            added = []
            errors = []
            for pat in kwargs.get("out_scope", []):
                try:
                    scope.add_out_scope(pat)
                    added.append(pat)
                except re.error as exc:
                    errors.append(f"{pat!r}: {exc}")
            result = {"status": "added_out_scope", "added": added}
            if errors:
                result["errors"] = errors
            return json.dumps(result)

        else:
            raise ToolExecutionError(f"Unknown action: {action}", tool_name="scope_manager")


# ---------------------------------------------------------------------------
# Convenience: all tools in one place
# ---------------------------------------------------------------------------

ALL_PROXY_TOOLS: List[BaseTool] = [
    HttpInterceptTool(),
    RequestReplayTool(),
    RequestIntruderTool(),
    RequestComparerTool(),
    TrafficLoggerTool(),
    ScopeManagerTool(),
]

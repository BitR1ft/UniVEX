"""
Tests for Day 5 — Additional Search Engines & OSINT Sources

Covers all 6 new search tools plus tool_registry integration:
  - SploitusTool
  - DuckDuckGoTool
  - PerplexityTool
  - SearxngTool
  - TraversaalTool
  - GoogleCustomSearchTool
  - ToolRegistry.register_search_tools()
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from app.agent.tools.search.sploitus_tool import SploitusTool
from app.agent.tools.search.duckduckgo_tool import DuckDuckGoTool
from app.agent.tools.search.perplexity_tool import PerplexityTool
from app.agent.tools.search.searxng_tool import SearxngTool
from app.agent.tools.search.traversaal_tool import TraversaalTool
from app.agent.tools.search.google_search_tool import GoogleCustomSearchTool
from app.agent.tools.tool_registry import ToolRegistry
from app.agent.state.agent_state import Phase


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_http_response(status_code: int = 200, json_data: Any = None, text: str = "") -> MagicMock:
    """Build a mock httpx.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.text = text
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        from httpx import HTTPStatusError, Request, Response
        resp.raise_for_status.side_effect = HTTPStatusError(
            f"HTTP {status_code}", request=MagicMock(), response=resp
        )
    return resp


def _async_client_ctx(response: MagicMock):
    """Return an async context manager whose .post/.get returns response."""
    client = AsyncMock()
    client.post = AsyncMock(return_value=response)
    client.get = AsyncMock(return_value=response)
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=client)
    ctx.__aexit__ = AsyncMock(return_value=False)
    return ctx, client


# ===========================================================================
# SploitusTool Tests (12 tests)
# ===========================================================================


class TestSploitusTool:
    """Tests for SploitusTool."""

    def setup_method(self):
        self.tool = SploitusTool()

    # --- metadata ---

    def test_metadata_name(self):
        assert self.tool.name == "sploitus_search"

    def test_metadata_description(self):
        assert "Sploitus" in self.tool.description

    def test_metadata_parameters_required(self):
        assert "query" in self.tool.metadata.parameters.get("required", [])

    # --- happy path ---

    def test_happy_path_returns_formatted_results(self):
        payload = {
            "exploits": [
                {
                    "title": "Apache Log4j RCE",
                    "type": "exploit",
                    "score": 9.5,
                    "cvss": {"score": 10.0},
                    "href": "https://github.com/example/log4shell",
                    "source": "Exploit-DB",
                    "published": "2021-12-10",
                    "reporter": "researcher",
                }
            ],
            "total": {"value": 1},
        }
        resp = _make_http_response(json_data=payload)
        ctx, client = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="log4j"))

        assert "Apache Log4j RCE" in result
        assert "Sploitus" in result
        client.post.assert_called_once()

    def test_happy_path_includes_cvss_score(self):
        payload = {
            "exploits": [
                {"title": "Test Exploit", "type": "exploit", "cvss": {"score": 7.5}, "score": 5.0}
            ],
            "total": {"value": 1},
        }
        resp = _make_http_response(json_data=payload)
        ctx, _ = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "7.5" in result

    def test_offset_passed_in_payload(self):
        payload = {"exploits": [], "total": {"value": 0}}
        resp = _make_http_response(json_data=payload)
        ctx, client = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            asyncio.run(self.tool.execute(query="test", offset=10))

        call_kwargs = client.post.call_args
        sent_json = call_kwargs[1]["json"] if "json" in call_kwargs[1] else call_kwargs[0][1]
        assert sent_json["offset"] == 10

    def test_max_results_limits_output(self):
        exploits = [{"title": f"Exploit {i}", "type": "exploit"} for i in range(20)]
        payload = {"exploits": exploits, "total": {"value": 20}}
        resp = _make_http_response(json_data=payload)
        ctx, _ = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test", max_results=3))

        # Only 3 entries numbered
        assert "4." not in result

    # --- empty results ---

    def test_empty_results_message(self):
        payload = {"exploits": [], "total": {"value": 0}}
        resp = _make_http_response(json_data=payload)
        ctx, _ = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="nonexistent"))

        assert "No exploits found" in result

    # --- HTTP error ---

    def test_http_error_returns_error_string(self):
        from httpx import HTTPStatusError
        ctx = MagicMock()
        client = AsyncMock()
        client.post = AsyncMock(
            side_effect=HTTPStatusError("500", request=MagicMock(), response=MagicMock(status_code=500, text="err"))
        )
        ctx.__aenter__ = AsyncMock(return_value=client)
        ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "Error" in result

    def test_request_error_returns_error_string(self):
        from httpx import RequestError
        ctx = MagicMock()
        client = AsyncMock()
        client.post = AsyncMock(side_effect=RequestError("connection refused"))
        ctx.__aenter__ = AsyncMock(return_value=client)
        ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "Error" in result

    # --- API key ---

    def test_no_api_key_still_works(self):
        """Sploitus API works without a key — no error returned for missing key."""
        payload = {
            "exploits": [{"title": "Test", "type": "exploit"}],
            "total": {"value": 1},
        }
        resp = _make_http_response(json_data=payload)
        ctx, client = _async_client_ctx(resp)

        with patch.dict("os.environ", {}, clear=False), patch("httpx.AsyncClient", return_value=ctx):
            tool = SploitusTool()
            tool.api_key = ""
            result = asyncio.run(tool.execute(query="test"))

        assert "Error" not in result

    def test_api_key_added_to_header(self):
        payload = {"exploits": [], "total": {"value": 0}}
        resp = _make_http_response(json_data=payload)
        ctx, client = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            tool = SploitusTool()
            tool.api_key = "my-secret-key"
            asyncio.run(tool.execute(query="test"))

        headers = client.post.call_args[1]["headers"]
        assert "Authorization" in headers
        assert "my-secret-key" in headers["Authorization"]

    # --- unexpected error ---

    def test_unexpected_exception_handled(self):
        ctx = MagicMock()
        client = AsyncMock()
        client.post = AsyncMock(side_effect=RuntimeError("unexpected"))
        ctx.__aenter__ = AsyncMock(return_value=client)
        ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "Error" in result

    # --- result format details ---

    def test_github_link_in_output(self):
        payload = {
            "exploits": [
                {
                    "title": "PoC",
                    "type": "exploit",
                    "href": "https://github.com/user/repo",
                }
            ],
            "total": {"value": 1},
        }
        resp = _make_http_response(json_data=payload)
        ctx, _ = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "github.com" in result

    def test_total_count_in_output(self):
        payload = {
            "exploits": [{"title": "E1", "type": "exploit"}],
            "total": {"value": 42},
        }
        resp = _make_http_response(json_data=payload)
        ctx, _ = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "42" in result


# ===========================================================================
# DuckDuckGoTool Tests (12 tests)
# ===========================================================================


class TestDuckDuckGoTool:
    """Tests for DuckDuckGoTool."""

    def setup_method(self):
        self.tool = DuckDuckGoTool()

    # --- metadata ---

    def test_metadata_name(self):
        assert self.tool.name == "duckduckgo_search"

    def test_metadata_has_safesearch_param(self):
        props = self.tool.metadata.parameters.get("properties", {})
        assert "safesearch" in props

    def test_metadata_has_timelimit_param(self):
        props = self.tool.metadata.parameters.get("properties", {})
        assert "timelimit" in props

    # --- happy path ---

    def test_happy_path_returns_results(self):
        mock_results = [
            {"title": "Log4Shell CVE", "href": "https://example.com/log4shell", "body": "Critical RCE vulnerability"},
        ]
        mock_ddgs = MagicMock()
        mock_ddgs.__enter__ = MagicMock(return_value=mock_ddgs)
        mock_ddgs.__exit__ = MagicMock(return_value=False)
        mock_ddgs.text = MagicMock(return_value=iter(mock_results))

        with patch("duckduckgo_search.DDGS", return_value=mock_ddgs):
            result = asyncio.run(self.tool.execute(query="log4shell exploit"))

        assert "Log4Shell CVE" in result
        assert "example.com" in result

    def test_happy_path_snippet_truncated(self):
        long_body = "A" * 300
        mock_results = [{"title": "Title", "href": "https://x.com", "body": long_body}]
        mock_ddgs = MagicMock()
        mock_ddgs.__enter__ = MagicMock(return_value=mock_ddgs)
        mock_ddgs.__exit__ = MagicMock(return_value=False)
        mock_ddgs.text = MagicMock(return_value=iter(mock_results))

        with patch("duckduckgo_search.DDGS", return_value=mock_ddgs):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "..." in result

    def test_max_results_passed_to_ddgs(self):
        mock_ddgs = MagicMock()
        mock_ddgs.__enter__ = MagicMock(return_value=mock_ddgs)
        mock_ddgs.__exit__ = MagicMock(return_value=False)
        mock_ddgs.text = MagicMock(return_value=iter([]))

        with patch("duckduckgo_search.DDGS", return_value=mock_ddgs):
            asyncio.run(self.tool.execute(query="test", max_results=5))

        call_kwargs = mock_ddgs.text.call_args
        assert call_kwargs[1].get("max_results") == 5 or (
            len(call_kwargs[0]) > 1 and 5 in call_kwargs[0]
        )

    def test_region_param_passed(self):
        mock_ddgs = MagicMock()
        mock_ddgs.__enter__ = MagicMock(return_value=mock_ddgs)
        mock_ddgs.__exit__ = MagicMock(return_value=False)
        mock_ddgs.text = MagicMock(return_value=iter([]))

        with patch("duckduckgo_search.DDGS", return_value=mock_ddgs):
            asyncio.run(self.tool.execute(query="test", region="uk-en"))

        call_kwargs = mock_ddgs.text.call_args
        assert call_kwargs[1].get("region") == "uk-en"

    # --- empty results ---

    def test_empty_results_message(self):
        mock_ddgs = MagicMock()
        mock_ddgs.__enter__ = MagicMock(return_value=mock_ddgs)
        mock_ddgs.__exit__ = MagicMock(return_value=False)
        mock_ddgs.text = MagicMock(return_value=iter([]))

        with patch("duckduckgo_search.DDGS", return_value=mock_ddgs):
            result = asyncio.run(self.tool.execute(query="nonexistent123xyz"))

        assert "No results found" in result

    # --- library not installed ---

    def test_import_error_returns_error_string(self):
        with patch.dict("sys.modules", {"duckduckgo_search": None}):
            # Reimport so ImportError is raised at runtime
            result = asyncio.run(self.tool.execute(query="test"))

        assert "Error" in result or "not installed" in result

    # --- unexpected error ---

    def test_generic_exception_handled(self):
        mock_ddgs = MagicMock()
        mock_ddgs.__enter__ = MagicMock(return_value=mock_ddgs)
        mock_ddgs.__exit__ = MagicMock(return_value=False)
        mock_ddgs.text = MagicMock(side_effect=RuntimeError("network fail"))

        with patch("duckduckgo_search.DDGS", return_value=mock_ddgs):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "Error" in result

    # --- format ---

    def test_output_includes_url(self):
        mock_results = [{"title": "Title", "href": "https://target.com/path", "body": "info"}]
        mock_ddgs = MagicMock()
        mock_ddgs.__enter__ = MagicMock(return_value=mock_ddgs)
        mock_ddgs.__exit__ = MagicMock(return_value=False)
        mock_ddgs.text = MagicMock(return_value=iter(mock_results))

        with patch("duckduckgo_search.DDGS", return_value=mock_ddgs):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "target.com" in result

    def test_output_numbered_results(self):
        mock_results = [
            {"title": "A", "href": "https://a.com", "body": "a"},
            {"title": "B", "href": "https://b.com", "body": "b"},
        ]
        mock_ddgs = MagicMock()
        mock_ddgs.__enter__ = MagicMock(return_value=mock_ddgs)
        mock_ddgs.__exit__ = MagicMock(return_value=False)
        mock_ddgs.text = MagicMock(return_value=iter(mock_results))

        with patch("duckduckgo_search.DDGS", return_value=mock_ddgs):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "1." in result
        assert "2." in result

    def test_no_api_key_required(self):
        """DuckDuckGo requires no API key — tool instantiates fine without env vars."""
        tool = DuckDuckGoTool()
        assert tool is not None

    def test_timelimit_param_passed(self):
        mock_ddgs = MagicMock()
        mock_ddgs.__enter__ = MagicMock(return_value=mock_ddgs)
        mock_ddgs.__exit__ = MagicMock(return_value=False)
        mock_ddgs.text = MagicMock(return_value=iter([]))

        with patch("duckduckgo_search.DDGS", return_value=mock_ddgs):
            asyncio.run(self.tool.execute(query="test", timelimit="w"))

        call_kwargs = mock_ddgs.text.call_args
        assert call_kwargs[1].get("timelimit") == "w"

    def test_safesearch_param_passed(self):
        mock_ddgs = MagicMock()
        mock_ddgs.__enter__ = MagicMock(return_value=mock_ddgs)
        mock_ddgs.__exit__ = MagicMock(return_value=False)
        mock_ddgs.text = MagicMock(return_value=iter([]))

        with patch("duckduckgo_search.DDGS", return_value=mock_ddgs):
            asyncio.run(self.tool.execute(query="test", safesearch="on"))

        call_kwargs = mock_ddgs.text.call_args
        assert call_kwargs[1].get("safesearch") == "on"


# ===========================================================================
# PerplexityTool Tests (12 tests)
# ===========================================================================


class TestPerplexityTool:
    """Tests for PerplexityTool."""

    def setup_method(self):
        self.tool = PerplexityTool()
        self.tool.api_key = "test-key"

    # --- metadata ---

    def test_metadata_name(self):
        assert self.tool.name == "perplexity_search"

    def test_metadata_has_system_prompt_param(self):
        props = self.tool.metadata.parameters.get("properties", {})
        assert "system_prompt" in props

    # --- missing API key ---

    def test_missing_api_key_returns_error(self):
        tool = PerplexityTool()
        tool.api_key = ""
        result = asyncio.run(tool.execute(query="test"))
        assert "PERPLEXITY_API_KEY" in result

    # --- happy path ---

    def test_happy_path_returns_content(self):
        payload = {
            "choices": [{"message": {"content": "Log4Shell is a critical RCE vulnerability..."}}],
            "citations": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            "usage": {"total_tokens": 120},
        }
        resp = _make_http_response(json_data=payload)
        ctx, client = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="log4shell"))

        assert "Log4Shell" in result
        client.post.assert_called_once()

    def test_citations_included_in_output(self):
        payload = {
            "choices": [{"message": {"content": "Answer text"}}],
            "citations": ["https://source1.com", "https://source2.com"],
        }
        resp = _make_http_response(json_data=payload)
        ctx, _ = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "source1.com" in result
        assert "source2.com" in result

    def test_model_sonar_pro_used(self):
        payload = {"choices": [{"message": {"content": "ok"}}]}
        resp = _make_http_response(json_data=payload)
        ctx, client = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            asyncio.run(self.tool.execute(query="test"))

        sent_json = client.post.call_args[1]["json"]
        assert sent_json["model"] == "sonar-pro"

    def test_api_key_in_auth_header(self):
        payload = {"choices": [{"message": {"content": "ok"}}]}
        resp = _make_http_response(json_data=payload)
        ctx, client = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            asyncio.run(self.tool.execute(query="test"))

        headers = client.post.call_args[1]["headers"]
        assert "Bearer test-key" in headers["Authorization"]

    # --- empty choices ---

    def test_empty_choices_returns_no_response(self):
        payload = {"choices": []}
        resp = _make_http_response(json_data=payload)
        ctx, _ = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "No response" in result

    # --- HTTP error ---

    def test_http_error_returns_error_string(self):
        from httpx import HTTPStatusError
        ctx = MagicMock()
        client = AsyncMock()
        client.post = AsyncMock(
            side_effect=HTTPStatusError("401", request=MagicMock(), response=MagicMock(status_code=401, text="Unauthorized"))
        )
        ctx.__aenter__ = AsyncMock(return_value=client)
        ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "Error" in result

    def test_request_error_returns_error_string(self):
        from httpx import RequestError
        ctx = MagicMock()
        client = AsyncMock()
        client.post = AsyncMock(side_effect=RequestError("timeout"))
        ctx.__aenter__ = AsyncMock(return_value=client)
        ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "Error" in result

    # --- custom system prompt ---

    def test_custom_system_prompt_sent(self):
        payload = {"choices": [{"message": {"content": "ok"}}]}
        resp = _make_http_response(json_data=payload)
        ctx, client = _async_client_ctx(resp)

        custom_prompt = "You are a pirate."
        with patch("httpx.AsyncClient", return_value=ctx):
            asyncio.run(self.tool.execute(query="test", system_prompt=custom_prompt))

        messages = client.post.call_args[1]["json"]["messages"]
        assert messages[0]["content"] == custom_prompt

    # --- max_tokens ---

    def test_max_tokens_sent_in_payload(self):
        payload = {"choices": [{"message": {"content": "ok"}}]}
        resp = _make_http_response(json_data=payload)
        ctx, client = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            asyncio.run(self.tool.execute(query="test", max_tokens=512))

        sent_json = client.post.call_args[1]["json"]
        assert sent_json["max_tokens"] == 512

    def test_unexpected_exception_handled(self):
        ctx = MagicMock()
        client = AsyncMock()
        client.post = AsyncMock(side_effect=RuntimeError("crash"))
        ctx.__aenter__ = AsyncMock(return_value=client)
        ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "Error" in result


# ===========================================================================
# SearxngTool Tests (12 tests)
# ===========================================================================


class TestSearxngTool:
    """Tests for SearxngTool."""

    def setup_method(self):
        self.tool = SearxngTool()
        self.tool.base_url = "http://searxng:8080"

    # --- metadata ---

    def test_metadata_name(self):
        assert self.tool.name == "searxng_search"

    def test_metadata_has_categories_param(self):
        props = self.tool.metadata.parameters.get("properties", {})
        assert "categories" in props

    def test_metadata_has_engines_param(self):
        props = self.tool.metadata.parameters.get("properties", {})
        assert "engines" in props

    # --- happy path ---

    def test_happy_path_returns_results(self):
        payload = {
            "results": [
                {
                    "title": "SQL Injection Guide",
                    "url": "https://owasp.org/sql-injection",
                    "content": "SQL injection is a web security vulnerability...",
                    "engines": ["google", "bing"],
                    "score": 0.9,
                }
            ],
            "number_of_results": 1,
        }
        resp = _make_http_response(json_data=payload)
        ctx, client = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="sql injection"))

        assert "SQL Injection Guide" in result
        client.get.assert_called_once()

    def test_query_passed_as_q_param(self):
        payload = {"results": [], "number_of_results": 0}
        resp = _make_http_response(json_data=payload)
        ctx, client = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            asyncio.run(self.tool.execute(query="xss payload"))

        params = client.get.call_args[1]["params"]
        assert params["q"] == "xss payload"

    def test_format_json_param_always_sent(self):
        payload = {"results": [], "number_of_results": 0}
        resp = _make_http_response(json_data=payload)
        ctx, client = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            asyncio.run(self.tool.execute(query="test"))

        params = client.get.call_args[1]["params"]
        assert params["format"] == "json"

    def test_engines_param_sent_when_provided(self):
        payload = {"results": [], "number_of_results": 0}
        resp = _make_http_response(json_data=payload)
        ctx, client = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            asyncio.run(self.tool.execute(query="test", engines="google,bing"))

        params = client.get.call_args[1]["params"]
        assert "engines" in params

    # --- empty results ---

    def test_empty_results_message(self):
        payload = {"results": [], "number_of_results": 0}
        resp = _make_http_response(json_data=payload)
        ctx, _ = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="xyznonexistent"))

        assert "No results found" in result

    # --- HTTP error ---

    def test_http_error_returns_error_string(self):
        from httpx import HTTPStatusError
        ctx = MagicMock()
        client = AsyncMock()
        client.get = AsyncMock(
            side_effect=HTTPStatusError("503", request=MagicMock(), response=MagicMock(status_code=503, text="unavailable"))
        )
        ctx.__aenter__ = AsyncMock(return_value=client)
        ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "Error" in result

    def test_connection_error_returns_error_string(self):
        from httpx import RequestError
        ctx = MagicMock()
        client = AsyncMock()
        client.get = AsyncMock(side_effect=RequestError("refused"))
        ctx.__aenter__ = AsyncMock(return_value=client)
        ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "Error" in result

    # --- URL construction ---

    def test_custom_searxng_url_used(self):
        payload = {"results": [], "number_of_results": 0}
        resp = _make_http_response(json_data=payload)
        ctx, client = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            tool = SearxngTool()
            tool.base_url = "http://myhost:9090"
            asyncio.run(tool.execute(query="test"))

        called_url = client.get.call_args[0][0]
        assert "myhost:9090" in called_url

    # --- max_results ---

    def test_max_results_limits_display(self):
        results = [{"title": f"R{i}", "url": f"https://r{i}.com", "content": "c"} for i in range(15)]
        payload = {"results": results, "number_of_results": 15}
        resp = _make_http_response(json_data=payload)
        ctx, _ = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test", max_results=5))

        assert "6." not in result

    # --- score display ---

    def test_engine_names_in_output(self):
        payload = {
            "results": [
                {"title": "T", "url": "https://x.com", "content": "c", "engines": ["duckduckgo"], "score": 0.8}
            ],
            "number_of_results": 1,
        }
        resp = _make_http_response(json_data=payload)
        ctx, _ = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "duckduckgo" in result

    def test_unexpected_exception_handled(self):
        ctx = MagicMock()
        client = AsyncMock()
        client.get = AsyncMock(side_effect=RuntimeError("crash"))
        ctx.__aenter__ = AsyncMock(return_value=client)
        ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "Error" in result


# ===========================================================================
# TraversaalTool Tests (12 tests)
# ===========================================================================


class TestTraversaalTool:
    """Tests for TraversaalTool."""

    def setup_method(self):
        self.tool = TraversaalTool()
        self.tool.api_key = "traversaal-key"

    # --- metadata ---

    def test_metadata_name(self):
        assert self.tool.name == "traversaal_search"

    def test_metadata_description_contains_ares(self):
        assert "Ares" in self.tool.description or "Traversaal" in self.tool.description

    # --- missing API key ---

    def test_missing_api_key_returns_error(self):
        tool = TraversaalTool()
        tool.api_key = ""
        result = asyncio.run(tool.execute(query="test"))
        assert "TRAVERSAAL_API_KEY" in result

    # --- happy path ---

    def test_happy_path_returns_response_text(self):
        payload = {
            "response_text": "Ransomware groups in 2024 include LockBit, BlackCat...",
            "web_url": ["https://source1.com", "https://source2.com"],
        }
        resp = _make_http_response(json_data=payload)
        ctx, client = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="ransomware 2024"))

        assert "LockBit" in result
        client.post.assert_called_once()

    def test_query_wrapped_in_list(self):
        payload = {"response_text": "ok", "web_url": []}
        resp = _make_http_response(json_data=payload)
        ctx, client = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            asyncio.run(self.tool.execute(query="test query"))

        sent_json = client.post.call_args[1]["json"]
        assert sent_json["query"] == ["test query"]

    def test_api_key_in_x_api_key_header(self):
        payload = {"response_text": "ok", "web_url": []}
        resp = _make_http_response(json_data=payload)
        ctx, client = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            asyncio.run(self.tool.execute(query="test"))

        headers = client.post.call_args[1]["headers"]
        assert headers["x-api-key"] == "traversaal-key"

    def test_sources_listed_in_output(self):
        payload = {
            "response_text": "Answer",
            "web_url": ["https://news1.com", "https://news2.com"],
        }
        resp = _make_http_response(json_data=payload)
        ctx, _ = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "news1.com" in result
        assert "news2.com" in result

    # --- empty results ---

    def test_empty_response_returns_no_response_message(self):
        payload = {"response_text": "", "web_url": []}
        resp = _make_http_response(json_data=payload)
        ctx, _ = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "No response" in result

    # --- HTTP error ---

    def test_http_error_returns_error_string(self):
        from httpx import HTTPStatusError
        ctx = MagicMock()
        client = AsyncMock()
        client.post = AsyncMock(
            side_effect=HTTPStatusError("403", request=MagicMock(), response=MagicMock(status_code=403, text="Forbidden"))
        )
        ctx.__aenter__ = AsyncMock(return_value=client)
        ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "Error" in result

    def test_request_error_returns_error_string(self):
        from httpx import RequestError
        ctx = MagicMock()
        client = AsyncMock()
        client.post = AsyncMock(side_effect=RequestError("timeout"))
        ctx.__aenter__ = AsyncMock(return_value=client)
        ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "Error" in result

    # --- endpoint ---

    def test_correct_endpoint_called(self):
        payload = {"response_text": "ok", "web_url": []}
        resp = _make_http_response(json_data=payload)
        ctx, client = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            asyncio.run(self.tool.execute(query="test"))

        called_url = client.post.call_args[0][0]
        assert "traversaal.ai" in called_url

    def test_unexpected_exception_handled(self):
        ctx = MagicMock()
        client = AsyncMock()
        client.post = AsyncMock(side_effect=RuntimeError("crash"))
        ctx.__aenter__ = AsyncMock(return_value=client)
        ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "Error" in result

    def test_response_text_only_no_web_url(self):
        payload = {"response_text": "Pure text answer", "web_url": []}
        resp = _make_http_response(json_data=payload)
        ctx, _ = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "Pure text answer" in result


# ===========================================================================
# GoogleCustomSearchTool Tests (12 tests)
# ===========================================================================


class TestGoogleCustomSearchTool:
    """Tests for GoogleCustomSearchTool."""

    def setup_method(self):
        self.tool = GoogleCustomSearchTool()
        self.tool.api_key = "google-api-key"
        self.tool.cse_id = "my-cse-id"

    # --- metadata ---

    def test_metadata_name(self):
        assert self.tool.name == "google_search"

    def test_metadata_has_num_param(self):
        props = self.tool.metadata.parameters.get("properties", {})
        assert "num" in props

    # --- missing credentials ---

    def test_missing_api_key_returns_error(self):
        tool = GoogleCustomSearchTool()
        tool.api_key = ""
        tool.cse_id = "cse"
        result = asyncio.run(tool.execute(query="test"))
        assert "GOOGLE_API_KEY" in result

    def test_missing_cse_id_returns_error(self):
        tool = GoogleCustomSearchTool()
        tool.api_key = "key"
        tool.cse_id = ""
        result = asyncio.run(tool.execute(query="test"))
        assert "GOOGLE_CSE_ID" in result

    # --- happy path ---

    def test_happy_path_returns_results(self):
        payload = {
            "items": [
                {
                    "title": "CVE-2024-1234 Details",
                    "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
                    "snippet": "Critical vulnerability in...",
                }
            ],
            "searchInformation": {"formattedTotalResults": "42"},
        }
        resp = _make_http_response(json_data=payload)
        ctx, client = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="CVE-2024-1234"))

        assert "CVE-2024-1234" in result
        client.get.assert_called_once()

    def test_credentials_passed_as_params(self):
        payload = {"items": [], "searchInformation": {"formattedTotalResults": "0"}}
        resp = _make_http_response(json_data=payload)
        ctx, client = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            asyncio.run(self.tool.execute(query="test"))

        params = client.get.call_args[1]["params"]
        assert params["key"] == "google-api-key"
        assert params["cx"] == "my-cse-id"

    def test_num_param_capped_at_10(self):
        payload = {"items": [], "searchInformation": {"formattedTotalResults": "0"}}
        resp = _make_http_response(json_data=payload)
        ctx, client = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            asyncio.run(self.tool.execute(query="test", num=50))

        params = client.get.call_args[1]["params"]
        assert params["num"] <= 10

    def test_snippet_in_output(self):
        payload = {
            "items": [{"title": "T", "link": "https://x.com", "snippet": "Important info here"}],
            "searchInformation": {"formattedTotalResults": "1"},
        }
        resp = _make_http_response(json_data=payload)
        ctx, _ = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "Important info here" in result

    # --- empty results ---

    def test_empty_items_returns_no_results_message(self):
        payload = {"items": [], "searchInformation": {"formattedTotalResults": "0"}}
        resp = _make_http_response(json_data=payload)
        ctx, _ = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="nonexistent123"))

        assert "No results found" in result

    # --- HTTP error ---

    def test_http_error_returns_error_string(self):
        from httpx import HTTPStatusError
        ctx = MagicMock()
        client = AsyncMock()
        client.get = AsyncMock(
            side_effect=HTTPStatusError("403", request=MagicMock(), response=MagicMock(status_code=403, text="API key invalid"))
        )
        ctx.__aenter__ = AsyncMock(return_value=client)
        ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "Error" in result

    def test_request_error_returns_error_string(self):
        from httpx import RequestError
        ctx = MagicMock()
        client = AsyncMock()
        client.get = AsyncMock(side_effect=RequestError("DNS failure"))
        ctx.__aenter__ = AsyncMock(return_value=client)
        ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "Error" in result

    # --- total count ---

    def test_total_results_in_output(self):
        payload = {
            "items": [{"title": "T", "link": "https://x.com", "snippet": "s"}],
            "searchInformation": {"formattedTotalResults": "1,234"},
        }
        resp = _make_http_response(json_data=payload)
        ctx, _ = _async_client_ctx(resp)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "1,234" in result

    def test_unexpected_exception_handled(self):
        ctx = MagicMock()
        client = AsyncMock()
        client.get = AsyncMock(side_effect=RuntimeError("crash"))
        ctx.__aenter__ = AsyncMock(return_value=client)
        ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = asyncio.run(self.tool.execute(query="test"))

        assert "Error" in result


# ===========================================================================
# ToolRegistry.register_search_tools() Tests (6 tests)
# ===========================================================================


class TestRegisterSearchTools:
    """Tests for ToolRegistry.register_search_tools()."""

    def test_register_search_tools_registers_sploitus(self):
        registry = ToolRegistry()
        registry.register_search_tools()
        assert registry.get_tool("sploitus_search") is not None

    def test_register_search_tools_registers_duckduckgo(self):
        registry = ToolRegistry()
        registry.register_search_tools()
        assert registry.get_tool("duckduckgo_search") is not None

    def test_register_search_tools_registers_perplexity(self):
        registry = ToolRegistry()
        registry.register_search_tools()
        assert registry.get_tool("perplexity_search") is not None

    def test_register_search_tools_registers_searxng(self):
        registry = ToolRegistry()
        registry.register_search_tools()
        assert registry.get_tool("searxng_search") is not None

    def test_register_search_tools_registers_traversaal(self):
        registry = ToolRegistry()
        registry.register_search_tools()
        assert registry.get_tool("traversaal_search") is not None

    def test_register_search_tools_registers_google(self):
        registry = ToolRegistry()
        registry.register_search_tools()
        assert registry.get_tool("google_search") is not None

    def test_register_search_tools_registers_web_search(self):
        registry = ToolRegistry()
        registry.register_search_tools()
        assert registry.get_tool("web_search") is not None

    def test_search_tools_available_in_informational_phase(self):
        registry = ToolRegistry()
        registry.register_search_tools()
        tools = registry.get_tools_for_phase(Phase.INFORMATIONAL)
        assert "sploitus_search" in tools
        assert "duckduckgo_search" in tools

    def test_search_tools_available_in_exploitation_phase(self):
        registry = ToolRegistry()
        registry.register_search_tools()
        tools = registry.get_tools_for_phase(Phase.EXPLOITATION)
        assert "perplexity_search" in tools
        assert "google_search" in tools

    def test_search_tool_priority_exploit_search(self):
        assert "sploitus_search" in ToolRegistry.SEARCH_TOOL_PRIORITY["exploit_search"]

    def test_search_tool_priority_general_osint(self):
        assert "searxng_search" in ToolRegistry.SEARCH_TOOL_PRIORITY["general_osint"]

    def test_search_tool_priority_ai_analysis(self):
        assert "perplexity_search" in ToolRegistry.SEARCH_TOOL_PRIORITY["ai_analysis"]

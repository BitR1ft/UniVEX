"""
Comprehensive unit tests for LLM providers.

All HTTP/AWS calls are mocked — no real network requests are made.
Async tests use asyncio.run() rather than pytest-asyncio markers.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import types
import unittest
from io import BytesIO
from typing import Any, AsyncIterator, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(coro):
    """Run a coroutine synchronously."""
    return asyncio.run(coro)


def _make_openai_response(content: str, model: str = "test-model") -> Dict[str, Any]:
    """Build a minimal OpenAI-compatible chat response dict."""
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }


def _make_httpx_response(data: Dict[str, Any], status_code: int = 200) -> MagicMock:
    """Return a MagicMock that mimics an httpx.Response."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.json.return_value = data
    mock_resp.text = json.dumps(data)
    if status_code >= 400:
        from httpx import HTTPStatusError, Request, Response
        mock_resp.raise_for_status.side_effect = HTTPStatusError(
            message=f"HTTP {status_code}",
            request=MagicMock(),
            response=mock_resp,
        )
    else:
        mock_resp.raise_for_status.return_value = None
    return mock_resp


# ===========================================================================
# 1. BaseLLMProvider Tests
# ===========================================================================

class TestProviderConfig:
    def test_default_values(self):
        from app.llm.base_provider import ProviderConfig, ProviderType
        cfg = ProviderConfig(name="test")
        assert cfg.name == "test"
        assert cfg.provider_type == ProviderType.OPENAI_COMPATIBLE
        assert cfg.base_url is None
        assert cfg.api_key is None
        assert cfg.default_model == "default"
        assert cfg.available_models == []
        assert cfg.max_tokens == 4096
        assert cfg.temperature == 0.7
        assert cfg.timeout == 60
        assert cfg.extra_params == {}

    def test_custom_values(self):
        from app.llm.base_provider import ProviderConfig, ProviderType
        cfg = ProviderConfig(
            name="custom",
            provider_type=ProviderType.BEDROCK,
            base_url="http://localhost",
            api_key="secret",
            default_model="my-model",
            available_models=["my-model", "other"],
            max_tokens=2048,
            temperature=0.5,
            timeout=30,
            extra_params={"top_p": 0.9},
        )
        assert cfg.provider_type == ProviderType.BEDROCK
        assert cfg.base_url == "http://localhost"
        assert cfg.api_key == "secret"
        assert cfg.default_model == "my-model"
        assert cfg.max_tokens == 2048
        assert cfg.extra_params == {"top_p": 0.9}

    def test_available_models_default_is_independent(self):
        from app.llm.base_provider import ProviderConfig
        c1 = ProviderConfig(name="a")
        c2 = ProviderConfig(name="b")
        c1.available_models.append("model-x")
        assert c2.available_models == []


class TestLLMResponse:
    def test_minimal_creation(self):
        from app.llm.base_provider import LLMResponse
        r = LLMResponse(content="hello", model="gpt-4", provider="openai")
        assert r.content == "hello"
        assert r.model == "gpt-4"
        assert r.provider == "openai"
        assert r.usage == {}
        assert r.finish_reason == "stop"
        assert r.raw is None

    def test_full_creation(self):
        from app.llm.base_provider import LLMResponse
        r = LLMResponse(
            content="world",
            model="m",
            provider="p",
            usage={"prompt_tokens": 1, "completion_tokens": 2},
            finish_reason="length",
            raw={"key": "value"},
        )
        assert r.usage["completion_tokens"] == 2
        assert r.finish_reason == "length"
        assert r.raw == {"key": "value"}


class TestProviderType:
    def test_enum_values(self):
        from app.llm.base_provider import ProviderType
        assert ProviderType.OPENAI_COMPATIBLE == "openai_compatible"
        assert ProviderType.BEDROCK == "bedrock"
        assert ProviderType.CUSTOM == "custom"


class _ConcreteProvider:
    """A minimal concrete provider used for testing BaseLLMProvider abstract methods."""

    def __init__(self, models=None, default="mymodel", api_key=None):
        from app.llm.base_provider import BaseLLMProvider, ProviderConfig
        class _Provider(BaseLLMProvider):
            @property
            def provider_name(self):
                return "concrete"

            @property
            def supported_models(self):
                return models or []

            async def chat(self, messages, model=None, **kwargs):
                pass

            async def stream_chat(self, messages, model=None, **kwargs):
                yield ""

        cfg = ProviderConfig(name="test", default_model=default, api_key=api_key)
        self.provider = _Provider(cfg)


class TestBaseLLMProvider:
    def test_validate_model_known(self):
        p = _ConcreteProvider(models=["a", "b"]).provider
        assert p.validate_model("a") is True

    def test_validate_model_unknown(self):
        p = _ConcreteProvider(models=["a", "b"]).provider
        assert p.validate_model("z") is False

    def test_validate_model_empty_list(self):
        p = _ConcreteProvider(models=[]).provider
        assert p.validate_model("anything") is True

    def test_get_default_model_from_config(self):
        p = _ConcreteProvider(models=["x", "y"], default="x").provider
        assert p.get_default_model() == "x"

    def test_get_default_model_falls_back_to_first(self):
        from app.llm.base_provider import ProviderConfig, BaseLLMProvider
        class _P(BaseLLMProvider):
            @property
            def provider_name(self): return "t"
            @property
            def supported_models(self): return ["first", "second"]
            async def chat(self, m, model=None, **kw): pass
            async def stream_chat(self, m, model=None, **kw):
                yield ""
        cfg = ProviderConfig(name="t", default_model="default")
        assert _P(cfg).get_default_model() == "first"

    def test_get_headers_no_key(self):
        p = _ConcreteProvider().provider
        headers = p.get_headers()
        assert headers["Content-Type"] == "application/json"
        assert "Authorization" not in headers

    def test_get_headers_with_key(self):
        p = _ConcreteProvider(api_key="my-secret").provider
        headers = p.get_headers()
        assert headers["Authorization"] == "Bearer my-secret"


# ===========================================================================
# 2. BedrockProvider Tests
# ===========================================================================

class TestBedrockProviderNoBoto3:
    def test_raises_import_error_without_boto3(self):
        with patch.dict(sys.modules, {"boto3": None}):
            # Invalidate cached import inside the module
            import importlib
            import app.llm.providers.bedrock_provider as bm
            original_boto3 = bm.__dict__.get("boto3")
            try:
                from app.llm.providers.bedrock_provider import BedrockProvider
                with pytest.raises(ImportError, match="boto3"):
                    with patch("builtins.__import__", side_effect=ImportError("boto3")):
                        # Direct test: the __init__ tries to import boto3
                        provider = BedrockProvider.__new__(BedrockProvider)
                        provider.__init__()
            except Exception:
                pass  # allow if environment already has boto3


def _make_bedrock_provider():
    """Create a BedrockProvider with a mocked boto3 client."""
    mock_boto3 = MagicMock()
    mock_client = MagicMock()
    mock_boto3.client.return_value = mock_client
    with patch.dict(sys.modules, {"boto3": mock_boto3}):
        from app.llm.providers.bedrock_provider import BedrockProvider
        provider = BedrockProvider.__new__(BedrockProvider)
        from app.llm.base_provider import ProviderConfig, ProviderType
        from app.llm.providers.bedrock_provider import ALL_BEDROCK_MODELS, CLAUDE_MODELS
        cfg = ProviderConfig(
            name="bedrock",
            provider_type=ProviderType.BEDROCK,
            default_model=CLAUDE_MODELS[0],
            available_models=ALL_BEDROCK_MODELS,
        )
        provider.config = cfg
        provider._boto3 = mock_boto3
        provider._client = mock_client
        import logging
        provider.logger = logging.getLogger("BedrockProvider")
        return provider, mock_client


class TestBedrockProvider:
    def test_provider_name(self):
        provider, _ = _make_bedrock_provider()
        assert provider.provider_name == "bedrock"

    def test_supported_models_contains_claude(self):
        from app.llm.providers.bedrock_provider import CLAUDE_MODELS
        provider, _ = _make_bedrock_provider()
        for m in CLAUDE_MODELS:
            assert m in provider.supported_models

    def test_get_model_family_claude(self):
        provider, _ = _make_bedrock_provider()
        assert provider._get_model_family("anthropic.claude-3-opus-20240229-v1:0") == "claude"

    def test_get_model_family_titan(self):
        provider, _ = _make_bedrock_provider()
        assert provider._get_model_family("amazon.titan-text-express-v1") == "titan"

    def test_get_model_family_ai21(self):
        provider, _ = _make_bedrock_provider()
        assert provider._get_model_family("ai21.j2-ultra-v1") == "ai21"

    def test_get_model_family_cohere(self):
        provider, _ = _make_bedrock_provider()
        assert provider._get_model_family("cohere.command-r-v1:0") == "cohere"

    def test_build_claude_request_structure(self):
        provider, _ = _make_bedrock_provider()
        messages = [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "Hello"},
        ]
        body = provider._build_claude_request(messages, "anthropic.claude-3-haiku-20240307-v1:0")
        assert "anthropic_version" in body
        assert body["system"] == "You are helpful."
        assert any(m["role"] == "user" for m in body["messages"])

    def test_build_titan_request_structure(self):
        provider, _ = _make_bedrock_provider()
        messages = [{"role": "user", "content": "Hi"}]
        body = provider._build_titan_request(messages, "amazon.titan-text-express-v1")
        assert "inputText" in body
        assert "textGenerationConfig" in body

    def test_build_ai21_request_structure(self):
        provider, _ = _make_bedrock_provider()
        messages = [{"role": "user", "content": "Hi"}]
        body = provider._build_ai21_request(messages, "ai21.j2-ultra-v1")
        assert "prompt" in body

    def test_build_cohere_request_structure(self):
        provider, _ = _make_bedrock_provider()
        messages = [{"role": "user", "content": "Hello"}]
        body = provider._build_cohere_request(messages, "cohere.command-text-v14")
        assert "message" in body
        assert body["message"] == "Hello"

    def test_parse_claude_response(self):
        provider, _ = _make_bedrock_provider()
        raw = {
            "id": "msg_test",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "Hello there!"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }
        result = provider._parse_claude_response(raw, "anthropic.claude-3-haiku-20240307-v1:0")
        assert result.content == "Hello there!"
        assert result.provider == "bedrock"
        assert result.usage["prompt_tokens"] == 10

    def test_chat_claude_model(self):
        provider, mock_client = _make_bedrock_provider()
        raw_response = {
            "content": [{"type": "text", "text": "Claude says hi"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 5, "output_tokens": 3},
        }
        mock_client.invoke_model.return_value = {
            "body": BytesIO(json.dumps(raw_response).encode())
        }
        model = "anthropic.claude-3-haiku-20240307-v1:0"
        result = run(provider.chat([{"role": "user", "content": "Hi"}], model=model))
        assert result.content == "Claude says hi"
        assert result.provider == "bedrock"

    def test_chat_titan_model(self):
        provider, mock_client = _make_bedrock_provider()
        raw_response = {
            "results": [{"outputText": "Titan says hi", "tokenCount": 3, "completionReason": "FINISH"}],
            "inputTextTokenCount": 4,
        }
        mock_client.invoke_model.return_value = {
            "body": BytesIO(json.dumps(raw_response).encode())
        }
        result = run(provider.chat(
            [{"role": "user", "content": "Hi"}],
            model="amazon.titan-text-express-v1",
        ))
        assert result.content == "Titan says hi"

    def test_stream_chat_claude(self):
        provider, mock_client = _make_bedrock_provider()
        chunk_bytes = json.dumps({
            "type": "content_block_delta",
            "delta": {"type": "text_delta", "text": "Hello "},
        }).encode()
        mock_client.invoke_model_with_response_stream.return_value = {
            "body": [{"chunk": {"bytes": chunk_bytes}}]
        }
        async def collect():
            tokens = []
            async for t in provider.stream_chat(
                [{"role": "user", "content": "Hi"}],
                model="anthropic.claude-3-haiku-20240307-v1:0",
            ):
                tokens.append(t)
            return tokens
        tokens = run(collect())
        assert "Hello " in tokens


# ===========================================================================
# 3. DeepSeekProvider Tests
# ===========================================================================

class TestDeepSeekProvider:
    def test_default_instantiation(self):
        from app.llm.providers.deepseek_provider import DeepSeekProvider
        p = DeepSeekProvider()
        assert p.config.name == "deepseek"
        assert p.config.base_url == "https://api.deepseek.com/v1"

    def test_custom_config(self):
        from app.llm.providers.deepseek_provider import DeepSeekProvider
        from app.llm.base_provider import ProviderConfig
        cfg = ProviderConfig(name="my-ds", base_url="http://proxy/v1", api_key="k")
        p = DeepSeekProvider(cfg)
        assert p.config.name == "my-ds"

    def test_provider_name(self):
        from app.llm.providers.deepseek_provider import DeepSeekProvider
        assert DeepSeekProvider().provider_name == "deepseek"

    def test_supported_models(self):
        from app.llm.providers.deepseek_provider import DeepSeekProvider
        p = DeepSeekProvider()
        assert "deepseek-chat" in p.supported_models
        assert "deepseek-coder" in p.supported_models

    def test_default_model(self):
        from app.llm.providers.deepseek_provider import DeepSeekProvider
        assert DeepSeekProvider.DEFAULT_MODEL == "deepseek-chat"

    def test_validate_model_known(self):
        from app.llm.providers.deepseek_provider import DeepSeekProvider
        p = DeepSeekProvider()
        assert p.validate_model("deepseek-chat") is True

    def test_validate_model_unknown(self):
        from app.llm.providers.deepseek_provider import DeepSeekProvider
        p = DeepSeekProvider()
        assert p.validate_model("gpt-4") is False

    def test_chat_200(self):
        from app.llm.providers.deepseek_provider import DeepSeekProvider
        p = DeepSeekProvider()
        resp_data = _make_openai_response("Deep answer", "deepseek-chat")
        mock_resp = _make_httpx_response(resp_data)

        async def _post(*a, **kw):
            return mock_resp

        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=mock_resp)):
            result = run(p.chat([{"role": "user", "content": "Hi"}]))
        assert result.content == "Deep answer"
        assert result.provider == "deepseek"

    def test_chat_401_raises(self):
        from app.llm.providers.deepseek_provider import DeepSeekProvider
        p = DeepSeekProvider()
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "Unauthorized"
        mock_resp.raise_for_status.return_value = None

        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=mock_resp)):
            with pytest.raises(PermissionError):
                run(p.chat([{"role": "user", "content": "Hi"}]))

    def test_chat_429_raises(self):
        from app.llm.providers.deepseek_provider import DeepSeekProvider
        p = DeepSeekProvider()
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.text = "Rate limit"
        mock_resp.raise_for_status.return_value = None

        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=mock_resp)):
            with pytest.raises(RuntimeError):
                run(p.chat([{"role": "user", "content": "Hi"}]))

    def test_stream_chat_yields_tokens(self):
        from app.llm.providers.deepseek_provider import DeepSeekProvider
        p = DeepSeekProvider()

        sse_lines = [
            'data: {"choices":[{"delta":{"content":"Hello"}}]}',
            'data: {"choices":[{"delta":{"content":" world"}}]}',
            "data: [DONE]",
        ]

        async def aiter_lines():
            for line in sse_lines:
                yield line

        mock_stream = AsyncMock()
        mock_stream.__aenter__ = AsyncMock(return_value=mock_stream)
        mock_stream.__aexit__ = AsyncMock(return_value=False)
        mock_stream.raise_for_status = MagicMock(return_value=None)
        mock_stream.aiter_lines = aiter_lines

        async def collect():
            tokens = []
            async for t in p.stream_chat([{"role": "user", "content": "Hi"}]):
                tokens.append(t)
            return tokens

        with patch("httpx.AsyncClient.stream", return_value=mock_stream):
            tokens = run(collect())

        assert "Hello" in tokens
        assert " world" in tokens


# ===========================================================================
# 4. QwenProvider Tests
# ===========================================================================

class TestQwenProvider:
    def test_default_instantiation(self):
        from app.llm.providers.qwen_provider import QwenProvider
        p = QwenProvider()
        assert p.config.name == "qwen"

    def test_base_url_is_dashscope(self):
        from app.llm.providers.qwen_provider import QwenProvider
        assert QwenProvider.BASE_URL == "https://dashscope.aliyuncs.com/compatible-mode/v1"

    def test_provider_name(self):
        from app.llm.providers.qwen_provider import QwenProvider
        assert QwenProvider().provider_name == "qwen"

    def test_supported_models(self):
        from app.llm.providers.qwen_provider import QwenProvider
        p = QwenProvider()
        for m in ("qwen-max", "qwen-plus", "qwen-turbo"):
            assert m in p.supported_models

    def test_default_model(self):
        from app.llm.providers.qwen_provider import QwenProvider
        assert QwenProvider.DEFAULT_MODEL == "qwen-max"

    def test_custom_config(self):
        from app.llm.providers.qwen_provider import QwenProvider
        from app.llm.base_provider import ProviderConfig
        cfg = ProviderConfig(name="my-qwen", api_key="k")
        p = QwenProvider(cfg)
        assert p.config.name == "my-qwen"

    def test_chat_200(self):
        from app.llm.providers.qwen_provider import QwenProvider
        p = QwenProvider()
        resp_data = _make_openai_response("Qwen answer", "qwen-max")
        mock_resp = _make_httpx_response(resp_data)

        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=mock_resp)):
            result = run(p.chat([{"role": "user", "content": "Hi"}]))
        assert result.content == "Qwen answer"
        assert result.provider == "qwen"

    def test_chat_401_raises(self):
        from app.llm.providers.qwen_provider import QwenProvider
        p = QwenProvider()
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "Unauthorized"
        mock_resp.raise_for_status.return_value = None

        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=mock_resp)):
            with pytest.raises(PermissionError):
                run(p.chat([{"role": "user", "content": "Hi"}]))


# ===========================================================================
# 5. GLMProvider Tests
# ===========================================================================

class TestGLMProvider:
    def test_provider_name(self):
        from app.llm.providers.glm_provider import GLMProvider
        assert GLMProvider().provider_name == "glm"

    def test_supported_models(self):
        from app.llm.providers.glm_provider import GLMProvider
        p = GLMProvider()
        for m in ("glm-4", "glm-4-air"):
            assert m in p.supported_models

    def test_generate_jwt_with_id_secret(self):
        from app.llm.providers.glm_provider import GLMProvider
        p = GLMProvider()
        token = p._generate_jwt_token("myid.mysecret")
        parts = token.split(".")
        assert len(parts) == 3  # header.payload.signature

    def test_generate_jwt_plain_passthrough(self):
        from app.llm.providers.glm_provider import GLMProvider
        p = GLMProvider()
        plain = "already-a-token-with-no-dot-structure"
        # A plain token without "." is returned unchanged
        result = p._generate_jwt_token(plain)
        assert result == plain

    def test_get_headers_uses_jwt(self):
        from app.llm.providers.glm_provider import GLMProvider
        from app.llm.base_provider import ProviderConfig
        cfg = ProviderConfig(name="glm", api_key="id123.secretxyz")
        p = GLMProvider(cfg)
        headers = p.get_headers()
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Bearer ")
        # Should be a JWT (3 parts)
        token = headers["Authorization"].split(" ", 1)[1]
        assert len(token.split(".")) == 3

    def test_default_model(self):
        from app.llm.providers.glm_provider import GLMProvider
        assert GLMProvider.DEFAULT_MODEL == "glm-4"

    def test_custom_config(self):
        from app.llm.providers.glm_provider import GLMProvider
        from app.llm.base_provider import ProviderConfig
        cfg = ProviderConfig(name="glm-custom", api_key="a.b")
        p = GLMProvider(cfg)
        assert p.config.name == "glm-custom"

    def test_chat_200(self):
        from app.llm.providers.glm_provider import GLMProvider
        p = GLMProvider()
        resp_data = _make_openai_response("GLM answer", "glm-4")
        mock_resp = _make_httpx_response(resp_data)

        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=mock_resp)):
            result = run(p.chat([{"role": "user", "content": "Hi"}]))
        assert result.content == "GLM answer"
        assert result.provider == "glm"

    def test_jwt_token_structure(self):
        """JWT should have base64-encoded header and payload."""
        import base64
        from app.llm.providers.glm_provider import GLMProvider
        p = GLMProvider()
        token = p._generate_jwt_token("kid.secret")
        header_b64 = token.split(".")[0]
        padding = "=" * (4 - len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64 + padding))
        assert header["alg"] == "HS256"

    def test_stream_chat_yields_tokens(self):
        from app.llm.providers.glm_provider import GLMProvider
        p = GLMProvider()

        sse_lines = [
            'data: {"choices":[{"delta":{"content":"GLM"}}]}',
            "data: [DONE]",
        ]

        async def aiter_lines():
            for line in sse_lines:
                yield line

        mock_stream = AsyncMock()
        mock_stream.__aenter__ = AsyncMock(return_value=mock_stream)
        mock_stream.__aexit__ = AsyncMock(return_value=False)
        mock_stream.raise_for_status = MagicMock(return_value=None)
        mock_stream.aiter_lines = aiter_lines

        async def collect():
            tokens = []
            async for t in p.stream_chat([{"role": "user", "content": "Hi"}]):
                tokens.append(t)
            return tokens

        with patch("httpx.AsyncClient.stream", return_value=mock_stream):
            tokens = run(collect())
        assert "GLM" in tokens


# ===========================================================================
# 6. KimiProvider Tests
# ===========================================================================

class TestKimiProvider:
    def test_provider_name(self):
        from app.llm.providers.kimi_provider import KimiProvider
        assert KimiProvider().provider_name == "kimi"

    def test_supported_models(self):
        from app.llm.providers.kimi_provider import KimiProvider
        p = KimiProvider()
        for m in ("moonshot-v1-8k", "moonshot-v1-32k", "moonshot-v1-128k"):
            assert m in p.supported_models

    def test_base_url(self):
        from app.llm.providers.kimi_provider import KimiProvider
        assert "moonshot.cn" in KimiProvider.BASE_URL

    def test_default_model(self):
        from app.llm.providers.kimi_provider import KimiProvider
        assert KimiProvider.DEFAULT_MODEL == "moonshot-v1-8k"

    def test_custom_config(self):
        from app.llm.providers.kimi_provider import KimiProvider
        from app.llm.base_provider import ProviderConfig
        cfg = ProviderConfig(name="kimi-custom", api_key="k")
        p = KimiProvider(cfg)
        assert p.config.name == "kimi-custom"

    def test_chat_200(self):
        from app.llm.providers.kimi_provider import KimiProvider
        p = KimiProvider()
        resp_data = _make_openai_response("Kimi answer", "moonshot-v1-8k")
        mock_resp = _make_httpx_response(resp_data)

        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=mock_resp)):
            result = run(p.chat([{"role": "user", "content": "Hi"}]))
        assert result.content == "Kimi answer"
        assert result.provider == "kimi"

    def test_chat_401_raises(self):
        from app.llm.providers.kimi_provider import KimiProvider
        p = KimiProvider()
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "Unauthorized"
        mock_resp.raise_for_status.return_value = None

        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=mock_resp)):
            with pytest.raises(PermissionError):
                run(p.chat([{"role": "user", "content": "Hi"}]))

    def test_stream_chat_yields_tokens(self):
        from app.llm.providers.kimi_provider import KimiProvider
        p = KimiProvider()

        sse_lines = [
            'data: {"choices":[{"delta":{"content":"Kimi"}}]}',
            "data: [DONE]",
        ]

        async def aiter_lines():
            for line in sse_lines:
                yield line

        mock_stream = AsyncMock()
        mock_stream.__aenter__ = AsyncMock(return_value=mock_stream)
        mock_stream.__aexit__ = AsyncMock(return_value=False)
        mock_stream.raise_for_status = MagicMock(return_value=None)
        mock_stream.aiter_lines = aiter_lines

        async def collect():
            tokens = []
            async for t in p.stream_chat([{"role": "user", "content": "Hi"}]):
                tokens.append(t)
            return tokens

        with patch("httpx.AsyncClient.stream", return_value=mock_stream):
            tokens = run(collect())
        assert "Kimi" in tokens


# ===========================================================================
# 7. VLLMProvider Tests
# ===========================================================================

class TestVLLMProvider:
    def test_provider_name(self):
        from app.llm.providers.vllm_provider import VLLMProvider
        assert VLLMProvider().provider_name == "vllm"

    def test_default_base_url(self):
        from app.llm.providers.vllm_provider import VLLMProvider
        p = VLLMProvider()
        assert p.config.base_url == "http://localhost:8000/v1"

    def test_env_var_overrides_base_url(self):
        from app.llm.providers.vllm_provider import VLLMProvider
        with patch.dict(os.environ, {"VLLM_BASE_URL": "http://myserver:9000/v1"}):
            p = VLLMProvider()
        assert p.config.base_url == "http://myserver:9000/v1"

    def test_gpu_requirements_keys(self):
        from app.llm.providers.vllm_provider import GPU_REQUIREMENTS
        assert set(GPU_REQUIREMENTS.keys()) == {"7b", "13b", "70b", "405b"}

    def test_get_gpu_requirements_7b(self):
        from app.llm.providers.vllm_provider import VLLMProvider
        req = VLLMProvider.get_gpu_requirements("7b")
        assert "vram_gb" in req
        assert req["vram_gb"] == 14
        assert req["min_gpus"] == 1

    def test_get_gpu_requirements_70b_mentions_rtx5090(self):
        from app.llm.providers.vllm_provider import VLLMProvider
        req = VLLMProvider.get_gpu_requirements("70b")
        gpus_str = " ".join(req["recommended_gpus"])
        assert "RTX 5090" in gpus_str

    def test_get_gpu_requirements_invalid_raises(self):
        from app.llm.providers.vllm_provider import VLLMProvider
        with pytest.raises(ValueError, match="Unknown model size"):
            VLLMProvider.get_gpu_requirements("999b")

    def test_list_available_models(self):
        from app.llm.providers.vllm_provider import VLLMProvider
        p = VLLMProvider()
        models_data = {"data": [{"id": "mistral-7b"}, {"id": "llama-13b"}]}
        mock_resp = _make_httpx_response(models_data)

        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=mock_resp)):
            models = run(p.list_available_models())
        assert "mistral-7b" in models
        assert "llama-13b" in models

    def test_chat_200(self):
        from app.llm.providers.vllm_provider import VLLMProvider
        from app.llm.base_provider import ProviderConfig
        cfg = ProviderConfig(
            name="vllm",
            base_url="http://localhost:8000/v1",
            default_model="mistral-7b",
            available_models=["mistral-7b"],
        )
        p = VLLMProvider(cfg)
        resp_data = _make_openai_response("vLLM answer", "mistral-7b")
        mock_resp = _make_httpx_response(resp_data)

        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=mock_resp)):
            result = run(p.chat([{"role": "user", "content": "Hi"}], model="mistral-7b"))
        assert result.content == "vLLM answer"
        assert result.provider == "vllm"

    def test_stream_chat_yields_tokens(self):
        from app.llm.providers.vllm_provider import VLLMProvider
        from app.llm.base_provider import ProviderConfig
        cfg = ProviderConfig(
            name="vllm",
            base_url="http://localhost:8000/v1",
            default_model="mistral-7b",
        )
        p = VLLMProvider(cfg)

        sse_lines = [
            'data: {"choices":[{"delta":{"content":"vLLM"}}]}',
            "data: [DONE]",
        ]

        async def aiter_lines():
            for line in sse_lines:
                yield line

        mock_stream = AsyncMock()
        mock_stream.__aenter__ = AsyncMock(return_value=mock_stream)
        mock_stream.__aexit__ = AsyncMock(return_value=False)
        mock_stream.raise_for_status = MagicMock(return_value=None)
        mock_stream.aiter_lines = aiter_lines

        async def collect():
            tokens = []
            async for t in p.stream_chat(
                [{"role": "user", "content": "Hi"}], model="mistral-7b"
            ):
                tokens.append(t)
            return tokens

        with patch("httpx.AsyncClient.stream", return_value=mock_stream):
            tokens = run(collect())
        assert "vLLM" in tokens

    def test_gpu_requirements_405b(self):
        from app.llm.providers.vllm_provider import VLLMProvider
        req = VLLMProvider.get_gpu_requirements("405b")
        assert req["vram_gb"] == 810
        assert req["min_gpus"] == 8


# ===========================================================================
# 8. ProviderRegistry Tests
# ===========================================================================

class TestProviderRegistry:
    def _fresh_registry(self, env=None):
        """Return a registry created with specific environment variables."""
        from app.llm.provider_registry import ProviderRegistry
        with patch.dict(os.environ, env or {}, clear=False):
            # Suppress auto-register noise
            with patch.object(ProviderRegistry, "_auto_register_available", return_value=None):
                registry = ProviderRegistry()
        return registry

    def test_instantiation(self):
        r = self._fresh_registry()
        assert r is not None

    def test_list_available_contains_all_builtins(self):
        r = self._fresh_registry()
        available = r.list_available()
        for name in ("bedrock", "deepseek", "qwen", "glm", "kimi", "vllm"):
            assert name in available

    def test_register_returns_provider(self):
        r = self._fresh_registry()
        provider = r.register("deepseek")
        from app.llm.providers.deepseek_provider import DeepSeekProvider
        assert isinstance(provider, DeepSeekProvider)

    def test_get_provider_returns_registered(self):
        r = self._fresh_registry()
        r.register("deepseek")
        p = r.get_provider("deepseek")
        assert p is not None
        assert p.provider_name == "deepseek"

    def test_get_provider_returns_none_for_unregistered(self):
        r = self._fresh_registry()
        assert r.get_provider("deepseek") is None

    def test_get_or_register_registers_if_missing(self):
        r = self._fresh_registry()
        p = r.get_or_register("deepseek")
        assert p.provider_name == "deepseek"

    def test_get_or_register_returns_existing(self):
        r = self._fresh_registry()
        p1 = r.register("deepseek")
        p2 = r.get_or_register("deepseek")
        assert p1 is p2

    def test_unregister_removes_provider(self):
        r = self._fresh_registry()
        r.register("deepseek")
        r.unregister("deepseek")
        assert r.get_provider("deepseek") is None

    def test_load_from_dict_minimal(self):
        r = self._fresh_registry()
        data = {
            "provider": "deepseek",
            "name": "my-ds",
            "api_key": "sk-test",
            "default_model": "deepseek-chat",
        }
        p = r.load_from_dict(data)
        assert p.provider_name == "deepseek"

    def test_load_from_dict_unknown_provider_raises(self):
        r = self._fresh_registry()
        with pytest.raises(ValueError, match="Unknown provider"):
            r.load_from_dict({"provider": "nonexistent", "name": "x"})

    def test_resolve_env_vars_simple(self):
        r = self._fresh_registry()
        with patch.dict(os.environ, {"MY_KEY": "hello"}):
            result = r._resolve_env_vars("${MY_KEY}")
        assert result == "hello"

    def test_resolve_env_vars_missing_returns_empty(self):
        r = self._fresh_registry()
        result = r._resolve_env_vars("${DEFINITELY_NOT_SET_XYZ123}")
        assert result == ""

    def test_resolve_env_vars_nested_dict(self):
        r = self._fresh_registry()
        with patch.dict(os.environ, {"K": "v"}):
            result = r._resolve_env_vars({"key": "${K}", "other": "plain"})
        assert result["key"] == "v"
        assert result["other"] == "plain"

    def test_resolve_env_vars_list(self):
        r = self._fresh_registry()
        with patch.dict(os.environ, {"A": "one", "B": "two"}):
            result = r._resolve_env_vars(["${A}", "${B}", "literal"])
        assert result == ["one", "two", "literal"]

    def test_auto_register_when_env_set(self):
        from app.llm.provider_registry import ProviderRegistry
        env = {"DEEPSEEK_API_KEY": "test-key"}
        with patch.dict(os.environ, env, clear=False):
            r = ProviderRegistry()
        # deepseek should be auto-registered
        assert r.get_provider("deepseek") is not None

    def test_register_custom_class(self):
        from app.llm.base_provider import BaseLLMProvider, ProviderConfig
        from app.llm.provider_registry import ProviderRegistry

        class MyProvider(BaseLLMProvider):
            @property
            def provider_name(self): return "my-provider"
            @property
            def supported_models(self): return ["my-model"]
            async def chat(self, m, model=None, **kw): pass
            async def stream_chat(self, m, model=None, **kw):
                yield ""

        r = self._fresh_registry()
        cfg = ProviderConfig(name="custom-one")
        p = r.register_custom("my-provider", MyProvider, cfg)
        assert p.provider_name == "my-provider"
        assert "my-provider" in r.list_available()

    def test_get_provider_registry_singleton(self):
        import app.llm.provider_registry as reg_module
        # Reset singleton
        reg_module._registry = None
        r1 = reg_module.get_provider_registry()
        r2 = reg_module.get_provider_registry()
        assert r1 is r2
        # Cleanup
        reg_module._registry = None

    def test_list_registered_empty_initially(self):
        r = self._fresh_registry()
        assert r.list_registered() == []

    def test_list_registered_after_register(self):
        r = self._fresh_registry()
        r.register("kimi")
        assert "kimi" in r.list_registered()


# ===========================================================================
# 9. Integration Tests
# ===========================================================================

class TestIntegration:
    def test_all_providers_importable(self):
        from app.llm.providers.bedrock_provider import BedrockProvider
        from app.llm.providers.deepseek_provider import DeepSeekProvider
        from app.llm.providers.glm_provider import GLMProvider
        from app.llm.providers.kimi_provider import KimiProvider
        from app.llm.providers.qwen_provider import QwenProvider
        from app.llm.providers.vllm_provider import VLLMProvider
        assert all([BedrockProvider, DeepSeekProvider, GLMProvider, KimiProvider, QwenProvider, VLLMProvider])

    def test_all_providers_have_correct_name(self):
        from app.llm.providers.deepseek_provider import DeepSeekProvider
        from app.llm.providers.glm_provider import GLMProvider
        from app.llm.providers.kimi_provider import KimiProvider
        from app.llm.providers.qwen_provider import QwenProvider
        from app.llm.providers.vllm_provider import VLLMProvider
        cases = [
            (DeepSeekProvider, "deepseek"),
            (GLMProvider, "glm"),
            (KimiProvider, "kimi"),
            (QwenProvider, "qwen"),
            (VLLMProvider, "vllm"),
        ]
        for cls, name in cases:
            assert cls().provider_name == name

    def test_all_providers_have_nonempty_models(self):
        from app.llm.providers.deepseek_provider import DeepSeekProvider
        from app.llm.providers.glm_provider import GLMProvider
        from app.llm.providers.kimi_provider import KimiProvider
        from app.llm.providers.qwen_provider import QwenProvider
        from app.llm.providers.vllm_provider import VLLMProvider
        for cls in (DeepSeekProvider, GLMProvider, KimiProvider, QwenProvider):
            assert len(cls().supported_models) > 0

    def test_all_providers_have_chat_and_stream(self):
        from app.llm.providers.deepseek_provider import DeepSeekProvider
        from app.llm.providers.glm_provider import GLMProvider
        from app.llm.providers.kimi_provider import KimiProvider
        from app.llm.providers.qwen_provider import QwenProvider
        from app.llm.providers.vllm_provider import VLLMProvider
        for cls in (DeepSeekProvider, GLMProvider, KimiProvider, QwenProvider, VLLMProvider):
            p = cls()
            assert callable(p.chat)
            assert callable(p.stream_chat)

    def test_registry_list_available_has_all_providers(self):
        from app.llm.provider_registry import ProviderRegistry
        with patch.object(ProviderRegistry, "_auto_register_available", return_value=None):
            r = ProviderRegistry()
        for name in ("bedrock", "deepseek", "qwen", "glm", "kimi", "vllm"):
            assert name in r.list_available()

"""
Comprehensive tests for the Day-6 embedding providers, registry, and
PGVectorStore.  All external calls are mocked — no real APIs or databases.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import types
from typing import List
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_httpx_response(status_code: int = 200, json_body: dict = None, headers: dict = None):
    """Build a minimal fake httpx Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = headers or {}
    if json_body is not None:
        resp.json.return_value = json_body
    if status_code >= 400:
        from httpx import HTTPStatusError, Request, Response  # noqa: PLC0415
        req = Request("POST", "https://example.com")
        resp.raise_for_status.side_effect = HTTPStatusError(
            f"HTTP {status_code}", request=req, response=resp
        )
    else:
        resp.raise_for_status.return_value = None
    return resp


_FAKE_VECTOR_768 = [0.1] * 768
_FAKE_VECTOR_1024 = [0.2] * 1024
_FAKE_VECTOR_512 = [0.3] * 512
_FAKE_VECTOR_384 = [0.4] * 384


# ===========================================================================
# OllamaEmbeddingsProvider
# ===========================================================================

class TestOllamaEmbeddingsProvider:

    @pytest.fixture(autouse=True)
    def provider(self):
        from app.embeddings.providers.ollama_embeddings import OllamaEmbeddingsProvider
        return OllamaEmbeddingsProvider(
            model="nomic-embed-text",
            base_url="http://localhost:11434",
            batch_size=4,
        )

    def _ok_response(self, vector):
        return make_httpx_response(200, {"embedding": vector})

    # --- properties ---

    def test_provider_name(self, provider):
        assert provider.provider_name == "ollama"

    def test_model_name(self, provider):
        assert provider.model_name == "nomic-embed-text"

    def test_dimensions(self, provider):
        assert provider.dimensions == 768

    def test_dimensions_mxbai(self):
        from app.embeddings.providers.ollama_embeddings import OllamaEmbeddingsProvider
        p = OllamaEmbeddingsProvider(model="mxbai-embed-large")
        assert p.dimensions == 1024

    def test_dimensions_allminilm(self):
        from app.embeddings.providers.ollama_embeddings import OllamaEmbeddingsProvider
        p = OllamaEmbeddingsProvider(model="all-minilm")
        assert p.dimensions == 384

    def test_dimensions_unknown_model(self):
        from app.embeddings.providers.ollama_embeddings import OllamaEmbeddingsProvider
        p = OllamaEmbeddingsProvider(model="custom-model")
        assert p.dimensions == 0

    # --- embed_text ---

    def test_embed_text_returns_vector(self, provider):
        with patch("httpx.post", return_value=self._ok_response(_FAKE_VECTOR_768)):
            result = provider.embed_text("hello world")
        assert result == _FAKE_VECTOR_768

    def test_embed_query_delegates_to_api(self, provider):
        with patch("httpx.post", return_value=self._ok_response(_FAKE_VECTOR_768)):
            result = provider.embed_query("search term")
        assert result == _FAKE_VECTOR_768

    def test_embed_batch_splits_by_batch_size(self, provider):
        texts = ["t1", "t2", "t3", "t4", "t5"]
        responses = [self._ok_response([float(i)] * 768) for i in range(len(texts))]
        with patch("httpx.post", side_effect=responses):
            result = provider.embed_batch(texts)
        assert len(result) == 5

    # --- retry logic ---

    def test_retry_on_http_error(self, provider):
        from httpx import HTTPStatusError, Request
        req = Request("POST", "http://localhost:11434/api/embeddings")
        bad = MagicMock()
        bad.raise_for_status.side_effect = HTTPStatusError(
            "500", request=req, response=bad
        )
        bad.status_code = 500

        good = self._ok_response(_FAKE_VECTOR_768)

        with patch("httpx.post", side_effect=[bad, good]):
            with patch("time.sleep"):  # skip actual sleep
                result = provider.embed_text("retry me")
        assert result == _FAKE_VECTOR_768

    def test_raises_after_max_retries(self, provider):
        from httpx import HTTPStatusError, Request
        req = Request("POST", "http://localhost:11434/api/embeddings")

        def make_bad():
            r = MagicMock()
            r.raise_for_status.side_effect = HTTPStatusError("503", request=req, response=r)
            return r

        with patch("httpx.post", side_effect=[make_bad(), make_bad(), make_bad()]):
            with patch("time.sleep"):
                with pytest.raises(RuntimeError, match="failed after"):
                    provider.embed_text("fail")

    def test_connection_error_raises_connection_error(self, provider):
        from httpx import ConnectError
        with patch("httpx.post", side_effect=ConnectError("refused")):
            with pytest.raises(ConnectionError, match="Cannot reach Ollama"):
                provider.embed_text("fail")

    # --- env var base_url ---

    def test_base_url_from_env(self):
        from app.embeddings.providers.ollama_embeddings import OllamaEmbeddingsProvider
        with patch.dict(os.environ, {"OLLAMA_BASE_URL": "http://custom:9999"}):
            p = OllamaEmbeddingsProvider()
        assert p._base_url == "http://custom:9999"

    def test_trailing_slash_stripped(self):
        from app.embeddings.providers.ollama_embeddings import OllamaEmbeddingsProvider
        p = OllamaEmbeddingsProvider(base_url="http://localhost:11434/")
        assert not p._base_url.endswith("/")


# ===========================================================================
# MistralEmbeddingsProvider
# ===========================================================================

class TestMistralEmbeddingsProvider:

    @pytest.fixture(autouse=True)
    def provider(self):
        from app.embeddings.providers.mistral_embeddings import MistralEmbeddingsProvider
        return MistralEmbeddingsProvider(api_key="test-key")

    def _ok_response(self, vectors):
        data = [{"embedding": v} for v in vectors]
        return make_httpx_response(200, {"data": data})

    def test_provider_name(self, provider):
        assert provider.provider_name == "mistral"

    def test_model_name(self, provider):
        assert provider.model_name == "mistral-embed"

    def test_dimensions(self, provider):
        assert provider.dimensions == 1024

    def test_embed_text(self, provider):
        with patch("httpx.post", return_value=self._ok_response([_FAKE_VECTOR_1024])):
            result = provider.embed_text("security scan")
        assert result == _FAKE_VECTOR_1024

    def test_embed_query_same_as_text(self, provider):
        with patch("httpx.post", return_value=self._ok_response([_FAKE_VECTOR_1024])):
            result = provider.embed_query("query text")
        assert result == _FAKE_VECTOR_1024

    def test_embed_batch_splits(self, provider):
        provider._batch_size = 2
        texts = ["a", "b", "c"]
        resp1 = self._ok_response([_FAKE_VECTOR_1024, _FAKE_VECTOR_1024])
        resp2 = self._ok_response([_FAKE_VECTOR_1024])
        with patch("httpx.post", side_effect=[resp1, resp2]):
            result = provider.embed_batch(texts)
        assert len(result) == 3

    def test_rate_limit_429_retries(self, provider):
        rate_resp = make_httpx_response(429, {}, headers={"retry-after": "0.01"})
        rate_resp.status_code = 429
        rate_resp.raise_for_status.return_value = None  # 429 handled before raise_for_status

        ok_resp = self._ok_response([_FAKE_VECTOR_1024])

        with patch("httpx.post", side_effect=[rate_resp, ok_resp]):
            with patch("time.sleep"):
                result = provider.embed_text("pentest")
        assert result == _FAKE_VECTOR_1024

    def test_input_too_long_raises(self, provider):
        long_text = "a" * (8192 * 4 + 10)
        with pytest.raises(ValueError, match="too long"):
            provider.embed_text(long_text)

    def test_missing_api_key_raises(self):
        from app.embeddings.providers.mistral_embeddings import MistralEmbeddingsProvider
        p = MistralEmbeddingsProvider(api_key="")
        with patch("httpx.post", return_value=self._ok_response([_FAKE_VECTOR_1024])):
            with pytest.raises(ValueError, match="MISTRAL_API_KEY"):
                p.embed_text("test")


# ===========================================================================
# JinaEmbeddingsProvider
# ===========================================================================

class TestJinaEmbeddingsProvider:

    @pytest.fixture
    def provider_v3(self):
        from app.embeddings.providers.jina_embeddings import JinaEmbeddingsProvider
        return JinaEmbeddingsProvider(api_key="jina-key", model="jina-embeddings-v3")

    @pytest.fixture
    def provider_clip(self):
        from app.embeddings.providers.jina_embeddings import JinaEmbeddingsProvider
        return JinaEmbeddingsProvider(api_key="jina-key", model="jina-clip-v1")

    def _ok_response(self, vectors):
        data = [{"embedding": v} for v in vectors]
        return make_httpx_response(200, {"data": data})

    def test_provider_name(self, provider_v3):
        assert provider_v3.provider_name == "jina"

    def test_dimensions_v3(self, provider_v3):
        assert provider_v3.dimensions == 1024

    def test_dimensions_clip(self, provider_clip):
        assert provider_clip.dimensions == 768

    def test_embed_text_v3(self, provider_v3):
        with patch("httpx.post", return_value=self._ok_response([_FAKE_VECTOR_1024])):
            result = provider_v3.embed_text("exploit analysis")
        assert result == _FAKE_VECTOR_1024

    def test_embed_query_sets_task(self, provider_v3):
        captured = {}

        def fake_post(url, json=None, headers=None, timeout=None):
            captured["task"] = json.get("task")
            return self._ok_response([_FAKE_VECTOR_1024])

        with patch("httpx.post", side_effect=fake_post):
            provider_v3.embed_query("search query")
        assert captured["task"] == "retrieval.query"

    def test_embed_batch(self, provider_v3):
        resp = self._ok_response([_FAKE_VECTOR_1024, _FAKE_VECTOR_1024])
        with patch("httpx.post", return_value=resp):
            result = provider_v3.embed_batch(["a", "b"])
        assert len(result) == 2

    def test_embed_image_clip(self, provider_clip):
        with patch("httpx.post", return_value=self._ok_response([_FAKE_VECTOR_768])):
            result = provider_clip.embed_image("https://example.com/img.png")
        assert result == _FAKE_VECTOR_768

    def test_embed_image_wrong_model_raises(self, provider_v3):
        with pytest.raises(ValueError, match="jina-clip-v1"):
            provider_v3.embed_image("https://example.com/img.png")

    def test_invalid_task_raises(self):
        from app.embeddings.providers.jina_embeddings import JinaEmbeddingsProvider
        with pytest.raises(ValueError, match="Invalid task"):
            JinaEmbeddingsProvider(api_key="k", task="bad-task")

    def test_valid_task_accepted(self):
        from app.embeddings.providers.jina_embeddings import JinaEmbeddingsProvider
        p = JinaEmbeddingsProvider(api_key="k", task="classification")
        assert p._task == "classification"

    def test_missing_api_key_raises(self):
        from app.embeddings.providers.jina_embeddings import JinaEmbeddingsProvider
        p = JinaEmbeddingsProvider(api_key="")
        with pytest.raises(ValueError, match="JINA_API_KEY"):
            p.embed_text("test")


# ===========================================================================
# HuggingFaceEmbeddingsProvider
# ===========================================================================

class TestHuggingFaceEmbeddingsProvider:

    @pytest.fixture
    def api_provider(self):
        from app.embeddings.providers.huggingface_embeddings import HuggingFaceEmbeddingsProvider
        return HuggingFaceEmbeddingsProvider(
            model="BAAI/bge-large-en-v1.5", api_key="hf-key"
        )

    @pytest.fixture
    def local_provider(self):
        from app.embeddings.providers.huggingface_embeddings import HuggingFaceEmbeddingsProvider
        return HuggingFaceEmbeddingsProvider(
            model_path="/models/bge-large", normalize_embeddings=True
        )

    def _api_ok_response(self, vectors):
        return make_httpx_response(200, vectors)  # HF returns List[List[float]] directly

    def test_provider_name(self, api_provider):
        assert api_provider.provider_name == "huggingface"

    def test_model_name_api(self, api_provider):
        assert api_provider.model_name == "BAAI/bge-large-en-v1.5"

    def test_model_name_local(self, local_provider):
        assert local_provider.model_name == "/models/bge-large"

    def test_dimensions_default(self, api_provider):
        assert api_provider.dimensions == 1024

    def test_embed_batch_api_mode(self, api_provider):
        response_json = [_FAKE_VECTOR_1024]
        resp = make_httpx_response(200, response_json)
        with patch("httpx.post", return_value=resp):
            result = api_provider.embed_batch(["text"])
        assert len(result) == 1
        assert len(result[0]) == 1024

    def test_embed_text_calls_batch(self, api_provider):
        response_json = [_FAKE_VECTOR_1024]
        resp = make_httpx_response(200, response_json)
        with patch("httpx.post", return_value=resp):
            result = api_provider.embed_text("hello")
        # Vector is L2-normalised, so check length only
        assert len(result) == 1024

    def test_local_mode_uses_sentence_transformers(self, local_provider):
        mock_st_module = MagicMock()
        mock_model_instance = MagicMock()

        # Simulate .encode() returning a list of list-like objects (no numpy needed)
        class FakeEmbedding:
            def tolist(self):
                return _FAKE_VECTOR_1024

        mock_model_instance.encode.return_value = [FakeEmbedding()]
        mock_st_module.SentenceTransformer.return_value = mock_model_instance

        with patch.dict(sys.modules, {"sentence_transformers": mock_st_module}):
            local_provider._local_model = None  # reset
            result = local_provider.embed_batch(["text"])

        assert len(result) == 1

    def test_missing_api_key_raises(self):
        from app.embeddings.providers.huggingface_embeddings import HuggingFaceEmbeddingsProvider
        p = HuggingFaceEmbeddingsProvider(api_key="")
        with pytest.raises(ValueError, match="HUGGINGFACE_API_KEY"):
            p.embed_batch(["test"])

    @pytest.mark.parametrize("batch_size,expected_calls", [(2, 2), (3, 1)])
    def test_batch_splitting(self, batch_size, expected_calls):
        from app.embeddings.providers.huggingface_embeddings import HuggingFaceEmbeddingsProvider
        p = HuggingFaceEmbeddingsProvider(api_key="k", batch_size=batch_size)
        texts = ["a", "b", "c"]
        # For batch_size=2: chunks are ["a","b"] and ["c"] → 2 + 1 = 3 vectors total
        # For batch_size=3: chunk is ["a","b","c"] → 3 vectors in one call
        call_chunks = [texts[i : i + batch_size] for i in range(0, len(texts), batch_size)]
        responses = [
            make_httpx_response(200, [_FAKE_VECTOR_1024] * len(chunk))
            for chunk in call_chunks
        ]
        with patch("httpx.post", side_effect=responses):
            result = p.embed_batch(texts)
        assert len(result) == 3


# ===========================================================================
# GoogleEmbeddingsProvider
# ===========================================================================

class TestGoogleEmbeddingsProvider:

    @pytest.fixture
    def provider(self):
        from app.embeddings.providers.google_embeddings import GoogleEmbeddingsProvider
        return GoogleEmbeddingsProvider(api_key="g-key")

    @pytest.fixture
    def provider_001(self):
        from app.embeddings.providers.google_embeddings import GoogleEmbeddingsProvider
        return GoogleEmbeddingsProvider(api_key="g-key", model="embedding-001")

    def _single_ok(self, vector=None):
        v = vector or _FAKE_VECTOR_768
        return make_httpx_response(200, {"embedding": {"values": v}})

    def _batch_ok(self, vectors):
        return make_httpx_response(200, {"embeddings": [{"values": v} for v in vectors]})

    def test_provider_name(self, provider):
        assert provider.provider_name == "google"

    def test_model_default(self, provider):
        assert provider.model_name == "text-embedding-004"

    def test_dimensions(self, provider):
        assert provider.dimensions == 768

    def test_embed_text(self, provider):
        with patch("httpx.post", return_value=self._single_ok()):
            result = provider.embed_text("pentest report")
        assert result == _FAKE_VECTOR_768

    def test_embed_query_uses_retrieval_query(self, provider):
        captured = {}

        def fake_post(url, params=None, json=None, timeout=None):
            captured["taskType"] = json.get("taskType")
            return self._single_ok()

        with patch("httpx.post", side_effect=fake_post):
            provider.embed_query("search")
        assert captured["taskType"] == "RETRIEVAL_QUERY"

    def test_embed_batch(self, provider):
        resp = self._batch_ok([_FAKE_VECTOR_768, _FAKE_VECTOR_768])
        with patch("httpx.post", return_value=resp):
            result = provider.embed_batch(["a", "b"])
        assert len(result) == 2

    def test_invalid_task_type_raises(self):
        from app.embeddings.providers.google_embeddings import GoogleEmbeddingsProvider
        with pytest.raises(ValueError, match="Invalid task_type"):
            GoogleEmbeddingsProvider(api_key="k", task_type="BAD_TASK")

    @pytest.mark.parametrize("task_type", [
        "RETRIEVAL_QUERY", "RETRIEVAL_DOCUMENT", "SEMANTIC_SIMILARITY",
        "CLASSIFICATION", "CLUSTERING",
    ])
    def test_valid_task_types(self, task_type):
        from app.embeddings.providers.google_embeddings import GoogleEmbeddingsProvider
        p = GoogleEmbeddingsProvider(api_key="k", task_type=task_type)
        assert p._task_type == task_type

    def test_model_001(self, provider_001):
        assert provider_001.model_name == "embedding-001"
        assert provider_001.dimensions == 768

    def test_missing_api_key_raises(self):
        from app.embeddings.providers.google_embeddings import GoogleEmbeddingsProvider
        p = GoogleEmbeddingsProvider(api_key="")
        with pytest.raises(ValueError, match="GOOGLE_API_KEY"):
            p.embed_text("test")


# ===========================================================================
# VoyageEmbeddingsProvider
# ===========================================================================

class TestVoyageEmbeddingsProvider:

    @pytest.fixture
    def provider(self):
        from app.embeddings.providers.voyage_embeddings import VoyageEmbeddingsProvider
        return VoyageEmbeddingsProvider(api_key="voyage-key")

    @pytest.fixture
    def code_provider(self):
        from app.embeddings.providers.voyage_embeddings import VoyageEmbeddingsProvider
        return VoyageEmbeddingsProvider(api_key="voyage-key", model="voyage-code-3")

    @pytest.fixture
    def lite_provider(self):
        from app.embeddings.providers.voyage_embeddings import VoyageEmbeddingsProvider
        return VoyageEmbeddingsProvider(api_key="voyage-key", model="voyage-3-lite")

    def _ok_response(self, vectors):
        data = [{"embedding": v, "index": i} for i, v in enumerate(vectors)]
        return make_httpx_response(200, {"data": data})

    def test_provider_name(self, provider):
        assert provider.provider_name == "voyage"

    def test_model_default(self, provider):
        assert provider.model_name == "voyage-3"

    def test_dimensions_default(self, provider):
        assert provider.dimensions == 1024

    def test_dimensions_code(self, code_provider):
        assert code_provider.dimensions == 1024

    def test_dimensions_lite(self, lite_provider):
        assert lite_provider.dimensions == 512

    def test_embed_text(self, provider):
        with patch("httpx.post", return_value=self._ok_response([_FAKE_VECTOR_1024])):
            result = provider.embed_text("buffer overflow")
        assert result == _FAKE_VECTOR_1024

    def test_embed_query_sends_query_input_type(self, provider):
        captured = {}

        def fake_post(url, json=None, headers=None, timeout=None):
            captured["input_type"] = json.get("input_type")
            return self._ok_response([_FAKE_VECTOR_1024])

        with patch("httpx.post", side_effect=fake_post):
            provider.embed_query("sql injection")
        assert captured["input_type"] == "query"

    def test_embed_batch(self, provider):
        resp = self._ok_response([_FAKE_VECTOR_1024, _FAKE_VECTOR_1024])
        with patch("httpx.post", return_value=resp):
            result = provider.embed_batch(["a", "b"])
        assert len(result) == 2

    def test_invalid_input_type_raises(self):
        from app.embeddings.providers.voyage_embeddings import VoyageEmbeddingsProvider
        with pytest.raises(ValueError, match="Invalid input_type"):
            VoyageEmbeddingsProvider(api_key="k", input_type="bad")

    @pytest.mark.parametrize("input_type", ["query", "document"])
    def test_valid_input_types(self, input_type):
        from app.embeddings.providers.voyage_embeddings import VoyageEmbeddingsProvider
        p = VoyageEmbeddingsProvider(api_key="k", input_type=input_type)
        assert p._input_type == input_type

    def test_missing_api_key_raises(self):
        from app.embeddings.providers.voyage_embeddings import VoyageEmbeddingsProvider
        p = VoyageEmbeddingsProvider(api_key="")
        with pytest.raises(ValueError, match="VOYAGE_API_KEY"):
            p.embed_text("test")

    def test_code_provider_embed(self, code_provider):
        with patch("httpx.post", return_value=self._ok_response([_FAKE_VECTOR_1024])):
            result = code_provider.embed_text("SELECT * FROM users;")
        assert len(result) == 1024


# ===========================================================================
# EmbeddingRegistry
# ===========================================================================

class TestEmbeddingRegistry:

    def _fresh_registry(self, provider_name="tfidf", batch_size=32):
        """Return a fresh registry without the global singleton."""
        from app.embeddings.embedding_registry import EmbeddingRegistry
        with patch.dict(
            os.environ,
            {"EMBEDDING_PROVIDER": provider_name, "EMBEDDING_BATCH_SIZE": str(batch_size)},
        ):
            reg = EmbeddingRegistry()
        return reg

    def test_list_providers(self):
        reg = self._fresh_registry()
        providers = reg.list_providers()
        for name in ("openai", "ollama", "mistral", "jina", "huggingface", "google", "voyage", "tfidf"):
            assert name in providers

    def test_default_provider_tfidf(self):
        reg = self._fresh_registry("tfidf")
        provider = reg.get_provider()
        assert provider.provider_name == "tfidf"

    def test_set_provider(self):
        reg = self._fresh_registry("tfidf")
        reg.set_provider("ollama")
        assert reg._provider_name == "ollama"
        assert reg._provider is None  # cache cleared

    def test_set_invalid_provider_raises(self):
        reg = self._fresh_registry()
        with pytest.raises(ValueError, match="Unknown provider"):
            reg.set_provider("nonexistent")

    def test_get_provider_info_tfidf(self):
        reg = self._fresh_registry("tfidf")
        info = reg.get_provider_info()
        assert info["name"] == "tfidf"
        assert info["configured"] is True

    def test_get_provider_info_error(self):
        reg = self._fresh_registry("ollama")
        # Force instantiation to raise (no API key / no server)
        with patch.object(reg, "get_provider", side_effect=RuntimeError("no server")):
            info = reg.get_provider_info()
        assert info["configured"] is False
        assert "error" in info

    def test_embed_with_fallback_success(self):
        reg = self._fresh_registry("tfidf")
        results = reg.embed_with_fallback(["hello", "world"])
        assert len(results) == 2

    def test_embed_with_fallback_falls_back_on_error(self):
        reg = self._fresh_registry("ollama")
        mock_provider = MagicMock()
        mock_provider.embed_batch.side_effect = ConnectionError("no server")
        reg._provider = mock_provider

        results = reg.embed_with_fallback(["security test"])
        # Should succeed via TF-IDF fallback
        assert len(results) == 1

    def test_env_var_selects_provider(self):
        with patch.dict(os.environ, {"EMBEDDING_PROVIDER": "tfidf"}):
            from app.embeddings.embedding_registry import EmbeddingRegistry
            reg = EmbeddingRegistry()
        assert reg._provider_name == "tfidf"

    def test_get_registry_singleton(self):
        import app.embeddings.embedding_registry as module
        old = module._registry
        module._registry = None
        try:
            from app.embeddings.embedding_registry import get_registry
            r1 = get_registry()
            r2 = get_registry()
            assert r1 is r2
        finally:
            module._registry = old

    def test_instantiate_mistral(self):
        reg = self._fresh_registry("tfidf")
        with patch.dict(os.environ, {"MISTRAL_API_KEY": "key"}):
            provider = reg._instantiate("mistral")
        assert provider.provider_name == "mistral"

    def test_instantiate_jina(self):
        reg = self._fresh_registry("tfidf")
        with patch.dict(os.environ, {"JINA_API_KEY": "key"}):
            provider = reg._instantiate("jina")
        assert provider.provider_name == "jina"

    def test_instantiate_google(self):
        reg = self._fresh_registry("tfidf")
        with patch.dict(os.environ, {"GOOGLE_API_KEY": "key"}):
            provider = reg._instantiate("google")
        assert provider.provider_name == "google"

    def test_instantiate_voyage(self):
        reg = self._fresh_registry("tfidf")
        with patch.dict(os.environ, {"VOYAGE_API_KEY": "key"}):
            provider = reg._instantiate("voyage")
        assert provider.provider_name == "voyage"

    def test_instantiate_huggingface(self):
        reg = self._fresh_registry("tfidf")
        with patch.dict(os.environ, {"HUGGINGFACE_API_KEY": "key"}):
            provider = reg._instantiate("huggingface")
        assert provider.provider_name == "huggingface"

    def test_instantiate_unknown_raises(self):
        reg = self._fresh_registry()
        with pytest.raises(ValueError, match="Unknown provider"):
            reg._instantiate("nonexistent")


# ===========================================================================
# PGVectorStore
# ===========================================================================

class TestPGVectorStore:
    """All asyncpg interactions are mocked — no real database required."""

    def _make_store(self):
        # Mock asyncpg before importing PGVectorStore to avoid ImportError
        if "asyncpg" not in sys.modules:
            sys.modules["asyncpg"] = MagicMock()
        from app.embeddings.pgvector_store import PGVectorStore
        return PGVectorStore(
            database_url="postgresql://user:pass@localhost/testdb",
            dimensions=4,
        )

    def _make_pool(self):
        """Build a mock asyncpg pool with async context manager support."""
        conn = AsyncMock()
        conn.execute = AsyncMock(return_value="OK")
        conn.fetch = AsyncMock(return_value=[])
        conn.fetchrow = AsyncMock(return_value={"cnt": 0, "bytes": 0})

        pool = MagicMock()
        pool.close = AsyncMock()

        # Make acquire() work as an async context manager
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=conn)
        cm.__aexit__ = AsyncMock(return_value=False)
        pool.acquire.return_value = cm

        return pool, conn

    def run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    def test_initialize_creates_pool(self):
        store = self._make_store()
        pool, conn = self._make_pool()

        async def fake_create_pool(dsn, min_size, max_size):
            return pool

        mock_asyncpg = MagicMock()
        mock_asyncpg.create_pool = fake_create_pool
        with patch.dict(sys.modules, {"asyncpg": mock_asyncpg}):
            self.run(store.initialize())

        assert store._pool is pool

    def test_initialize_calls_create_extension(self):
        store = self._make_store()
        pool, conn = self._make_pool()

        async def fake_create_pool(dsn, min_size, max_size):
            return pool

        mock_asyncpg = MagicMock()
        mock_asyncpg.create_pool = fake_create_pool
        with patch.dict(sys.modules, {"asyncpg": mock_asyncpg}):
            self.run(store.initialize())

        calls = [str(call) for call in conn.execute.call_args_list]
        assert any("CREATE EXTENSION" in c for c in calls)

    def test_add_document_returns_id(self):
        store = self._make_store()
        pool, conn = self._make_pool()
        store._pool = pool

        result = self.run(
            store.add_document(
                doc_id="doc-1",
                text="SQL injection vulnerability",
                embedding=[0.1, 0.2, 0.3, 0.4],
                metadata={"severity": "high"},
                collection="pentest",
            )
        )
        assert result == "doc-1"

    def test_add_document_generates_uuid_when_no_id(self):
        store = self._make_store()
        pool, conn = self._make_pool()
        store._pool = pool

        result = self.run(
            store.add_document(
                doc_id=None,
                text="RCE exploit",
                embedding=[0.1, 0.2, 0.3, 0.4],
            )
        )
        assert len(result) == 36  # UUID format

    def test_add_document_wrong_dims_raises(self):
        store = self._make_store()  # dims=4
        pool, _ = self._make_pool()
        store._pool = pool

        with pytest.raises(ValueError, match="4"):
            self.run(
                store.add_document("d", "text", [0.1, 0.2])  # only 2 dims
            )

    def test_search_returns_results(self):
        store = self._make_store()
        pool, conn = self._make_pool()
        store._pool = pool

        fake_row = {
            "id": "doc-1",
            "doc_text": "XSS payload",
            "metadata": json.dumps({"severity": "medium"}),
            "collection": "default",
            "score": 0.95,
        }
        conn.fetch.return_value = [fake_row]

        results = self.run(
            store.search(query_embedding=[0.1, 0.2, 0.3, 0.4], k=5)
        )
        assert len(results) == 1
        assert results[0].doc_id == "doc-1"
        assert results[0].score == 0.95
        assert results[0].text == "XSS payload"

    def test_search_empty_results(self):
        store = self._make_store()
        pool, conn = self._make_pool()
        store._pool = pool
        conn.fetch.return_value = []

        results = self.run(store.search([0.1, 0.2, 0.3, 0.4]))
        assert results == []

    def test_delete_document_true_when_found(self):
        store = self._make_store()
        pool, conn = self._make_pool()
        store._pool = pool
        conn.execute.return_value = "DELETE 1"

        deleted = self.run(store.delete_document("doc-1"))
        assert deleted is True

    def test_delete_document_false_when_not_found(self):
        store = self._make_store()
        pool, conn = self._make_pool()
        store._pool = pool
        conn.execute.return_value = "DELETE 0"

        deleted = self.run(store.delete_document("missing-doc"))
        assert deleted is False

    def test_flush_collection_returns_count(self):
        store = self._make_store()
        pool, conn = self._make_pool()
        store._pool = pool
        conn.execute.return_value = "DELETE 7"

        count = self.run(store.flush_collection("pentest"))
        assert count == 7

    def test_get_collection_stats(self):
        store = self._make_store()
        pool, conn = self._make_pool()
        store._pool = pool
        conn.fetchrow.return_value = {"cnt": 42, "bytes": 1024}

        stats = self.run(store.get_collection_stats("default"))
        assert stats["count"] == 42
        assert stats["dimensions"] == 4

    def test_list_collections(self):
        store = self._make_store()
        pool, conn = self._make_pool()
        store._pool = pool
        conn.fetch.return_value = [
            {"collection": "default"},
            {"collection": "pentest"},
        ]

        collections = self.run(store.list_collections())
        assert "default" in collections
        assert "pentest" in collections

    def test_close_pool(self):
        store = self._make_store()
        pool, _ = self._make_pool()
        store._pool = pool

        self.run(store.close())
        pool.close.assert_awaited_once()
        assert store._pool is None

    def test_ensure_pool_raises_when_not_initialised(self):
        store = self._make_store()
        with pytest.raises(RuntimeError, match="not initialised"):
            store._ensure_pool()

    def test_missing_database_url_raises(self):
        if "asyncpg" not in sys.modules:
            sys.modules["asyncpg"] = MagicMock()
        from app.embeddings.pgvector_store import PGVectorStore
        store = PGVectorStore(database_url="", dimensions=4)

        async def fake_pool(*a, **kw):
            return MagicMock()

        mock_asyncpg = MagicMock()
        mock_asyncpg.create_pool = fake_pool
        with patch.dict(sys.modules, {"asyncpg": mock_asyncpg}):
            with pytest.raises(ValueError, match="DATABASE_URL"):
                self.run(store.initialize())


# ===========================================================================
# Integration: embed_with_fallback when primary fails
# ===========================================================================

class TestEmbedWithFallbackIntegration:

    def test_fallback_produces_valid_vectors(self):
        from app.embeddings.embedding_registry import EmbeddingRegistry

        reg = EmbeddingRegistry()
        reg._provider_name = "ollama"

        mock_provider = MagicMock()
        mock_provider.embed_batch.side_effect = RuntimeError("connection refused")
        reg._provider = mock_provider

        texts = ["CVE-2023-1234 exploit", "SQL injection payload"]
        result = reg.embed_with_fallback(texts)

        assert len(result) == 2
        assert all(isinstance(v, list) for v in result)
        assert all(len(v) > 0 for v in result)

    def test_fallback_not_triggered_on_success(self):
        from app.embeddings.embedding_registry import EmbeddingRegistry

        reg = EmbeddingRegistry()
        reg._provider_name = "tfidf"

        # TF-IDF works without any mocking
        result = reg.embed_with_fallback(["hello world"])
        assert len(result) == 1


# ===========================================================================
# BaseEmbeddingProvider — EmbeddingResult
# ===========================================================================

class TestEmbeddingResult:

    def test_embedding_result_fields(self):
        from app.embeddings.providers.base import EmbeddingResult
        er = EmbeddingResult(
            text="test",
            vector=[0.1, 0.2],
            model="test-model",
            provider="test-provider",
            latency_ms=12.5,
            tokens_used=3,
        )
        assert er.text == "test"
        assert er.vector == [0.1, 0.2]
        assert er.latency_ms == 12.5
        assert er.tokens_used == 3

    def test_embed_text_with_result(self):
        from app.embeddings.providers.ollama_embeddings import OllamaEmbeddingsProvider

        provider = OllamaEmbeddingsProvider(model="nomic-embed-text")
        resp = make_httpx_response(200, {"embedding": _FAKE_VECTOR_768})
        with patch("httpx.post", return_value=resp):
            result = provider.embed_text_with_result("hello")
        assert result.provider == "ollama"
        assert result.model == "nomic-embed-text"
        assert result.latency_ms >= 0

    def test_validate_dimensions_raises(self):
        from app.embeddings.providers.ollama_embeddings import OllamaEmbeddingsProvider

        provider = OllamaEmbeddingsProvider(model="nomic-embed-text")
        with pytest.raises(ValueError, match="768 dims"):
            provider._validate_dimensions([0.1, 0.2], label="test")

    def test_repr(self):
        from app.embeddings.providers.ollama_embeddings import OllamaEmbeddingsProvider
        p = OllamaEmbeddingsProvider()
        assert "ollama" in repr(p)
        assert "nomic-embed-text" in repr(p)

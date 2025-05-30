"""
Ollama embedding provider for local/self-hosted models.

Uses the Ollama REST API (``POST /api/embeddings``) via ``httpx`` (lazy
import).  Supports retry logic with exponential back-off.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Dict, List

from .base import BaseEmbeddingProvider

logger = logging.getLogger(__name__)

# Model → default embedding dimensions
_MODEL_DIMS: Dict[str, int] = {
    "nomic-embed-text": 768,
    "mxbai-embed-large": 1024,
    "all-minilm": 384,
}

_DEFAULT_MODEL = "nomic-embed-text"
_MAX_RETRIES = 3
_RETRY_BASE_DELAY = 1.0  # seconds


class OllamaEmbeddingsProvider(BaseEmbeddingProvider):
    """
    Embedding provider backed by a locally running Ollama instance.

    Environment variables
    ---------------------
    OLLAMA_BASE_URL
        Base URL of the Ollama server (default: ``http://localhost:11434``).

    Parameters
    ----------
    model:
        One of ``nomic-embed-text`` (default), ``mxbai-embed-large``,
        ``all-minilm``.
    base_url:
        Override the server URL (falls back to ``OLLAMA_BASE_URL`` env var).
    batch_size:
        Number of texts to embed per HTTP call (default 16).
    timeout:
        HTTP request timeout in seconds (default 30).
    """

    def __init__(
        self,
        model: str = _DEFAULT_MODEL,
        base_url: str | None = None,
        batch_size: int = 16,
        timeout: float = 30.0,
    ) -> None:
        self._model = model
        self._base_url = (
            base_url
            or os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
        ).rstrip("/")
        self._batch_size = batch_size
        self._timeout = timeout

    # ------------------------------------------------------------------
    # BaseEmbeddingProvider interface
    # ------------------------------------------------------------------

    @property
    def provider_name(self) -> str:
        return "ollama"

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def dimensions(self) -> int:
        return _MODEL_DIMS.get(self._model, 0)

    def embed_text(self, text: str) -> List[float]:
        return self._call_api(text)

    def embed_query(self, text: str) -> List[float]:
        return self._call_api(text)

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        results: List[List[float]] = []
        for i in range(0, len(texts), self._batch_size):
            chunk = texts[i : i + self._batch_size]
            for text in chunk:
                results.append(self._call_api(text))
        return results

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _call_api(self, text: str) -> List[float]:
        """POST to ``/api/embeddings`` with retry logic."""
        try:
            import httpx  # lazy import
        except ImportError as exc:
            raise ImportError(
                "httpx is required for OllamaEmbeddingsProvider. "
                "Install it with: pip install httpx"
            ) from exc

        url = f"{self._base_url}/api/embeddings"
        payload = {"model": self._model, "prompt": text}

        last_error: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                response = httpx.post(url, json=payload, timeout=self._timeout)
                response.raise_for_status()
                data = response.json()
                embedding: List[float] = data["embedding"]
                logger.debug(
                    "Ollama embed: model=%s dims=%d attempt=%d",
                    self._model,
                    len(embedding),
                    attempt + 1,
                )
                return embedding
            except httpx.ConnectError as exc:
                raise ConnectionError(
                    f"Cannot reach Ollama at {self._base_url}. "
                    "Ensure Ollama is running and OLLAMA_BASE_URL is correct."
                ) from exc
            except httpx.HTTPStatusError as exc:
                last_error = exc
                logger.warning(
                    "Ollama HTTP error (attempt %d/%d): %s",
                    attempt + 1,
                    _MAX_RETRIES,
                    exc,
                )
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                logger.warning(
                    "Ollama request error (attempt %d/%d): %s",
                    attempt + 1,
                    _MAX_RETRIES,
                    exc,
                )

            if attempt < _MAX_RETRIES - 1:
                delay = _RETRY_BASE_DELAY * (2**attempt)
                logger.info("Retrying in %.1fs…", delay)
                time.sleep(delay)

        raise RuntimeError(
            f"Ollama embedding failed after {_MAX_RETRIES} attempts: {last_error}"
        )


__all__ = ["OllamaEmbeddingsProvider"]

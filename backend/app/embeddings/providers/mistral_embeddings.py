"""
Mistral AI embedding provider.

Uses the Mistral REST API (``POST https://api.mistral.ai/v1/embeddings``).
Handles batching and HTTP 429 rate-limit responses automatically.
"""

from __future__ import annotations

import logging
import os
import time
from typing import List

from .base import BaseEmbeddingProvider

logger = logging.getLogger(__name__)

_API_URL = "https://api.mistral.ai/v1/embeddings"
_DEFAULT_MODEL = "mistral-embed"
_DIMENSIONS = 1024
_MAX_TOKENS_PER_TEXT = 8192
_DEFAULT_BATCH_SIZE = 32


class MistralEmbeddingsProvider(BaseEmbeddingProvider):
    """
    Embedding provider backed by the Mistral AI API.

    Environment variables
    ---------------------
    MISTRAL_API_KEY
        Required.  Your Mistral API key.

    Parameters
    ----------
    api_key:
        Override ``MISTRAL_API_KEY`` env var.
    model:
        Model identifier (default: ``mistral-embed``).
    batch_size:
        Texts per API request (default 32, max recommended by Mistral).
    timeout:
        HTTP timeout in seconds (default 60).
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = _DEFAULT_MODEL,
        batch_size: int = _DEFAULT_BATCH_SIZE,
        timeout: float = 60.0,
    ) -> None:
        self._api_key = api_key or os.environ.get("MISTRAL_API_KEY", "")
        self._model = model
        self._batch_size = batch_size
        self._timeout = timeout

    # ------------------------------------------------------------------
    # BaseEmbeddingProvider interface
    # ------------------------------------------------------------------

    @property
    def provider_name(self) -> str:
        return "mistral"

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def dimensions(self) -> int:
        return _DIMENSIONS

    def embed_text(self, text: str) -> List[float]:
        self._validate_input(text)
        return self._embed_batch_api([text])[0]

    def embed_query(self, text: str) -> List[float]:
        return self.embed_text(text)

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        for text in texts:
            self._validate_input(text)
        results: List[List[float]] = []
        for i in range(0, len(texts), self._batch_size):
            chunk = texts[i : i + self._batch_size]
            results.extend(self._embed_batch_api(chunk))
        return results

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _validate_input(self, text: str) -> None:
        """Rough token estimate — 1 token ≈ 4 chars."""
        estimated_tokens = len(text) // 4
        if estimated_tokens > _MAX_TOKENS_PER_TEXT:
            raise ValueError(
                f"Text too long (~{estimated_tokens} tokens, max {_MAX_TOKENS_PER_TEXT})."
            )

    def _embed_batch_api(self, texts: List[str]) -> List[List[float]]:
        """Call the Mistral embeddings API, handling 429 rate limits."""
        try:
            import httpx  # lazy import
        except ImportError as exc:
            raise ImportError(
                "httpx is required for MistralEmbeddingsProvider. "
                "Install it with: pip install httpx"
            ) from exc

        if not self._api_key:
            raise ValueError(
                "MISTRAL_API_KEY is not set. "
                "Set the environment variable or pass api_key to the constructor."
            )

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        payload = {"model": self._model, "input": texts}

        max_retries = 5
        for attempt in range(max_retries):
            response = httpx.post(
                _API_URL, json=payload, headers=headers, timeout=self._timeout
            )

            if response.status_code == 429:
                retry_after = float(response.headers.get("retry-after", 2 ** attempt))
                logger.warning(
                    "Mistral rate limited; retrying in %.1fs (attempt %d/%d)",
                    retry_after,
                    attempt + 1,
                    max_retries,
                )
                time.sleep(retry_after)
                continue

            response.raise_for_status()
            data = response.json()
            embeddings = [item["embedding"] for item in data["data"]]
            logger.debug(
                "Mistral embed: model=%s texts=%d dims=%d",
                self._model,
                len(texts),
                len(embeddings[0]) if embeddings else 0,
            )
            return embeddings

        raise RuntimeError(
            f"Mistral API rate-limit persisted after {max_retries} attempts."
        )


__all__ = ["MistralEmbeddingsProvider"]

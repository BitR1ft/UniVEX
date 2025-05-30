"""
Google Generative AI embedding provider.

Uses the Google Generative Language REST API:
``POST https://generativelanguage.googleapis.com/v1beta/models/{model}:embedContent``
"""

from __future__ import annotations

import logging
import os
from typing import Dict, List, Optional

from .base import BaseEmbeddingProvider

logger = logging.getLogger(__name__)

_API_URL_TPL = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:embedContent"
)
_BATCH_URL_TPL = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:batchEmbedContents"
)

_MODEL_DIMS: Dict[str, int] = {
    "text-embedding-004": 768,
    "embedding-001": 768,
}

_DEFAULT_MODEL = "text-embedding-004"
_MAX_BATCH_SIZE = 100

_VALID_TASK_TYPES = frozenset(
    {
        "RETRIEVAL_QUERY",
        "RETRIEVAL_DOCUMENT",
        "SEMANTIC_SIMILARITY",
        "CLASSIFICATION",
        "CLUSTERING",
    }
)


class GoogleEmbeddingsProvider(BaseEmbeddingProvider):
    """
    Embedding provider backed by Google Generative AI.

    Environment variables
    ---------------------
    GOOGLE_API_KEY
        Required.  Your Google AI Studio / Generative AI API key.

    Parameters
    ----------
    api_key:
        Override ``GOOGLE_API_KEY`` env var.
    model:
        ``text-embedding-004`` (default) or ``embedding-001`` (both 768 dims).
    task_type:
        Optional semantic hint.  One of ``RETRIEVAL_QUERY``,
        ``RETRIEVAL_DOCUMENT``, ``SEMANTIC_SIMILARITY``, ``CLASSIFICATION``,
        ``CLUSTERING``.
    batch_size:
        Texts per API call (max 100).
    timeout:
        HTTP timeout in seconds (default 60).
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = _DEFAULT_MODEL,
        task_type: Optional[str] = None,
        batch_size: int = 100,
        timeout: float = 60.0,
    ) -> None:
        if task_type is not None and task_type not in _VALID_TASK_TYPES:
            raise ValueError(
                f"Invalid task_type {task_type!r}. "
                f"Choose from: {sorted(_VALID_TASK_TYPES)}"
            )
        self._api_key = api_key or os.environ.get("GOOGLE_API_KEY", "")
        self._model = model
        self._task_type = task_type
        self._batch_size = min(batch_size, _MAX_BATCH_SIZE)
        self._timeout = timeout

    # ------------------------------------------------------------------
    # BaseEmbeddingProvider interface
    # ------------------------------------------------------------------

    @property
    def provider_name(self) -> str:
        return "google"

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def dimensions(self) -> int:
        return _MODEL_DIMS.get(self._model, 768)

    def embed_text(self, text: str) -> List[float]:
        return self._single_embed(text, task_type=self._task_type)

    def embed_query(self, text: str) -> List[float]:
        return self._single_embed(text, task_type="RETRIEVAL_QUERY")

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        results: List[List[float]] = []
        for i in range(0, len(texts), self._batch_size):
            chunk = texts[i : i + self._batch_size]
            results.extend(self._batch_embed(chunk))
        return results

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _get_client(self):
        try:
            import httpx  # lazy import
        except ImportError as exc:
            raise ImportError(
                "httpx is required for GoogleEmbeddingsProvider. "
                "Install it with: pip install httpx"
            ) from exc
        if not self._api_key:
            raise ValueError(
                "GOOGLE_API_KEY is not set. "
                "Set the environment variable or pass api_key to the constructor."
            )
        return httpx

    def _build_part(self, text: str) -> dict:
        return {"parts": [{"text": text}]}

    def _single_embed(
        self, text: str, task_type: Optional[str] = None
    ) -> List[float]:
        httpx = self._get_client()
        url = _API_URL_TPL.format(model=self._model)
        params = {"key": self._api_key}
        payload: dict = {"content": self._build_part(text)}
        if task_type:
            payload["taskType"] = task_type

        response = httpx.post(url, params=params, json=payload, timeout=self._timeout)
        response.raise_for_status()
        data = response.json()
        embedding: List[float] = data["embedding"]["values"]
        logger.debug(
            "Google embed: model=%s dims=%d task=%s",
            self._model,
            len(embedding),
            task_type,
        )
        return embedding

    def _batch_embed(self, texts: List[str]) -> List[List[float]]:
        httpx = self._get_client()
        url = _BATCH_URL_TPL.format(model=self._model)
        params = {"key": self._api_key}

        requests_list = []
        for text in texts:
            req: dict = {
                "model": f"models/{self._model}",
                "content": self._build_part(text),
            }
            if self._task_type:
                req["taskType"] = self._task_type
            requests_list.append(req)

        payload = {"requests": requests_list}
        response = httpx.post(url, params=params, json=payload, timeout=self._timeout)
        response.raise_for_status()
        data = response.json()
        embeddings = [item["values"] for item in data["embeddings"]]
        logger.debug(
            "Google batch embed: model=%s texts=%d dims=%d",
            self._model,
            len(texts),
            len(embeddings[0]) if embeddings else 0,
        )
        return embeddings


__all__ = ["GoogleEmbeddingsProvider"]

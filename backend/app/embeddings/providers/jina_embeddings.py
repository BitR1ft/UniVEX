"""
Jina AI embedding provider.

Supports text and multi-modal (image) embeddings.  Uses the Jina REST API
(``POST https://api.jina.ai/v1/embeddings``).
"""

from __future__ import annotations

import logging
import os
from typing import Dict, List, Optional

from .base import BaseEmbeddingProvider

logger = logging.getLogger(__name__)

_API_URL = "https://api.jina.ai/v1/embeddings"

_MODEL_DIMS: Dict[str, int] = {
    "jina-embeddings-v3": 1024,
    "jina-clip-v1": 768,
}

_DEFAULT_MODEL = "jina-embeddings-v3"
_MAX_BATCH_SIZE = 256

# Valid task types
_TASK_TYPES = frozenset(
    {
        "retrieval.query",
        "retrieval.passage",
        "text-matching",
        "classification",
        "separation",
    }
)


class JinaEmbeddingsProvider(BaseEmbeddingProvider):
    """
    Embedding provider backed by the Jina AI API.

    Environment variables
    ---------------------
    JINA_API_KEY
        Required.  Your Jina API key.

    Parameters
    ----------
    api_key:
        Override ``JINA_API_KEY`` env var.
    model:
        ``jina-embeddings-v3`` (default, 1024 dims) or ``jina-clip-v1``
        (768 dims, multi-modal).
    task:
        Optional task hint sent to the API. One of ``retrieval.query``,
        ``retrieval.passage``, ``text-matching``, ``classification``,
        ``separation``.
    batch_size:
        Texts per API call (max 256).
    timeout:
        HTTP timeout in seconds (default 60).
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = _DEFAULT_MODEL,
        task: Optional[str] = None,
        batch_size: int = 64,
        timeout: float = 60.0,
    ) -> None:
        if task is not None and task not in _TASK_TYPES:
            raise ValueError(
                f"Invalid task {task!r}. Choose from: {sorted(_TASK_TYPES)}"
            )
        self._api_key = api_key or os.environ.get("JINA_API_KEY", "")
        self._model = model
        self._task = task
        self._batch_size = min(batch_size, _MAX_BATCH_SIZE)
        self._timeout = timeout

    # ------------------------------------------------------------------
    # BaseEmbeddingProvider interface
    # ------------------------------------------------------------------

    @property
    def provider_name(self) -> str:
        return "jina"

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def dimensions(self) -> int:
        return _MODEL_DIMS.get(self._model, 1024)

    def embed_text(self, text: str) -> List[float]:
        return self._embed_texts([text])[0]

    def embed_query(self, text: str) -> List[float]:
        original_task = self._task
        self._task = "retrieval.query"
        try:
            return self._embed_texts([text])[0]
        finally:
            self._task = original_task

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        results: List[List[float]] = []
        for i in range(0, len(texts), self._batch_size):
            chunk = texts[i : i + self._batch_size]
            results.extend(self._embed_texts(chunk))
        return results

    # ------------------------------------------------------------------
    # Multi-modal
    # ------------------------------------------------------------------

    def embed_image(self, image_url: str) -> List[float]:
        """
        Return an embedding for an image URL.

        Only available with ``jina-clip-v1`` (multi-modal model).

        Parameters
        ----------
        image_url:
            Publicly accessible URL of the image.
        """
        if self._model != "jina-clip-v1":
            raise ValueError(
                "embed_image() requires model='jina-clip-v1' "
                f"(current: {self._model!r})"
            )
        return self._call_api(inputs=[{"image": image_url}])[0]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _embed_texts(self, texts: List[str]) -> List[List[float]]:
        inputs = [{"text": t} for t in texts]
        return self._call_api(inputs=inputs)

    def _call_api(self, inputs: list) -> List[List[float]]:
        try:
            import httpx  # lazy import
        except ImportError as exc:
            raise ImportError(
                "httpx is required for JinaEmbeddingsProvider. "
                "Install it with: pip install httpx"
            ) from exc

        if not self._api_key:
            raise ValueError(
                "JINA_API_KEY is not set. "
                "Set the environment variable or pass api_key to the constructor."
            )

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        payload: dict = {"model": self._model, "input": inputs}
        if self._task:
            payload["task"] = self._task

        response = httpx.post(
            _API_URL, json=payload, headers=headers, timeout=self._timeout
        )
        response.raise_for_status()
        data = response.json()
        embeddings = [item["embedding"] for item in data["data"]]
        logger.debug(
            "Jina embed: model=%s inputs=%d dims=%d task=%s",
            self._model,
            len(inputs),
            len(embeddings[0]) if embeddings else 0,
            self._task,
        )
        return embeddings


__all__ = ["JinaEmbeddingsProvider"]

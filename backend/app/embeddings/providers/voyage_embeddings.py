"""
VoyageAI embedding provider.

Particularly well-suited for security/pen-test content thanks to
``voyage-code-3`` which is optimised for code, exploits and technical text.

Uses the VoyageAI REST API: ``POST https://api.voyageai.com/v1/embeddings``.
"""

from __future__ import annotations

import logging
import os
from typing import Dict, List, Optional

from .base import BaseEmbeddingProvider

logger = logging.getLogger(__name__)

_API_URL = "https://api.voyageai.com/v1/embeddings"

_MODEL_DIMS: Dict[str, int] = {
    "voyage-3": 1024,
    "voyage-code-3": 1024,
    "voyage-3-lite": 512,
}

_DEFAULT_MODEL = "voyage-3"
_MAX_BATCH_SIZE = 128

_VALID_INPUT_TYPES = frozenset({"query", "document"})


class VoyageEmbeddingsProvider(BaseEmbeddingProvider):
    """
    Embedding provider backed by VoyageAI.

    For penetration testing workloads consider using ``voyage-code-3``,
    which is specifically optimised for code snippets, exploit descriptions,
    and technical security documentation.

    Environment variables
    ---------------------
    VOYAGE_API_KEY
        Required.  Your VoyageAI API key.

    Parameters
    ----------
    api_key:
        Override ``VOYAGE_API_KEY`` env var.
    model:
        One of ``voyage-3`` (default, 1024 dims), ``voyage-code-3`` (1024
        dims, optimised for code/security), or ``voyage-3-lite`` (512 dims).
    input_type:
        ``"query"`` or ``"document"`` — VoyageAI best practice to improve
        retrieval quality by distinguishing query vs. passage embeddings.
        Pass ``None`` to omit (symmetric mode).
    batch_size:
        Texts per API call (max 128).
    timeout:
        HTTP timeout in seconds (default 60).
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = _DEFAULT_MODEL,
        input_type: Optional[str] = None,
        batch_size: int = 64,
        timeout: float = 60.0,
    ) -> None:
        if input_type is not None and input_type not in _VALID_INPUT_TYPES:
            raise ValueError(
                f"Invalid input_type {input_type!r}. "
                f"Choose from: {sorted(_VALID_INPUT_TYPES)}"
            )
        self._api_key = api_key or os.environ.get("VOYAGE_API_KEY", "")
        self._model = model
        self._input_type = input_type
        self._batch_size = min(batch_size, _MAX_BATCH_SIZE)
        self._timeout = timeout

    # ------------------------------------------------------------------
    # BaseEmbeddingProvider interface
    # ------------------------------------------------------------------

    @property
    def provider_name(self) -> str:
        return "voyage"

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def dimensions(self) -> int:
        return _MODEL_DIMS.get(self._model, 1024)

    def embed_text(self, text: str) -> List[float]:
        return self._call_api([text], input_type=self._input_type)[0]

    def embed_query(self, text: str) -> List[float]:
        return self._call_api([text], input_type="query")[0]

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        results: List[List[float]] = []
        for i in range(0, len(texts), self._batch_size):
            chunk = texts[i : i + self._batch_size]
            results.extend(self._call_api(chunk, input_type=self._input_type))
        return results

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _call_api(
        self, texts: List[str], input_type: Optional[str] = None
    ) -> List[List[float]]:
        try:
            import httpx  # lazy import
        except ImportError as exc:
            raise ImportError(
                "httpx is required for VoyageEmbeddingsProvider. "
                "Install it with: pip install httpx"
            ) from exc

        if not self._api_key:
            raise ValueError(
                "VOYAGE_API_KEY is not set. "
                "Set the environment variable or pass api_key to the constructor."
            )

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        payload: dict = {"model": self._model, "input": texts}
        if input_type:
            payload["input_type"] = input_type

        response = httpx.post(
            _API_URL, json=payload, headers=headers, timeout=self._timeout
        )
        response.raise_for_status()
        data = response.json()
        # VoyageAI returns {"data": [{"embedding": [...], "index": N}, ...]}
        sorted_items = sorted(data["data"], key=lambda x: x["index"])
        embeddings = [item["embedding"] for item in sorted_items]
        logger.debug(
            "Voyage embed: model=%s texts=%d dims=%d input_type=%s",
            self._model,
            len(texts),
            len(embeddings[0]) if embeddings else 0,
            input_type,
        )
        return embeddings


__all__ = ["VoyageEmbeddingsProvider"]

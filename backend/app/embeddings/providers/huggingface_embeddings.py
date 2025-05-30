"""
HuggingFace embedding provider.

Supports two modes:
1. **Inference API** — when ``HUGGINGFACE_API_KEY`` is set; calls the HF
   hosted inference endpoint.
2. **Local sentence-transformers** — when ``model_path`` is supplied; loads
   the model in-process (lazy import of ``sentence_transformers``).
"""

from __future__ import annotations

import logging
import os
from typing import List, Optional

from .base import BaseEmbeddingProvider

logger = logging.getLogger(__name__)

_API_URL_TPL = (
    "https://api-inference.huggingface.co/pipeline/feature-extraction/{model}"
)
_DEFAULT_MODEL = "BAAI/bge-large-en-v1.5"
_DEFAULT_DIMS = 1024
_MAX_BATCH_SIZE = 512


class HuggingFaceEmbeddingsProvider(BaseEmbeddingProvider):
    """
    Embedding provider backed by HuggingFace (API or local).

    Environment variables
    ---------------------
    HUGGINGFACE_API_KEY
        When set, the provider calls the HuggingFace Inference API.

    Parameters
    ----------
    model:
        Model identifier on the Hub (default: ``BAAI/bge-large-en-v1.5``).
    model_path:
        Local filesystem path or Hub identifier for sentence-transformers
        local mode.  When supplied, the Inference API is **not** used even
        if ``HUGGINGFACE_API_KEY`` is set.
    api_key:
        Override ``HUGGINGFACE_API_KEY`` env var.
    normalize_embeddings:
        L2-normalise embeddings (default True).
    batch_size:
        Texts per API/local call (max 512).
    timeout:
        HTTP timeout for Inference API calls (seconds, default 60).
    """

    def __init__(
        self,
        model: str = _DEFAULT_MODEL,
        model_path: Optional[str] = None,
        api_key: Optional[str] = None,
        normalize_embeddings: bool = True,
        batch_size: int = 64,
        timeout: float = 60.0,
    ) -> None:
        self._model = model
        self._model_path = model_path
        self._api_key = api_key or os.environ.get("HUGGINGFACE_API_KEY", "")
        self._normalize = normalize_embeddings
        self._batch_size = min(batch_size, _MAX_BATCH_SIZE)
        self._timeout = timeout
        self._local_model = None  # lazy SentenceTransformer instance

    # ------------------------------------------------------------------
    # BaseEmbeddingProvider interface
    # ------------------------------------------------------------------

    @property
    def provider_name(self) -> str:
        return "huggingface"

    @property
    def model_name(self) -> str:
        return self._model_path or self._model

    @property
    def dimensions(self) -> int:
        if self._local_model is not None:
            # sentence-transformers exposes get_sentence_embedding_dimension()
            try:
                return self._local_model.get_sentence_embedding_dimension()
            except Exception:  # noqa: BLE001
                pass
        return _DEFAULT_DIMS

    def embed_text(self, text: str) -> List[float]:
        return self.embed_batch([text])[0]

    def embed_query(self, text: str) -> List[float]:
        return self.embed_text(text)

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        results: List[List[float]] = []
        for i in range(0, len(texts), self._batch_size):
            chunk = texts[i : i + self._batch_size]
            if self._model_path:
                results.extend(self._embed_local(chunk))
            else:
                results.extend(self._embed_api(chunk))
        return results

    # ------------------------------------------------------------------
    # Local sentence-transformers
    # ------------------------------------------------------------------

    def _get_local_model(self):
        if self._local_model is None:
            try:
                from sentence_transformers import SentenceTransformer  # noqa: PLC0415
            except ImportError as exc:
                raise ImportError(
                    "sentence-transformers is required for local HuggingFace mode. "
                    "Install it with: pip install sentence-transformers"
                ) from exc
            self._local_model = SentenceTransformer(self._model_path or self._model)
        return self._local_model

    def _embed_local(self, texts: List[str]) -> List[List[float]]:
        model = self._get_local_model()
        embeddings = model.encode(
            texts,
            normalize_embeddings=self._normalize,
            show_progress_bar=False,
        )
        return [e.tolist() for e in embeddings]

    # ------------------------------------------------------------------
    # HuggingFace Inference API
    # ------------------------------------------------------------------

    def _embed_api(self, texts: List[str]) -> List[List[float]]:
        try:
            import httpx  # lazy import
        except ImportError as exc:
            raise ImportError(
                "httpx is required for HuggingFaceEmbeddingsProvider (API mode). "
                "Install it with: pip install httpx"
            ) from exc

        if not self._api_key:
            raise ValueError(
                "HUGGINGFACE_API_KEY is not set and no local model_path was given. "
                "Set the environment variable or pass model_path for local mode."
            )

        url = _API_URL_TPL.format(model=self._model)
        headers = {"Authorization": f"Bearer {self._api_key}"}
        payload = {"inputs": texts, "options": {"wait_for_model": True}}

        response = httpx.post(
            url, json=payload, headers=headers, timeout=self._timeout
        )
        response.raise_for_status()
        data = response.json()

        # API returns List[List[float]] for batch inputs
        if isinstance(data, list) and data and isinstance(data[0], list):
            if isinstance(data[0][0], list):
                # token-level embeddings → mean-pool
                embeddings = [
                    [sum(tok[d] for tok in seq) / len(seq) for d in range(len(seq[0]))]
                    for seq in data
                ]
            else:
                embeddings = data
        else:
            raise ValueError(f"Unexpected HuggingFace API response shape: {type(data)}")

        if self._normalize:
            import math  # noqa: PLC0415

            def _l2(v: List[float]) -> List[float]:
                mag = math.sqrt(sum(x * x for x in v))
                return [x / mag for x in v] if mag else v

            embeddings = [_l2(e) for e in embeddings]

        logger.debug(
            "HuggingFace embed: model=%s texts=%d dims=%d",
            self._model,
            len(texts),
            len(embeddings[0]) if embeddings else 0,
        )
        return embeddings


__all__ = ["HuggingFaceEmbeddingsProvider"]

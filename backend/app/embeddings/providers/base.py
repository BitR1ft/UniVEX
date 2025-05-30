"""
Abstract base class for embedding providers.

All concrete providers must implement ``embed_text``, ``embed_batch``, and
``embed_query``, and expose ``provider_name``, ``model_name``, and
``dimensions`` as properties.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class EmbeddingResult:
    """Rich wrapper around a single embedding operation."""

    text: str
    vector: List[float]
    model: str
    provider: str
    latency_ms: float
    tokens_used: Optional[int] = None
    metadata: dict = field(default_factory=dict)


class BaseEmbeddingProvider(ABC):
    """
    Abstract base class for all UniVex embedding providers.

    Concrete implementations must supply:
    - ``provider_name`` — human-readable provider identifier (e.g. ``"ollama"``)
    - ``model_name``    — model identifier used for embeddings
    - ``dimensions``    — output vector size (0 if not yet known)
    - ``embed_text``    — embed a single string, may update internal state
    - ``embed_batch``   — embed a list of strings efficiently
    - ``embed_query``   — embed a query string (read-only; same dims as documents)
    """

    # ------------------------------------------------------------------
    # Abstract properties
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Unique short name for this provider (e.g. ``"ollama"``)."""

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Model identifier (e.g. ``"nomic-embed-text"``)."""

    @property
    @abstractmethod
    def dimensions(self) -> int:
        """Embedding vector size; 0 if dynamically determined."""

    # ------------------------------------------------------------------
    # Abstract methods
    # ------------------------------------------------------------------

    @abstractmethod
    def embed_text(self, text: str) -> List[float]:
        """Return an embedding vector for *text*."""

    @abstractmethod
    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Return embedding vectors for each string in *texts*."""

    @abstractmethod
    def embed_query(self, text: str) -> List[float]:
        """
        Return an embedding for a *query* string.

        By default identical to :meth:`embed_text`, but some providers
        (e.g. Voyage, Jina) apply different processing for queries vs.
        documents.
        """

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def embed_text_with_result(self, text: str) -> EmbeddingResult:
        """Embed *text* and return a rich :class:`EmbeddingResult`."""
        t0 = time.monotonic()
        vector = self.embed_text(text)
        latency_ms = (time.monotonic() - t0) * 1000.0
        return EmbeddingResult(
            text=text,
            vector=vector,
            model=self.model_name,
            provider=self.provider_name,
            latency_ms=latency_ms,
        )

    def _validate_dimensions(self, vector: List[float], label: str = "") -> None:
        """Raise ``ValueError`` when *vector* has the wrong number of dimensions."""
        expected = self.dimensions
        if expected and len(vector) != expected:
            raise ValueError(
                f"[{self.provider_name}] {label} expected {expected} dims, "
                f"got {len(vector)}"
            )

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} provider={self.provider_name!r} "
            f"model={self.model_name!r} dims={self.dimensions}>"
        )


__all__ = ["BaseEmbeddingProvider", "EmbeddingResult"]

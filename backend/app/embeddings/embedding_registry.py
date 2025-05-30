"""
Centralized embedding registry for UniVex.

Selects a provider based on the ``EMBEDDING_PROVIDER`` environment variable,
auto-configures it from related env vars, and provides a fallback chain so
the platform never fully loses search capability.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_SUPPORTED_PROVIDERS = [
    "openai",
    "ollama",
    "mistral",
    "jina",
    "huggingface",
    "google",
    "voyage",
    "tfidf",
]


class EmbeddingRegistry:
    """
    Centralized registry for embedding providers.

    Configuration is driven entirely by environment variables so that no
    code changes are required when switching providers in production.

    Environment variables
    ---------------------
    EMBEDDING_PROVIDER
        Provider to use (default: ``tfidf``).  Supported values:
        ``openai``, ``ollama``, ``mistral``, ``jina``, ``huggingface``,
        ``google``, ``voyage``, ``tfidf``.
    EMBEDDING_BATCH_SIZE
        Default batch size forwarded to the active provider (default: 32).
    """

    def __init__(self) -> None:
        self._provider_name: str = os.environ.get(
            "EMBEDDING_PROVIDER", "tfidf"
        ).lower()
        self._batch_size: int = int(os.environ.get("EMBEDDING_BATCH_SIZE", "32"))
        self._provider = None  # lazy; instantiated on first access

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_provider(self):
        """Return the active :class:`BaseEmbeddingProvider` instance."""
        if self._provider is None:
            self._provider = self._instantiate(self._provider_name)
        return self._provider

    def set_provider(self, name: str) -> None:
        """Switch the active provider by name, discarding any cached instance."""
        name = name.lower()
        if name not in _SUPPORTED_PROVIDERS:
            raise ValueError(
                f"Unknown provider {name!r}. "
                f"Supported: {_SUPPORTED_PROVIDERS}"
            )
        self._provider_name = name
        self._provider = None
        logger.info("EmbeddingRegistry: switched to provider %r", name)

    def list_providers(self) -> List[str]:
        """Return all supported provider names."""
        return list(_SUPPORTED_PROVIDERS)

    def get_provider_info(self) -> Dict[str, Any]:
        """
        Return metadata about the currently configured provider.

        Returns
        -------
        dict with keys: ``name``, ``model``, ``dimensions``, ``configured``
        """
        try:
            provider = self.get_provider()
            return {
                "name": provider.provider_name,
                "model": provider.model_name,
                "dimensions": provider.dimensions,
                "configured": True,
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "name": self._provider_name,
                "model": "unknown",
                "dimensions": 0,
                "configured": False,
                "error": str(exc),
            }

    def embed_with_fallback(self, texts: List[str]) -> List[List[float]]:
        """
        Embed *texts* using the configured provider, falling back to TF-IDF
        on any error.

        This ensures the platform always has *some* vector representation
        even if the primary provider is temporarily unreachable.
        """
        try:
            provider = self.get_provider()
            return provider.embed_batch(texts)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Primary provider %r failed (%s); falling back to TF-IDF.",
                self._provider_name,
                exc,
            )
            from app.embeddings.providers.tfidf_embeddings import TFIDFEmbeddingProvider  # noqa: PLC0415

            fallback = TFIDFEmbeddingProvider()
            return fallback.embed_batch(texts)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _instantiate(self, name: str):
        """Construct the provider instance for *name*."""
        batch = self._batch_size

        if name == "tfidf":
            from app.embeddings.providers.tfidf_embeddings import TFIDFEmbeddingProvider  # noqa: PLC0415
            return TFIDFEmbeddingProvider()

        if name == "openai":
            from app.agent.knowledge.embeddings import OpenAIEmbeddingProvider  # noqa: PLC0415
            model = os.environ.get("OPENAI_EMBEDDING_MODEL", "text-embedding-3-small")
            return OpenAIEmbeddingProvider(model=model)

        if name == "ollama":
            from app.embeddings.providers.ollama_embeddings import (  # noqa: PLC0415
                OllamaEmbeddingsProvider,
            )
            model = os.environ.get("OLLAMA_EMBEDDING_MODEL", "nomic-embed-text")
            return OllamaEmbeddingsProvider(model=model, batch_size=batch)

        if name == "mistral":
            from app.embeddings.providers.mistral_embeddings import (  # noqa: PLC0415
                MistralEmbeddingsProvider,
            )
            return MistralEmbeddingsProvider(batch_size=batch)

        if name == "jina":
            from app.embeddings.providers.jina_embeddings import (  # noqa: PLC0415
                JinaEmbeddingsProvider,
            )
            model = os.environ.get("JINA_EMBEDDING_MODEL", "jina-embeddings-v3")
            return JinaEmbeddingsProvider(model=model, batch_size=batch)

        if name == "huggingface":
            from app.embeddings.providers.huggingface_embeddings import (  # noqa: PLC0415
                HuggingFaceEmbeddingsProvider,
            )
            model = os.environ.get(
                "HUGGINGFACE_EMBEDDING_MODEL", "BAAI/bge-large-en-v1.5"
            )
            model_path = os.environ.get("HUGGINGFACE_MODEL_PATH") or None
            return HuggingFaceEmbeddingsProvider(
                model=model, model_path=model_path, batch_size=batch
            )

        if name == "google":
            from app.embeddings.providers.google_embeddings import (  # noqa: PLC0415
                GoogleEmbeddingsProvider,
            )
            model = os.environ.get(
                "GOOGLE_EMBEDDING_MODEL", "text-embedding-004"
            )
            return GoogleEmbeddingsProvider(model=model, batch_size=batch)

        if name == "voyage":
            from app.embeddings.providers.voyage_embeddings import (  # noqa: PLC0415
                VoyageEmbeddingsProvider,
            )
            model = os.environ.get("VOYAGE_EMBEDDING_MODEL", "voyage-3")
            return VoyageEmbeddingsProvider(model=model, batch_size=batch)

        raise ValueError(f"Unknown provider: {name!r}")


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_registry: Optional[EmbeddingRegistry] = None


def get_registry() -> EmbeddingRegistry:
    """Return the global :class:`EmbeddingRegistry` singleton."""
    global _registry  # noqa: PLW0603
    if _registry is None:
        _registry = EmbeddingRegistry()
    return _registry


__all__ = ["EmbeddingRegistry", "get_registry"]

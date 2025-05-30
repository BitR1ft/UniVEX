"""
Embeddings package for UniVex.

Provides the embedding registry, all concrete providers, and the pgvector store.
"""

from __future__ import annotations

from .embedding_registry import EmbeddingRegistry, get_registry
from .pgvector_store import PGVectorStore, SearchResult
from .providers import (
    BaseEmbeddingProvider,
    EmbeddingResult,
    GoogleEmbeddingsProvider,
    HuggingFaceEmbeddingsProvider,
    JinaEmbeddingsProvider,
    MistralEmbeddingsProvider,
    OllamaEmbeddingsProvider,
    VoyageEmbeddingsProvider,
)

__all__ = [
    # Registry
    "EmbeddingRegistry",
    "get_registry",
    # Store
    "PGVectorStore",
    "SearchResult",
    # Base
    "BaseEmbeddingProvider",
    "EmbeddingResult",
    # Providers
    "GoogleEmbeddingsProvider",
    "HuggingFaceEmbeddingsProvider",
    "JinaEmbeddingsProvider",
    "MistralEmbeddingsProvider",
    "OllamaEmbeddingsProvider",
    "VoyageEmbeddingsProvider",
]

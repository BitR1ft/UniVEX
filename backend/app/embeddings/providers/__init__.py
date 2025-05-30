"""
Embedding providers package.

Exports all six concrete providers plus the base class.
"""

from __future__ import annotations

from .base import BaseEmbeddingProvider, EmbeddingResult
from .google_embeddings import GoogleEmbeddingsProvider
from .huggingface_embeddings import HuggingFaceEmbeddingsProvider
from .jina_embeddings import JinaEmbeddingsProvider
from .mistral_embeddings import MistralEmbeddingsProvider
from .ollama_embeddings import OllamaEmbeddingsProvider
from .tfidf_embeddings import TFIDFEmbeddingProvider
from .voyage_embeddings import VoyageEmbeddingsProvider

__all__ = [
    "BaseEmbeddingProvider",
    "EmbeddingResult",
    "GoogleEmbeddingsProvider",
    "HuggingFaceEmbeddingsProvider",
    "JinaEmbeddingsProvider",
    "MistralEmbeddingsProvider",
    "OllamaEmbeddingsProvider",
    "TFIDFEmbeddingProvider",
    "VoyageEmbeddingsProvider",
]

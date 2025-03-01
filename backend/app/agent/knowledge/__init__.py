"""
RAG Knowledge Base & Exploit Intelligence — public API.

Exports:
    RAGEngine, create_default_rag_engine
    DocumentLoader, Document, DocumentCategory
    EmbeddingProvider, TFIDFEmbeddingProvider, OpenAIEmbeddingProvider,
    get_default_embedding_provider
    VectorStore, InMemoryVectorStore, ChromaDBVectorStore
    RAGResult
"""

from .document_loader import Document, DocumentCategory, DocumentLoader
from .embeddings import (
    EmbeddingProvider,
    OpenAIEmbeddingProvider,
    TFIDFEmbeddingProvider,
    get_default_embedding_provider,
)
from .rag_engine import (
    ChromaDBVectorStore,
    InMemoryVectorStore,
    RAGEngine,
    RAGResult,
    VectorStore,
    create_default_rag_engine,
)

__all__ = [
    # Core engine
    "RAGEngine",
    "create_default_rag_engine",
    # Results
    "RAGResult",
    # Vector stores
    "VectorStore",
    "InMemoryVectorStore",
    "ChromaDBVectorStore",
    # Documents
    "Document",
    "DocumentCategory",
    "DocumentLoader",
    # Embeddings
    "EmbeddingProvider",
    "TFIDFEmbeddingProvider",
    "OpenAIEmbeddingProvider",
    "get_default_embedding_provider",
]

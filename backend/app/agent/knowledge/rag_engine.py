"""
RAG Engine — Retrieval-Augmented Generation for exploit intelligence.

Provides :class:`RAGEngine` backed by a pluggable :class:`VectorStore` and
:class:`EmbeddingProvider`.  The default stack is fully in-process (no external
services required): :class:`InMemoryVectorStore` + :class:`TFIDFEmbeddingProvider`.

A :class:`ChromaDBVectorStore` is also available but requires the ``chromadb``
package; it is imported lazily so that the rest of the module works without it.
"""

from __future__ import annotations

import asyncio
import math
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .document_loader import Document, DocumentCategory, DocumentLoader
from .embeddings import EmbeddingProvider, TFIDFEmbeddingProvider


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class RAGResult:
    """A single retrieval result from the vector store."""

    content: str
    metadata: Dict[str, Any]
    score: float
    document_id: str

    @property
    def title(self) -> str:
        return self.metadata.get("title", "")

    @property
    def category(self) -> Optional[str]:
        return self.metadata.get("category")

    @property
    def severity(self) -> Optional[str]:
        return self.metadata.get("severity")


# ---------------------------------------------------------------------------
# VectorStore abstraction
# ---------------------------------------------------------------------------

class VectorStore(ABC):
    """Abstract interface for vector stores."""

    @abstractmethod
    def add_documents(self, docs: List[Tuple[str, List[float], Document]]) -> None:
        """Add a list of ``(id, embedding, document)`` tuples."""

    @abstractmethod
    def search(
        self,
        query_embedding: List[float],
        top_k: int,
        category_filter: Optional[DocumentCategory] = None,
        severity_filter: Optional[str] = None,
    ) -> List[RAGResult]:
        """Return the top-*k* documents most similar to *query_embedding*."""

    @abstractmethod
    def delete(self, doc_id: str) -> None:
        """Remove a document by ID."""

    @abstractmethod
    def clear(self) -> None:
        """Remove all documents."""

    @abstractmethod
    def count(self) -> int:
        """Return the total number of stored documents."""

    @abstractmethod
    def count_by_category(self) -> Dict[str, int]:
        """Return a mapping of category → document count."""


# ---------------------------------------------------------------------------
# Cosine similarity helper
# ---------------------------------------------------------------------------

def _cosine_similarity(a: List[float], b: List[float]) -> float:
    """Compute cosine similarity between two equal-length vectors."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(x * x for x in b))
    if mag_a == 0.0 or mag_b == 0.0:
        return 0.0
    return dot / (mag_a * mag_b)


# ---------------------------------------------------------------------------
# In-memory vector store
# ---------------------------------------------------------------------------

class InMemoryVectorStore(VectorStore):
    """
    Pure-Python in-memory vector store using cosine similarity.

    Storage is a ``List[Tuple[str, List[float], Document]]``
    (document_id, embedding, document).  No external dependencies.
    """

    def __init__(self) -> None:
        self._store: List[Tuple[str, List[float], Document]] = []

    def add_documents(self, docs: List[Tuple[str, List[float], Document]]) -> None:
        for doc_id, embedding, document in docs:
            # Replace if ID already exists
            self._store = [(did, emb, doc) for did, emb, doc in self._store if did != doc_id]
            self._store.append((doc_id, embedding, document))

    def search(
        self,
        query_embedding: List[float],
        top_k: int,
        category_filter: Optional[DocumentCategory] = None,
        severity_filter: Optional[str] = None,
    ) -> List[RAGResult]:
        candidates = self._store

        if category_filter is not None:
            cat_value = category_filter.value if isinstance(category_filter, DocumentCategory) else str(category_filter)
            candidates = [
                (did, emb, doc) for did, emb, doc in candidates
                if self._match_category(doc, cat_value)
            ]

        if severity_filter is not None:
            sev = severity_filter.lower()
            candidates = [
                (did, emb, doc) for did, emb, doc in candidates
                if doc.metadata.get("severity", "").lower() == sev
            ]

        scored: List[Tuple[float, str, Document]] = []
        for doc_id, embedding, document in candidates:
            score = _cosine_similarity(query_embedding, embedding)
            scored.append((score, doc_id, document))

        scored.sort(key=lambda x: x[0], reverse=True)

        return [
            RAGResult(
                content=doc.content,
                metadata=doc.metadata,
                score=score,
                document_id=doc_id,
            )
            for score, doc_id, doc in scored[:top_k]
        ]

    def delete(self, doc_id: str) -> None:
        self._store = [(did, emb, doc) for did, emb, doc in self._store if did != doc_id]

    def clear(self) -> None:
        self._store = []

    def count(self) -> int:
        return len(self._store)

    def count_by_category(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for _, _, doc in self._store:
            cat = str(doc.metadata.get("category", "unknown"))
            counts[cat] = counts.get(cat, 0) + 1
        return counts

    # ------------------------------------------------------------------

    @staticmethod
    def _match_category(doc: Document, cat_value: str) -> bool:
        doc_cat = doc.metadata.get("category")
        if doc_cat is None:
            return False
        if isinstance(doc_cat, DocumentCategory):
            return doc_cat.value == cat_value
        return str(doc_cat) == cat_value


# ---------------------------------------------------------------------------
# ChromaDB vector store (lazy import)
# ---------------------------------------------------------------------------

class ChromaDBVectorStore(VectorStore):
    """
    ChromaDB-backed vector store.

    ``chromadb`` is imported lazily.  If it is not installed an :exc:`ImportError`
    with a helpful message is raised at construction time.
    """

    def __init__(
        self,
        collection_name: str = "univex_knowledge",
        persist_directory: Optional[str] = None,
        host: Optional[str] = None,
        port: int = 8000,
    ) -> None:
        try:
            import chromadb  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                "chromadb is required for ChromaDBVectorStore. "
                "Install it with: pip install chromadb>=1.5.5  "
                "or use InMemoryVectorStore for a dependency-free alternative."
            ) from exc

        if host:
            self._client = chromadb.HttpClient(host=host, port=port)
        elif persist_directory:
            self._client = chromadb.PersistentClient(path=persist_directory)
        else:
            self._client = chromadb.EphemeralClient()

        self._collection = self._client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"},
        )

    def add_documents(self, docs: List[Tuple[str, List[float], Document]]) -> None:
        if not docs:
            return
        ids = [doc_id for doc_id, _, _ in docs]
        embeddings = [emb for _, emb, _ in docs]
        documents = [doc.content for _, _, doc in docs]
        metadatas = [self._serialise_metadata(doc.metadata) for _, _, doc in docs]

        self._collection.upsert(
            ids=ids,
            embeddings=embeddings,
            documents=documents,
            metadatas=metadatas,
        )

    def search(
        self,
        query_embedding: List[float],
        top_k: int,
        category_filter: Optional[DocumentCategory] = None,
        severity_filter: Optional[str] = None,
    ) -> List[RAGResult]:
        where: Optional[Dict[str, Any]] = None
        conditions: List[Dict[str, Any]] = []

        if category_filter is not None:
            cat_value = category_filter.value if isinstance(category_filter, DocumentCategory) else str(category_filter)
            conditions.append({"category": {"$eq": cat_value}})

        if severity_filter is not None:
            conditions.append({"severity": {"$eq": severity_filter.lower()}})

        if len(conditions) == 1:
            where = conditions[0]
        elif len(conditions) > 1:
            where = {"$and": conditions}

        results = self._collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k,
            where=where,
            include=["documents", "metadatas", "distances"],
        )

        rag_results: List[RAGResult] = []
        for i, doc_id in enumerate(results["ids"][0]):
            distance = results["distances"][0][i]
            score = 1.0 - distance  # ChromaDB cosine distance → similarity
            rag_results.append(
                RAGResult(
                    content=results["documents"][0][i],
                    metadata=results["metadatas"][0][i],
                    score=score,
                    document_id=doc_id,
                )
            )
        return rag_results

    def delete(self, doc_id: str) -> None:
        self._collection.delete(ids=[doc_id])

    def clear(self) -> None:
        self._collection.delete(where={"category": {"$ne": ""}})

    def count(self) -> int:
        return self._collection.count()

    def count_by_category(self) -> Dict[str, int]:
        results = self._collection.get(include=["metadatas"])
        counts: Dict[str, int] = {}
        for meta in results.get("metadatas", []):
            cat = str(meta.get("category", "unknown"))
            counts[cat] = counts.get(cat, 0) + 1
        return counts

    @staticmethod
    def _serialise_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
        """ChromaDB only supports str/int/float/bool metadata values."""
        serialised: Dict[str, Any] = {}
        for k, v in metadata.items():
            if isinstance(v, (str, int, float, bool)):
                serialised[k] = v
            elif isinstance(v, DocumentCategory):
                serialised[k] = v.value
            elif isinstance(v, list):
                serialised[k] = ", ".join(str(i) for i in v)
            else:
                serialised[k] = str(v)
        return serialised


# ---------------------------------------------------------------------------
# RAG Engine
# ---------------------------------------------------------------------------

class RAGEngine:
    """
    Retrieval-Augmented Generation engine for penetration-testing intelligence.

    Combines a :class:`VectorStore` and an :class:`EmbeddingProvider` to
    provide semantic search over security knowledge documents (CVEs, advisories,
    tool docs, engagement history …).

    By default uses :class:`InMemoryVectorStore` + :class:`TFIDFEmbeddingProvider`
    — no external services required.
    """

    def __init__(
        self,
        vector_store: Optional[VectorStore] = None,
        embedding_provider: Optional[EmbeddingProvider] = None,
        top_k: int = 5,
    ) -> None:
        self._store = vector_store or InMemoryVectorStore()
        self._embedder = embedding_provider or TFIDFEmbeddingProvider()
        self._default_top_k = top_k
        self._loader = DocumentLoader()

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def ingest_document(self, document: Document) -> str:
        """Embed and store a single document.  Returns the document ID."""
        embedding = self._embedder.embed_text(document.content)
        self._store.add_documents([(document.id, embedding, document)])
        return document.id

    def ingest_documents(self, documents: List[Document]) -> List[str]:
        """Batch-embed and store documents.  Returns list of document IDs."""
        if not documents:
            return []
        contents = [doc.content for doc in documents]
        embeddings = self._embedder.embed_batch(contents)
        triples = [
            (doc.id, emb, doc)
            for doc, emb in zip(documents, embeddings)
        ]
        self._store.add_documents(triples)
        return [doc.id for doc in documents]

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def retrieve(
        self,
        query: str,
        top_k: Optional[int] = None,
        category_filter: Optional[DocumentCategory] = None,
        severity_filter: Optional[str] = None,
    ) -> List[RAGResult]:
        """Semantic search with optional category/severity filters."""
        k = top_k if top_k is not None else self._default_top_k
        # Use embed_query to avoid mutating vocabulary and causing dimension drift
        query_embedding = self._embedder.embed_query(query)
        return self._store.search(
            query_embedding=query_embedding,
            top_k=k,
            category_filter=category_filter,
            severity_filter=severity_filter,
        )

    def retrieve_for_agent(self, task_description: str, top_k: int = 5) -> str:
        """
        Retrieve relevant context and format it as a string for injection into
        an agent prompt.
        """
        results = self.retrieve(task_description, top_k=top_k)
        if not results:
            return "No relevant knowledge base context found."

        lines: List[str] = ["=== Relevant Knowledge Base Context ===\n"]
        for i, result in enumerate(results, 1):
            title = result.title or "Untitled"
            cat = result.category or "unknown"
            score = result.score
            lines.append(f"[{i}] {title} (category={cat}, relevance={score:.3f})")
            lines.append(result.content[:500] + ("…" if len(result.content) > 500 else ""))
            lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Convenience methods
    # ------------------------------------------------------------------

    def get_tool_context(self, tool_name: str) -> str:
        """Retrieve documentation for a specific tool."""
        results = self.retrieve(
            f"tool documentation {tool_name}",
            top_k=3,
            category_filter=DocumentCategory.TOOL_DOCUMENTATION,
        )
        if not results:
            return f"No documentation found for tool: {tool_name}"
        return results[0].content

    def record_engagement(
        self,
        target: str,
        phase: str,
        findings: List[str],
        tools_used: List[str],
        success: bool,
    ) -> str:
        """Store an engagement record and return its document ID."""
        doc = self._loader.load_engagement_history(
            target=target,
            phase=phase,
            findings=findings,
            tools_used=tools_used,
            success=success,
        )
        return self.ingest_document(doc)

    def retrieve_similar_engagements(
        self, target_description: str, top_k: int = 3
    ) -> List[RAGResult]:
        """Retrieve past engagement records similar to *target_description*."""
        return self.retrieve(
            target_description,
            top_k=top_k,
            category_filter=DocumentCategory.ENGAGEMENT_HISTORY,
        )

    def get_stats(self) -> Dict[str, Any]:
        """Return document counts by category and totals."""
        by_category = self._store.count_by_category()
        return {
            "total": self._store.count(),
            "by_category": by_category,
        }

    def clear_category(self, category: DocumentCategory) -> None:
        """Remove all documents of a given category."""
        # We need to identify IDs to delete; InMemoryVectorStore exposes the
        # internal list so we can filter.  For a generic implementation we
        # retrieve all docs, filter, and delete individually.
        if isinstance(self._store, InMemoryVectorStore):
            cat_value = category.value if isinstance(category, DocumentCategory) else str(category)
            to_delete = [
                doc_id
                for doc_id, _, doc in self._store._store
                if InMemoryVectorStore._match_category(doc, cat_value)
            ]
            for doc_id in to_delete:
                self._store.delete(doc_id)
        else:
            # Generic fallback: search with a broad query and delete matches
            # This is best-effort for external stores
            results = self.retrieve("", top_k=10000, category_filter=category)
            for result in results:
                self._store.delete(result.document_id)

    # ------------------------------------------------------------------
    # NVD feed ingestion (async)
    # ------------------------------------------------------------------

    async def ingest_nvd_feed(self, url: str) -> int:
        """
        Fetch an NVD CVE JSON feed from *url* and ingest all CVE documents.

        Returns the number of documents ingested.  Network I/O is performed
        with :mod:`aiohttp` (lazy import); falls back to :mod:`urllib.request`
        if aiohttp is unavailable.
        """
        feed_data = await self._fetch_json(url)
        documents = self._loader.load_from_nvd_feed(feed_data)
        self.ingest_documents(documents)
        return len(documents)

    @staticmethod
    async def _fetch_json(url: str) -> Dict[str, Any]:
        """Fetch JSON from *url*, preferring aiohttp."""
        try:
            import aiohttp  # noqa: PLC0415

            async with aiohttp.ClientSession() as session:
                async with session.get(url) as resp:
                    resp.raise_for_status()
                    return await resp.json()
        except ImportError:
            import json  # noqa: PLC0415
            import urllib.request  # noqa: PLC0415

            loop = asyncio.get_event_loop()
            with urllib.request.urlopen(url) as resp:  # noqa: S310
                raw = await loop.run_in_executor(None, resp.read)
            return json.loads(raw)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def create_default_rag_engine(top_k: int = 5) -> RAGEngine:
    """
    Create a :class:`RAGEngine` with the default in-process stack.

    Uses :class:`InMemoryVectorStore` and :class:`TFIDFEmbeddingProvider` —
    no external services or packages are required.
    """
    return RAGEngine(
        vector_store=InMemoryVectorStore(),
        embedding_provider=TFIDFEmbeddingProvider(),
        top_k=top_k,
    )

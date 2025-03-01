"""
Embedding provider abstractions for the RAG knowledge base.

Provides a pure-Python TF-IDF fallback that works without any ML libraries,
plus an OpenAI provider backed by LangChain (lazy import).
"""

from __future__ import annotations

import math
import re
from abc import ABC, abstractmethod
from collections import Counter
from typing import Dict, List, Optional


class EmbeddingProvider(ABC):
    """Abstract base class for embedding providers."""

    @abstractmethod
    def embed_text(self, text: str) -> List[float]:
        """Return an embedding vector for *text*, updating any internal vocabulary."""

    def embed_query(self, text: str) -> List[float]:
        """
        Return an embedding vector for *text* without updating internal vocabulary.

        Override in subclasses that maintain a vocabulary (e.g. TF-IDF) so that
        retrieval queries share the same dimension as stored document embeddings.
        The default implementation delegates to :meth:`embed_text`.
        """
        return self.embed_text(text)

    @abstractmethod
    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Return unit-length embedding vectors for each text in *texts*."""


# ---------------------------------------------------------------------------
# Pure-Python TF-IDF provider
# ---------------------------------------------------------------------------

def _tokenize(text: str) -> List[str]:
    """Lowercase, strip punctuation, return word tokens."""
    return re.findall(r"[a-z0-9]+", text.lower())


def _normalize(vec: List[float]) -> List[float]:
    """Return a unit-length copy of *vec* (L2 normalisation)."""
    magnitude = math.sqrt(sum(v * v for v in vec))
    if magnitude == 0.0:
        return vec[:]
    return [v / magnitude for v in vec]


class TFIDFEmbeddingProvider(EmbeddingProvider):
    """
    Pure-Python TF-IDF embedding provider.

    Builds a vocabulary incrementally from ingested text.  For unseen terms
    the embedding dimension is zero-filled.  The output dimension is
    ``min(1000, vocab_size)`` using the top-IDF terms.

    No external ML libraries are required — this is intentional so the RAG
    engine can run in environments without scikit-learn / numpy.
    """

    MAX_DIM: int = 1000

    def __init__(self) -> None:
        # document frequency: term → number of documents that contain it
        self._df: Dict[str, int] = {}
        # total number of documents seen so far
        self._n_docs: int = 0
        # ordered vocabulary (top-IDF terms, rebuilt lazily)
        self._vocab: Optional[List[str]] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def embed_text(self, text: str) -> List[float]:
        """
        Embed a single text string, updating the vocabulary.

        Use :meth:`embed_query` when you want to embed a query against
        the *existing* vocabulary without modifying it (e.g. at retrieval
        time, to avoid dimension drift).
        """
        return self._tfidf_vector(text, update=True)

    def embed_query(self, text: str) -> List[float]:
        """
        Embed *text* using the **current** vocabulary without updating it.

        This is the correct method to use at retrieval time so that the
        query vector has the same dimension and term order as the stored
        document embeddings.
        """
        return self._tfidf_vector(text, update=False)

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Embed a list of text strings (updates vocabulary for each)."""
        # Two passes: first update DF counts, then compute vectors so that
        # all texts share the same final vocabulary.
        for text in texts:
            self._update_df(text)
        self._vocab = None  # invalidate cached vocab
        return [self._tfidf_vector(text, update=False) for text in texts]

    def update_vocabulary(self, text: str) -> None:
        """Explicitly add *text* to the vocabulary without returning a vector."""
        self._update_df(text)
        self._vocab = None

    @property
    def vocab_size(self) -> int:
        return len(self._df)

    @property
    def dimension(self) -> int:
        return min(self.MAX_DIM, self.vocab_size)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _update_df(self, text: str) -> None:
        tokens = set(_tokenize(text))
        for token in tokens:
            self._df[token] = self._df.get(token, 0) + 1
        self._n_docs += 1

    def _get_vocab(self) -> List[str]:
        """Return the ordered vocabulary (top-IDF terms, cached)."""
        if self._vocab is not None:
            return self._vocab

        if not self._df:
            self._vocab = []
            return self._vocab

        n = max(self._n_docs, 1)
        idf_scores = {
            term: math.log((n + 1) / (df + 1)) + 1.0
            for term, df in self._df.items()
        }
        sorted_terms = sorted(idf_scores, key=lambda t: idf_scores[t], reverse=True)
        self._vocab = sorted_terms[: self.MAX_DIM]
        return self._vocab

    def _tfidf_vector(self, text: str, update: bool = True) -> List[float]:
        """Compute a normalised TF-IDF vector for *text*."""
        if update:
            self._update_df(text)
            self._vocab = None

        vocab = self._get_vocab()
        if not vocab:
            return []

        tokens = _tokenize(text)
        if not tokens:
            return [0.0] * len(vocab)

        tf = Counter(tokens)
        n_tokens = len(tokens)
        n_docs = max(self._n_docs, 1)

        vec: List[float] = []
        for term in vocab:
            raw_tf = tf.get(term, 0) / n_tokens
            df = self._df.get(term, 0)
            idf = math.log((n_docs + 1) / (df + 1)) + 1.0
            vec.append(raw_tf * idf)

        return _normalize(vec)


# ---------------------------------------------------------------------------
# OpenAI provider (lazy import)
# ---------------------------------------------------------------------------

class OpenAIEmbeddingProvider(EmbeddingProvider):
    """
    LangChain OpenAI embedding provider.

    ``langchain-openai`` is imported lazily so that the rest of the knowledge
    module works even when the package is not installed.
    """

    def __init__(self, model: str = "text-embedding-3-small", **kwargs) -> None:
        self._model = model
        self._kwargs = kwargs
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                from langchain_openai import OpenAIEmbeddings  # noqa: PLC0415
            except ImportError as exc:
                raise ImportError(
                    "langchain-openai is required for OpenAIEmbeddingProvider. "
                    "Install it with: pip install langchain-openai"
                ) from exc
            self._client = OpenAIEmbeddings(model=self._model, **self._kwargs)
        return self._client

    def embed_text(self, text: str) -> List[float]:
        return self._get_client().embed_query(text)

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        return self._get_client().embed_documents(texts)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def get_default_embedding_provider(
    provider: str = "tfidf",
    **kwargs,
) -> EmbeddingProvider:
    """
    Return an embedding provider by name.

    Args:
        provider: ``"tfidf"`` (default, no dependencies) or ``"openai"``.
        **kwargs: Forwarded to the provider constructor.

    Returns:
        An :class:`EmbeddingProvider` instance.
    """
    if provider == "tfidf":
        return TFIDFEmbeddingProvider()
    if provider == "openai":
        return OpenAIEmbeddingProvider(**kwargs)
    raise ValueError(f"Unknown embedding provider: {provider!r}. Choose 'tfidf' or 'openai'.")

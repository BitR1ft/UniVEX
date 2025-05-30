"""
Pure-Python TF-IDF embedding provider — no external dependencies.

Provides ``TFIDFEmbeddingProvider`` compatible with :class:`BaseEmbeddingProvider`
as a zero-dependency fallback that works in any environment.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Dict, List, Optional

from .base import BaseEmbeddingProvider


def _tokenize(text: str) -> List[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


def _normalize(vec: List[float]) -> List[float]:
    mag = math.sqrt(sum(v * v for v in vec))
    if mag == 0.0:
        return vec[:]
    return [v / mag for v in vec]


class TFIDFEmbeddingProvider(BaseEmbeddingProvider):
    """
    Pure-Python TF-IDF embedding provider.

    Builds a vocabulary incrementally from ingested text.  Suitable as a
    zero-dependency fallback when no external provider is available.

    Max vocabulary size: 1000 terms (top by IDF score).
    """

    MAX_DIM: int = 1000

    def __init__(self) -> None:
        self._df: Dict[str, int] = {}
        self._n_docs: int = 0
        self._vocab: Optional[List[str]] = None

    # ------------------------------------------------------------------
    # BaseEmbeddingProvider interface
    # ------------------------------------------------------------------

    @property
    def provider_name(self) -> str:
        return "tfidf"

    @property
    def model_name(self) -> str:
        return "tfidf-internal"

    @property
    def dimensions(self) -> int:
        return min(self.MAX_DIM, len(self._df))

    def embed_text(self, text: str) -> List[float]:
        return self._tfidf_vector(text, update=True)

    def embed_query(self, text: str) -> List[float]:
        return self._tfidf_vector(text, update=False)

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        for text in texts:
            self._update_df(text)
        self._vocab = None
        return [self._tfidf_vector(text, update=False) for text in texts]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _update_df(self, text: str) -> None:
        tokens = set(_tokenize(text))
        for token in tokens:
            self._df[token] = self._df.get(token, 0) + 1
        self._n_docs += 1

    def _get_vocab(self) -> List[str]:
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
        sorted_terms = sorted(
            idf_scores, key=lambda t: idf_scores[t], reverse=True
        )
        self._vocab = sorted_terms[: self.MAX_DIM]
        return self._vocab

    def _tfidf_vector(self, text: str, update: bool = True) -> List[float]:
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


__all__ = ["TFIDFEmbeddingProvider"]

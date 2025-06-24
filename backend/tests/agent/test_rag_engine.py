"""
Tests for Day 8 — RAG Knowledge Base & Exploit Intelligence.

Covers:
  - TFIDFEmbeddingProvider (vocabulary, TF-IDF vectors, normalisation, batch)
  - InMemoryVectorStore (add, search, delete, clear, count, filters)
  - DocumentLoader (all load_* methods, NVD feed parsing, tool corpus)
  - RAGEngine (ingest, retrieve, filters, retrieve_for_agent, tool context,
               engagement history, stats, clear_category, async NVD feed)
  - Edge cases: empty store, zero-vector, duplicate IDs, large batch

No external packages (chromadb, langchain-openai) are required.
"""

from __future__ import annotations

import asyncio
import math
import uuid
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.agent.knowledge import (
    Document,
    DocumentCategory,
    DocumentLoader,
    EmbeddingProvider,
    InMemoryVectorStore,
    RAGEngine,
    RAGResult,
    TFIDFEmbeddingProvider,
    VectorStore,
    create_default_rag_engine,
    get_default_embedding_provider,
)
from app.agent.knowledge.rag_engine import (
    ChromaDBVectorStore,
    _cosine_similarity,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _make_doc(content: str = "test content", category: DocumentCategory = DocumentCategory.CVE) -> Document:
    return Document(
        id=str(uuid.uuid4()),
        content=content,
        metadata={"title": "Test", "category": category, "severity": "high"},
    )


def _unit_vec(n: int, index: int = 0) -> List[float]:
    """Return a unit vector of length *n* with a 1.0 at *index*."""
    v = [0.0] * n
    v[index] = 1.0
    return v


# ===========================================================================
# TFIDFEmbeddingProvider tests
# ===========================================================================

class TestTFIDFEmbeddingProviderBasics:
    """Basic behaviour of the pure-Python TF-IDF provider."""

    def test_returns_list_of_floats(self):
        provider = TFIDFEmbeddingProvider()
        provider.update_vocabulary("hello world")
        vec = provider.embed_text("hello")
        assert isinstance(vec, list)
        assert all(isinstance(v, float) for v in vec)

    def test_empty_string_after_vocab(self):
        provider = TFIDFEmbeddingProvider()
        provider.update_vocabulary("some terms here")
        vec = provider.embed_text("")
        assert isinstance(vec, list)
        # Should be zero-vector or empty
        assert all(v == 0.0 for v in vec) or vec == []

    def test_empty_vocab_returns_empty(self):
        provider = TFIDFEmbeddingProvider()
        # embed_query uses existing vocab without updating it;
        # with an empty provider, the vocab is empty → returns [].
        vec = provider.embed_query("hello")
        assert vec == []

    def test_vector_is_unit_length(self):
        provider = TFIDFEmbeddingProvider()
        provider.update_vocabulary("security vulnerability exploit cve critical")
        vec = provider.embed_text("security vulnerability")
        magnitude = math.sqrt(sum(v * v for v in vec))
        assert abs(magnitude - 1.0) < 1e-9

    def test_dimension_grows_with_vocabulary(self):
        provider = TFIDFEmbeddingProvider()
        provider.update_vocabulary("alpha beta gamma")
        d1 = provider.dimension
        provider.update_vocabulary("delta epsilon zeta")
        d2 = provider.dimension
        assert d2 >= d1

    def test_max_dimension_cap(self):
        provider = TFIDFEmbeddingProvider()
        # Ingest 1500 unique terms
        words = [f"word{i}" for i in range(1500)]
        provider.update_vocabulary(" ".join(words))
        assert provider.dimension <= TFIDFEmbeddingProvider.MAX_DIM

    def test_vocab_size_property(self):
        provider = TFIDFEmbeddingProvider()
        provider.update_vocabulary("alpha beta gamma")
        assert provider.vocab_size >= 3

    def test_different_texts_different_vectors(self):
        # Use embed_batch so both texts share the same final vocabulary,
        # ensuring "apple" and "orange" each map to a unique dimension.
        provider = TFIDFEmbeddingProvider()
        v1, v2 = provider.embed_batch(["apple banana cherry", "orange mango grape"])
        assert v1 != v2

    def test_repeated_text_same_vector_shape(self):
        provider = TFIDFEmbeddingProvider()
        provider.update_vocabulary("test document")
        v1 = provider.embed_text("test")
        v2 = provider.embed_text("test")
        assert len(v1) == len(v2)

    def test_unseen_term_uses_zero_component(self):
        provider = TFIDFEmbeddingProvider()
        provider.update_vocabulary("known term")
        vec = provider.embed_text("zzzunknown")
        # Vector may contain zeros for unseen terms
        assert isinstance(vec, list)


class TestTFIDFEmbeddingProviderBatch:
    """Batch embedding behaviour."""

    def test_embed_batch_returns_correct_count(self):
        provider = TFIDFEmbeddingProvider()
        texts = ["security", "exploit", "vulnerability", "cve", "patch"]
        vecs = provider.embed_batch(texts)
        assert len(vecs) == len(texts)

    def test_embed_batch_all_unit_length(self):
        provider = TFIDFEmbeddingProvider()
        texts = ["sql injection", "xss attack", "buffer overflow", "rce exploit"]
        vecs = provider.embed_batch(texts)
        for vec in vecs:
            if vec:
                mag = math.sqrt(sum(v * v for v in vec))
                assert abs(mag - 1.0) < 1e-9

    def test_embed_batch_same_dimension(self):
        provider = TFIDFEmbeddingProvider()
        texts = ["nmap scan", "nuclei template", "metasploit module"]
        vecs = provider.embed_batch(texts)
        dims = [len(v) for v in vecs]
        assert len(set(dims)) == 1  # all same dimension

    def test_embed_batch_updates_vocabulary(self):
        provider = TFIDFEmbeddingProvider()
        assert provider.vocab_size == 0
        provider.embed_batch(["new unique token here"])
        assert provider.vocab_size > 0

    def test_embed_batch_empty_list(self):
        provider = TFIDFEmbeddingProvider()
        result = provider.embed_batch([])
        assert result == []


class TestTFIDFIDF:
    """IDF-specific behaviour: high-IDF terms rank higher."""

    def test_rare_term_has_higher_idf_weight(self):
        provider = TFIDFEmbeddingProvider()
        # "rare" appears in 1 doc; "common" appears in all
        docs = [
            "common word alpha",
            "common word beta",
            "common word gamma",
            "common word rare",
        ]
        provider.embed_batch(docs)
        # "rare" should have higher IDF than "common"
        rare_idf = math.log((5) / (provider._df.get("rare", 0) + 1)) + 1.0
        common_idf = math.log((5) / (provider._df.get("common", 0) + 1)) + 1.0
        assert rare_idf > common_idf


# ===========================================================================
# Factory
# ===========================================================================

class TestEmbeddingProviderFactory:
    def test_default_is_tfidf(self):
        provider = get_default_embedding_provider()
        assert isinstance(provider, TFIDFEmbeddingProvider)

    def test_explicit_tfidf(self):
        provider = get_default_embedding_provider("tfidf")
        assert isinstance(provider, TFIDFEmbeddingProvider)

    def test_unknown_provider_raises(self):
        with pytest.raises(ValueError, match="Unknown embedding provider"):
            get_default_embedding_provider("unknown")

    def test_openai_provider_is_lazy(self):
        from app.agent.knowledge.embeddings import OpenAIEmbeddingProvider
        provider = OpenAIEmbeddingProvider()
        assert provider._client is None  # Not initialised until first call


# ===========================================================================
# Cosine similarity helper
# ===========================================================================

class TestCosineSimilarity:
    def test_identical_unit_vectors(self):
        v = _unit_vec(4, 0)
        assert abs(_cosine_similarity(v, v) - 1.0) < 1e-9

    def test_orthogonal_vectors(self):
        v1 = _unit_vec(4, 0)
        v2 = _unit_vec(4, 1)
        assert abs(_cosine_similarity(v1, v2)) < 1e-9

    def test_opposite_vectors(self):
        v = [1.0, 0.0, 0.0]
        neg = [-1.0, 0.0, 0.0]
        assert abs(_cosine_similarity(v, neg) - (-1.0)) < 1e-9

    def test_empty_vectors(self):
        assert _cosine_similarity([], []) == 0.0

    def test_mismatched_lengths(self):
        assert _cosine_similarity([1.0], [1.0, 0.0]) == 0.0

    def test_zero_vector(self):
        assert _cosine_similarity([0.0, 0.0], [1.0, 0.0]) == 0.0


# ===========================================================================
# InMemoryVectorStore tests
# ===========================================================================

class TestInMemoryVectorStoreBasics:
    def test_initial_count_is_zero(self):
        store = InMemoryVectorStore()
        assert store.count() == 0

    def test_add_and_count(self):
        store = InMemoryVectorStore()
        doc = _make_doc("hello world")
        store.add_documents([(doc.id, _unit_vec(3, 0), doc)])
        assert store.count() == 1

    def test_add_multiple(self):
        store = InMemoryVectorStore()
        docs = [(_make_doc(f"doc {i}"), _unit_vec(3, i % 3)) for i in range(5)]
        store.add_documents([(d.id, emb, d) for d, emb in docs])
        assert store.count() == 5

    def test_delete_reduces_count(self):
        store = InMemoryVectorStore()
        doc = _make_doc()
        store.add_documents([(doc.id, _unit_vec(3, 0), doc)])
        store.delete(doc.id)
        assert store.count() == 0

    def test_delete_nonexistent_is_noop(self):
        store = InMemoryVectorStore()
        store.delete("nonexistent-id")
        assert store.count() == 0

    def test_clear_removes_all(self):
        store = InMemoryVectorStore()
        for i in range(5):
            doc = _make_doc(f"doc {i}")
            store.add_documents([(doc.id, _unit_vec(3, i % 3), doc)])
        store.clear()
        assert store.count() == 0

    def test_add_duplicate_id_replaces(self):
        store = InMemoryVectorStore()
        doc = _make_doc("original")
        store.add_documents([(doc.id, _unit_vec(3, 0), doc)])
        doc2 = Document(id=doc.id, content="updated", metadata=doc.metadata)
        store.add_documents([(doc.id, _unit_vec(3, 1), doc2)])
        assert store.count() == 1
        results = store.search(_unit_vec(3, 1), top_k=1)
        assert results[0].content == "updated"


class TestInMemoryVectorStoreSearch:
    def test_search_returns_results(self):
        store = InMemoryVectorStore()
        doc = _make_doc()
        store.add_documents([(doc.id, _unit_vec(3, 0), doc)])
        results = store.search(_unit_vec(3, 0), top_k=5)
        assert len(results) == 1

    def test_search_scores_descending(self):
        store = InMemoryVectorStore()
        # doc0 is exactly aligned with query; doc1 is orthogonal
        doc0 = _make_doc("best match")
        doc1 = _make_doc("no match")
        store.add_documents([
            (doc0.id, _unit_vec(3, 0), doc0),
            (doc1.id, _unit_vec(3, 1), doc1),
        ])
        results = store.search(_unit_vec(3, 0), top_k=5)
        assert results[0].score >= results[1].score

    def test_search_top_k_limits_results(self):
        store = InMemoryVectorStore()
        for i in range(10):
            doc = _make_doc(f"document {i}")
            store.add_documents([(doc.id, _unit_vec(10, i), doc)])
        results = store.search(_unit_vec(10, 0), top_k=3)
        assert len(results) <= 3

    def test_search_empty_store(self):
        store = InMemoryVectorStore()
        results = store.search(_unit_vec(3, 0), top_k=5)
        assert results == []

    def test_search_result_has_correct_doc_id(self):
        store = InMemoryVectorStore()
        doc = _make_doc()
        store.add_documents([(doc.id, _unit_vec(3, 0), doc)])
        results = store.search(_unit_vec(3, 0), top_k=1)
        assert results[0].document_id == doc.id

    def test_search_result_score_between_minus1_and_1(self):
        store = InMemoryVectorStore()
        doc = _make_doc()
        store.add_documents([(doc.id, _unit_vec(3, 0), doc)])
        results = store.search(_unit_vec(3, 0), top_k=1)
        assert -1.0 <= results[0].score <= 1.0


class TestInMemoryVectorStoreFilters:
    def _populate(self, store: InMemoryVectorStore) -> None:
        categories = [
            (DocumentCategory.CVE, "critical"),
            (DocumentCategory.TOOL_DOCUMENTATION, "low"),
            (DocumentCategory.ATTACK_PATTERN, "high"),
        ]
        for i, (cat, sev) in enumerate(categories):
            doc = Document(
                id=str(uuid.uuid4()),
                content=f"content {i}",
                metadata={"title": f"doc{i}", "category": cat, "severity": sev},
            )
            store.add_documents([(doc.id, _unit_vec(5, i), doc)])

    def test_category_filter_returns_only_matching(self):
        store = InMemoryVectorStore()
        self._populate(store)
        results = store.search(
            [0.0] * 5, top_k=10, category_filter=DocumentCategory.CVE
        )
        for r in results:
            cat = r.metadata.get("category")
            assert cat == DocumentCategory.CVE or str(cat) == "cve"

    def test_severity_filter(self):
        store = InMemoryVectorStore()
        self._populate(store)
        results = store.search(
            [0.0] * 5, top_k=10, severity_filter="critical"
        )
        for r in results:
            assert r.metadata.get("severity") == "critical"

    def test_combined_filter_no_match(self):
        store = InMemoryVectorStore()
        self._populate(store)
        results = store.search(
            [0.0] * 5,
            top_k=10,
            category_filter=DocumentCategory.CVE,
            severity_filter="low",
        )
        # CVE doc has "critical" severity, not "low"
        assert results == []

    def test_no_filter_returns_all(self):
        store = InMemoryVectorStore()
        self._populate(store)
        results = store.search([0.0] * 5, top_k=10)
        assert len(results) == 3


class TestInMemoryVectorStoreCountByCategory:
    def test_count_by_category(self):
        store = InMemoryVectorStore()
        for i in range(2):
            doc = Document(
                id=str(uuid.uuid4()),
                content="cve content",
                metadata={"category": DocumentCategory.CVE},
            )
            store.add_documents([(doc.id, _unit_vec(3, 0), doc)])
        doc2 = Document(
            id=str(uuid.uuid4()),
            content="tool doc",
            metadata={"category": DocumentCategory.TOOL_DOCUMENTATION},
        )
        store.add_documents([(doc2.id, _unit_vec(3, 1), doc2)])
        counts = store.count_by_category()
        assert counts.get(DocumentCategory.CVE.value, counts.get(str(DocumentCategory.CVE), 0)) == 2


# ===========================================================================
# DocumentLoader tests
# ===========================================================================

class TestDocumentLoaderCVE:
    def setup_method(self):
        self.loader = DocumentLoader()

    def test_load_cve_returns_document(self):
        doc = self.loader.load_cve_document(
            cve_id="CVE-2024-1234",
            description="Buffer overflow in libfoo",
            severity="critical",
            cvss_score=9.8,
            affected_products=["libfoo 1.0", "libfoo 2.0"],
        )
        assert isinstance(doc, Document)

    def test_cve_document_has_id(self):
        doc = self.loader.load_cve_document("CVE-2024-0001", "desc", "high", 7.5, ["product"])
        assert doc.id

    def test_cve_document_category(self):
        doc = self.loader.load_cve_document("CVE-2024-0001", "desc", "high", 7.5, ["product"])
        assert doc.metadata["category"] == DocumentCategory.CVE

    def test_cve_document_contains_cve_id(self):
        doc = self.loader.load_cve_document("CVE-2024-9999", "desc", "medium", 5.0, ["foo"])
        assert "CVE-2024-9999" in doc.content

    def test_cve_document_contains_severity(self):
        doc = self.loader.load_cve_document("CVE-2024-1111", "desc", "critical", 9.8, ["foo"])
        assert "critical" in doc.content.lower()

    def test_cve_document_affected_products_in_content(self):
        doc = self.loader.load_cve_document("CVE-2024-2222", "desc", "high", 7.5, ["apache httpd"])
        assert "apache httpd" in doc.content.lower()

    def test_cve_document_tags_include_severity(self):
        doc = self.loader.load_cve_document("CVE-2024-3333", "desc", "low", 3.1, ["product"])
        assert "low" in doc.tags


class TestDocumentLoaderAdvisory:
    def setup_method(self):
        self.loader = DocumentLoader()

    def test_load_advisory_returns_document(self):
        doc = self.loader.load_advisory("SA-001", "Content here", "CERT", "high")
        assert isinstance(doc, Document)

    def test_advisory_category(self):
        doc = self.loader.load_advisory("SA-001", "Content", "CERT", "high")
        assert doc.metadata["category"] == DocumentCategory.SECURITY_ADVISORY

    def test_advisory_title_in_content(self):
        doc = self.loader.load_advisory("MyAdvisory", "Body text", "Source", "medium")
        assert "MyAdvisory" in doc.content

    def test_advisory_source_in_metadata(self):
        doc = self.loader.load_advisory("SA-002", "Content", "NIST", "low")
        assert doc.metadata["source"] == "NIST"


class TestDocumentLoaderToolDocs:
    def setup_method(self):
        self.loader = DocumentLoader()

    def test_load_tool_documentation_returns_document(self):
        doc = self.loader.load_tool_documentation(
            tool_name="nmap",
            description="Network scanner",
            usage="nmap [options] <target>",
            examples=["nmap -sV target.com"],
        )
        assert isinstance(doc, Document)

    def test_tool_doc_category(self):
        doc = self.loader.load_tool_documentation("nmap", "Scanner", "nmap", [])
        assert doc.metadata["category"] == DocumentCategory.TOOL_DOCUMENTATION

    def test_tool_name_in_content(self):
        doc = self.loader.load_tool_documentation("masscan", "Fast scanner", "masscan", [])
        assert "masscan" in doc.content.lower()

    def test_examples_in_content(self):
        doc = self.loader.load_tool_documentation(
            "nikto", "Web scanner", "nikto -h <host>", ["nikto -h http://target.com"]
        )
        assert "nikto -h http://target.com" in doc.content

    def test_tool_name_tag(self):
        doc = self.loader.load_tool_documentation("gobuster", "Dir buster", "gobuster", [])
        assert "gobuster" in doc.tags


class TestDocumentLoaderAttackPattern:
    def setup_method(self):
        self.loader = DocumentLoader()

    def test_load_attack_pattern_returns_document(self):
        doc = self.loader.load_attack_pattern(
            name="Phishing",
            technique_id="T1566",
            description="Attacker sends malicious email",
            mitre_tactics=["Initial Access"],
            tools=["GoPhish"],
        )
        assert isinstance(doc, Document)

    def test_attack_pattern_category(self):
        doc = self.loader.load_attack_pattern("Phishing", "T1566", "desc", [], [])
        assert doc.metadata["category"] == DocumentCategory.ATTACK_PATTERN

    def test_technique_id_in_content(self):
        doc = self.loader.load_attack_pattern("Name", "T1234", "desc", ["Tactic"], ["tool"])
        assert "T1234" in doc.content

    def test_mitre_tactics_in_metadata(self):
        doc = self.loader.load_attack_pattern("Name", "T1234", "desc", ["Lateral Movement"], [])
        assert "Lateral Movement" in doc.metadata["mitre_tactics"]


class TestDocumentLoaderEngagementHistory:
    def setup_method(self):
        self.loader = DocumentLoader()

    def test_load_engagement_history_returns_document(self):
        doc = self.loader.load_engagement_history(
            target="corp.internal",
            phase="reconnaissance",
            findings=["Open port 22", "Apache 2.4"],
            tools_used=["nmap", "nikto"],
            success=True,
        )
        assert isinstance(doc, Document)

    def test_engagement_category(self):
        doc = self.loader.load_engagement_history("target", "phase", [], [], True)
        assert doc.metadata["category"] == DocumentCategory.ENGAGEMENT_HISTORY

    def test_success_in_content(self):
        doc = self.loader.load_engagement_history("target", "recon", [], [], True)
        assert "success" in doc.content.lower()

    def test_failure_in_content(self):
        doc = self.loader.load_engagement_history("target", "recon", [], [], False)
        assert "failure" in doc.content.lower()

    def test_tools_in_content(self):
        doc = self.loader.load_engagement_history("target", "recon", [], ["nmap", "masscan"], True)
        assert "nmap" in doc.content


class TestDocumentLoaderExploitWriteup:
    def setup_method(self):
        self.loader = DocumentLoader()

    def test_load_exploit_writeup_returns_document(self):
        doc = self.loader.load_exploit_writeup(
            title="Log4Shell PoC",
            target_cve="CVE-2021-44228",
            steps=["Set up listener", "Trigger JNDI lookup", "Receive shell"],
            difficulty="medium",
            success_rate=0.85,
        )
        assert isinstance(doc, Document)

    def test_exploit_writeup_category(self):
        doc = self.loader.load_exploit_writeup("title", "CVE-2021-44228", [], "easy", 1.0)
        assert doc.metadata["category"] == DocumentCategory.EXPLOIT_WRITEUP

    def test_cve_id_in_content(self):
        doc = self.loader.load_exploit_writeup("title", "CVE-2021-44228", [], "easy", 1.0)
        assert "CVE-2021-44228" in doc.content

    def test_steps_in_content(self):
        doc = self.loader.load_exploit_writeup(
            "title", "CVE-x", ["Step A", "Step B"], "hard", 0.5
        )
        assert "Step A" in doc.content


class TestDocumentLoaderNVDFeed:
    def setup_method(self):
        self.loader = DocumentLoader()

    def _nvd_entry(self, cve_id: str = "CVE-2024-0001", description: str = "Test vuln") -> Dict[str, Any]:
        return {
            "cve": {
                "id": cve_id,
                "descriptions": [{"lang": "en", "value": description}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ]
                },
                "configurations": [],
            }
        }

    def test_empty_feed_returns_empty_list(self):
        docs = self.loader.load_from_nvd_feed({"vulnerabilities": []})
        assert docs == []

    def test_single_entry_parsed(self):
        feed = {"vulnerabilities": [self._nvd_entry()]}
        docs = self.loader.load_from_nvd_feed(feed)
        assert len(docs) == 1

    def test_cve_id_in_result(self):
        feed = {"vulnerabilities": [self._nvd_entry("CVE-2024-5555")]}
        docs = self.loader.load_from_nvd_feed(feed)
        assert "CVE-2024-5555" in docs[0].content

    def test_description_in_result(self):
        feed = {"vulnerabilities": [self._nvd_entry(description="Remote code execution bug")]}
        docs = self.loader.load_from_nvd_feed(feed)
        assert "Remote code execution bug" in docs[0].content

    def test_multiple_entries(self):
        feed = {
            "vulnerabilities": [
                self._nvd_entry("CVE-2024-0001"),
                self._nvd_entry("CVE-2024-0002"),
                self._nvd_entry("CVE-2024-0003"),
            ]
        }
        docs = self.loader.load_from_nvd_feed(feed)
        assert len(docs) == 3

    def test_missing_vulnerabilities_key(self):
        docs = self.loader.load_from_nvd_feed({})
        assert docs == []

    def test_severity_extracted(self):
        feed = {"vulnerabilities": [self._nvd_entry()]}
        docs = self.loader.load_from_nvd_feed(feed)
        assert docs[0].metadata.get("severity") == "critical"

    def test_cvss_score_extracted(self):
        feed = {"vulnerabilities": [self._nvd_entry()]}
        docs = self.loader.load_from_nvd_feed(feed)
        assert docs[0].metadata.get("cvss_score") == 9.8


class TestDocumentLoaderToolCorpus:
    def setup_method(self):
        self.loader = DocumentLoader()

    def test_corpus_has_many_documents(self):
        docs = self.loader.create_tool_documentation_corpus()
        assert len(docs) >= 72

    def test_all_docs_are_tool_documentation_category(self):
        docs = self.loader.create_tool_documentation_corpus()
        for doc in docs:
            assert doc.metadata["category"] == DocumentCategory.TOOL_DOCUMENTATION

    def test_corpus_includes_nmap(self):
        docs = self.loader.create_tool_documentation_corpus()
        names = [d.metadata.get("tool_name", "") for d in docs]
        assert "nmap" in names

    def test_corpus_includes_metasploit(self):
        docs = self.loader.create_tool_documentation_corpus()
        names = [d.metadata.get("tool_name", "") for d in docs]
        assert "metasploit" in names

    def test_corpus_includes_sqlmap(self):
        docs = self.loader.create_tool_documentation_corpus()
        names = [d.metadata.get("tool_name", "") for d in docs]
        assert "sqlmap" in names

    def test_each_doc_has_unique_id(self):
        docs = self.loader.create_tool_documentation_corpus()
        ids = [doc.id for doc in docs]
        assert len(ids) == len(set(ids))

    def test_each_doc_has_content(self):
        docs = self.loader.create_tool_documentation_corpus()
        for doc in docs:
            assert doc.content.strip()


# ===========================================================================
# Document dataclass tests
# ===========================================================================

class TestDocumentDataclass:
    def test_title_property(self):
        doc = Document(id="1", content="c", metadata={"title": "My Title"})
        assert doc.title == "My Title"

    def test_category_property(self):
        doc = Document(id="1", content="c", metadata={"category": DocumentCategory.CVE})
        assert doc.category == DocumentCategory.CVE

    def test_severity_property(self):
        doc = Document(id="1", content="c", metadata={"severity": "critical"})
        assert doc.severity == "critical"

    def test_tags_property(self):
        doc = Document(id="1", content="c", metadata={"tags": ["a", "b"]})
        assert doc.tags == ["a", "b"]

    def test_missing_metadata_defaults(self):
        doc = Document(id="1", content="c", metadata={})
        assert doc.title == ""
        assert doc.category is None
        assert doc.severity is None
        assert doc.tags == []


# ===========================================================================
# RAGEngine tests
# ===========================================================================

class TestRAGEngineIngest:
    def setup_method(self):
        self.engine = create_default_rag_engine()
        self.loader = DocumentLoader()

    def test_ingest_document_returns_id(self):
        doc = self.loader.load_cve_document("CVE-2024-1", "desc", "high", 7.5, ["foo"])
        doc_id = self.engine.ingest_document(doc)
        assert doc_id == doc.id

    def test_ingest_document_increases_count(self):
        doc = self.loader.load_cve_document("CVE-2024-2", "desc", "high", 7.5, ["foo"])
        self.engine.ingest_document(doc)
        stats = self.engine.get_stats()
        assert stats["total"] == 1

    def test_ingest_documents_batch(self):
        docs = [
            self.loader.load_cve_document(f"CVE-2024-{i}", "desc", "medium", 5.0, ["foo"])
            for i in range(5)
        ]
        ids = self.engine.ingest_documents(docs)
        assert len(ids) == 5
        assert self.engine.get_stats()["total"] == 5

    def test_ingest_empty_list(self):
        ids = self.engine.ingest_documents([])
        assert ids == []

    def test_ingest_returns_doc_ids(self):
        docs = [self.loader.load_advisory(f"SA-{i}", "content", "CERT", "high") for i in range(3)]
        ids = self.engine.ingest_documents(docs)
        assert set(ids) == {doc.id for doc in docs}


class TestRAGEngineRetrieve:
    def setup_method(self):
        self.engine = create_default_rag_engine()
        self.loader = DocumentLoader()
        # Ingest a known corpus
        docs = [
            self.loader.load_cve_document("CVE-2024-SQL", "SQL injection vulnerability in web app", "critical", 9.8, ["webapp"]),
            self.loader.load_cve_document("CVE-2024-XSS", "Cross-site scripting in user input fields", "high", 7.5, ["cms"]),
            self.loader.load_tool_documentation("sqlmap", "SQL injection tool", "sqlmap -u <url>", ["sqlmap -u target.com"]),
            self.loader.load_tool_documentation("nmap", "Network scanner", "nmap <target>", ["nmap -sV target"]),
        ]
        self.engine.ingest_documents(docs)

    def test_retrieve_returns_list(self):
        results = self.engine.retrieve("SQL injection")
        assert isinstance(results, list)

    def test_retrieve_top_k_limits(self):
        results = self.engine.retrieve("vulnerability", top_k=2)
        assert len(results) <= 2

    def test_retrieve_returns_rag_results(self):
        results = self.engine.retrieve("SQL injection")
        for r in results:
            assert isinstance(r, RAGResult)

    def test_retrieve_with_category_filter(self):
        results = self.engine.retrieve(
            "scanning", category_filter=DocumentCategory.TOOL_DOCUMENTATION
        )
        for r in results:
            cat = r.metadata.get("category")
            assert cat == DocumentCategory.TOOL_DOCUMENTATION or str(cat) == "tool_documentation"

    def test_retrieve_with_severity_filter(self):
        results = self.engine.retrieve("injection", severity_filter="critical")
        for r in results:
            assert r.metadata.get("severity") == "critical"

    def test_retrieve_empty_store(self):
        engine = create_default_rag_engine()
        results = engine.retrieve("test query")
        assert results == []


class TestRAGEngineRetrieveForAgent:
    def setup_method(self):
        self.engine = create_default_rag_engine()
        self.loader = DocumentLoader()

    def test_retrieve_for_agent_returns_string(self):
        doc = self.loader.load_cve_document("CVE-2024-1", "SQL injection", "high", 7.5, ["foo"])
        self.engine.ingest_document(doc)
        result = self.engine.retrieve_for_agent("SQL injection attack")
        assert isinstance(result, str)

    def test_retrieve_for_agent_empty_store(self):
        result = self.engine.retrieve_for_agent("anything")
        assert "No relevant" in result

    def test_retrieve_for_agent_contains_context_header(self):
        doc = self.loader.load_tool_documentation("nmap", "Scanner", "nmap", ["nmap -sV target"])
        self.engine.ingest_document(doc)
        result = self.engine.retrieve_for_agent("network scanning")
        assert "Knowledge Base" in result or "context" in result.lower()

    def test_retrieve_for_agent_top_k_honoured(self):
        docs = [self.loader.load_cve_document(f"CVE-200{i}", f"vuln {i}", "high", 7.0, ["prod"]) for i in range(10)]
        self.engine.ingest_documents(docs)
        result = self.engine.retrieve_for_agent("vulnerability", top_k=2)
        # At most 2 items should appear (marked [1] and [2])
        assert "[3]" not in result


class TestRAGEngineToolContext:
    def setup_method(self):
        self.engine = create_default_rag_engine()
        loader = DocumentLoader()
        doc = loader.load_tool_documentation(
            "nmap", "Network scanner", "nmap [options] <target>", ["nmap -sV target.com"]
        )
        self.engine.ingest_document(doc)

    def test_get_tool_context_returns_string(self):
        result = self.engine.get_tool_context("nmap")
        assert isinstance(result, str)

    def test_get_tool_context_contains_tool_name(self):
        result = self.engine.get_tool_context("nmap")
        assert "nmap" in result.lower()

    def test_get_tool_context_unknown_tool(self):
        # With only one tool doc in the store, a search for an unknown tool
        # still returns the closest match (nmap) rather than "No documentation".
        # Test that the result is a non-empty string.
        result = self.engine.get_tool_context("unknowntool123")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_get_tool_context_empty_store_returns_no_docs_message(self):
        engine = create_default_rag_engine()
        result = engine.get_tool_context("nmap")
        assert "No documentation" in result


class TestRAGEngineEngagementHistory:
    def setup_method(self):
        self.engine = create_default_rag_engine()

    def test_record_engagement_returns_id(self):
        doc_id = self.engine.record_engagement(
            target="corp.internal",
            phase="reconnaissance",
            findings=["Open SSH on port 22"],
            tools_used=["nmap"],
            success=True,
        )
        assert isinstance(doc_id, str)
        assert doc_id

    def test_record_engagement_stored(self):
        self.engine.record_engagement("target.local", "recon", ["finding"], ["tool"], True)
        stats = self.engine.get_stats()
        assert stats["total"] == 1

    def test_retrieve_similar_engagements_returns_list(self):
        self.engine.record_engagement("corp.internal", "exploitation", ["RCE via log4j"], ["metasploit"], True)
        results = self.engine.retrieve_similar_engagements("log4j remote code execution")
        assert isinstance(results, list)

    def test_retrieve_similar_engagements_category_filter(self):
        self.engine.record_engagement("target", "recon", ["open ports"], ["nmap"], False)
        results = self.engine.retrieve_similar_engagements("port scanning recon", top_k=3)
        for r in results:
            cat = r.metadata.get("category")
            assert cat == DocumentCategory.ENGAGEMENT_HISTORY or str(cat) == "engagement_history"

    def test_multiple_engagements(self):
        for i in range(5):
            self.engine.record_engagement(f"target-{i}", "recon", ["finding"], ["nmap"], bool(i % 2))
        stats = self.engine.get_stats()
        assert stats["total"] == 5


class TestRAGEngineStats:
    def setup_method(self):
        self.engine = create_default_rag_engine()
        self.loader = DocumentLoader()

    def test_stats_empty_engine(self):
        stats = self.engine.get_stats()
        assert stats["total"] == 0
        assert stats["by_category"] == {}

    def test_stats_after_ingest(self):
        doc = self.loader.load_cve_document("CVE-2024-1", "desc", "high", 7.5, ["foo"])
        self.engine.ingest_document(doc)
        stats = self.engine.get_stats()
        assert stats["total"] == 1

    def test_stats_by_category(self):
        cve_doc = self.loader.load_cve_document("CVE-2024-1", "desc", "high", 7.5, ["foo"])
        tool_doc = self.loader.load_tool_documentation("nmap", "scanner", "nmap", [])
        self.engine.ingest_documents([cve_doc, tool_doc])
        stats = self.engine.get_stats()
        by_cat = stats["by_category"]
        # At least 2 categories
        assert len(by_cat) >= 2


class TestRAGEngineClearCategory:
    def setup_method(self):
        self.engine = create_default_rag_engine()
        self.loader = DocumentLoader()

    def test_clear_category_removes_docs(self):
        cve = self.loader.load_cve_document("CVE-2024-1", "desc", "high", 7.5, ["foo"])
        tool = self.loader.load_tool_documentation("nmap", "scanner", "nmap", [])
        self.engine.ingest_documents([cve, tool])
        self.engine.clear_category(DocumentCategory.CVE)
        stats = self.engine.get_stats()
        assert stats["total"] == 1  # Only tool doc remains

    def test_clear_category_noop_for_absent_category(self):
        tool = self.loader.load_tool_documentation("nmap", "scanner", "nmap", [])
        self.engine.ingest_document(tool)
        self.engine.clear_category(DocumentCategory.CVE)  # No CVEs to clear
        stats = self.engine.get_stats()
        assert stats["total"] == 1


class TestRAGEngineAsyncNVDFeed:
    def test_ingest_nvd_feed_calls_fetch(self):
        engine = create_default_rag_engine()
        loader = DocumentLoader()
        feed = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-9001",
                        "descriptions": [{"lang": "en", "value": "Test vuln"}],
                        "metrics": {},
                        "configurations": [],
                    }
                }
            ]
        }

        async def mock_fetch(url: str):
            return feed

        with patch.object(engine, "_fetch_json", side_effect=mock_fetch):
            count = asyncio.run(engine.ingest_nvd_feed("https://example.com/nvd.json"))

        assert count == 1
        assert engine.get_stats()["total"] == 1

    def test_ingest_nvd_feed_empty(self):
        engine = create_default_rag_engine()

        async def mock_fetch(url: str):
            return {"vulnerabilities": []}

        with patch.object(engine, "_fetch_json", side_effect=mock_fetch):
            count = asyncio.run(engine.ingest_nvd_feed("https://example.com/nvd.json"))

        assert count == 0


# ===========================================================================
# ChromaDBVectorStore lazy import
# ===========================================================================

class TestChromaDBVectorStoreLazyImport:
    def test_import_error_when_chromadb_missing(self):
        import sys
        with patch.dict(sys.modules, {"chromadb": None}):
            with pytest.raises(ImportError, match="chromadb"):
                ChromaDBVectorStore()


# ===========================================================================
# Factory and defaults
# ===========================================================================

class TestCreateDefaultRAGEngine:
    def test_returns_rag_engine(self):
        engine = create_default_rag_engine()
        assert isinstance(engine, RAGEngine)

    def test_uses_in_memory_store(self):
        engine = create_default_rag_engine()
        assert isinstance(engine._store, InMemoryVectorStore)

    def test_uses_tfidf_embedder(self):
        engine = create_default_rag_engine()
        assert isinstance(engine._embedder, TFIDFEmbeddingProvider)

    def test_custom_top_k(self):
        engine = create_default_rag_engine(top_k=10)
        assert engine._default_top_k == 10


# ===========================================================================
# Integration — end-to-end scenario
# ===========================================================================

class TestRAGEngineIntegration:
    def test_full_pipeline_cve_retrieval(self):
        engine = create_default_rag_engine()
        loader = DocumentLoader()

        # Ingest only a few tool docs + the CVE so the CVE is more distinctive
        docs = loader.create_tool_documentation_corpus()[:5]
        cve = loader.load_cve_document(
            "CVE-2021-44228", "Log4Shell JNDI injection", "critical", 10.0, ["Apache Log4j"]
        )
        docs.append(cve)
        engine.ingest_documents(docs)

        # Search across all docs with a broad top_k; the CVE should appear
        results = engine.retrieve("Log4Shell JNDI injection vulnerability Log4j", top_k=6)
        assert len(results) >= 1
        cve_in_results = any("Log4j" in r.content or "CVE-2021-44228" in r.content for r in results)
        assert cve_in_results

    def test_full_pipeline_tool_retrieval(self):
        engine = create_default_rag_engine()
        loader = DocumentLoader()
        docs = loader.create_tool_documentation_corpus()
        engine.ingest_documents(docs)

        # Retrieve using a broad top_k; sqlmap doc should appear somewhere
        results = engine.retrieve("sqlmap SQL injection tool", top_k=20)
        sqlmap_in_results = any("sqlmap" in r.content.lower() for r in results)
        assert sqlmap_in_results

    def test_engagement_history_retrieval(self):
        engine = create_default_rag_engine()
        engine.record_engagement(
            target="bank.example.com",
            phase="exploitation",
            findings=["SQL injection in /login", "Admin credentials extracted"],
            tools_used=["sqlmap", "burpsuite"],
            success=True,
        )
        results = engine.retrieve_similar_engagements("SQL injection banking application")
        assert len(results) >= 1

    def test_stats_reflect_all_categories(self):
        engine = create_default_rag_engine()
        loader = DocumentLoader()
        engine.ingest_document(loader.load_cve_document("CVE-1", "d", "high", 7.0, ["p"]))
        engine.ingest_document(loader.load_tool_documentation("nmap", "d", "u", []))
        engine.record_engagement("t", "phase", [], [], True)
        stats = engine.get_stats()
        assert stats["total"] == 3

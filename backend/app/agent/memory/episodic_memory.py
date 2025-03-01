"""
EpisodicMemoryStore — Persistent Episodic Memory for Agent Sessions

Persists successful attack patterns, tool results, and agent decisions per
pentest session.  Future sessions can query historical successes by:
  - Target type  (web, api, network, ad, cloud, …)
  - CVE identifier
  - MITRE ATT&CK technique (T-code)
  - Tool name
  - Memory type  (answer | memory | guide | code)

Storage backend: in-memory dict (swap for Redis / ChromaDB / pgvector in prod).
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# MemoryType — matching PentAGI memory type filtering
# ---------------------------------------------------------------------------


class MemoryType(str, Enum):
    """Semantic category of a memory entry (mirrors PentAGI convention)."""
    ANSWER = "answer"    # Factual answer from a tool or agent response
    MEMORY = "memory"    # Episodic / contextual recollection
    GUIDE = "guide"      # Step-by-step guidance, playbook excerpts
    CODE = "code"        # Exploit code, scripts, payloads


# ---------------------------------------------------------------------------
# MemoryEntry
# ---------------------------------------------------------------------------


@dataclass
class MemoryEntry:
    """
    A single episodic memory record.

    Attributes:
        entry_id       – Deterministic SHA-256 hex digest (8 chars).
        flow_id        – Pentest campaign / flow identifier.
        session_id     – Individual session within the flow.
        agent_role     – Name of the agent that created this entry.
        memory_type    – Semantic category (MemoryType).
        content        – Free-form text content of the memory.
        target_type    – Target category: web | api | network | ad | cloud.
        cve            – Associated CVE identifier (optional).
        technique      – MITRE ATT&CK technique T-code (optional).
        tool_name      – Tool that produced this result (optional).
        tags           – Additional metadata tags.
        score          – Relevance / confidence score (0.0 – 1.0).
        created_at     – Unix timestamp.
    """

    flow_id: str
    session_id: str
    agent_role: str
    memory_type: MemoryType
    content: str
    target_type: str = "web"
    cve: Optional[str] = None
    technique: Optional[str] = None
    tool_name: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    score: float = 1.0
    created_at: float = field(default_factory=time.time)
    entry_id: str = field(init=False)

    def __post_init__(self) -> None:
        # Deterministic ID from content + flow_id + session_id
        raw = f"{self.flow_id}:{self.session_id}:{self.content}"
        self.entry_id = hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["memory_type"] = self.memory_type.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MemoryEntry":
        data = dict(data)
        data["memory_type"] = MemoryType(data["memory_type"])
        # Remove computed field before construction
        data.pop("entry_id", None)
        return cls(**data)


# ---------------------------------------------------------------------------
# EpisodicMemoryStore
# ---------------------------------------------------------------------------


class EpisodicMemoryStore:
    """
    In-process episodic memory store for agent sessions.

    Features:
    - Write memory entries via ``capture()``
    - Query by CVE, target type, technique, tool, or memory type via ``query()``
    - Namespace isolation per ``flow_id`` via ``for_flow()``
    - Retrieve recent memories via ``recent()``
    - Bulk export / import via ``export()`` / ``import_entries()``

    In production, replace the internal ``_store`` dict with a ChromaDB or
    pgvector backed implementation — the public API remains identical.
    """

    def __init__(self, max_entries_per_flow: int = 10_000) -> None:
        self._max = max_entries_per_flow
        # Nested storage: flow_id → list of MemoryEntry
        self._store: Dict[str, List[MemoryEntry]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def capture(self, entry: MemoryEntry) -> MemoryEntry:
        """
        Persist a new episodic memory entry.

        Deduplicates by ``entry_id`` within the same flow.
        Evicts oldest entry when the per-flow cap is reached.
        """
        flow_entries = self._store[entry.flow_id]
        # Deduplication
        existing_ids = {e.entry_id for e in flow_entries}
        if entry.entry_id in existing_ids:
            logger.debug("Memory %s already captured — skipping", entry.entry_id)
            return entry

        # Eviction
        if len(flow_entries) >= self._max:
            flow_entries.sort(key=lambda e: e.created_at)
            evicted = flow_entries.pop(0)
            logger.debug("Evicted oldest memory entry %s", evicted.entry_id)

        flow_entries.append(entry)
        logger.debug(
            "Captured memory %s (type=%s, flow=%s)",
            entry.entry_id, entry.memory_type.value, entry.flow_id,
        )
        return entry

    def capture_many(self, entries: Sequence[MemoryEntry]) -> List[MemoryEntry]:
        """Batch-capture multiple entries, returning all successfully stored."""
        return [self.capture(e) for e in entries]

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def query(
        self,
        flow_id: Optional[str] = None,
        *,
        target_type: Optional[str] = None,
        cve: Optional[str] = None,
        technique: Optional[str] = None,
        tool_name: Optional[str] = None,
        memory_type: Optional[MemoryType] = None,
        agent_role: Optional[str] = None,
        tags: Optional[List[str]] = None,
        min_score: float = 0.0,
        limit: int = 50,
    ) -> List[MemoryEntry]:
        """
        Return memory entries matching all supplied filters.

        Pass ``flow_id=None`` to search across all flows.
        Results are sorted by descending ``score`` then descending ``created_at``.
        """
        # Select candidate pool
        if flow_id is not None:
            candidates: List[MemoryEntry] = list(self._store.get(flow_id, []))
        else:
            candidates = [e for entries in self._store.values() for e in entries]

        # Apply filters
        def _matches(entry: MemoryEntry) -> bool:
            if target_type and entry.target_type != target_type:
                return False
            if cve and entry.cve != cve:
                return False
            if technique and entry.technique != technique:
                return False
            if tool_name and entry.tool_name != tool_name:
                return False
            if memory_type and entry.memory_type != memory_type:
                return False
            if agent_role and entry.agent_role != agent_role:
                return False
            if tags and not all(t in entry.tags for t in tags):
                return False
            if entry.score < min_score:
                return False
            return True

        results = [e for e in candidates if _matches(e)]
        results.sort(key=lambda e: (-e.score, -e.created_at))
        return results[:limit]

    def recent(
        self,
        flow_id: str,
        n: int = 10,
        memory_type: Optional[MemoryType] = None,
    ) -> List[MemoryEntry]:
        """Return the *n* most recent entries for a flow, optionally filtered by type."""
        entries = self._store.get(flow_id, [])
        if memory_type:
            entries = [e for e in entries if e.memory_type == memory_type]
        return sorted(entries, key=lambda e: -e.created_at)[:n]

    def get(self, entry_id: str, flow_id: str) -> Optional[MemoryEntry]:
        """Retrieve a specific entry by ID within a flow."""
        for entry in self._store.get(flow_id, []):
            if entry.entry_id == entry_id:
                return entry
        return None

    # ------------------------------------------------------------------
    # Namespace helper
    # ------------------------------------------------------------------

    def for_flow(self, flow_id: str) -> "_FlowView":
        """Return a scoped view of this store restricted to ``flow_id``."""
        return _FlowView(self, flow_id)

    # ------------------------------------------------------------------
    # Stats & export
    # ------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        """Return summary statistics across all flows."""
        total = sum(len(v) for v in self._store.values())
        by_type: Dict[str, int] = defaultdict(int)
        for entries in self._store.values():
            for e in entries:
                by_type[e.memory_type.value] += 1
        return {
            "total_entries": total,
            "flow_count": len(self._store),
            "by_type": dict(by_type),
            "max_entries_per_flow": self._max,
        }

    def export(self, flow_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Export all entries (or a specific flow) as JSON-serialisable dicts."""
        if flow_id is not None:
            entries = self._store.get(flow_id, [])
        else:
            entries = [e for v in self._store.values() for e in v]
        return [e.to_dict() for e in entries]

    def import_entries(self, data: List[Dict[str, Any]]) -> int:
        """Import entries from a list of dicts (as produced by ``export()``)."""
        count = 0
        for item in data:
            entry = MemoryEntry.from_dict(item)
            self.capture(entry)
            count += 1
        return count

    def clear_flow(self, flow_id: str) -> int:
        """Remove all entries for a flow. Returns the number of entries removed."""
        removed = len(self._store.get(flow_id, []))
        self._store.pop(flow_id, None)
        return removed

    def clear_all(self) -> None:
        """Wipe the entire memory store."""
        self._store.clear()


# ---------------------------------------------------------------------------
# _FlowView — scoped proxy
# ---------------------------------------------------------------------------


class _FlowView:
    """
    A flow-scoped proxy around EpisodicMemoryStore.

    All operations are automatically scoped to the ``flow_id`` this view
    was created for.
    """

    def __init__(self, store: EpisodicMemoryStore, flow_id: str) -> None:
        self._store = store
        self.flow_id = flow_id

    def capture(
        self,
        *,
        session_id: str,
        agent_role: str,
        memory_type: MemoryType,
        content: str,
        **kwargs: Any,
    ) -> MemoryEntry:
        entry = MemoryEntry(
            flow_id=self.flow_id,
            session_id=session_id,
            agent_role=agent_role,
            memory_type=memory_type,
            content=content,
            **kwargs,
        )
        return self._store.capture(entry)

    def query(self, **kwargs: Any) -> List[MemoryEntry]:
        return self._store.query(self.flow_id, **kwargs)

    def recent(self, n: int = 10, memory_type: Optional[MemoryType] = None) -> List[MemoryEntry]:
        return self._store.recent(self.flow_id, n=n, memory_type=memory_type)

    def stats(self) -> Dict[str, Any]:
        entries = self._store._store.get(self.flow_id, [])
        by_type: Dict[str, int] = defaultdict(int)
        for e in entries:
            by_type[e.memory_type.value] += 1
        return {
            "flow_id": self.flow_id,
            "total_entries": len(entries),
            "by_type": dict(by_type),
        }

    def clear(self) -> int:
        return self._store.clear_flow(self.flow_id)

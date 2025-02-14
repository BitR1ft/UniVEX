"""
CWE-CAPEC Mapping Service

Builds and queries the bidirectional relationship graph between CWE
weakness entries and CAPEC attack patterns.

Features
--------
- CWE → CAPEC mapping: given a CWE, find all attack patterns that
  exploit that weakness.
- CAPEC → CWE mapping: given an attack pattern, find all weaknesses it
  targets.
- Attack pattern enrichment: add attack-pattern context to Findings.
- Graph summary statistics.

Usage::

    mapper = CWECAPECMapper(cwe_svc, capec_svc)
    await mapper.build()

    attacks = mapper.attacks_for_cwe("CWE-89")
    # [CAPECEntry(id="CAPEC-66", name="SQL Injection"), ...]

    weaknesses = mapper.weaknesses_for_capec("CAPEC-66")
    # [CWEEntry(id="CWE-89", name="SQL Injection"), ...]
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CWECAPECMapper
# ---------------------------------------------------------------------------

class CWECAPECMapper:
    """
    Bidirectional CWE ↔ CAPEC relationship mapper.

    The mapping graph is built by cross-referencing the CAPEC entries'
    ``related_cwe_ids`` lists and the CWE entries' ``capec_ids`` lists.
    Both directions are indexed at build time for O(1) lookup.
    """

    def __init__(self, cwe_service: Any, capec_service: Any) -> None:
        self._cwe = cwe_service
        self._capec = capec_service
        # Forward: CWE-id → [CAPEC-id, ...]
        self._cwe_to_capec: Dict[str, List[str]] = {}
        # Reverse: CAPEC-id → [CWE-id, ...]
        self._capec_to_cwe: Dict[str, List[str]] = {}
        self._built = False

    async def build(self) -> None:
        """
        Populate the mapping graph from the loaded CWE and CAPEC services.

        Must be called after both services have loaded their data.
        """
        if not self._cwe.is_loaded():
            await self._cwe.load()
        if not self._capec.is_loaded():
            await self._capec.load()

        # Build from CAPEC side (primary authority for CWE relationships)
        for capec_entry in self._capec.all():
            for cwe_id in capec_entry.related_cwe_ids:
                self._cwe_to_capec.setdefault(cwe_id, [])
                if capec_entry.id not in self._cwe_to_capec[cwe_id]:
                    self._cwe_to_capec[cwe_id].append(capec_entry.id)

                self._capec_to_cwe.setdefault(capec_entry.id, [])
                if cwe_id not in self._capec_to_cwe[capec_entry.id]:
                    self._capec_to_cwe[capec_entry.id].append(cwe_id)

        # Also build from CWE side (captures relationships CWE declares)
        for cwe_entry in self._cwe.all():
            for capec_id in cwe_entry.capec_ids:
                self._cwe_to_capec.setdefault(cwe_entry.id, [])
                if capec_id not in self._cwe_to_capec[cwe_entry.id]:
                    self._cwe_to_capec[cwe_entry.id].append(capec_id)

                self._capec_to_cwe.setdefault(capec_id, [])
                if cwe_entry.id not in self._capec_to_cwe[capec_id]:
                    self._capec_to_cwe[capec_id].append(cwe_entry.id)

        self._built = True
        logger.info(
            "CWE-CAPEC mapping built: %d CWE→CAPEC, %d CAPEC→CWE relationships",
            sum(len(v) for v in self._cwe_to_capec.values()),
            sum(len(v) for v in self._capec_to_cwe.values()),
        )

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    def attacks_for_cwe(self, cwe_id: str) -> List[Any]:
        """
        Return all CAPEC attack patterns that target the given CWE.

        Args:
            cwe_id: CWE identifier (e.g. ``"CWE-89"`` or ``"89"``).

        Returns:
            List of :class:`~app.services.cwe_capec.capec_service.CAPECEntry` objects.
        """
        key = _normalise_cwe(cwe_id)
        capec_ids = self._cwe_to_capec.get(key, [])
        return [self._capec.lookup(c) for c in capec_ids if self._capec.lookup(c)]

    def weaknesses_for_capec(self, capec_id: str) -> List[Any]:
        """
        Return all CWE weaknesses targeted by the given CAPEC attack pattern.

        Args:
            capec_id: CAPEC identifier (e.g. ``"CAPEC-66"`` or ``"66"``).

        Returns:
            List of :class:`~app.services.cwe_capec.cwe_service.CWEEntry` objects.
        """
        key = _normalise_capec(capec_id)
        cwe_ids = self._capec_to_cwe.get(key, [])
        return [self._cwe.lookup(c) for c in cwe_ids if self._cwe.lookup(c)]

    # ------------------------------------------------------------------
    # Attack pattern enrichment
    # ------------------------------------------------------------------

    def enrich_with_attack_patterns(self, finding: Any) -> Any:
        """
        Add CAPEC attack pattern metadata to a Finding object.

        For each CWE ID in ``finding.cwe_ids``, the related CAPEC attack
        patterns are looked up and their IDs / names are stored in
        ``finding.extra["attack_patterns"]``.

        Returns the mutated finding (also mutates in-place).
        """
        patterns: List[Dict[str, str]] = []

        for cwe_id in finding.cwe_ids:
            for capec in self.attacks_for_cwe(cwe_id):
                entry = {"id": capec.id, "name": capec.name, "severity": capec.severity or "unknown"}
                if entry not in patterns:
                    patterns.append(entry)

        if patterns:
            finding.extra.setdefault("attack_patterns", [])
            existing_ids = {p["id"] for p in finding.extra["attack_patterns"]}
            for p in patterns:
                if p["id"] not in existing_ids:
                    finding.extra["attack_patterns"].append(p)

        return finding

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        """Return a summary of the mapping graph."""
        return {
            "built": self._built,
            "cwe_with_capec_mappings": len(self._cwe_to_capec),
            "capec_with_cwe_mappings": len(self._capec_to_cwe),
            "total_cwe_to_capec_edges": sum(len(v) for v in self._cwe_to_capec.values()),
            "total_capec_to_cwe_edges": sum(len(v) for v in self._capec_to_cwe.values()),
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalise_cwe(cwe_ref: str) -> str:
    ref = cwe_ref.strip().upper()
    if not ref.startswith("CWE-"):
        return f"CWE-{ref}"
    return ref


def _normalise_capec(capec_ref: str) -> str:
    ref = capec_ref.strip().upper()
    if not ref.startswith("CAPEC-"):
        return f"CAPEC-{ref}"
    return ref

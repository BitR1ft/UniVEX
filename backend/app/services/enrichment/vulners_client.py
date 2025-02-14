"""
Vulners API Client

Implements vulnerability search and exploit availability checking
against the Vulners API (https://vulners.com/api/v3).

Features
--------
- CVE lookup enriched with Vulners bulletin data
- Exploit availability checking (ExploitDB, Metasploit, PoC references)
- Merging of NVD and Vulners data via :func:`~.merge`
- Rate-limited async HTTP calls
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_VULNERS_API_BASE = "https://vulners.com/api/v3"


# ---------------------------------------------------------------------------
# VulnersClient
# ---------------------------------------------------------------------------

class VulnersClient:
    """
    Async HTTP client for the Vulners API.

    An API key is required for most endpoints.  Without a key, only the
    public free-tier endpoints (id lookup) are available.

    Args:
        api_key:     Vulners API key (optional – restricts available endpoints).
        timeout:     Per-request timeout.
        max_retries: Retry count on transient HTTP errors.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: int = 15,
        max_retries: int = 3,
    ) -> None:
        self._api_key = api_key
        self._timeout = timeout
        self._max_retries = max_retries

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def fetch(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Look up a CVE in Vulners and return a dict with exploit metadata.

        The returned dict has the shape expected by
        :func:`~app.services.enrichment.enrichment_service._merge_vulners`:

        .. code-block:: json

            {
              "exploit_count": 3,
              "exploit_refs": ["https://..."],
              "maturity": "proof-of-concept",
              "bulletins": [...]
            }

        Returns ``None`` when no Vulners data is found.
        """
        payload: Dict[str, Any] = {"id": cve_id}
        if self._api_key:
            payload["apiKey"] = self._api_key

        raw = await self._post("id/id/", payload)
        if not raw:
            return None

        return self._parse_vuln_data(cve_id, raw)

    async def search(self, query: str, max_results: int = 20) -> List[Dict[str, Any]]:
        """
        Search Vulners for vulnerabilities matching *query*.

        Args:
            query:       Free-text search string or CVE ID.
            max_results: Maximum number of results to return.

        Returns:
            List of raw Vulners bulletin dicts.
        """
        payload: Dict[str, Any] = {
            "query": query,
            "skip": 0,
            "size": max_results,
        }
        if self._api_key:
            payload["apiKey"] = self._api_key

        raw = await self._post("search/lucene/", payload)
        if not raw:
            return []

        return raw.get("data", {}).get("search", [])

    # ------------------------------------------------------------------
    # HTTP layer
    # ------------------------------------------------------------------

    async def _post(self, path: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Make a retrying POST request to the Vulners API."""
        import httpx

        url = f"{_VULNERS_API_BASE}/{path}"

        for attempt in range(1, self._max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    resp = await client.post(url, json=payload)

                if resp.status_code == 404:
                    return None
                if resp.status_code == 401:
                    logger.warning("Vulners: unauthorised – check API key")
                    return None
                if resp.status_code == 429:
                    await asyncio.sleep(int(resp.headers.get("Retry-After", "10")))
                    continue
                resp.raise_for_status()
                data = resp.json()
                if data.get("result") != "OK":
                    return None
                return data

            except Exception as exc:
                if attempt == self._max_retries:
                    logger.error("Vulners request failed: %s", exc)
                    return None
                await asyncio.sleep(2 ** attempt)

        return None

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_vuln_data(cve_id: str, raw: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract exploit availability and related metadata from a Vulners ID
        response and return the normalised dict used by :func:`_merge_vulners`.
        """
        data = raw.get("data", {})
        documents: List[Dict[str, Any]] = data.get("documents", {})
        if isinstance(documents, dict):
            # Vulners sometimes returns a dict keyed by bulletin ID
            documents = list(documents.values())

        exploit_sources: List[str] = []
        exploit_refs: List[str] = []
        maturity: Optional[str] = None

        exploit_type_map = {
            "exploitdb": "functional",
            "exploit": "proof-of-concept",
            "metasploit": "weaponised",
            "packetstorm": "proof-of-concept",
            "seebug": "proof-of-concept",
        }

        for doc in documents:
            bulletin_type = (doc.get("type") or "").lower()
            bulletin_id = (doc.get("id") or "").lower()
            href = doc.get("href") or doc.get("url") or ""

            matched_level: Optional[str] = None

            # Check type field first (most reliable), then bulletin ID
            for keyword, level in exploit_type_map.items():
                if keyword in bulletin_type:
                    matched_level = level
                    break

            if matched_level is None:
                for keyword, level in exploit_type_map.items():
                    if keyword in bulletin_id:
                        matched_level = level
                        break

            if matched_level is None:
                continue

            if bulletin_id not in exploit_sources:
                exploit_sources.append(bulletin_id)
            if href and href not in exploit_refs:
                exploit_refs.append(href)

            # Upgrade maturity if higher level seen
            _levels = ["proof-of-concept", "functional", "weaponised"]
            current_idx = _levels.index(maturity) if maturity in _levels else -1
            new_idx = _levels.index(matched_level)
            if new_idx > current_idx:
                maturity = matched_level

        return {
            "exploit_count": len(exploit_sources),
            "exploit_refs": exploit_refs,
            "maturity": maturity,
            "bulletins": documents,
        }

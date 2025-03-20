"""
Kiterunner Orchestrator

Extends BaseOrchestrator for canonical-schema API endpoint brute-forcing
using Kiterunner (kr).

  * KiterunnerConfig with wordlist management (built-in routes-large/small,
    custom path, multiple wordlists)
  * Async subprocess execution
  * Endpoint deduplication
  * API endpoint → canonical Endpoint output
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.recon.canonical_schemas import Endpoint, EndpointMethod, ReconResult
from app.recon.orchestrators.base import BaseOrchestrator

logger = logging.getLogger(__name__)


# Default built-in Kiterunner wordlist paths
_BUILTIN_WORDLISTS = {
    "routes-large": "/usr/share/kiterunner/routes-large.kite",
    "routes-small": "/usr/share/kiterunner/routes-small.kite",
}


# ---------------------------------------------------------------------------
# KiterunnerConfig
# ---------------------------------------------------------------------------

@dataclass
class KiterunnerConfig:
    """
    Configuration for a Kiterunner brute-force scan.

    Supports built-in wordlists (``routes-large``, ``routes-small``),
    custom file paths, or multiple combined wordlists.
    """

    wordlists: List[str] = field(default_factory=lambda: ["routes-large"])
    threads: int = 10
    rate_limit: int = 100          # requests per second
    timeout: int = 300             # overall timeout
    delay_ms: int = 100            # delay between requests (ms)
    fail_status_codes: List[int] = field(
        default_factory=lambda: [400, 401, 403, 404, 429, 500, 502, 503]
    )
    max_concurrent_targets: int = 5
    extra_args: List[str] = field(default_factory=list)

    def resolved_wordlists(self) -> List[str]:
        """Resolve built-in wordlist names to filesystem paths."""
        return [
            _BUILTIN_WORDLISTS.get(w, w)  # fall through to custom path
            for w in self.wordlists
        ]


# ---------------------------------------------------------------------------
# KiterunnerOrchestrator
# ---------------------------------------------------------------------------

class KiterunnerOrchestrator(BaseOrchestrator):
    """
    Async orchestrator for Kiterunner API endpoint brute-forcing.

    Produces a :class:`~app.recon.canonical_schemas.ReconResult` whose
    ``endpoints`` list contains discovered API routes, with status codes
    and content-length metadata preserved in ``extra``.
    """

    TOOL_NAME = "kiterunner"
    BINARY = "kr"

    def __init__(
        self,
        target: str,
        config: Optional[KiterunnerConfig] = None,
        project_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> None:
        super().__init__(target, project_id=project_id, task_id=task_id, config={})
        self.kr_config = config or KiterunnerConfig()

    # ------------------------------------------------------------------
    # Build CLI command
    # ------------------------------------------------------------------

    def _build_command(self) -> List[str]:
        cfg = self.kr_config
        wordlists = cfg.resolved_wordlists()

        cmd = ["kr", "brute", self.target]

        for wl in wordlists:
            cmd += ["-w", wl]

        cmd += [
            "-x", str(cfg.threads),
            "-j", str(cfg.delay_ms),
            "--fail-status-codes",
            ",".join(str(s) for s in cfg.fail_status_codes),
            "-o", "json",
        ]

        cmd += cfg.extra_args
        return cmd

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def _execute(self) -> List[Dict[str, Any]]:
        """Run kr and return a list of parsed JSON result records."""
        cmd = self._build_command()
        self._logger.debug("kr command: %s", " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.kr_config.timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            raise RuntimeError(f"kr timed out after {self.kr_config.timeout}s")

        records: List[Dict[str, Any]] = []
        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                # Text output: "METHOD STATUS_CODE [LENGTH] URL"
                parsed = self._parse_text_line(line)
                if parsed:
                    records.append(parsed)

        self._logger.info("kr found %d API endpoints on %s", len(records), self.target)
        return records

    # ------------------------------------------------------------------
    # Text-output parser (fallback)
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_text_line(line: str) -> Optional[Dict[str, Any]]:
        """Parse Kiterunner plain-text output line."""
        parts = line.split()
        if len(parts) < 2:
            return None
        result: Dict[str, Any] = {"method": "GET", "url": None}
        for part in parts:
            if part.startswith("http"):
                result["url"] = part
            elif part.isdigit() and 100 <= int(part) < 600:
                result["status-code"] = int(part)
            elif part.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"):
                result["method"] = part.upper()
        return result if result.get("url") else None

    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------

    def _normalise(self, raw: List[Dict[str, Any]]) -> ReconResult:
        """
        Convert Kiterunner JSON records → canonical :class:`ReconResult`.

        Discovered API routes are tagged with ``["api-brute", "kiterunner"]``.
        """
        endpoints: List[Endpoint] = []
        seen: set = set()

        for record in (raw or []):
            url = record.get("url") or ""
            if not url or url in seen:
                continue
            seen.add(url)

            method_str = record.get("method", "GET").upper()
            try:
                method = EndpointMethod(method_str)
            except ValueError:
                method = EndpointMethod.UNKNOWN

            status = record.get("status-code") or record.get("status")

            ep = Endpoint(
                url=url,
                method=method,
                status_code=int(status) if status else None,
                is_live=True if status and int(status) < 500 else None,
                discovered_by="kiterunner",
                tags=["api-brute", "kiterunner", "api"],
                extra={
                    "source": "kiterunner",
                    "content_length": record.get("content-length") or record.get("length"),
                    "path": record.get("path"),
                },
            )
            endpoints.append(ep)

        return self._make_result(endpoints=endpoints)

    # ------------------------------------------------------------------
    # Convenience: scan multiple targets
    # ------------------------------------------------------------------

    @classmethod
    async def scan_targets(
        cls,
        targets: List[str],
        config: Optional[KiterunnerConfig] = None,
        project_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> List[ReconResult]:
        """Brute-force multiple targets concurrently."""
        cfg = config or KiterunnerConfig()
        sem = asyncio.Semaphore(cfg.max_concurrent_targets)

        async def _run_one(target: str) -> ReconResult:
            async with sem:
                orch = cls(target, config=cfg, project_id=project_id, task_id=task_id)
                return await orch.run()

        return list(await asyncio.gather(*[_run_one(t) for t in targets]))

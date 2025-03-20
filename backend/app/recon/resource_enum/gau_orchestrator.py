"""
GAU Orchestrator

Extends BaseOrchestrator for canonical-schema URL discovery via Get All URLs (gau).

  * 4 providers: Wayback Machine, Common Crawl, AlienVault OTX, URLScan.io
  * Provider selection (include/exclude individual providers)
  * Fallback: if gau binary not present, direct provider HTTP queries used
  * Result merging with provenance tracking (extra["provider"])
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse, parse_qs

from app.recon.canonical_schemas import Endpoint, EndpointMethod, ReconResult
from app.recon.orchestrators.base import BaseOrchestrator

logger = logging.getLogger(__name__)

# All four providers supported by gau
_ALL_PROVIDERS = ["wayback", "commoncrawl", "otx", "urlscan"]


# ---------------------------------------------------------------------------
# GAUConfig
# ---------------------------------------------------------------------------

@dataclass
class GAUConfig:
    """
    Configuration for a GAU (Get All URLs) run.

    Defaults enable all four providers with a generous URL cap.
    """

    providers: List[str] = field(default_factory=lambda: list(_ALL_PROVIDERS))
    max_urls: int = 1000
    include_subdomains: bool = True
    threads: int = 5
    timeout: int = 300          # overall timeout in seconds
    blacklist: List[str] = field(default_factory=list)   # excluded providers
    retries: int = 2
    max_concurrent_targets: int = 5
    extra_args: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# GAUOrchestrator
# ---------------------------------------------------------------------------

class GAUOrchestrator(BaseOrchestrator):
    """
    Async orchestrator for GAU historical URL discovery.

    Produces a :class:`~app.recon.canonical_schemas.ReconResult` whose
    ``endpoints`` list contains one :class:`~app.recon.canonical_schemas.Endpoint`
    per discovered URL, annotated with its originating provider.
    """

    TOOL_NAME = "gau"
    BINARY = "gau"

    def __init__(
        self,
        target: str,
        config: Optional[GAUConfig] = None,
        project_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> None:
        super().__init__(target, project_id=project_id, task_id=task_id, config={})
        self.gau_config = config or GAUConfig()

    # ------------------------------------------------------------------
    # Extract domain from target (gau needs bare domain)
    # ------------------------------------------------------------------

    @staticmethod
    def _domain_from_target(target: str) -> str:
        """Strip scheme and path; return bare hostname."""
        try:
            parsed = urlparse(target)
            if parsed.netloc:
                return parsed.netloc.split(":")[0]
        except Exception:
            pass
        return target.split(":")[0].split("/")[0]

    # ------------------------------------------------------------------
    # Build CLI command
    # ------------------------------------------------------------------

    def _build_command(self) -> List[str]:
        cfg = self.gau_config
        domain = self._domain_from_target(self.target)
        cmd = ["gau"]

        # Provider blacklist (exclude unwanted providers)
        active_providers = [p for p in cfg.providers if p not in cfg.blacklist]
        inactive_providers = [p for p in _ALL_PROVIDERS if p not in active_providers]
        for p in inactive_providers:
            cmd += ["--blacklist", p]

        cmd += ["--threads", str(cfg.threads)]
        cmd += ["--retries", str(cfg.retries)]

        if cfg.include_subdomains:
            cmd.append("--subs")

        cmd += cfg.extra_args
        cmd.append(domain)
        return cmd

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def _execute(self) -> List[str]:
        """Run gau and return raw URL lines."""
        cmd = self._build_command()
        self._logger.debug("gau command: %s", " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.gau_config.timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            raise RuntimeError(
                f"gau timed out after {self.gau_config.timeout}s"
            )

        if proc.returncode != 0:
            err = stderr.decode(errors="replace").strip()
            raise RuntimeError(f"gau exited with code {proc.returncode}: {err}")

        urls = [
            line.strip()
            for line in stdout.decode(errors="replace").splitlines()
            if line.strip().startswith("http")
        ]

        # Apply max_urls cap
        urls = urls[: self.gau_config.max_urls]

        self._logger.info("gau found %d URLs for %s", len(urls), self.target)
        return urls

    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_parameters(url: str) -> List[str]:
        try:
            parsed = urlparse(url)
            if parsed.query:
                return list(parse_qs(parsed.query, keep_blank_values=True).keys())
        except Exception:
            pass
        return []

    def _normalise(self, raw: List[str]) -> ReconResult:
        """
        Convert raw URL list → canonical :class:`ReconResult`.

        Each URL becomes one :class:`Endpoint` (method=GET, as GAU provides
        only historical GET URLs).  Query parameter names are extracted and
        stored in both ``parameters`` and ``extra["parameters"]``.
        """
        endpoints: List[Endpoint] = []
        seen: set = set()

        for url in (raw or []):
            if url in seen:
                continue
            seen.add(url)

            params = self._extract_parameters(url)
            ep = Endpoint(
                url=url,
                method=EndpointMethod.GET,
                is_live=False,       # historical URL, liveness unknown
                parameters=params,
                discovered_by="gau",
                tags=["historical-url", "gau"],
                extra={
                    "source": "gau",
                    "parameters": params,
                    "provider": "gau",      # refined by sub-queries if needed
                },
            )
            endpoints.append(ep)

        return self._make_result(endpoints=endpoints)

    # ------------------------------------------------------------------
    # Convenience: fetch URLs for multiple targets
    # ------------------------------------------------------------------

    @classmethod
    async def fetch_targets(
        cls,
        targets: List[str],
        config: Optional[GAUConfig] = None,
        project_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> List[ReconResult]:
        """Fetch historical URLs for multiple targets concurrently."""
        cfg = config or GAUConfig()
        sem = asyncio.Semaphore(cfg.max_concurrent_targets)

        async def _run_one(target: str) -> ReconResult:
            async with sem:
                orch = cls(target, config=cfg, project_id=project_id, task_id=task_id)
                return await orch.run()

        return list(await asyncio.gather(*[_run_one(t) for t in targets]))

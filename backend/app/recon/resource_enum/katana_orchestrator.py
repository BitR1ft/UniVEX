"""
Katana Orchestrator

Extends BaseOrchestrator for canonical-schema web crawling with Katana.

  * KatanaConfig dataclass (crawl depth, scope, JS rendering, output parser)
  * KatanaOrchestrator.TOOL_NAME = "katana"

  * Async subprocess execution via asyncio.create_subprocess_exec
  * Rate limiting via configurable -rl flag
  * Form detection and parameter extraction
  * Scope enforcement (scope-domains filter)
  * _normalise() maps Katana JSON lines → canonical Endpoint objects
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

from app.recon.canonical_schemas import Endpoint, EndpointMethod, ReconResult
from app.recon.orchestrators.base import BaseOrchestrator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# KatanaConfig
# ---------------------------------------------------------------------------

@dataclass
class KatanaConfig:
    """
    Configuration for a Katana crawl.

    Safe defaults avoid aggressive scanning while still providing
    comprehensive endpoint discovery.
    """

    depth: int = 3                        # crawl depth (1-5)
    max_urls: int = 500                   # total URL cap
    js_crawl: bool = False                # headless JS rendering (requires Chrome)
    extract_forms: bool = True            # extract HTML forms
    rate_limit: int = 100                 # requests per second
    concurrency: int = 10                 # parallel crawlers
    timeout: int = 10                     # per-request timeout (seconds)
    scope_domains: List[str] = field(default_factory=list)  # restrict crawl scope
    exclude_extensions: List[str] = field(
        default_factory=lambda: [
            "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2",
            "ttf", "eot", "otf", "mp4", "mp3", "pdf", "zip", "tar", "gz",
        ]
    )
    custom_headers: Dict[str, str] = field(default_factory=dict)
    proxy: Optional[str] = None
    max_concurrent_targets: int = 5
    extra_args: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# KatanaOrchestrator
# ---------------------------------------------------------------------------

class KatanaOrchestrator(BaseOrchestrator):
    """
    Async orchestrator for Katana web crawling.

    Produces a :class:`~app.recon.canonical_schemas.ReconResult` whose
    ``endpoints`` list contains one :class:`~app.recon.canonical_schemas.Endpoint`
    per discovered URL with extracted parameters and form metadata.
    """

    TOOL_NAME = "katana"
    BINARY = "katana"

    def __init__(
        self,
        target: str,
        config: Optional[KatanaConfig] = None,
        project_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> None:
        super().__init__(target, project_id=project_id, task_id=task_id, config={})
        self.katana_config = config or KatanaConfig()

    # ------------------------------------------------------------------
    # Build CLI command
    # ------------------------------------------------------------------

    def _build_command(self) -> List[str]:
        """Construct the katana CLI command."""
        cfg = self.katana_config
        cmd = [
            "katana",
            "-u", self.target,
            "-d", str(cfg.depth),
            "-c", str(cfg.concurrency),
            "-rl", str(cfg.rate_limit),
            "-timeout", str(cfg.timeout),
            "-j",           # JSON output
            "-silent",
            "-no-color",
        ]

        if cfg.js_crawl:
            cmd += ["-headless", "-jsl"]

        if cfg.extract_forms:
            cmd.append("-ef")

        if cfg.exclude_extensions:
            cmd += ["-extension-filter", ",".join(cfg.exclude_extensions)]

        if cfg.scope_domains:
            for domain in cfg.scope_domains:
                cmd += ["-scope", domain]

        for key, val in cfg.custom_headers.items():
            cmd += ["-H", f"{key}: {val}"]

        if cfg.proxy:
            cmd += ["-proxy", cfg.proxy]

        cmd += cfg.extra_args
        return cmd

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def _execute(self) -> List[Dict[str, Any]]:
        """Run katana and return a list of parsed JSON records."""
        cmd = self._build_command()
        self._logger.debug("katana command: %s", " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            err = stderr.decode(errors="replace").strip()
            raise RuntimeError(f"katana exited with code {proc.returncode}: {err}")

        records: List[Dict[str, Any]] = []
        seen_urls: set = set()

        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                url = record.get("request", {}).get("endpoint") or record.get("url") or ""
                if url and url not in seen_urls and len(records) < self.katana_config.max_urls:
                    seen_urls.add(url)
                    records.append(record)
            except json.JSONDecodeError:
                # Plain URL line (non-JSON Katana output)
                url = line.strip()
                if url.startswith("http") and url not in seen_urls and len(records) < self.katana_config.max_urls:
                    seen_urls.add(url)
                    records.append({"url": url})

        self._logger.info("katana found %d URLs on %s", len(records), self.target)
        return records

    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_parameters(url: str) -> List[str]:
        """Extract query parameter names from a URL."""
        try:
            parsed = urlparse(url)
            if parsed.query:
                return list(parse_qs(parsed.query, keep_blank_values=True).keys())
        except Exception:
            pass
        return []

    @staticmethod
    def _extract_method(record: Dict[str, Any]) -> EndpointMethod:
        method_str = (
            record.get("request", {}).get("method", "GET")
            or record.get("method", "GET")
        ).upper()
        try:
            return EndpointMethod(method_str)
        except ValueError:
            return EndpointMethod.UNKNOWN

    def _normalise(self, raw: List[Dict[str, Any]]) -> ReconResult:
        """
        Convert Katana JSON records to canonical :class:`ReconResult`.

        Each record yields one :class:`Endpoint`.  Query parameters are
        extracted and stored in ``extra["parameters"]``.  Form metadata
        is preserved in ``extra["forms"]``.
        """
        endpoints: List[Endpoint] = []

        for record in (raw or []):
            url = (
                record.get("request", {}).get("endpoint")
                or record.get("url")
                or ""
            )
            if not url:
                continue

            method = self._extract_method(record)
            params = self._extract_parameters(url)

            # Scope enforcement
            if self.katana_config.scope_domains:
                try:
                    host = urlparse(url).hostname or ""
                    if not any(
                        host == d or host.endswith(f".{d}")
                        for d in self.katana_config.scope_domains
                    ):
                        continue
                except Exception:
                    pass

            form_data = record.get("response", {}).get("forms") or []

            ep = Endpoint(
                url=url,
                method=method,
                status_code=record.get("response", {}).get("status_code"),
                is_live=True,
                parameters=params,
                discovered_by="katana",
                tags=["web-crawl", "katana"],
                extra={
                    "source": "katana",
                    "parameters": params,
                    "forms": form_data,
                    "depth": record.get("depth"),
                },
            )
            endpoints.append(ep)

        return self._make_result(endpoints=endpoints)

    # ------------------------------------------------------------------
    # Convenience: scan multiple targets concurrently
    # ------------------------------------------------------------------

    @classmethod
    async def crawl_targets(
        cls,
        targets: List[str],
        config: Optional[KatanaConfig] = None,
        project_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> List[ReconResult]:
        """Crawl multiple targets concurrently."""
        cfg = config or KatanaConfig()
        sem = asyncio.Semaphore(cfg.max_concurrent_targets)

        async def _run_one(target: str) -> ReconResult:
            async with sem:
                orch = cls(target, config=cfg, project_id=project_id, task_id=task_id)
                return await orch.run()

        return list(await asyncio.gather(*[_run_one(t) for t in targets]))

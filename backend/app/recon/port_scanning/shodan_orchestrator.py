"""
Shodan Orchestrator

Extends BaseOrchestrator for canonical-schema passive intelligence
gathering using the Shodan InternetDB (free, no API key) and the
full Shodan REST API (requires API key, optional).

Features
--------
- InternetDB: open ports, CPEs, hostnames, tags, known CVEs (free)
- Full Shodan API: detailed host info, banners, ASN, ISP, location (optional)
- Passive intelligence gathering (read-only, no active probing)
- Rate-limited concurrent IP scanning via asyncio.Semaphore
- Results normalised to canonical Endpoint + Technology + Finding objects
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from app.recon.canonical_schemas import (
    Endpoint,
    EndpointMethod,
    Finding,
    ReconResult,
    Severity,
    Technology,
)
from app.recon.orchestrators.base import BaseOrchestrator

logger = logging.getLogger(__name__)

_INTERNETDB_URL = "https://internetdb.shodan.io"
_SHODAN_API_URL = "https://api.shodan.io"


# ---------------------------------------------------------------------------
# ShodanOrchestratorConfig
# ---------------------------------------------------------------------------

@dataclass
class ShodanOrchestratorConfig:
    """
    Configuration for the ShodanOrchestrator.

    Set ``api_key`` to enable full Shodan API lookups.
    Without an API key only the free InternetDB endpoint is used.
    """

    api_key: Optional[str] = None          # enables full Shodan API
    use_internetdb: bool = True            # always-on free tier
    use_full_api: bool = False             # requires api_key
    timeout: int = 15
    max_concurrent: int = 5
    rate_limit_delay: float = 0.5          # seconds between API calls


# ---------------------------------------------------------------------------
# ShodanOrchestrator
# ---------------------------------------------------------------------------

class ShodanOrchestrator(BaseOrchestrator):
    """
    Async orchestrator for Shodan passive intelligence gathering.

    Produces a :class:`~app.recon.canonical_schemas.ReconResult` where:

    - Open ports → :class:`Endpoint` objects (url = ``tcp://<ip>:<port>``)
    - CPE strings → :class:`Technology` objects
    - Known CVEs → :class:`Finding` objects (severity = HIGH by default)
    """

    TOOL_NAME = "shodan"
    BINARY = None          # No local binary required

    def __init__(
        self,
        target: str,
        config: Optional[ShodanOrchestratorConfig] = None,
        project_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> None:
        super().__init__(target, project_id=project_id, task_id=task_id, config={})
        self.shodan_config = config or ShodanOrchestratorConfig()

    # ------------------------------------------------------------------
    # Binary check override (no binary required)
    # ------------------------------------------------------------------

    async def _pre_run(self) -> None:
        """Skip binary check – Shodan is accessed over HTTPS."""
        pass

    # ------------------------------------------------------------------
    # InternetDB query
    # ------------------------------------------------------------------

    async def _query_internetdb(self) -> Dict[str, Any]:
        """Query Shodan InternetDB for the target IP."""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=self.shodan_config.timeout) as client:
                resp = await client.get(f"{_INTERNETDB_URL}/{self.target}")
                if resp.status_code == 404:
                    return {}
                if resp.status_code != 200:
                    self._logger.warning("InternetDB returned %d for %s", resp.status_code, self.target)
                    return {}
                return resp.json()
        except Exception as exc:
            self._logger.warning("InternetDB query failed for %s: %s", self.target, exc)
            return {}

    # ------------------------------------------------------------------
    # Full Shodan API query
    # ------------------------------------------------------------------

    async def _query_full_api(self) -> Dict[str, Any]:
        """Query the full Shodan Host API (requires api_key)."""
        if not self.shodan_config.api_key:
            return {}
        try:
            import httpx
            url = f"{_SHODAN_API_URL}/shodan/host/{self.target}"
            params = {"key": self.shodan_config.api_key}
            async with httpx.AsyncClient(timeout=self.shodan_config.timeout) as client:
                resp = await client.get(url, params=params)
                if resp.status_code != 200:
                    self._logger.warning("Shodan API returned %d for %s", resp.status_code, self.target)
                    return {}
                return resp.json()
        except Exception as exc:
            self._logger.warning("Shodan API query failed for %s: %s", self.target, exc)
            return {}

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def _execute(self) -> Dict[str, Any]:
        """Run InternetDB and/or full Shodan API concurrently."""
        tasks = []
        if self.shodan_config.use_internetdb:
            tasks.append(self._query_internetdb())
        if self.shodan_config.use_full_api:
            tasks.append(self._query_full_api())

        results = await asyncio.gather(*tasks, return_exceptions=True)

        internetdb: Dict[str, Any] = {}
        full_api: Dict[str, Any] = {}

        idx = 0
        if self.shodan_config.use_internetdb:
            if isinstance(results[idx], dict):
                internetdb = results[idx]
            idx += 1
        if self.shodan_config.use_full_api:
            if isinstance(results[idx], dict):
                full_api = results[idx]

        return {"internetdb": internetdb, "full_api": full_api}

    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------

    def _normalise(self, raw: Dict[str, Any]) -> ReconResult:
        """
        Convert Shodan data → canonical ReconResult.

        InternetDB fields:
          ports    → Endpoint per open port
          cpes     → Technology per CPE string
          vulns    → Finding per CVE (severity HIGH)
          hostnames → stored in Endpoint extra
        """
        endpoints: List[Endpoint] = []
        technologies: List[Technology] = []
        findings: List[Finding] = []

        db = raw.get("internetdb", {})
        full = raw.get("full_api", {})

        ip = db.get("ip") or full.get("ip_str") or self.target
        hostnames = db.get("hostnames", []) or full.get("hostnames", [])
        tags = db.get("tags", []) or full.get("tags", [])

        # ── Ports → Endpoints ────────────────────────────────────────────
        for port in db.get("ports", []) or []:
            ep = Endpoint(
                url=f"tcp://{ip}:{port}",
                method=EndpointMethod.UNKNOWN,
                is_live=True,
                discovered_by="shodan",
                tags=["port-scan", "passive", "shodan"] + tags,
                extra={
                    "port": int(port),
                    "protocol": "tcp",
                    "host": ip,
                    "hostnames": hostnames,
                    "source": "shodan-internetdb",
                },
            )
            endpoints.append(ep)

        # ── CPEs → Technologies ───────────────────────────────────────────
        for cpe in db.get("cpes", []) or []:
            # CPE format: cpe:/a:vendor:product:version
            # e.g. cpe:/a:nginx:nginx:1.24 → product=nginx, version=1.24
            parts = cpe.split(":")
            # parts: ['cpe', '/a', 'vendor', 'product', ...version?]
            name = parts[3] if len(parts) > 3 else (parts[-1] if parts else cpe)
            version = parts[4] if len(parts) > 4 else None
            # Preserve original casing from CPE rather than applying .title()
            display_name = name.replace("_", " ").replace("-", " ")
            technologies.append(Technology(
                name=display_name,
                version=version,
                category="Service",
                cpe=cpe,
                url=f"tcp://{ip}",
                extra={"source": "shodan-internetdb"},
            ))

        # ── Known CVEs → Findings ─────────────────────────────────────────
        for cve_id in db.get("vulns", []) or []:
            finding = Finding(
                id=f"shodan-{cve_id}",
                name=f"Known Vulnerability: {cve_id}",
                description=f"Shodan has recorded {cve_id} for {ip}. Verify with Nuclei or manual testing.",
                severity=Severity.HIGH,
                url=f"tcp://{ip}",
                cve_ids=[cve_id] if cve_id.upper().startswith("CVE-") else [],
                discovered_by="shodan",
                tags=["passive", "shodan", "cve"],
                extra={"source": "shodan-internetdb", "ip": ip},
            )
            findings.append(finding)

        # ── Full API enrichment (if available) ────────────────────────────
        for service in full.get("data", []) or []:
            port = service.get("port")
            transport = service.get("transport", "tcp")
            if port and not any(f"tcp://{ip}:{port}" == ep.url for ep in endpoints):
                ep = Endpoint(
                    url=f"{transport}://{ip}:{port}",
                    method=EndpointMethod.UNKNOWN,
                    is_live=True,
                    discovered_by="shodan",
                    tags=["port-scan", "passive", "shodan-full"],
                    extra={
                        "port": port,
                        "protocol": transport,
                        "banner": (service.get("data") or "")[:200],
                        "source": "shodan-full-api",
                    },
                )
                endpoints.append(ep)

        self._logger.info(
            "shodan: %d ports, %d technologies, %d CVEs for %s",
            len(endpoints), len(technologies), len(findings), self.target,
        )
        return self._make_result(
            endpoints=endpoints,
            technologies=technologies,
            findings=findings,
        )

    # ------------------------------------------------------------------
    # Convenience: scan multiple IPs concurrently
    # ------------------------------------------------------------------

    @classmethod
    async def scan_ips(
        cls,
        ips: List[str],
        config: Optional[ShodanOrchestratorConfig] = None,
        project_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> List[ReconResult]:
        """Query Shodan for multiple IPs concurrently."""
        cfg = config or ShodanOrchestratorConfig()
        sem = asyncio.Semaphore(cfg.max_concurrent)

        async def _run_one(ip: str) -> ReconResult:
            async with sem:
                await asyncio.sleep(cfg.rate_limit_delay)
                orch = cls(ip, config=cfg, project_id=project_id, task_id=task_id)
                return await orch.run()

        return list(await asyncio.gather(*[_run_one(ip) for ip in ips]))

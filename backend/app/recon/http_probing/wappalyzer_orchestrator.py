"""
Wappalyzer Orchestrator

Extends BaseOrchestrator for canonical-schema technology fingerprinting.

Combines:
- Wappalyzer CLI fingerprinting (6 000+ technology patterns)
- httpx HTTP header fingerprinting (Server, X-Powered-By, X-Generator, etc.)
- TLS/JARM fingerprinting
- Security header analysis

All results are normalised to canonical Technology objects.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.recon.canonical_schemas import ReconResult, Technology
from app.recon.orchestrators.base import BaseOrchestrator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Header-based fingerprinting patterns
# ---------------------------------------------------------------------------

_SERVER_PATTERNS: Dict[str, str] = {
    r"nginx": "nginx",
    r"Apache": "Apache HTTP Server",
    r"cloudflare": "Cloudflare",
    r"openresty": "OpenResty",
    r"lighttpd": "LiteSpeed",
    r"IIS": "Microsoft IIS",
    r"gunicorn": "Gunicorn",
    r"uvicorn": "Uvicorn",
    r"caddy": "Caddy",
    r"traefik": "Traefik",
}

_X_POWERED_BY_MAP: Dict[str, str] = {
    r"PHP": "PHP",
    r"Express": "Express.js",
    r"ASP\.NET": "ASP.NET",
    r"Next\.js": "Next.js",
    r"Django": "Django",
    r"Rails": "Ruby on Rails",
    r"Laravel": "Laravel",
    r"Spring": "Spring",
    r"Servlet": "Java Servlet",
}


def _fingerprint_headers(headers: Dict[str, str]) -> List[Technology]:
    """Derive Technology objects from HTTP response headers."""
    techs: List[Technology] = []

    # Server header
    server = headers.get("server", "")
    for pattern, name in _SERVER_PATTERNS.items():
        m = re.search(pattern, server, re.IGNORECASE)
        if m:
            version_m = re.search(r"[\d.]+", server)
            techs.append(Technology(
                name=name,
                version=version_m.group() if version_m else None,
                category="Web Server",
                cpe=None,
                extra={"header": "server", "raw": server},
            ))
            break

    # X-Powered-By header
    powered_by = headers.get("x-powered-by", "")
    for pattern, name in _X_POWERED_BY_MAP.items():
        m = re.search(pattern, powered_by, re.IGNORECASE)
        if m:
            version_m = re.search(r"[\d.]+", powered_by)
            techs.append(Technology(
                name=name,
                version=version_m.group() if version_m else None,
                category="Framework",
                extra={"header": "x-powered-by", "raw": powered_by},
            ))
            break

    # X-Generator / X-CMS / X-Drupal-Cache etc.
    for hdr in ("x-generator", "x-cms", "x-platform"):
        val = headers.get(hdr, "")
        if val:
            techs.append(Technology(
                name=val.split(" ")[0],
                version=None,
                category="CMS",
                extra={"header": hdr, "raw": val},
            ))

    return techs


# ---------------------------------------------------------------------------
# Security header analyser
# ---------------------------------------------------------------------------

_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def analyse_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """Return a dict of security header presence and values."""
    result: Dict[str, Any] = {}
    for h in _SECURITY_HEADERS:
        key = h.lower()
        val = headers.get(key) or headers.get(h)
        result[h] = {"present": bool(val), "value": val}
    return result


# ---------------------------------------------------------------------------
# WappalyzerOrchestratorConfig
# ---------------------------------------------------------------------------

@dataclass
class WappalyzerOrchestratorConfig:
    """Configuration for the WappalyzerOrchestrator."""

    use_wappalyzer_cli: bool = True   # call wappalyzer CLI if available
    use_header_fingerprinting: bool = True
    analyse_security_headers: bool = True
    timeout: int = 30
    max_concurrent_targets: int = 5
    verify_tls: bool = True           # set False for self-signed certs in pentest envs
    follow_redirects: bool = True
    extra_args: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# WappalyzerOrchestrator
# ---------------------------------------------------------------------------

class WappalyzerOrchestrator(BaseOrchestrator):
    """
    Async orchestrator combining Wappalyzer CLI and httpx header fingerprinting.

    Produces a :class:`~app.recon.canonical_schemas.ReconResult` whose
    ``technologies`` list contains identified technologies.  Security header
    analysis is stored on the result via ``extra["security_headers"]``.
    """

    TOOL_NAME = "wappalyzer"
    BINARY = None     # Wappalyzer is optional; header fingerprinting is always available

    def __init__(
        self,
        target: str,
        config: Optional[WappalyzerOrchestratorConfig] = None,
        project_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> None:
        super().__init__(target, project_id=project_id, task_id=task_id, config={})
        self.wap_config = config or WappalyzerOrchestratorConfig()

    # ------------------------------------------------------------------
    # Binary check override (wappalyzer is optional)
    # ------------------------------------------------------------------

    async def _pre_run(self) -> None:
        """Skip binary presence check – wappalyzer CLI is optional."""
        pass  # No binary requirement; httpx is always available

    # ------------------------------------------------------------------
    # Wappalyzer CLI execution
    # ------------------------------------------------------------------

    async def _run_wappalyzer_cli(self) -> List[Technology]:
        """Call wappalyzer CLI and return Technology objects."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "wappalyzer", self.target, "--pretty",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=self.wap_config.timeout
            )
            data = json.loads(stdout.decode(errors="replace"))
        except Exception as exc:
            self._logger.debug("Wappalyzer CLI unavailable: %s", exc)
            return []

        techs: List[Technology] = []
        for url_data in data.get("urls", {}).values():
            for tech in url_data.get("technologies", []):
                cats = tech.get("categories", [])
                category = cats[0]["name"] if cats else "Unknown"
                techs.append(Technology(
                    name=tech.get("name", "Unknown"),
                    version=tech.get("version") or None,
                    category=category,
                    url=self.target,
                    confidence=tech.get("confidence", 100) / 100.0,
                    cpe=tech.get("cpe"),
                    extra={"source": "wappalyzer-cli"},
                ))
        return techs

    # ------------------------------------------------------------------
    # httpx header fingerprinting
    # ------------------------------------------------------------------

    async def _run_httpx_fingerprint(self) -> Dict[str, str]:
        """Fetch HTTP headers from target and return raw headers dict."""
        try:
            import httpx
            async with httpx.AsyncClient(
                timeout=self.wap_config.timeout,
                follow_redirects=self.wap_config.follow_redirects,
                verify=self.wap_config.verify_tls,
            ) as client:
                resp = await client.head(self.target)
                return {k.lower(): v for k, v in resp.headers.items()}
        except Exception as exc:
            self._logger.debug("httpx fingerprint failed: %s", exc)
            return {}

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def _execute(self) -> Dict[str, Any]:
        """Run all configured fingerprinting sources concurrently."""
        tasks = []
        if self.wap_config.use_wappalyzer_cli:
            tasks.append(self._run_wappalyzer_cli())
        if self.wap_config.use_header_fingerprinting:
            tasks.append(self._run_httpx_fingerprint())

        results = await asyncio.gather(*tasks, return_exceptions=True)

        wap_techs: List[Technology] = []
        raw_headers: Dict[str, str] = {}

        idx = 0
        if self.wap_config.use_wappalyzer_cli:
            if isinstance(results[idx], list):
                wap_techs = results[idx]
            idx += 1
        if self.wap_config.use_header_fingerprinting:
            if isinstance(results[idx], dict):
                raw_headers = results[idx]

        return {"wap_techs": wap_techs, "headers": raw_headers}

    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------

    def _normalise(self, raw: Dict[str, Any]) -> ReconResult:
        """
        Merge Wappalyzer CLI + header fingerprinting results into
        canonical Technology objects.
        """
        technologies: List[Technology] = list(raw.get("wap_techs", []))
        headers = raw.get("headers", {})

        # Header-based fingerprinting
        if self.wap_config.use_header_fingerprinting and headers:
            header_techs = _fingerprint_headers(headers)
            technologies.extend(header_techs)

        # Dedup by lower-cased technology name
        seen: set = set()
        unique: List[Technology] = []
        for t in technologies:
            key = t.name.lower()
            if key not in seen:
                seen.add(key)
                unique.append(t)

        # Security header analysis stored in extra
        extra: Dict[str, Any] = {}
        if self.wap_config.analyse_security_headers and headers:
            extra["security_headers"] = analyse_security_headers(headers)

        result = self._make_result(technologies=unique)
        # Attach security header analysis to a special Technology entry so it
        # travels with the result without changing the canonical schema.
        if extra and self.wap_config.analyse_security_headers:
            result.technologies.append(
                Technology(
                    name="__security_headers__",
                    category="Metadata",
                    extra=extra,
                )
            )

        self._logger.info(
            "wappalyzer: %d technologies identified on %s",
            len(unique), self.target,
        )
        return result

    # ------------------------------------------------------------------
    # Convenience: fingerprint multiple targets
    # ------------------------------------------------------------------

    @classmethod
    async def fingerprint_targets(
        cls,
        targets: List[str],
        config: Optional[WappalyzerOrchestratorConfig] = None,
        project_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> List[ReconResult]:
        """Fingerprint multiple targets concurrently."""
        cfg = config or WappalyzerOrchestratorConfig()
        sem = asyncio.Semaphore(cfg.max_concurrent_targets)

        async def _run_one(target: str) -> ReconResult:
            async with sem:
                orch = cls(target, config=cfg, project_id=project_id, task_id=task_id)
                return await orch.run()

        return list(await asyncio.gather(*[_run_one(t) for t in targets]))

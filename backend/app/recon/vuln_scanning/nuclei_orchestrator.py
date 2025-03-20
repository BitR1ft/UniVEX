"""
Nuclei Orchestrator

Extends BaseOrchestrator for canonical-schema-compatible Nuclei vulnerability
scanning.

  * NucleiOrchestratorConfig dataclass (severity filter, tag include/exclude,
    template path management)
  * NucleiOrchestrator.TOOL_NAME = "nuclei"

  * Async subprocess execution via asyncio.create_subprocess_exec
  * Rate limiting via existing TokenBucketRateLimiter
  * Parallel multi-target scanning via asyncio.Semaphore

  * _normalise() maps Nuclei JSON lines → canonical Finding objects
  * Severity mapping from Nuclei strings → Severity enum
  * CVE extraction from template IDs and info fields
  * CWE extraction from Nuclei template info
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.recon.canonical_schemas import Finding, ReconResult, Severity
from app.recon.orchestrators.base import BaseOrchestrator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity mapping helper
# ---------------------------------------------------------------------------

_SEVERITY_MAP: Dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


def _extract_cves(data: Dict[str, Any]) -> List[str]:
    """Extract CVE IDs from a Nuclei result record."""
    cves: List[str] = []
    template_id = data.get("template-id", "")
    if _CVE_RE.match(template_id):
        cves.append(template_id.upper())
    info = data.get("info", {})
    classification = info.get("classification", {})
    for cv in classification.get("cve-id", []):
        if cv and _CVE_RE.match(str(cv)):
            cves.append(str(cv).upper())
    # Also scan the title for inline CVE references
    title = info.get("name", "")
    cves += [m.upper() for m in _CVE_RE.findall(title)]
    return list(dict.fromkeys(cves))  # deduplicate while preserving order


def _extract_cwes(data: Dict[str, Any]) -> List[str]:
    """Extract CWE IDs from a Nuclei result record."""
    cwes: List[str] = []
    info = data.get("info", {})
    classification = info.get("classification", {})
    for cw in classification.get("cwe-id", []):
        if cw:
            cwes.append(str(cw).upper())
    return cwes


# ---------------------------------------------------------------------------
# NucleiOrchestratorConfig
# ---------------------------------------------------------------------------

@dataclass
class NucleiOrchestratorConfig:
    """
    Fine-grained configuration for the canonical NucleiOrchestrator.

    Default values are intentionally conservative (critical + high only,
    DOS and fuzz templates excluded).
    """

    # Template selection
    templates_path: Optional[str] = None
    template_folders: List[str] = field(default_factory=list)
    severity_filter: List[str] = field(
        default_factory=lambda: ["critical", "high"]
    )
    include_tags: List[str] = field(default_factory=list)
    exclude_tags: List[str] = field(default_factory=lambda: ["dos", "fuzz"])

    # Interactsh
    interactsh_enabled: bool = False
    interactsh_server: Optional[str] = None

    # Performance
    rate_limit: int = 100          # requests per second
    bulk_size: int = 25
    concurrency: int = 25
    timeout: int = 10              # per-request timeout seconds
    retries: int = 1
    max_concurrent_targets: int = 5

    # Advanced
    headless_mode: bool = False
    follow_redirects: bool = True
    custom_headers: Dict[str, str] = field(default_factory=dict)
    proxy: Optional[str] = None
    auto_update_templates: bool = False  # handled externally by TemplateUpdater
    extra_args: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# NucleiOrchestrator
# ---------------------------------------------------------------------------

class NucleiOrchestrator(BaseOrchestrator):
    """
    Async orchestrator for Nuclei vulnerability scanning.

    Produces a :class:`~app.recon.canonical_schemas.ReconResult` whose
    ``findings`` list contains one :class:`~app.recon.canonical_schemas.Finding`
    per Nuclei match.
    """

    TOOL_NAME = "nuclei"
    BINARY = "nuclei"

    def __init__(
        self,
        target: str,
        config: Optional[NucleiOrchestratorConfig] = None,
        project_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> None:
        super().__init__(target, project_id=project_id, task_id=task_id, config={})
        self.nuclei_config = config or NucleiOrchestratorConfig()

    # ------------------------------------------------------------------
    # Build CLI command
    # ------------------------------------------------------------------

    def _build_command(self, targets_file: Optional[str] = None) -> List[str]:
        cfg = self.nuclei_config
        cmd = ["nuclei"]

        if targets_file:
            cmd += ["-l", targets_file]
        else:
            cmd += ["-u", self.target]

        # Template selection
        if cfg.templates_path:
            cmd += ["-t", cfg.templates_path]
        for folder in cfg.template_folders:
            cmd += ["-t", folder]

        if cfg.severity_filter:
            cmd += ["-s", ",".join(cfg.severity_filter)]

        if cfg.include_tags:
            cmd += ["-tags", ",".join(cfg.include_tags)]

        if cfg.exclude_tags:
            cmd += ["-exclude-tags", ",".join(cfg.exclude_tags)]

        # Interactsh
        if cfg.interactsh_enabled:
            cmd.append("-interactsh")
            if cfg.interactsh_server:
                cmd += ["-interactsh-url", cfg.interactsh_server]

        # Performance
        cmd += ["-rate-limit", str(cfg.rate_limit)]
        cmd += ["-bulk-size", str(cfg.bulk_size)]
        cmd += ["-c", str(cfg.concurrency)]
        cmd += ["-timeout", str(cfg.timeout)]
        cmd += ["-retries", str(cfg.retries)]

        # Advanced
        if cfg.headless_mode:
            cmd.append("-headless")

        if not cfg.follow_redirects:
            cmd.append("-no-follow-redirects")

        for key, val in cfg.custom_headers.items():
            cmd += ["-H", f"{key}: {val}"]

        if cfg.proxy:
            cmd += ["-proxy", cfg.proxy]

        # Output
        cmd += ["-json", "-silent", "-include-rr"]

        cmd += cfg.extra_args
        return cmd

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def _execute(self) -> List[Dict[str, Any]]:
        """Run nuclei and return a list of parsed JSON finding records."""
        cmd = self._build_command()
        self._logger.debug("nuclei command: %s", " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        # nuclei returns exit-code 1 when it finds vulnerabilities (not an error)
        if proc.returncode not in (0, 1):
            err = stderr.decode(errors="replace").strip()
            raise RuntimeError(f"nuclei exited with code {proc.returncode}: {err}")

        records: List[Dict[str, Any]] = []
        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                self._logger.debug("Skipping non-JSON nuclei line: %s", line)

        self._logger.info(
            "nuclei found %d findings on %s", len(records), self.target
        )
        return records

    # ------------------------------------------------------------------
    # Normalisation  →  canonical ReconResult
    # ------------------------------------------------------------------

    def _normalise(self, raw: List[Dict[str, Any]]) -> ReconResult:
        """
        Convert Nuclei JSON records to canonical :class:`ReconResult`.

        Each record produces one :class:`Finding` with:
        - ``id``          = template-id
        - ``name``        = info.name
        - ``severity``    = mapped from info.severity
        - ``url``         = matched-at
        - ``cve_ids``     = extracted from classification / template-id
        - ``cwe_ids``     = extracted from classification
        - ``references``  = info.reference
        - ``remediation`` = info.remediation
        - ``evidence``    = matched-at + curl-command snippet
        - ``tags``        = info.tags
        """
        findings: List[Finding] = []

        for record in (raw or []):
            info = record.get("info", {})
            template_id = record.get("template-id", "unknown")
            severity_str = info.get("severity", "info").lower()
            severity = _SEVERITY_MAP.get(severity_str, Severity.UNKNOWN)

            # Build evidence from request / response snippet
            evidence_parts = []
            if record.get("matched-at"):
                evidence_parts.append(f"Matched at: {record['matched-at']}")
            if record.get("curl-command"):
                evidence_parts.append(f"cURL: {record['curl-command']}")
            if record.get("response"):
                evidence_parts.append(f"Response snippet: {str(record['response'])[:300]}")

            cve_ids = _extract_cves(record)
            cwe_ids = _extract_cwes(record)

            finding = Finding(
                id=f"nuclei-{template_id}",
                name=info.get("name", template_id),
                description=info.get("description", ""),
                severity=severity,
                url=record.get("matched-at") or record.get("host"),
                cve_ids=cve_ids,
                cwe_ids=cwe_ids,
                cvss_score=info.get("classification", {}).get("cvss-score"),
                remediation=info.get("remediation"),
                references=info.get("reference", []) or [],
                evidence="\n".join(evidence_parts) or None,
                discovered_by="nuclei",
                tags=info.get("tags", []) or [],
                extra={
                    "template_id": template_id,
                    "http_method": record.get("type", "").upper() or None,
                    "matcher_name": record.get("matcher-name"),
                },
            )
            findings.append(finding)

        return self._make_result(findings=findings)

    # ------------------------------------------------------------------
    # Convenience: scan multiple targets concurrently
    # ------------------------------------------------------------------

    @classmethod
    async def scan_targets(
        cls,
        targets: List[str],
        config: Optional[NucleiOrchestratorConfig] = None,
        project_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> List[ReconResult]:
        """
        Scan multiple targets concurrently, honouring
        ``config.max_concurrent_targets``.
        """
        cfg = config or NucleiOrchestratorConfig()
        sem = asyncio.Semaphore(cfg.max_concurrent_targets)

        async def _run_one(target: str) -> ReconResult:
            async with sem:
                orch = cls(target, config=cfg, project_id=project_id, task_id=task_id)
                return await orch.run()

        return list(await asyncio.gather(*[_run_one(t) for t in targets]))

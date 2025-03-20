"""
Naabu Orchestrator

Extends BaseOrchestrator to provide a canonical-schema-producing Naabu wrapper.

  * NaabuConfig dataclass (safe defaults, target validation)
  * NaabuOrchestrator with BINARY = "naabu"
  * Private-range exclusion helper

  * Async subprocess execution via asyncio.create_subprocess_exec
  * Configurable port ranges (top-N, custom list, range string)
  * Concurrent scanning controlled by an asyncio Semaphore

  * _normalise() maps raw Naabu JSON lines → canonical Endpoint objects
  * Open ports become Endpoint entries with extra metadata
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.recon.canonical_schemas import Endpoint, EndpointMethod, ReconResult
from app.recon.orchestrators.base import BaseOrchestrator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Private-range CIDR blocks that should be excluded by default
# ---------------------------------------------------------------------------
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_private(host: str) -> bool:
    """Return True if *host* resolves to a private/loopback address."""
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in _PRIVATE_RANGES)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# NaabuConfig
# ---------------------------------------------------------------------------

@dataclass
class NaabuConfig:
    """
    Configuration for a Naabu scan.

    Safe defaults are applied automatically:
    - CONNECT scan (no raw-socket root required)
    - Top 1 000 ports
    - 1 000 pps rate limit
    - Private ranges excluded
    """

    scan_type: str = "c"                   # "s" = SYN, "c" = CONNECT
    top_ports: int = 1000                  # used when port_range/ports are not set
    ports: Optional[str] = None            # comma-separated list, e.g. "80,443,8080"
    port_range: Optional[str] = None       # range string, e.g. "1-1024"
    rate_limit: int = 1000                 # packets per second
    threads: int = 25                      # concurrent goroutines inside naabu
    timeout: int = 10                      # per-host timeout (seconds)
    exclude_private: bool = True           # skip RFC-1918 / loopback targets
    max_concurrent_hosts: int = 10         # asyncio-level concurrency cap
    extra_args: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# NaabuOrchestrator
# ---------------------------------------------------------------------------

class NaabuOrchestrator(BaseOrchestrator):
    """
    Async orchestrator for Naabu port scanning.

    Produces a :class:`~app.recon.canonical_schemas.ReconResult` whose
    ``endpoints`` list contains one :class:`~app.recon.canonical_schemas.Endpoint`
    per open (host, port) pair.  The ``extra`` dict on each endpoint carries the
    raw port/protocol/source metadata.
    """

    TOOL_NAME = "naabu"
    BINARY = "naabu"

    def __init__(
        self,
        target: str,
        config: Optional[NaabuConfig] = None,
        project_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> None:
        super().__init__(
            target,
            project_id=project_id,
            task_id=task_id,
            config={},
        )
        self.naabu_config = config or NaabuConfig()

    # ------------------------------------------------------------------
    # Pre-run: skip private hosts
    # ------------------------------------------------------------------

    async def _pre_run(self) -> None:
        if self.naabu_config.exclude_private and _is_private(self.target):
            raise RuntimeError(
                f"Target '{self.target}' is a private/loopback address and "
                "exclude_private is enabled."
            )
        await super()._pre_run()

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def _build_command(self) -> List[str]:
        """Construct the naabu CLI command list."""
        cfg = self.naabu_config
        cmd = [
            "naabu",
            "-host", self.target,
            "-json",
            "-s", cfg.scan_type,
            "-rate", str(cfg.rate_limit),
            "-c", str(cfg.threads),
            "-timeout", str(cfg.timeout),
            "-silent",
            "-no-color",
        ]

        if cfg.ports:
            cmd += ["-p", cfg.ports]
        elif cfg.port_range:
            cmd += ["-p", cfg.port_range]
        else:
            cmd += ["-top-ports", str(cfg.top_ports)]

        cmd += cfg.extra_args
        return cmd

    async def _execute(self) -> List[Dict[str, Any]]:
        """
        Run naabu and return a list of parsed JSON records.

        Each record has at minimum ``{"host": ..., "port": ..., "protocol": ...}``.
        """
        cmd = self._build_command()
        self._logger.debug("naabu command: %s", " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            err = stderr.decode(errors="replace").strip()
            raise RuntimeError(f"naabu exited with code {proc.returncode}: {err}")

        records: List[Dict[str, Any]] = []
        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                self._logger.debug("Skipping non-JSON naabu line: %s", line)

        self._logger.info(
            "naabu found %d open port records on %s", len(records), self.target
        )
        return records

    # ------------------------------------------------------------------
    # Normalisation  →  canonical ReconResult
    # ------------------------------------------------------------------

    def _normalise(self, raw: List[Dict[str, Any]]) -> ReconResult:
        """
        Convert raw naabu JSON records to canonical :class:`ReconResult`.

        Each open port produces one :class:`Endpoint` of the form::

            Endpoint(
                url="tcp://192.168.1.1:443",
                method=EndpointMethod.UNKNOWN,
                extra={"port": 443, "protocol": "tcp", "source": "naabu"},
            )
        """
        endpoints: List[Endpoint] = []

        for record in (raw or []):
            port = record.get("port")
            protocol = record.get("protocol", "tcp")
            host = record.get("host", self.target)

            if port is None:
                continue

            url = f"{protocol}://{host}:{port}"
            ep = Endpoint(
                url=url,
                method=EndpointMethod.UNKNOWN,
                is_live=True,
                discovered_by="naabu",
                tags=["port-scan", protocol],
                extra={
                    "port": int(port),
                    "protocol": protocol,
                    "host": host,
                    "source": "naabu",
                },
            )
            endpoints.append(ep)

        return self._make_result(endpoints=endpoints)

    # ------------------------------------------------------------------
    # Convenience: scan multiple targets concurrently
    # ------------------------------------------------------------------

    @classmethod
    async def scan_targets(
        cls,
        targets: List[str],
        config: Optional[NaabuConfig] = None,
        project_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> List[ReconResult]:
        """
        Scan multiple targets concurrently, honouring ``config.max_concurrent_hosts``.

        Args:
            targets:    List of IPs, CIDRs, or domain names.
            config:     Shared NaabuConfig applied to every scan.
            project_id: Optional project identifier forwarded to each result.
            task_id:    Optional task identifier forwarded to each result.

        Returns:
            List of :class:`ReconResult` objects, one per target.
        """
        cfg = config or NaabuConfig()
        sem = asyncio.Semaphore(cfg.max_concurrent_hosts)

        async def _run_one(target: str) -> ReconResult:
            async with sem:
                orch = cls(
                    target,
                    config=cfg,
                    project_id=project_id,
                    task_id=task_id,
                )
                return await orch.run()

        return list(await asyncio.gather(*[_run_one(t) for t in targets]))

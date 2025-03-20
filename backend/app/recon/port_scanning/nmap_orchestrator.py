"""
Nmap Orchestrator

Extends BaseOrchestrator to run Nmap for detailed service-version detection
and OS fingerprinting.  Results are normalised to canonical Endpoint and
Technology objects so they compose cleanly with NaabuOrchestrator output.

Features
--------
- Service version detection (-sV)
- OS detection (-O, optional)
- Script scanning for common checks (-sC, optional)
- JSON/XML output parsing via python-libnmap or direct XML parsing
- Rate-limited execution via configurable --min-rate / --max-rate
"""
from __future__ import annotations

import asyncio
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import List, Optional

from app.recon.canonical_schemas import Endpoint, EndpointMethod, ReconResult, Technology
from app.recon.orchestrators.base import BaseOrchestrator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# NmapConfig
# ---------------------------------------------------------------------------

@dataclass
class NmapConfig:
    """
    Configuration for an Nmap scan.

    Safe defaults avoid aggressive options that may trigger IDS/IPS.
    """

    ports: Optional[str] = None            # e.g. "22,80,443" or "1-1024"; None → top 1000
    timing_template: int = 3               # -T0…T5; 3 = Normal
    service_version: bool = True           # -sV
    os_detection: bool = False             # -O  (requires root)
    default_scripts: bool = False          # -sC
    min_rate: Optional[int] = None         # --min-rate
    max_rate: Optional[int] = 500          # --max-rate  (conservative default)
    timeout_ms: int = 5000                 # --host-timeout in ms
    extra_args: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# NmapOrchestrator
# ---------------------------------------------------------------------------

class NmapOrchestrator(BaseOrchestrator):
    """
    Async orchestrator for Nmap-based service / version / OS detection.

    Produces a :class:`~app.recon.canonical_schemas.ReconResult` where:

    - Each open port → one ``Endpoint`` (url = ``tcp://<host>:<port>``)
    - Each detected service/product → one ``Technology``
    """

    TOOL_NAME = "nmap"
    BINARY = "nmap"

    def __init__(
        self,
        target: str,
        config: Optional[NmapConfig] = None,
        project_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> None:
        super().__init__(target, project_id=project_id, task_id=task_id, config={})
        self.nmap_config = config or NmapConfig()

    # ------------------------------------------------------------------
    # Build CLI command
    # ------------------------------------------------------------------

    def _build_command(self, output_file: str) -> List[str]:
        cfg = self.nmap_config
        cmd = [
            "nmap",
            "-oX", output_file,          # XML output
            f"-T{cfg.timing_template}",
            "--host-timeout", f"{cfg.timeout_ms}ms",
        ]

        if cfg.ports:
            cmd += ["-p", cfg.ports]
        else:
            cmd += ["--top-ports", "1000"]

        if cfg.service_version:
            cmd.append("-sV")

        if cfg.os_detection:
            cmd.append("-O")

        if cfg.default_scripts:
            cmd.append("-sC")

        if cfg.min_rate is not None:
            cmd += ["--min-rate", str(cfg.min_rate)]

        if cfg.max_rate is not None:
            cmd += ["--max-rate", str(cfg.max_rate)]

        cmd += cfg.extra_args
        cmd.append(self.target)
        return cmd

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def _execute(self) -> str:
        """Run nmap and return raw XML output as a string."""
        import tempfile
        import os

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            tmp_path = tmp.name

        cmd = self._build_command(tmp_path)
        self._logger.debug("nmap command: %s", " ".join(cmd))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()

            if proc.returncode != 0:
                err = stderr.decode(errors="replace").strip()
                raise RuntimeError(f"nmap exited with code {proc.returncode}: {err}")

            with open(tmp_path, "r", errors="replace") as fh:
                xml_data = fh.read()

            return xml_data

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------

    def _normalise(self, raw: str) -> ReconResult:
        """
        Parse nmap XML output and convert to canonical :class:`ReconResult`.

        Open ports → Endpoint objects.
        Service / product / version info → Technology objects.
        """
        endpoints: List[Endpoint] = []
        technologies: List[Technology] = []

        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            self._logger.error("Failed to parse nmap XML: %s", exc)
            return self._make_result()

        for host_el in root.findall(".//host"):
            # Determine host address
            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host_el.find("address[@addrtype='ipv6']")
            host_addr = addr_el.get("addr", self.target) if addr_el is not None else self.target

            ports_el = host_el.find("ports")
            if ports_el is None:
                continue

            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                port_num = int(port_el.get("portid", 0))
                protocol = port_el.get("protocol", "tcp")
                url = f"{protocol}://{host_addr}:{port_num}"

                ep = Endpoint(
                    url=url,
                    method=EndpointMethod.UNKNOWN,
                    is_live=True,
                    discovered_by="nmap",
                    tags=["port-scan", "nmap", protocol],
                    extra={"port": port_num, "protocol": protocol, "host": host_addr},
                )
                endpoints.append(ep)

                # Service / version info → Technology
                svc_el = port_el.find("service")
                if svc_el is not None:
                    svc_name = svc_el.get("name")
                    product = svc_el.get("product")
                    version = svc_el.get("version")
                    cpe_el = port_el.find(".//cpe")

                    if product or svc_name:
                        tech = Technology(
                            name=product or svc_name or "unknown",
                            version=version,
                            category="Service",
                            url=url,
                            cpe=cpe_el.text if cpe_el is not None else None,
                            extra={
                                "port": port_num,
                                "protocol": protocol,
                                "service_name": svc_name,
                            },
                        )
                        technologies.append(tech)

        self._logger.info(
            "nmap: %d endpoints, %d technologies on %s",
            len(endpoints), len(technologies), self.target,
        )
        return self._make_result(endpoints=endpoints, technologies=technologies)

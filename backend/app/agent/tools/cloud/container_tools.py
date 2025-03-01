"""

Three agent tools for container security assessments:

  DockerImageScanTool  — scan Docker images for CVEs using Trivy integration
  DockerfileLintTool   — audit Dockerfiles for security best-practice violations
  ContainerEscapeTool  — test container escape vectors by inspecting the runtime environment

All tools are fully mockable for testing — subprocess calls and file reads are
abstracted behind ``_run_trivy()`` and ``_read_proc_file()`` helpers that tests
can patch.

Tools map to the CLOUD_SECURITY attack category in the AttackPathRouter and are
registered in ``tool_registry.py`` under CONTAINER_SECURITY.
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import truncate_output

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity classification (mirrors aws_tools.CloudFindingSeverity)
# ---------------------------------------------------------------------------


class CloudFindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ---------------------------------------------------------------------------
# Shared regex for secret-like names
# ---------------------------------------------------------------------------

_SECRET_PATTERN = re.compile(
    r"(PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL|PASSWD|PRIVATE_KEY|API_KEY|AUTH)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Dangerous Linux capabilities (decimal bit positions in CapEff hex mask)
# ---------------------------------------------------------------------------

_DANGEROUS_CAPS: Dict[int, str] = {
    21: "CAP_SYS_ADMIN",
    12: "CAP_NET_ADMIN",
    19: "CAP_SYS_PTRACE",
    7:  "CAP_SETUID",
    6:  "CAP_SETGID",
    27: "CAP_SYS_RAWIO",
    17: "CAP_SYS_MODULE",
}

# Full 40-bit effective capability mask (all caps set) — privileged container
_FULL_CAP_MASK = 0x000001FFFFFFFFFF


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------


@dataclass
class ContainerImageFinding:
    image_name: str
    vulnerability_id: str
    severity: CloudFindingSeverity
    package_name: str
    installed_version: str
    fixed_version: str
    title: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "image_name": self.image_name,
            "vulnerability_id": self.vulnerability_id,
            "severity": self.severity.value,
            "package_name": self.package_name,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "title": self.title,
        }


@dataclass
class DockerfileFinding:
    line_number: int
    instruction: str
    issue: str
    severity: CloudFindingSeverity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "line_number": self.line_number,
            "instruction": self.instruction,
            "issue": self.issue,
            "severity": self.severity.value,
        }


@dataclass
class EscapeFinding:
    vector: str
    severity: CloudFindingSeverity
    description: str
    evidence: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vector": self.vector,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
        }


# ---------------------------------------------------------------------------
# DockerImageScanTool
# ---------------------------------------------------------------------------


class DockerImageScanTool(BaseTool):
    """
    Scan Docker images for CVEs using Trivy integration.

    Checks:
      - CVEs across all severities (CRITICAL / HIGH / MEDIUM / LOW)
      - 'latest' tag usage as a best-practice warning
      - Missing Trivy installation (informational finding)

    The ``_run_trivy()`` method is intentionally thin so tests can patch it
    without spawning real subprocesses.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="docker_image_scan",
            description="Scan a Docker image for CVEs and security vulnerabilities using Trivy",
            parameters={
                "type": "object",
                "properties": {
                    "image": {
                        "type": "string",
                        "description": "Docker image name/tag to scan (e.g. nginx:latest)",
                    },
                },
                "required": ["image"],
            },
        )

    async def execute(self, image: str = "", **kwargs: Any) -> str:
        if not image:
            return json.dumps({"error": "image parameter is required", "status": "invalid_input"})

        findings, best_practice_issues = self._run_scan(image)

        severity_counts = {s.value: 0 for s in CloudFindingSeverity}
        for f in findings:
            severity_counts[f.severity.value] += 1

        result = {
            "status": "complete",
            "image": image,
            "vulnerability_count": len(findings),
            "severity_counts": severity_counts,
            "best_practice_issues": best_practice_issues,
            "findings": [f.to_dict() for f in findings],
        }
        return truncate_output(json.dumps(result, indent=2))

    def _run_scan(self, image: str) -> Tuple[List[ContainerImageFinding], List[str]]:
        """Core scan logic — separated for easy unit testing."""
        best_practice_issues: List[str] = []

        # Best-practice: warn on 'latest' tag
        if image.endswith(":latest") or ":" not in image:
            best_practice_issues.append(
                "Image uses 'latest' tag — pin to a specific digest for reproducibility and security"
            )

        trivy_output = self._run_trivy(image)
        if trivy_output is None:
            # Trivy not installed or invocation failed
            return (
                [
                    ContainerImageFinding(
                        image_name=image,
                        vulnerability_id="TOOL-NOT-INSTALLED",
                        severity=CloudFindingSeverity.INFO,
                        package_name="trivy",
                        installed_version="",
                        fixed_version="",
                        title="Trivy scanner is not installed — install from https://aquasecurity.github.io/trivy",
                    )
                ],
                best_practice_issues,
            )

        findings = self._parse_trivy_output(image, trivy_output)
        return findings, best_practice_issues

    def _run_trivy(self, image: str) -> Optional[Dict[str, Any]]:
        """
        Invoke Trivy and return parsed JSON output.

        Returns ``None`` if Trivy is not installed or the invocation fails.
        This method is intentionally thin so tests can patch it.
        """
        try:
            proc = subprocess.run(
                ["trivy", "image", "--format", "json", "--quiet", image],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if proc.returncode not in (0, 1):
                logger.warning("Trivy exited with code %d: %s", proc.returncode, proc.stderr[:200])
                return None
            return json.loads(proc.stdout)
        except FileNotFoundError:
            logger.info("Trivy not found in PATH")
            return None
        except (json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
            logger.warning("Trivy invocation failed: %s", exc)
            return None

    def _parse_trivy_output(self, image: str, trivy_data: Dict[str, Any]) -> List[ContainerImageFinding]:
        """Parse Trivy JSON output into ContainerImageFinding objects."""
        findings: List[ContainerImageFinding] = []
        _sev_map = {
            "CRITICAL": CloudFindingSeverity.CRITICAL,
            "HIGH": CloudFindingSeverity.HIGH,
            "MEDIUM": CloudFindingSeverity.MEDIUM,
            "LOW": CloudFindingSeverity.LOW,
        }

        for result in trivy_data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []) or []:
                raw_sev = vuln.get("Severity", "LOW").upper()
                severity = _sev_map.get(raw_sev, CloudFindingSeverity.LOW)
                findings.append(
                    ContainerImageFinding(
                        image_name=image,
                        vulnerability_id=vuln.get("VulnerabilityID", ""),
                        severity=severity,
                        package_name=vuln.get("PkgName", ""),
                        installed_version=vuln.get("InstalledVersion", ""),
                        fixed_version=vuln.get("FixedVersion", ""),
                        title=vuln.get("Title", ""),
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# DockerfileLintTool
# ---------------------------------------------------------------------------


class DockerfileLintTool(BaseTool):
    """
    Audit Dockerfiles for security best-practice violations.

    Checks:
      - USER root / missing USER instruction
      - COPY . . (broad copy)
      - ADD with remote URLs
      - Secrets/passwords in ENV or ARG
      - Insecure curl/wget flags (--no-check-certificate, -k)
      - FROM with 'latest' tag
      - Missing HEALTHCHECK
      - Multiple CMD / ENTRYPOINT directives
      - apt-get without pinned versions
      - chmod 777 combined with root execution
    """

    # Regex patterns used in line-by-line analysis
    _ADD_URL_RE = re.compile(r"^ADD\s+https?://", re.IGNORECASE)
    _ENV_SECRET_RE = re.compile(
        r"^(?:ENV|ARG)\s+(" + _SECRET_PATTERN.pattern + r")\s*[=\s]",
        re.IGNORECASE,
    )
    _INSECURE_CURL_RE = re.compile(
        r"(--no-check-certificate|curl\s[^#]*-[a-zA-Z]*k[a-zA-Z]*\s)",
        re.IGNORECASE,
    )
    _FROM_LATEST_RE = re.compile(r"^FROM\s+\S+:latest(\s|$)", re.IGNORECASE)
    _FROM_NO_TAG_RE = re.compile(r"^FROM\s+(?!scratch)(\S+?)(\s|$)(?!.*:)", re.IGNORECASE)

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="dockerfile_lint",
            description="Audit a Dockerfile for security misconfigurations and best-practice violations",
            parameters={
                "type": "object",
                "properties": {
                    "dockerfile_path": {
                        "type": "string",
                        "description": "Path to the Dockerfile on disk",
                    },
                    "dockerfile_content": {
                        "type": "string",
                        "description": "Raw Dockerfile content (alternative to dockerfile_path)",
                    },
                },
            },
        )

    async def execute(
        self,
        dockerfile_path: str = "",
        dockerfile_content: str = "",
        **kwargs: Any,
    ) -> str:
        content = self._resolve_content(dockerfile_path, dockerfile_content)
        if content is None:
            return json.dumps({
                "error": "Provide either dockerfile_path or dockerfile_content",
                "status": "invalid_input",
            })

        findings = self._lint(content)
        severity_counts = {s.value: 0 for s in CloudFindingSeverity}
        for f in findings:
            severity_counts[f.severity.value] += 1

        result = {
            "status": "complete",
            "source": dockerfile_path or "<inline>",
            "finding_count": len(findings),
            "severity_counts": severity_counts,
            "findings": [f.to_dict() for f in findings],
        }
        return truncate_output(json.dumps(result, indent=2))

    def _resolve_content(
        self, path: str, content: str
    ) -> Optional[str]:
        """Return Dockerfile text from inline content or file path."""
        if content:
            return content
        if path:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    return fh.read()
            except OSError as exc:
                logger.error("Cannot read Dockerfile at %s: %s", path, exc)
                return None
        return None

    def _lint(self, content: str) -> List[DockerfileFinding]:
        """Core lint logic — separated for easy unit testing."""
        findings: List[DockerfileFinding] = []
        lines = content.splitlines()

        has_user_instruction = False
        has_healthcheck = False
        cmd_count = 0
        entrypoint_count = 0
        running_as_root = True  # assume root until USER non-root seen

        for lineno, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            line.upper()
            instruction = line.split()[0].upper() if line.split() else ""

            # USER instruction
            if instruction == "USER":
                has_user_instruction = True
                user_val = line.split(None, 1)[1].strip() if len(line.split(None, 1)) > 1 else ""
                if user_val.lower() in ("root", "0"):
                    running_as_root = True
                    findings.append(DockerfileFinding(
                        line_number=lineno,
                        instruction="USER",
                        issue="Container runs as root — use a non-root USER for least privilege",
                        severity=CloudFindingSeverity.HIGH,
                    ))
                else:
                    running_as_root = False

            # COPY . .
            elif instruction == "COPY":
                rest = line.split(None, 1)[1].strip() if len(line.split(None, 1)) > 1 else ""
                # strip optional --chown / --chmod flags
                rest_clean = re.sub(r"--\S+\s+", "", rest).strip()
                if re.match(r"^\.\s+\.$", rest_clean) or re.match(r"^\.\s+/", rest_clean):
                    findings.append(DockerfileFinding(
                        line_number=lineno,
                        instruction="COPY",
                        issue="COPY . copies entire build context — use .dockerignore to exclude sensitive files",
                        severity=CloudFindingSeverity.MEDIUM,
                    ))

            # ADD with URL
            elif instruction == "ADD":
                if self._ADD_URL_RE.match(line):
                    findings.append(DockerfileFinding(
                        line_number=lineno,
                        instruction="ADD",
                        issue="ADD with a remote URL fetches content at build time without integrity verification — use curl with --fail and checksum verification instead",
                        severity=CloudFindingSeverity.HIGH,
                    ))

            # ENV / ARG with secret names
            elif instruction in ("ENV", "ARG"):
                if self._ENV_SECRET_RE.match(line):
                    matched = self._ENV_SECRET_RE.match(line)
                    key_name = matched.group(1) if matched else "UNKNOWN"
                    findings.append(DockerfileFinding(
                        line_number=lineno,
                        instruction=instruction,
                        issue=f"Sensitive variable '{key_name}' in Dockerfile — use Docker BuildKit secrets or runtime environment injection instead",
                        severity=CloudFindingSeverity.CRITICAL,
                    ))

            # FROM with latest tag
            elif instruction == "FROM":
                if self._FROM_LATEST_RE.match(line):
                    findings.append(DockerfileFinding(
                        line_number=lineno,
                        instruction="FROM",
                        issue="Base image uses 'latest' tag — pin to a specific version or digest for reproducible builds",
                        severity=CloudFindingSeverity.MEDIUM,
                    ))
                elif self._FROM_NO_TAG_RE.match(line):
                    findings.append(DockerfileFinding(
                        line_number=lineno,
                        instruction="FROM",
                        issue="Base image has no tag — implicitly pulls 'latest'; pin to a specific version or digest",
                        severity=CloudFindingSeverity.MEDIUM,
                    ))
                # Reset state for multi-stage builds
                has_user_instruction = False
                running_as_root = True

            # HEALTHCHECK
            elif instruction == "HEALTHCHECK":
                has_healthcheck = True

            # CMD / ENTRYPOINT counts
            elif instruction == "CMD":
                cmd_count += 1
            elif instruction == "ENTRYPOINT":
                entrypoint_count += 1

            # RUN checks (insecure flags, chmod 777, apt-get unpinned)
            if instruction == "RUN":
                run_body = line.split(None, 1)[1] if len(line.split(None, 1)) > 1 else ""

                if self._INSECURE_CURL_RE.search(run_body):
                    findings.append(DockerfileFinding(
                        line_number=lineno,
                        instruction="RUN",
                        issue="Insecure TLS flag detected (--no-check-certificate or curl -k) — remove to enforce certificate validation",
                        severity=CloudFindingSeverity.HIGH,
                    ))

                if "chmod 777" in run_body or "chmod -R 777" in run_body:
                    sev = CloudFindingSeverity.HIGH if running_as_root else CloudFindingSeverity.MEDIUM
                    findings.append(DockerfileFinding(
                        line_number=lineno,
                        instruction="RUN",
                        issue="chmod 777 grants world-writable permissions — use least-privilege file modes",
                        severity=sev,
                    ))

                # apt-get install without pinned versions (package=1.2.3 syntax)
                if re.search(r"apt-get\s+install\b", run_body, re.IGNORECASE):
                    if not re.search(r"\w+=[\w.\-]+", run_body):
                        findings.append(DockerfileFinding(
                            line_number=lineno,
                            instruction="RUN",
                            issue="apt-get install without pinned package versions — pin versions for reproducible builds (e.g. package=1.2.3)",
                            severity=CloudFindingSeverity.LOW,
                        ))

        # Post-loop checks
        if not has_user_instruction or running_as_root:
            findings.append(DockerfileFinding(
                line_number=0,
                instruction="(global)",
                issue="No non-root USER instruction found — container will run as root by default",
                severity=CloudFindingSeverity.HIGH,
            ))

        if not has_healthcheck:
            findings.append(DockerfileFinding(
                line_number=0,
                instruction="(global)",
                issue="No HEALTHCHECK instruction — orchestrators cannot detect unhealthy containers",
                severity=CloudFindingSeverity.LOW,
            ))

        if cmd_count > 1:
            findings.append(DockerfileFinding(
                line_number=0,
                instruction="(global)",
                issue=f"Multiple CMD instructions ({cmd_count}) — only the last CMD takes effect; remove duplicates",
                severity=CloudFindingSeverity.MEDIUM,
            ))

        if entrypoint_count > 1:
            findings.append(DockerfileFinding(
                line_number=0,
                instruction="(global)",
                issue=f"Multiple ENTRYPOINT instructions ({entrypoint_count}) — only the last takes effect; remove duplicates",
                severity=CloudFindingSeverity.MEDIUM,
            ))

        return findings


# ---------------------------------------------------------------------------
# ContainerEscapeTool
# ---------------------------------------------------------------------------


class ContainerEscapeTool(BaseTool):
    """
    Test container escape vectors by inspecting the runtime environment.

    Checks:
      - Whether code is running inside a container (cgroup detection)
      - Privileged mode (full effective capability mask)
      - Dangerous individual capabilities (CAP_SYS_ADMIN, etc.)
      - Host PID namespace sharing
      - Host network namespace sharing
      - Writable host filesystem mounts
      - Docker socket accessible from within the container
      - Kubernetes service account token present

    All file reads go through ``_read_proc_file()`` so tests can patch it.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="container_escape",
            description=(
                "Inspect container runtime environment for escape vectors "
                "(privileged mode, dangerous capabilities, host namespace sharing, "
                "writable host mounts, docker socket access)"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "container_id": {
                        "type": "string",
                        "description": "Container ID (informational only — checks run on current process environment)",
                    },
                },
            },
        )

    async def execute(self, container_id: str = "", **kwargs: Any) -> str:
        in_container, container_evidence = self._check_in_container()
        findings = self._run_checks()

        result = {
            "status": "complete",
            "container_id": container_id or "current",
            "in_container": in_container,
            "container_evidence": container_evidence,
            "finding_count": len(findings),
            "critical": sum(1 for f in findings if f.severity == CloudFindingSeverity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == CloudFindingSeverity.HIGH),
            "findings": [f.to_dict() for f in findings],
        }
        return truncate_output(json.dumps(result, indent=2))

    # ------------------------------------------------------------------
    # Mockable file-system helper
    # ------------------------------------------------------------------

    def _read_proc_file(self, path: str) -> Optional[str]:
        """
        Read a procfs / sysfs file and return its contents as a string.

        Returns ``None`` on any I/O error. Tests can replace this method to
        simulate arbitrary runtime environments without root privileges.
        """
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None

    # ------------------------------------------------------------------
    # Individual escape-vector detectors
    # ------------------------------------------------------------------

    def _check_in_container(self) -> Tuple[bool, str]:
        """Detect if we are running inside a container via cgroup info."""
        cgroup = self._read_proc_file("/proc/1/cgroup")
        if cgroup is None:
            return False, "Cannot read /proc/1/cgroup"
        indicators = ["docker", "containerd", "kubepods", "lxc", "/container"]
        for indicator in indicators:
            if indicator in cgroup.lower():
                return True, f"cgroup entry contains '{indicator}'"
        # Fallback: /.dockerenv file
        if os.path.exists("/.dockerenv"):
            return True, "/.dockerenv present"
        return False, "No container indicators found in cgroup"

    def _check_privileged_mode(self) -> Optional[EscapeFinding]:
        """Check if effective capabilities match a fully privileged container."""
        status = self._read_proc_file("/proc/self/status")
        if status is None:
            return None
        for line in status.splitlines():
            if line.startswith("CapEff:"):
                hex_val = line.split(":", 1)[1].strip()
                try:
                    cap_eff = int(hex_val, 16)
                except ValueError:
                    return None
                if cap_eff & _FULL_CAP_MASK == _FULL_CAP_MASK:
                    return EscapeFinding(
                        vector="privileged_mode",
                        severity=CloudFindingSeverity.CRITICAL,
                        description=(
                            "Container is running in privileged mode — all Linux capabilities "
                            "are granted, enabling host filesystem and device access"
                        ),
                        evidence=f"CapEff={hex_val} (all capabilities set)",
                    )
        return None

    def _check_dangerous_capabilities(self) -> List[EscapeFinding]:
        """Check for individual high-risk capabilities."""
        status = self._read_proc_file("/proc/self/status")
        if status is None:
            return []
        cap_eff = 0
        for line in status.splitlines():
            if line.startswith("CapEff:"):
                try:
                    cap_eff = int(line.split(":", 1)[1].strip(), 16)
                except ValueError:
                    return []
                break

        findings = []
        for bit, cap_name in _DANGEROUS_CAPS.items():
            if cap_eff & (1 << bit):
                findings.append(EscapeFinding(
                    vector=f"capability_{cap_name.lower()}",
                    severity=CloudFindingSeverity.HIGH,
                    description=(
                        f"{cap_name} is granted — this capability can be abused to "
                        "escape container isolation or escalate privileges on the host"
                    ),
                    evidence=f"CapEff bit {bit} set (CapEff=0x{cap_eff:016x})",
                ))
        return findings

    def _check_host_pid_namespace(self) -> Optional[EscapeFinding]:
        """
        Detect host PID namespace sharing.

        If /proc/1/sched is readable and the first line shows a process named
        something other than the container init (e.g. 'systemd' or a host process),
        the host PID namespace is likely shared.
        """
        sched = self._read_proc_file("/proc/1/sched")
        if sched is None:
            return None
        # Container init processes usually show a low PID (1) in the first line.
        # When hostPID=true the line contains the host PID (>1 typically).
        first_line = sched.splitlines()[0] if sched else ""
        # Pattern: "comm (pid, #threads: N, ...)"
        match = re.search(r"\((\d+),", first_line)
        if match:
            pid = int(match.group(1))
            if pid != 1:
                return EscapeFinding(
                    vector="host_pid_namespace",
                    severity=CloudFindingSeverity.HIGH,
                    description=(
                        "Host PID namespace is shared — container can see and signal "
                        "all host processes"
                    ),
                    evidence=f"/proc/1/sched shows pid={pid} (expected 1 in isolated namespace)",
                )
        return None

    def _check_host_network_namespace(self) -> Optional[EscapeFinding]:
        """Detect host network namespace sharing via inode comparison."""
        try:
            self_net_inode = os.stat("/proc/self/ns/net").st_ino
            host_net_inode = os.stat("/proc/1/ns/net").st_ino
        except OSError:
            return None

        if self_net_inode == host_net_inode:
            return EscapeFinding(
                vector="host_network_namespace",
                severity=CloudFindingSeverity.HIGH,
                description=(
                    "Host network namespace is shared — container has direct access to "
                    "host network interfaces and can sniff or spoof host traffic"
                ),
                evidence=f"/proc/self/ns/net and /proc/1/ns/net share inode {self_net_inode}",
            )
        return None

    def _check_writable_host_mounts(self) -> List[EscapeFinding]:
        """Check /proc/mounts for writable bind-mounts of host filesystem paths."""
        mounts_data = self._read_proc_file("/proc/mounts")
        if mounts_data is None:
            return []

        # Sensitive host paths that should not be writable from a container
        _SENSITIVE_PATHS = {"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/sys/firmware"}
        findings = []
        for line in mounts_data.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            mount_point = parts[1]
            options = parts[3]
            if any(mount_point == sp or mount_point.startswith(sp + "/") for sp in _SENSITIVE_PATHS):
                if "rw" in options.split(","):
                    findings.append(EscapeFinding(
                        vector="writable_host_mount",
                        severity=CloudFindingSeverity.CRITICAL,
                        description=(
                            f"Sensitive host path '{mount_point}' is mounted read-write — "
                            "an attacker can modify host system files to escape the container"
                        ),
                        evidence=f"Mount entry: {line}",
                    ))
        return findings

    def _check_docker_socket(self) -> Optional[EscapeFinding]:
        """Check if the Docker socket is accessible from within the container."""
        sock_path = "/var/run/docker.sock"
        try:
            stat = os.stat(sock_path)
            # S_ISSOCK
            import stat as stat_mod
            if stat_mod.S_ISSOCK(stat.st_mode):
                return EscapeFinding(
                    vector="docker_socket_mount",
                    severity=CloudFindingSeverity.CRITICAL,
                    description=(
                        "Docker socket is mounted inside the container — an attacker can "
                        "use it to create privileged containers and escape to the host"
                    ),
                    evidence=f"{sock_path} is accessible (inode {stat.st_ino})",
                )
        except OSError:
            pass
        return None

    def _check_k8s_service_account(self) -> Optional[EscapeFinding]:
        """Check for a mounted Kubernetes service account token."""
        token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        token = self._read_proc_file(token_path)
        if token and len(token.strip()) > 10:
            # Peek at audience without full JWT decode
            preview = token.strip()[:40] + "…"
            return EscapeFinding(
                vector="k8s_service_account_token",
                severity=CloudFindingSeverity.HIGH,
                description=(
                    "Kubernetes service account token is mounted — if the token has "
                    "cluster-admin or wide permissions, it can be used to compromise "
                    "the entire cluster"
                ),
                evidence=f"Token present at {token_path}: {preview}",
            )
        return None

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    def _run_checks(self) -> List[EscapeFinding]:
        """Run all escape-vector checks and aggregate findings."""
        findings: List[EscapeFinding] = []

        priv = self._check_privileged_mode()
        if priv:
            findings.append(priv)
            # Skip individual capability checks — all are set in privileged mode
        else:
            findings.extend(self._check_dangerous_capabilities())

        pid_finding = self._check_host_pid_namespace()
        if pid_finding:
            findings.append(pid_finding)

        net_finding = self._check_host_network_namespace()
        if net_finding:
            findings.append(net_finding)

        findings.extend(self._check_writable_host_mounts())

        sock_finding = self._check_docker_socket()
        if sock_finding:
            findings.append(sock_finding)

        sa_finding = self._check_k8s_service_account()
        if sa_finding:
            findings.append(sa_finding)

        return findings


# ---------------------------------------------------------------------------
# Public tool list
# ---------------------------------------------------------------------------

CONTAINER_TOOLS: List[BaseTool] = [
    DockerImageScanTool(),
    DockerfileLintTool(),
    ContainerEscapeTool(),
]

__all__ = [
    "DockerImageScanTool",
    "DockerfileLintTool",
    "ContainerEscapeTool",
    "CONTAINER_TOOLS",
    "ContainerImageFinding",
    "DockerfileFinding",
    "EscapeFinding",
    "CloudFindingSeverity",
]

"""
UniVex Interactive TUI Installer

Provides:
  - Prerequisite checking (Docker/Podman, RAM, disk, ports)
  - LLM provider selection and API key collection
  - Feature selection (MinIO, Langfuse, Searxng, ClickHouse, etc.)
  - Port conflict detection and alternative port suggestion
  - Automatic .env file generation
  - Health check with service status summary

Usage::

    from app.installer.tui_installer import InstallerConfig, PrerequisiteChecker
    from app.installer.tui_installer import EnvFileGenerator, PortChecker

    checker = PrerequisiteChecker()
    results = checker.check_all()

    config = InstallerConfig(llm_provider="openai", openai_api_key="<your-key>")
    gen = EnvFileGenerator(config)
    content = gen.generate()
"""
from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

UNIVEX_ASCII_LOGO = r"""
 _   _       _  _     _
| | | |_ __ (_)| |   | | _____ __
| | | | '_ \| || |   | |/ _ \ \/ /
| |_| | | | | || |___| |  __/>  <
 \___/|_| |_|_||_____|_|\___/_/\_\
         UniVex — v1.0.0

   AI-Powered Penetration Testing Framework
   Version 1.0.0 · Author: BitR1FT · MIT License
"""

# Minimum hardware requirements
MIN_RAM_GB = 4
MIN_DISK_GB = 20

# Default ports and service names
DEFAULT_PORTS: Dict[str, int] = {
    "frontend": 3000,
    "backend": 8000,
    "postgres": 5432,
    "neo4j_bolt": 7687,
    "neo4j_http": 7474,
    "redis": 6379,
    "minio": 9000,
    "minio_console": 9001,
    "langfuse": 3010,
    "searxng": 8080,
    "proxy": 8888,
    "proxy_mcp": 8008,
    "oob_http": 8090,
    "prometheus": 9090,
    "grafana": 3030,
    "loki": 3100,
    "jaeger": 16686,
    "clickhouse": 8123,
    "victoria_metrics": 8428,
}

LLM_PROVIDERS = [
    "openai",
    "anthropic",
    "groq",
    "openrouter",
    "bedrock",
    "deepseek",
    "qwen",
    "glm",
    "kimi",
    "vllm",
]

OPTIONAL_FEATURES = [
    "minio",
    "langfuse",
    "searxng",
    "clickhouse",
    "victoria_metrics",
    "jaeger",
    "loki",
]

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class PrerequisiteResult:
    """Result of a single prerequisite check."""

    name: str
    passed: bool
    message: str
    severity: str = "error"  # "error" | "warning" | "info"


@dataclass
class InstallerConfig:
    """
    Configuration collected during the interactive install session.

    All fields have safe defaults so unit tests can construct minimal configs.
    """

    # Runtime
    container_runtime: str = "docker"  # "docker" | "podman"

    # LLM provider
    llm_provider: str = "openai"
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    groq_api_key: str = ""
    openrouter_api_key: str = ""
    deepseek_api_key: str = ""
    qwen_api_key: str = ""
    glm_api_key: str = ""
    kimi_api_key: str = ""
    vllm_base_url: str = "http://localhost:8080"

    # AWS Bedrock
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_region: str = "us-east-1"

    # Security
    secret_key: str = ""
    postgres_password: str = ""
    neo4j_password: str = ""
    grafana_password: str = ""

    # Optional features enabled
    enabled_features: List[str] = field(default_factory=list)

    # Port overrides (service → port)
    port_overrides: Dict[str, int] = field(default_factory=dict)

    # Embedding provider
    embedding_provider: str = "openai"

    # Environment mode
    environment: str = "production"

    # Compose file path
    compose_file: str = "docker-compose.yml"

    # Output path for .env
    env_output_path: str = ".env"


# ---------------------------------------------------------------------------
# Prerequisite checking
# ---------------------------------------------------------------------------


class PrerequisiteChecker:
    """
    Validates system prerequisites before installation.

    Checks Docker/Podman availability, RAM, free disk, and port availability.
    Each check returns a :class:`PrerequisiteResult` so callers can display
    or act on individual results.
    """

    def __init__(self, runtime: str = "docker") -> None:
        self.runtime = runtime

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def check_runtime(self) -> PrerequisiteResult:
        """Verify Docker or Podman is installed and the daemon is reachable."""
        binary = self.runtime  # "docker" or "podman"
        binary_path = shutil.which(binary)
        if not binary_path:
            return PrerequisiteResult(
                name="container_runtime",
                passed=False,
                message=f"{binary} not found in PATH. Install it first.",
                severity="error",
            )

        # Try a lightweight version check to confirm the daemon is alive
        try:
            result = subprocess.run(
                [binary, "version", "--format", "{{.Server.Version}}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                version = result.stdout.strip() or "unknown"
                return PrerequisiteResult(
                    name="container_runtime",
                    passed=True,
                    message=f"{binary} daemon running (server {version})",
                    severity="info",
                )
            # daemon not running
            return PrerequisiteResult(
                name="container_runtime",
                passed=False,
                message=f"{binary} is installed but the daemon is not running. Start it first.",
                severity="error",
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return PrerequisiteResult(
                name="container_runtime",
                passed=False,
                message=f"Could not reach {binary} daemon.",
                severity="error",
            )

    def check_compose(self) -> PrerequisiteResult:
        """Verify compose is available (docker compose plugin or podman-compose)."""
        if self.runtime == "podman":
            binary = shutil.which("podman-compose")
            if binary:
                return PrerequisiteResult(
                    name="compose",
                    passed=True,
                    message="podman-compose available",
                    severity="info",
                )
            return PrerequisiteResult(
                name="compose",
                passed=False,
                message="podman-compose not found. Install with: pip install podman-compose",
                severity="error",
            )
        # Docker — try `docker compose` plugin first, then standalone
        try:
            result = subprocess.run(
                ["docker", "compose", "version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return PrerequisiteResult(
                    name="compose",
                    passed=True,
                    message="docker compose plugin available",
                    severity="info",
                )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return PrerequisiteResult(
            name="compose",
            passed=False,
            message="Docker Compose plugin not found. Upgrade Docker Desktop or install the compose plugin.",
            severity="error",
        )

    def check_ram(self) -> PrerequisiteResult:
        """Check available system RAM against the minimum requirement."""
        try:
            meminfo = Path("/proc/meminfo")
            if meminfo.exists():
                data = meminfo.read_text()
                for line in data.splitlines():
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        gb = kb / (1024 ** 2)
                        if gb >= MIN_RAM_GB:
                            return PrerequisiteResult(
                                name="ram",
                                passed=True,
                                message=f"{gb:.1f} GB RAM available (minimum {MIN_RAM_GB} GB)",
                                severity="info",
                            )
                        return PrerequisiteResult(
                            name="ram",
                            passed=False,
                            message=f"Only {gb:.1f} GB RAM found; {MIN_RAM_GB} GB required.",
                            severity="warning",
                        )
        except Exception:  # noqa: BLE001
            pass

        return PrerequisiteResult(
            name="ram",
            passed=True,
            message="RAM check skipped (not on Linux)",
            severity="warning",
        )

    def check_disk(self, path: str = ".") -> PrerequisiteResult:
        """Check free disk space at *path* against the minimum requirement."""
        try:
            usage = shutil.disk_usage(path)
            free_gb = usage.free / (1024 ** 3)
            if free_gb >= MIN_DISK_GB:
                return PrerequisiteResult(
                    name="disk",
                    passed=True,
                    message=f"{free_gb:.1f} GB free disk space (minimum {MIN_DISK_GB} GB)",
                    severity="info",
                )
            return PrerequisiteResult(
                name="disk",
                passed=False,
                message=f"Only {free_gb:.1f} GB free; {MIN_DISK_GB} GB required.",
                severity="warning",
            )
        except Exception:  # noqa: BLE001
            return PrerequisiteResult(
                name="disk",
                passed=True,
                message="Disk check failed — proceeding anyway",
                severity="warning",
            )

    def check_python_version(self) -> PrerequisiteResult:
        """Ensure Python 3.10+ is available."""
        major, minor = sys.version_info[:2]
        if major >= 3 and minor >= 10:
            return PrerequisiteResult(
                name="python_version",
                passed=True,
                message=f"Python {major}.{minor} detected (3.10+ required)",
                severity="info",
            )
        return PrerequisiteResult(
            name="python_version",
            passed=False,
            message=f"Python {major}.{minor} detected; 3.10+ required.",
            severity="error",
        )

    # ------------------------------------------------------------------
    # Aggregate
    # ------------------------------------------------------------------

    def check_all(self) -> List[PrerequisiteResult]:
        """Run all prerequisite checks and return a list of results."""
        return [
            self.check_runtime(),
            self.check_compose(),
            self.check_ram(),
            self.check_disk(),
            self.check_python_version(),
        ]

    def all_passed(self, results: Optional[List[PrerequisiteResult]] = None) -> bool:
        """Return True only when every *error*-severity check has passed."""
        if results is None:
            results = self.check_all()
        return all(r.passed for r in results if r.severity == "error")


# ---------------------------------------------------------------------------
# Port conflict detection
# ---------------------------------------------------------------------------


class PortChecker:
    """
    Detects port conflicts and suggests alternatives.

    Uses a raw socket bind attempt to discover whether a port is already
    in use — works without requiring elevated privileges.
    """

    def is_port_in_use(self, port: int, host: str = "127.0.0.1") -> bool:
        """Return True if *port* on *host* is already in use."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((host, port))
                return False
            except OSError:
                return True

    def suggest_alternative(self, port: int, max_attempts: int = 20) -> int:
        """
        Find the next available port starting from *port + 1*.

        Args:
            port:         Conflicting port to start from.
            max_attempts: Maximum ports to try before giving up.

        Returns:
            An available port number.

        Raises:
            RuntimeError: If no available port is found within *max_attempts*.
        """
        for candidate in range(port + 1, port + max_attempts + 1):
            if not self.is_port_in_use(candidate):
                return candidate
        raise RuntimeError(
            f"Could not find an available port near {port} after {max_attempts} attempts."
        )

    def check_all_ports(
        self, ports: Optional[Dict[str, int]] = None
    ) -> Dict[str, Tuple[int, bool, Optional[int]]]:
        """
        Check all default service ports.

        Returns:
            A dict mapping service name → (requested_port, in_use, suggested_alt).
            ``suggested_alt`` is ``None`` when the port is free.
        """
        if ports is None:
            ports = DEFAULT_PORTS
        results: Dict[str, Tuple[int, bool, Optional[int]]] = {}
        for service, port in ports.items():
            in_use = self.is_port_in_use(port)
            alt: Optional[int] = None
            if in_use:
                try:
                    alt = self.suggest_alternative(port)
                except RuntimeError:
                    pass
            results[service] = (port, in_use, alt)
        return results


# ---------------------------------------------------------------------------
# .env file generation
# ---------------------------------------------------------------------------


class EnvFileGenerator:
    """
    Generates a production-ready .env file from an :class:`InstallerConfig`.

    The output is deterministic for a given config so that it can be
    compared/diffed against an existing .env during upgrades.
    """

    def __init__(self, config: InstallerConfig) -> None:
        self.config = config
        # Pre-generate all secrets so generate() is idempotent for this instance
        self._secret_key = self._resolve_secret(config.secret_key, 64)
        self._postgres_password = self._resolve_secret(config.postgres_password, 32)
        self._neo4j_password = self._resolve_secret(config.neo4j_password, 32)
        self._grafana_password = self._resolve_secret(config.grafana_password, 32)

    # ------------------------------------------------------------------
    # Secret generation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_secret(length: int = 64) -> str:
        """Generate a hex secret of *length* hex characters (length/2 bytes)."""
        import secrets as _secrets  # noqa: PLC0415
        return _secrets.token_hex(length // 2)

    def _resolve_secret(self, provided: str, length: int = 64) -> str:
        """Use *provided* if non-empty, otherwise generate a new secret."""
        return provided if provided else self._generate_secret(length)

    # ------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------

    def _core_section(self) -> str:
        return f"""# ===========================================================================
# Core
# ===========================================================================
ENVIRONMENT={self.config.environment}
SECRET_KEY={self._secret_key}
DEBUG=false
"""

    def _database_section(self) -> str:
        return f"""# ===========================================================================
# Databases
# ===========================================================================
POSTGRES_USER=univex
POSTGRES_PASSWORD={self._postgres_password}
POSTGRES_DB=univex
POSTGRES_HOST=postgres
POSTGRES_PORT=5432

NEO4J_URI=bolt://neo4j:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD={self._neo4j_password}
NEO4J_DATABASE=neo4j

REDIS_URL=redis://redis:6379/0
"""

    def _llm_section(self) -> str:
        c = self.config
        lines = ["# ===========================================================================",
                 "# LLM Provider",
                 "# ===========================================================================",
                 f"DEFAULT_LLM_PROVIDER={c.llm_provider}"]
        if c.openai_api_key:
            lines.append(f"OPENAI_API_KEY={c.openai_api_key}")
        if c.anthropic_api_key:
            lines.append(f"ANTHROPIC_API_KEY={c.anthropic_api_key}")
        if c.groq_api_key:
            lines.append(f"GROQ_API_KEY={c.groq_api_key}")
        if c.openrouter_api_key:
            lines.append(f"OPENROUTER_API_KEY={c.openrouter_api_key}")
        if c.deepseek_api_key:
            lines.append(f"DEEPSEEK_API_KEY={c.deepseek_api_key}")
        if c.qwen_api_key:
            lines.append(f"QWEN_API_KEY={c.qwen_api_key}")
        if c.glm_api_key:
            lines.append(f"GLM_API_KEY={c.glm_api_key}")
        if c.kimi_api_key:
            lines.append(f"KIMI_API_KEY={c.kimi_api_key}")
        if c.vllm_base_url:
            lines.append(f"VLLM_BASE_URL={c.vllm_base_url}")
        if c.aws_access_key_id:
            lines.extend([
                f"AWS_ACCESS_KEY_ID={c.aws_access_key_id}",
                f"AWS_SECRET_ACCESS_KEY={c.aws_secret_access_key}",
                f"AWS_DEFAULT_REGION={c.aws_region}",
            ])
        return "\n".join(lines) + "\n"

    def _features_section(self) -> str:
        lines = ["# ===========================================================================",
                 "# Optional Feature Flags",
                 "# ==========================================================================="]
        for feature in OPTIONAL_FEATURES:
            enabled = "true" if feature in self.config.enabled_features else "false"
            lines.append(f"{feature.upper()}_ENABLED={enabled}")
        return "\n".join(lines) + "\n"

    def _minio_section(self) -> str:
        if "minio" not in self.config.enabled_features:
            return ""
        return """# ===========================================================================
# MinIO Artifact Storage
# ===========================================================================
MINIO_ENDPOINT=minio:9000
MINIO_ACCESS_KEY=univex-access-key
MINIO_SECRET_KEY=univex-secret-key
MINIO_BUCKET=univex-artifacts
MINIO_USE_SSL=false
"""

    def _grafana_section(self) -> str:
        return f"""# ===========================================================================
# Observability
# ===========================================================================
GRAFANA_PASSWORD={self._grafana_password}
PROMETHEUS_URL=http://prometheus:9090
GRAFANA_URL=http://grafana:3030
"""

    def _embedding_section(self) -> str:
        return f"""# ===========================================================================
# Embedding Provider
# ===========================================================================
EMBEDDING_PROVIDER={self.config.embedding_provider}
"""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self) -> str:
        """Generate the complete .env file content as a string."""
        sections = [
            "# UniVex .env — generated by tui_installer.py\n"
            "# Review all values before deploying to production.\n",
            self._core_section(),
            self._database_section(),
            self._llm_section(),
            self._features_section(),
            self._minio_section(),
            self._grafana_section(),
            self._embedding_section(),
        ]
        return "\n".join(s for s in sections if s)

    def write(self, path: Optional[str] = None) -> Path:
        """
        Write the generated .env to *path* (defaults to config.env_output_path).

        Returns:
            The :class:`~pathlib.Path` of the written file.
        """
        output_path = Path(path or self.config.env_output_path)
        output_path.write_text(self.generate(), encoding="utf-8")
        return output_path


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


class ServiceHealthChecker:
    """
    Lightweight HTTP health checker for all UniVex services.

    Uses the standard library ``http.client`` to avoid importing ``httpx``
    or ``requests`` at install time (they may not yet be installed).
    """

    # Service → health check URL path
    HEALTH_ENDPOINTS: Dict[str, Tuple[str, int, str]] = {
        "backend": ("localhost", 8000, "/api/health"),
        "frontend": ("localhost", 3000, "/api/health"),
        "minio": ("localhost", 9000, "/minio/health/live"),
        "prometheus": ("localhost", 9090, "/-/healthy"),
        "grafana": ("localhost", 3030, "/api/health"),
    }

    def check_service(self, host: str, port: int, path: str, timeout: int = 5) -> bool:
        """Return True if the service responds with HTTP 2xx."""
        import http.client  # noqa: PLC0415

        try:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.request("GET", path)
            resp = conn.getresponse()
            return 200 <= resp.status < 300
        except Exception:  # noqa: BLE001
            return False

    def check_all(
        self,
        endpoints: Optional[Dict[str, Tuple[str, int, str]]] = None,
    ) -> Dict[str, bool]:
        """Check all known service health endpoints."""
        eps = endpoints or self.HEALTH_ENDPOINTS
        return {
            name: self.check_service(host, port, path)
            for name, (host, port, path) in eps.items()
        }


# ---------------------------------------------------------------------------
# Compose orchestration helpers
# ---------------------------------------------------------------------------


class ComposeOrchestrator:
    """
    Wraps ``docker compose`` / ``podman-compose`` commands needed during
    the install flow.
    """

    def __init__(
        self,
        compose_file: str = "docker-compose.yml",
        runtime: str = "docker",
    ) -> None:
        self.compose_file = compose_file
        self.runtime = runtime

    def _base_cmd(self) -> List[str]:
        if self.runtime == "podman":
            return ["podman-compose", "-f", self.compose_file]
        return ["docker", "compose", "-f", self.compose_file]

    def up(
        self,
        services: Optional[List[str]] = None,
        detach: bool = True,
        extra_args: Optional[List[str]] = None,
    ) -> subprocess.CompletedProcess:
        """Run ``compose up``."""
        cmd = [*self._base_cmd(), "up"]
        if detach:
            cmd.append("-d")
        if extra_args:
            cmd.extend(extra_args)
        if services:
            cmd.extend(services)
        return subprocess.run(cmd, capture_output=True, text=True)

    def pull(self) -> subprocess.CompletedProcess:
        """Pull all images."""
        cmd = [*self._base_cmd(), "pull"]
        return subprocess.run(cmd, capture_output=True, text=True)

    def down(self, volumes: bool = False) -> subprocess.CompletedProcess:
        """Stop and remove containers."""
        cmd = [*self._base_cmd(), "down"]
        if volumes:
            cmd.append("-v")
        return subprocess.run(cmd, capture_output=True, text=True)

    def ps(self) -> subprocess.CompletedProcess:
        """List running containers."""
        cmd = [*self._base_cmd(), "ps"]
        return subprocess.run(cmd, capture_output=True, text=True)


# ---------------------------------------------------------------------------
# .env validation
# ---------------------------------------------------------------------------


class EnvValidator:
    """
    Validates a generated or existing .env file for common issues.

    Checks:
    - Required variables are set and non-empty
    - Secret keys meet minimum length requirements
    - No obvious placeholder values are left in place
    """

    REQUIRED_VARS = [
        "SECRET_KEY",
        "POSTGRES_PASSWORD",
        "NEO4J_PASSWORD",
        "ENVIRONMENT",
    ]

    PLACEHOLDER_PATTERNS = [
        r"your-secret-key",
        r"changeme",
        r"change-this",
        r"placeholder",
        r"example",
        r"REPLACE_ME",
    ]

    def __init__(self, env_content: str) -> None:
        self._vars = self._parse(env_content)

    @staticmethod
    def _parse(content: str) -> Dict[str, str]:
        """Parse KEY=VALUE lines from .env content."""
        result: Dict[str, str] = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                result[key.strip()] = value.strip()
        return result

    def validate(self) -> List[str]:
        """
        Run all validation rules.

        Returns:
            A list of human-readable error strings.  Empty list → all good.
        """
        errors: List[str] = []

        # Required var presence
        for var in self.REQUIRED_VARS:
            if var not in self._vars or not self._vars[var]:
                errors.append(f"Required variable {var!r} is missing or empty.")

        # Minimum lengths for secret fields
        secret_key = self._vars.get("SECRET_KEY", "")
        if secret_key and len(secret_key) < 32:
            errors.append(
                f"SECRET_KEY is only {len(secret_key)} chars; minimum 32 required."
            )

        # Placeholder detection
        for key, value in self._vars.items():
            for pattern in self.PLACEHOLDER_PATTERNS:
                if re.search(pattern, value, re.IGNORECASE):
                    errors.append(
                        f"Variable {key!r} appears to contain a placeholder value: {value!r}"
                    )
                    break

        return errors

    def is_valid(self) -> bool:
        """Return True when the .env passes all validation rules."""
        return len(self.validate()) == 0


# ---------------------------------------------------------------------------
# Podman-specific helpers
# ---------------------------------------------------------------------------


class PodmanCompatibilityHelper:
    """
    Utilities for making UniVex docker-compose files compatible with Podman.

    Rootless Podman has stricter defaults than Docker:
      - Named volumes require ``driver_opts`` to be empty or omitted
      - ``userns_mode: keep-id`` preserves the host UID inside rootless containers
      - SELinux hosts require ``:z`` or ``:Z`` on bind-mount volume entries
    """

    SELINUX_LABEL_SHARED = ":z"   # shared access
    SELINUX_LABEL_PRIVATE = ":Z"  # private / exclusive access

    @staticmethod
    def is_podman_available() -> bool:
        """Return True if the ``podman`` binary is in PATH."""
        return shutil.which("podman") is not None

    @staticmethod
    def is_selinux_enforcing() -> bool:
        """Return True if SELinux is in enforcing mode on this host."""
        selinux_status = shutil.which("getenforce")
        if not selinux_status:
            return False
        try:
            result = subprocess.run(
                ["getenforce"], capture_output=True, text=True, timeout=5
            )
            return result.stdout.strip().lower() == "enforcing"
        except Exception:  # noqa: BLE001
            return False

    @staticmethod
    def get_uid_gid() -> Tuple[int, int]:
        """Return the current process UID and GID."""
        return os.getuid(), os.getgid()

    @staticmethod
    def rootless_socket_path() -> str:
        """Return the default rootless Podman socket path for this user."""
        uid = os.getuid()
        return f"/run/user/{uid}/podman/podman.sock"

    @staticmethod
    def generate_podman_env_overrides(uid: Optional[int] = None) -> Dict[str, str]:
        """
        Generate environment variable overrides needed for rootless Podman.

        Returns a dict that can be merged into the .env file or set as
        process-level environment variables before running podman-compose.
        """
        if uid is None:
            uid = os.getuid()
        xdg_runtime = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{uid}")
        return {
            "DOCKER_HOST": f"unix://{xdg_runtime}/podman/podman.sock",
            "COMPOSE_IGNORE_ORPHANS": "true",
        }

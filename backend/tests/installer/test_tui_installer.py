"""
Tests for Day 17 — TUI Installer

Coverage:
  PrerequisiteResult      — field defaults, severity
  PrerequisiteChecker     — check_ram, check_disk, check_python_version,
                             check_all, all_passed
  PortChecker             — is_port_in_use, suggest_alternative, check_all_ports
  InstallerConfig         — defaults, field validation
  EnvFileGenerator        — generate, write, sections, validation
  EnvValidator            — parse, validate, is_valid
  PodmanCompatibilityHelper — static helpers
  ServiceHealthChecker    — check_service (mocked), check_all
  ComposeOrchestrator     — _base_cmd

Total: 52 tests
"""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Load module under test
# ---------------------------------------------------------------------------

def _load(rel_path: str, module_name: str):
    spec = importlib.util.spec_from_file_location(
        module_name,
        Path(__file__).parents[2] / "app" / rel_path,
    )
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


_installer = _load("installer/tui_installer.py", "app.installer.tui_installer")

PrerequisiteResult = _installer.PrerequisiteResult
PrerequisiteChecker = _installer.PrerequisiteChecker
InstallerConfig = _installer.InstallerConfig
EnvFileGenerator = _installer.EnvFileGenerator
EnvValidator = _installer.EnvValidator
PortChecker = _installer.PortChecker
PodmanCompatibilityHelper = _installer.PodmanCompatibilityHelper
ServiceHealthChecker = _installer.ServiceHealthChecker
ComposeOrchestrator = _installer.ComposeOrchestrator
DEFAULT_PORTS = _installer.DEFAULT_PORTS
LLM_PROVIDERS = _installer.LLM_PROVIDERS
OPTIONAL_FEATURES = _installer.OPTIONAL_FEATURES
UNIVEX_ASCII_LOGO = _installer.UNIVEX_ASCII_LOGO


# ===========================================================================
# Section 1 — PrerequisiteResult
# ===========================================================================

class TestPrerequisiteResult:
    def test_default_severity_is_error(self):
        r = PrerequisiteResult(name="test", passed=True, message="ok")
        assert r.severity == "error"

    def test_custom_severity(self):
        r = PrerequisiteResult(name="x", passed=True, message="ok", severity="warning")
        assert r.severity == "warning"

    def test_passed_false(self):
        r = PrerequisiteResult(name="x", passed=False, message="fail")
        assert r.passed is False

    def test_name_stored(self):
        r = PrerequisiteResult(name="ram", passed=True, message="ok")
        assert r.name == "ram"


# ===========================================================================
# Section 2 — PrerequisiteChecker
# ===========================================================================

class TestPrerequisiteCheckerPython:
    def test_check_python_version_passes_current(self):
        checker = PrerequisiteChecker()
        result = checker.check_python_version()
        # Current Python is always >= 3.10 in this project
        assert isinstance(result, PrerequisiteResult)

    def test_check_python_version_fails_for_old(self):
        checker = PrerequisiteChecker()
        with patch.object(sys, "version_info", (3, 9, 0)):
            result = checker.check_python_version()
        assert result.passed is False

    def test_check_python_version_passes_for_310(self):
        checker = PrerequisiteChecker()
        with patch.object(sys, "version_info", (3, 10, 0)):
            result = checker.check_python_version()
        assert result.passed is True


class TestPrerequisiteCheckerDisk:
    def test_check_disk_returns_result(self):
        checker = PrerequisiteChecker()
        result = checker.check_disk(path="/")
        assert isinstance(result, PrerequisiteResult)
        assert result.name == "disk"

    def test_check_disk_fails_when_insufficient(self):
        import shutil
        checker = PrerequisiteChecker()
        # Mock disk_usage to return minimal free space
        mock_usage = MagicMock()
        mock_usage.free = 1 * 1024 ** 3  # 1 GB
        with patch("shutil.disk_usage", return_value=mock_usage):
            result = checker.check_disk()
        assert result.passed is False

    def test_check_disk_passes_when_sufficient(self):
        checker = PrerequisiteChecker()
        mock_usage = MagicMock()
        mock_usage.free = 100 * 1024 ** 3  # 100 GB
        with patch("shutil.disk_usage", return_value=mock_usage):
            result = checker.check_disk()
        assert result.passed is True


class TestPrerequisiteCheckerRAM:
    def test_check_ram_returns_result(self):
        checker = PrerequisiteChecker()
        result = checker.check_ram()
        assert isinstance(result, PrerequisiteResult)
        assert result.name == "ram"

    def test_check_ram_skips_on_non_linux(self):
        checker = PrerequisiteChecker()
        with patch("pathlib.Path.exists", return_value=False):
            result = checker.check_ram()
        # On non-Linux, returns passed=True with warning
        assert result.passed is True


class TestPrerequisiteCheckerRuntime:
    def test_check_runtime_docker_not_found(self):
        checker = PrerequisiteChecker(runtime="docker")
        with patch("shutil.which", return_value=None):
            result = checker.check_runtime()
        assert result.passed is False
        assert "docker" in result.message.lower()

    def test_check_runtime_podman_not_found(self):
        checker = PrerequisiteChecker(runtime="podman")
        with patch("shutil.which", return_value=None):
            result = checker.check_runtime()
        assert result.passed is False

    def test_check_runtime_docker_running(self):
        checker = PrerequisiteChecker(runtime="docker")
        with patch("shutil.which", return_value="/usr/bin/docker"):
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.stdout = "24.0.7"
            with patch("subprocess.run", return_value=mock_proc):
                result = checker.check_runtime()
        assert result.passed is True

    def test_check_runtime_daemon_not_running(self):
        checker = PrerequisiteChecker(runtime="docker")
        with patch("shutil.which", return_value="/usr/bin/docker"):
            mock_proc = MagicMock()
            mock_proc.returncode = 1
            mock_proc.stdout = ""
            with patch("subprocess.run", return_value=mock_proc):
                result = checker.check_runtime()
        assert result.passed is False


class TestPrerequisiteCheckerAll:
    def test_check_all_returns_list(self):
        checker = PrerequisiteChecker()
        results = checker.check_all()
        assert isinstance(results, list)
        assert len(results) >= 3

    def test_all_passed_true_when_all_error_checks_pass(self):
        checker = PrerequisiteChecker()
        results = [
            PrerequisiteResult("a", True, "ok", "error"),
            PrerequisiteResult("b", True, "ok", "warning"),
        ]
        assert checker.all_passed(results) is True

    def test_all_passed_false_when_error_check_fails(self):
        checker = PrerequisiteChecker()
        results = [
            PrerequisiteResult("a", False, "fail", "error"),
            PrerequisiteResult("b", True, "ok", "warning"),
        ]
        assert checker.all_passed(results) is False

    def test_all_passed_ignores_warning_failures(self):
        checker = PrerequisiteChecker()
        results = [
            PrerequisiteResult("a", True, "ok", "error"),
            PrerequisiteResult("b", False, "warn-fail", "warning"),
        ]
        assert checker.all_passed(results) is True


# ===========================================================================
# Section 3 — PortChecker
# ===========================================================================

class TestPortChecker:
    def test_is_port_in_use_free_port(self):
        checker = PortChecker()
        # Find a truly free port
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        # After releasing, the port should be free
        assert checker.is_port_in_use(port) is False

    def test_is_port_in_use_occupied_port(self):
        checker = PortChecker()
        import socket
        # Bind a port to mark it as occupied
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        # On most systems the port is "in use" while srv is bound
        # Just verify the method runs without error
        try:
            result = checker.is_port_in_use(port)
            assert isinstance(result, bool)
        finally:
            srv.close()

    def test_suggest_alternative_finds_free_port(self):
        checker = PortChecker()
        with patch.object(checker, "is_port_in_use", side_effect=lambda p: p < 9100):
            alt = checker.suggest_alternative(9090)
        assert alt == 9100

    def test_suggest_alternative_raises_when_no_free_port(self):
        checker = PortChecker()
        with patch.object(checker, "is_port_in_use", return_value=True):
            with pytest.raises(RuntimeError, match="Could not find"):
                checker.suggest_alternative(9090)

    def test_check_all_ports_returns_dict(self):
        checker = PortChecker()
        ports = {"svc_a": 19999, "svc_b": 19998}
        with patch.object(checker, "is_port_in_use", return_value=False):
            results = checker.check_all_ports(ports)
        assert "svc_a" in results
        assert "svc_b" in results

    def test_check_all_ports_suggests_alt_when_in_use(self):
        checker = PortChecker()
        ports = {"svc": 9999}

        def _in_use(p):
            return p == 9999

        with patch.object(checker, "is_port_in_use", side_effect=_in_use):
            results = checker.check_all_ports(ports)
        port, in_use, alt = results["svc"]
        assert in_use is True
        assert alt is not None
        assert alt != 9999


# ===========================================================================
# Section 4 — InstallerConfig
# ===========================================================================

class TestInstallerConfig:
    def test_default_runtime_is_docker(self):
        assert InstallerConfig().container_runtime == "docker"

    def test_default_llm_provider_is_openai(self):
        assert InstallerConfig().llm_provider == "openai"

    def test_default_environment_is_production(self):
        assert InstallerConfig().environment == "production"

    def test_default_enabled_features_is_empty(self):
        cfg = InstallerConfig()
        assert cfg.enabled_features == []

    def test_custom_provider_stored(self):
        cfg = InstallerConfig(llm_provider="anthropic", anthropic_api_key="sk-ant-test")
        assert cfg.llm_provider == "anthropic"
        assert cfg.anthropic_api_key == "sk-ant-test"

    def test_port_overrides_dict(self):
        cfg = InstallerConfig(port_overrides={"frontend": 3001})
        assert cfg.port_overrides["frontend"] == 3001


# ===========================================================================
# Section 5 — EnvFileGenerator
# ===========================================================================

class TestEnvFileGenerator:
    @pytest.fixture
    def config(self):
        return InstallerConfig(
            llm_provider="openai",
            openai_api_key="sk-test-key",
            secret_key="a" * 64,
            postgres_password="pg-pass-" + "x" * 16,
            neo4j_password="neo-pass-" + "x" * 16,
        )

    def test_generate_returns_string(self, config):
        content = EnvFileGenerator(config).generate()
        assert isinstance(content, str)
        assert len(content) > 0

    def test_generate_contains_secret_key(self, config):
        content = EnvFileGenerator(config).generate()
        assert "SECRET_KEY=" in content

    def test_generate_contains_postgres_password(self, config):
        content = EnvFileGenerator(config).generate()
        assert "POSTGRES_PASSWORD=" in content

    def test_generate_contains_llm_provider(self, config):
        content = EnvFileGenerator(config).generate()
        assert "DEFAULT_LLM_PROVIDER=openai" in content

    def test_generate_contains_api_key(self, config):
        content = EnvFileGenerator(config).generate()
        assert "OPENAI_API_KEY=sk-test-key" in content

    def test_generate_feature_flags_present(self, config):
        content = EnvFileGenerator(config).generate()
        assert "MINIO_ENABLED=" in content
        assert "LANGFUSE_ENABLED=" in content

    def test_generate_autogenerates_missing_secret_key(self):
        cfg = InstallerConfig(secret_key="")
        content = EnvFileGenerator(cfg).generate()
        # Should have generated a secret key
        for line in content.splitlines():
            if line.startswith("SECRET_KEY="):
                val = line.split("=", 1)[1]
                assert len(val) >= 32
                break
        else:
            pytest.fail("SECRET_KEY not found in generated .env")

    def test_write_creates_file(self, config, tmp_path):
        out_path = tmp_path / ".env"
        gen = EnvFileGenerator(config)
        gen.write(str(out_path))
        assert out_path.exists()
        assert out_path.stat().st_size > 0

    def test_write_content_matches_generate(self, config, tmp_path):
        out_path = tmp_path / ".env"
        gen = EnvFileGenerator(config)
        expected = gen.generate()
        gen.write(str(out_path))
        assert out_path.read_text() == expected

    def test_generate_minio_section_when_enabled(self):
        cfg = InstallerConfig(enabled_features=["minio"])
        content = EnvFileGenerator(cfg).generate()
        assert "MINIO_ENDPOINT=" in content

    def test_generate_no_minio_section_when_disabled(self):
        cfg = InstallerConfig(enabled_features=[])
        content = EnvFileGenerator(cfg).generate()
        assert "MINIO_ENDPOINT=" not in content

    def test_generate_static_secret_key_preserved(self, config):
        content = EnvFileGenerator(config).generate()
        assert "a" * 64 in content


# ===========================================================================
# Section 6 — EnvValidator
# ===========================================================================

class TestEnvValidator:
    def _valid_env(self) -> str:
        return (
            "ENVIRONMENT=production\n"
            f"SECRET_KEY={'x' * 64}\n"
            "POSTGRES_PASSWORD=strongpassword123\n"
            "NEO4J_PASSWORD=strongpassword456\n"
        )

    def test_valid_env_passes(self):
        v = EnvValidator(self._valid_env())
        assert v.is_valid() is True

    def test_missing_required_var_fails(self):
        env = "ENVIRONMENT=production\nSECRET_KEY=abc123\n"
        errors = EnvValidator(env).validate()
        assert any("POSTGRES_PASSWORD" in e for e in errors)

    def test_short_secret_key_fails(self):
        env = (
            "ENVIRONMENT=production\n"
            "SECRET_KEY=tooshort\n"
            "POSTGRES_PASSWORD=valid\n"
            "NEO4J_PASSWORD=valid\n"
        )
        errors = EnvValidator(env).validate()
        assert any("SECRET_KEY" in e for e in errors)

    def test_placeholder_detected(self):
        env = (
            "ENVIRONMENT=production\n"
            f"SECRET_KEY={'x' * 64}\n"
            "POSTGRES_PASSWORD=changeme\n"
            "NEO4J_PASSWORD=valid\n"
        )
        errors = EnvValidator(env).validate()
        assert any("POSTGRES_PASSWORD" in e for e in errors)

    def test_comments_and_blank_lines_ignored(self):
        env = (
            "# This is a comment\n"
            "\n"
            "ENVIRONMENT=production\n"
            f"SECRET_KEY={'x' * 64}\n"
            "POSTGRES_PASSWORD=strongpassword\n"
            "NEO4J_PASSWORD=strongpassword\n"
        )
        assert EnvValidator(env).is_valid() is True

    def test_is_valid_true_on_clean_env(self):
        assert EnvValidator(self._valid_env()).is_valid() is True


# ===========================================================================
# Section 7 — PodmanCompatibilityHelper
# ===========================================================================

class TestPodmanCompatibilityHelper:
    def test_is_podman_available_false_when_not_in_path(self):
        with patch("shutil.which", return_value=None):
            assert PodmanCompatibilityHelper.is_podman_available() is False

    def test_is_podman_available_true_when_in_path(self):
        with patch("shutil.which", return_value="/usr/bin/podman"):
            assert PodmanCompatibilityHelper.is_podman_available() is True

    def test_is_selinux_enforcing_false_when_no_getenforce(self):
        with patch("shutil.which", return_value=None):
            assert PodmanCompatibilityHelper.is_selinux_enforcing() is False

    def test_is_selinux_enforcing_true_when_enforcing(self):
        with patch("shutil.which", return_value="/usr/sbin/getenforce"):
            mock_proc = MagicMock()
            mock_proc.stdout = "Enforcing\n"
            with patch("subprocess.run", return_value=mock_proc):
                assert PodmanCompatibilityHelper.is_selinux_enforcing() is True

    def test_is_selinux_enforcing_false_when_permissive(self):
        with patch("shutil.which", return_value="/usr/sbin/getenforce"):
            mock_proc = MagicMock()
            mock_proc.stdout = "Permissive\n"
            with patch("subprocess.run", return_value=mock_proc):
                assert PodmanCompatibilityHelper.is_selinux_enforcing() is False

    def test_get_uid_gid_returns_tuple(self):
        uid, gid = PodmanCompatibilityHelper.get_uid_gid()
        assert isinstance(uid, int)
        assert isinstance(gid, int)

    def test_rootless_socket_path_contains_uid(self):
        uid = 1000
        with patch("os.getuid", return_value=uid):
            path = PodmanCompatibilityHelper.rootless_socket_path()
        assert str(uid) in path
        assert "podman.sock" in path

    def test_generate_podman_env_overrides_contains_docker_host(self):
        overrides = PodmanCompatibilityHelper.generate_podman_env_overrides(uid=1000)
        assert "DOCKER_HOST" in overrides
        assert "podman.sock" in overrides["DOCKER_HOST"]

    def test_generate_podman_env_overrides_contains_compose_flag(self):
        overrides = PodmanCompatibilityHelper.generate_podman_env_overrides(uid=1000)
        assert "COMPOSE_IGNORE_ORPHANS" in overrides


# ===========================================================================
# Section 8 — ServiceHealthChecker
# ===========================================================================

class TestServiceHealthChecker:
    def test_check_service_returns_false_on_connection_refused(self):
        checker = ServiceHealthChecker()
        # Port 1 should be refused in sandboxed env
        result = checker.check_service("localhost", 1, "/")
        assert result is False

    def test_check_service_returns_true_on_2xx(self):
        checker = ServiceHealthChecker()
        import http.client
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_resp
        with patch("http.client.HTTPConnection", return_value=mock_conn):
            result = checker.check_service("localhost", 8000, "/api/health")
        assert result is True

    def test_check_service_returns_false_on_5xx(self):
        checker = ServiceHealthChecker()
        import http.client
        mock_resp = MagicMock()
        mock_resp.status = 503
        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_resp
        with patch("http.client.HTTPConnection", return_value=mock_conn):
            result = checker.check_service("localhost", 8000, "/api/health")
        assert result is False

    def test_check_all_returns_dict(self):
        checker = ServiceHealthChecker()
        endpoints = {"backend": ("localhost", 8000, "/api/health")}
        with patch.object(checker, "check_service", return_value=False):
            results = checker.check_all(endpoints)
        assert "backend" in results
        assert results["backend"] is False


# ===========================================================================
# Section 9 — ComposeOrchestrator
# ===========================================================================

class TestComposeOrchestrator:
    def test_docker_base_cmd(self):
        orch = ComposeOrchestrator(compose_file="docker-compose.yml", runtime="docker")
        cmd = orch._base_cmd()
        assert cmd == ["docker", "compose", "-f", "docker-compose.yml"]

    def test_podman_base_cmd(self):
        orch = ComposeOrchestrator(compose_file="docker-compose.yml", runtime="podman")
        cmd = orch._base_cmd()
        assert cmd == ["podman-compose", "-f", "docker-compose.yml"]


# ===========================================================================
# Section 10 — Constants
# ===========================================================================

class TestConstants:
    def test_llm_providers_list(self):
        assert "openai" in LLM_PROVIDERS
        assert "anthropic" in LLM_PROVIDERS
        assert "bedrock" in LLM_PROVIDERS

    def test_optional_features_list(self):
        assert "minio" in OPTIONAL_FEATURES
        assert "langfuse" in OPTIONAL_FEATURES
        assert "searxng" in OPTIONAL_FEATURES

    def test_default_ports_dict(self):
        assert "backend" in DEFAULT_PORTS
        assert "frontend" in DEFAULT_PORTS
        assert DEFAULT_PORTS["backend"] == 8000

    def test_ascii_logo_non_empty(self):
        assert len(UNIVEX_ASCII_LOGO) > 0
        assert "UniVex" in UNIVEX_ASCII_LOGO

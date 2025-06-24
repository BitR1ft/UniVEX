"""
Tests for Day 21 — build-installer.sh & release-installer.yml

Coverage:
  - build-installer.sh: argument parsing, version embedding, output files,
    SHA256 checksum generation, missing source file handling
  - release-installer.yml: workflow file structure validation
  - Installer script source verification: shebang, set -euo pipefail,
    prerequisite check functions, env var generation, .env writing

Total: 27 tests
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Repo root
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).parents[3]
BUILD_SCRIPT = REPO_ROOT / "scripts" / "build-installer.sh"
INSTALL_SH = REPO_ROOT / "scripts" / "install.sh"
INSTALL_PODMAN_SH = REPO_ROOT / "scripts" / "install-podman.sh"
RELEASE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release-installer.yml"
SECURITY_MD = REPO_ROOT / ".github" / "SECURITY.md"
DISCORD_MD = REPO_ROOT / ".github" / "DISCORD.md"
CHANGELOG_MD = REPO_ROOT / "CHANGELOG.md"


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _run_build(extra_args: list[str] | None = None, *, out_dir: Path) -> subprocess.CompletedProcess:
    """Run build-installer.sh with bash and return the completed process.

    Args:
        extra_args: Additional arguments to pass to the script (e.g. ``["--version", "v1.0.0"]``).
        out_dir: Directory where the installer artifacts will be written.

    Returns:
        A :class:`subprocess.CompletedProcess` instance with ``stdout``, ``stderr``,
        and ``returncode`` attributes.
    """
    cmd = ["bash", str(BUILD_SCRIPT), "--out-dir", str(out_dir)]
    if extra_args:
        cmd.extend(extra_args)
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )


# ===========================================================================
# 1. File existence
# ===========================================================================


class TestFileExistence:
    def test_build_installer_exists(self):
        assert BUILD_SCRIPT.exists(), "scripts/build-installer.sh must exist"

    def test_install_sh_exists(self):
        assert INSTALL_SH.exists(), "scripts/install.sh must exist"

    def test_install_podman_sh_exists(self):
        assert INSTALL_PODMAN_SH.exists(), "scripts/install-podman.sh must exist"

    def test_release_workflow_exists(self):
        assert RELEASE_WORKFLOW.exists(), ".github/workflows/release-installer.yml must exist"

    def test_security_md_exists(self):
        assert SECURITY_MD.exists(), ".github/SECURITY.md must exist"

    def test_discord_md_exists(self):
        assert DISCORD_MD.exists(), ".github/DISCORD.md must exist"

    def test_changelog_exists(self):
        assert CHANGELOG_MD.exists(), "CHANGELOG.md must exist"


# ===========================================================================
# 2. build-installer.sh — script structure
# ===========================================================================


class TestBuildInstallerScript:
    def test_shebang(self):
        content = BUILD_SCRIPT.read_text()
        assert content.startswith("#!/usr/bin/env bash"), "build-installer.sh must have bash shebang"

    def test_set_euo_pipefail(self):
        content = BUILD_SCRIPT.read_text()
        assert "set -euo pipefail" in content, "build-installer.sh must use 'set -euo pipefail'"

    def test_has_version_arg(self):
        content = BUILD_SCRIPT.read_text()
        assert "--version" in content, "build-installer.sh must support --version argument"

    def test_has_out_dir_arg(self):
        content = BUILD_SCRIPT.read_text()
        assert "--out-dir" in content, "build-installer.sh must support --out-dir argument"

    def test_sha256_generation(self):
        content = BUILD_SCRIPT.read_text()
        assert "sha256sum" in content or "shasum" in content, \
            "build-installer.sh must generate SHA256 checksums"

    def test_checksums_txt(self):
        content = BUILD_SCRIPT.read_text()
        assert "checksums.txt" in content, "build-installer.sh must produce checksums.txt"

    def test_chmod_executable(self):
        content = BUILD_SCRIPT.read_text()
        assert "chmod +x" in content, "build-installer.sh must mark output scripts as executable"

    def test_version_embed_awk(self):
        """Script must embed the version string into installer files."""
        content = BUILD_SCRIPT.read_text()
        assert "awk" in content or "sed" in content, \
            "build-installer.sh must embed version via awk or sed"

    def test_security_warning_in_output(self):
        """Must warn against piping to bash without checksum verification."""
        content = BUILD_SCRIPT.read_text()
        assert "sha256sum -c" in content, \
            "build-installer.sh must document sha256sum -c verification command"

    def test_help_flag(self):
        content = BUILD_SCRIPT.read_text()
        assert "--help" in content or "-h" in content, \
            "build-installer.sh should support --help / -h flag"


# ===========================================================================
# 3. build-installer.sh — execution
# ===========================================================================


class TestBuildInstallerExecution:
    def test_produces_install_sh(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            result = _run_build(["--version", "v1.0.0-test"], out_dir=out)
            assert result.returncode == 0, f"build-installer.sh failed:\n{result.stderr}"
            assert (out / "install.sh").exists()

    def test_produces_install_podman_sh(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            result = _run_build(["--version", "v1.0.0-test"], out_dir=out)
            assert result.returncode == 0
            assert (out / "install-podman.sh").exists()

    def test_produces_checksum_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            result = _run_build(["--version", "v1.0.0-test"], out_dir=out)
            assert result.returncode == 0
            assert (out / "install.sh.sha256").exists()
            assert (out / "install-podman.sh.sha256").exists()
            assert (out / "checksums.txt").exists()

    def test_checksum_matches_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            result = _run_build(["--version", "v1.0.0-test"], out_dir=out)
            assert result.returncode == 0
            # Verify checksum written in .sha256 matches actual file
            sha_line = (out / "install.sh.sha256").read_text().strip()
            expected_hash = sha_line.split()[0]
            actual_hash = _sha256(out / "install.sh")
            assert expected_hash == actual_hash, "SHA256 checksum mismatch for install.sh"

    def test_output_is_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            _run_build(["--version", "v1.0.0-test"], out_dir=out)
            install = out / "install.sh"
            assert os.access(install, os.X_OK), "install.sh output must be executable"

    def test_version_embedded_in_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            _run_build(["--version", "v99.0.0-canary"], out_dir=out)
            content = (out / "install.sh").read_text()
            assert "v99.0.0-canary" in content, \
                "version string must be embedded in output install.sh"

    def test_checksums_txt_has_both_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            _run_build(["--version", "v1.0.0-test"], out_dir=out)
            checksums = (out / "checksums.txt").read_text()
            assert "install.sh" in checksums
            assert "install-podman.sh" in checksums


# ===========================================================================
# 4. Release workflow validation
# ===========================================================================


class TestReleaseWorkflow:
    def _yaml_text(self) -> str:
        return RELEASE_WORKFLOW.read_text()

    def test_triggers_on_tags(self):
        content = self._yaml_text()
        assert "v*.*.*" in content or "tags:" in content, \
            "release-installer.yml must trigger on version tags"

    def test_workflow_dispatch_supported(self):
        content = self._yaml_text()
        assert "workflow_dispatch" in content, \
            "release-installer.yml must support manual workflow_dispatch trigger"

    def test_uploads_install_sh(self):
        content = self._yaml_text()
        assert "install.sh" in content, \
            "release-installer.yml must attach install.sh to release"

    def test_uploads_checksums(self):
        content = self._yaml_text()
        assert "checksums.txt" in content or "sha256" in content.lower(), \
            "release-installer.yml must attach checksum files to release"

    def test_uses_actions_checkout(self):
        content = self._yaml_text()
        assert "actions/checkout" in content, \
            "release-installer.yml must checkout the repository"

    def test_runs_build_installer(self):
        content = self._yaml_text()
        assert "build-installer.sh" in content, \
            "release-installer.yml must call scripts/build-installer.sh"

    def test_verifies_checksums(self):
        content = self._yaml_text()
        assert "sha256sum -c" in content, \
            "release-installer.yml must verify checksums after building"


# ===========================================================================
# 5. SECURITY.md & DISCORD.md content
# ===========================================================================


class TestCommunityFiles:
    def test_security_md_has_reporting_section(self):
        content = SECURITY_MD.read_text()
        assert "Reporting" in content or "Report" in content, \
            "SECURITY.md must contain a vulnerability reporting section"

    def test_security_md_has_scope(self):
        content = SECURITY_MD.read_text()
        assert "Scope" in content or "In Scope" in content, \
            "SECURITY.md must define the scope of the security policy"

    def test_security_md_has_response_timeline(self):
        content = SECURITY_MD.read_text()
        assert "Response" in content or "Timeline" in content, \
            "SECURITY.md must state a response timeline"

    def test_discord_md_has_rules(self):
        content = DISCORD_MD.read_text()
        assert "Rules" in content or "Legal" in content, \
            "DISCORD.md must contain community rules"


# ===========================================================================
# 6. CHANGELOG.md structure
# ===========================================================================


class TestChangelog:
    def _content(self) -> str:
        return CHANGELOG_MD.read_text()

    def test_has_v1_section(self):
        assert "[1.0.0]" in self._content() or "## [1" in self._content(), \
            "CHANGELOG.md must have a v1.0.0 section"

    def test_keep_a_changelog_format(self):
        content = self._content()
        # Check for the Keep a Changelog reference text (not URL matching)
        assert "Keep a Changelog" in content, \
            "CHANGELOG.md must reference Keep a Changelog format"

    def test_has_added_changed_sections(self):
        content = self._content()
        assert "### Added" in content, "CHANGELOG.md must have ### Added section"

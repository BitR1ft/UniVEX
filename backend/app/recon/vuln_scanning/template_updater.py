"""
Nuclei Template Updater

Provides:
- Auto-update of Nuclei templates via ``nuclei -update-templates``
- Template versioning (records installed version tag)
- Scheduled refresh via APScheduler (optional; falls back to manual calls)
- Per-update audit log entries
"""
from __future__ import annotations

import asyncio
import json
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default paths
# ---------------------------------------------------------------------------

_DEFAULT_STATE_FILE = Path.home() / ".univex" / "nuclei_templates_state.json"


# ---------------------------------------------------------------------------
# TemplateVersionInfo
# ---------------------------------------------------------------------------

class TemplateVersionInfo:
    """Records a single template update event."""

    def __init__(self, version: str, updated_at: datetime, success: bool, message: str = "") -> None:
        self.version = version
        self.updated_at = updated_at
        self.success = success
        self.message = message

    def to_dict(self) -> Dict:
        return {
            "version": self.version,
            "updated_at": self.updated_at.isoformat(),
            "success": self.success,
            "message": self.message,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "TemplateVersionInfo":
        return cls(
            version=d.get("version", "unknown"),
            updated_at=datetime.fromisoformat(d["updated_at"]),
            success=d.get("success", False),
            message=d.get("message", ""),
        )


# ---------------------------------------------------------------------------
# NucleiTemplateUpdater
# ---------------------------------------------------------------------------

class NucleiTemplateUpdater:
    """
    Manages Nuclei template updates, versioning, and an audit history.

    Usage::

        updater = NucleiTemplateUpdater()
        await updater.update()           # update now
        info = updater.current_version() # returns TemplateVersionInfo or None

    Scheduled refresh (requires ``apscheduler``)::

        updater.start_scheduler(interval_hours=24)
        # …
        updater.stop_scheduler()
    """

    def __init__(
        self,
        state_file: Optional[Path] = None,
        timeout_seconds: int = 300,
    ) -> None:
        self._state_file = state_file or _DEFAULT_STATE_FILE
        self._timeout = timeout_seconds
        self._history: List[TemplateVersionInfo] = []
        self._scheduler = None
        self._load_state()

    # ------------------------------------------------------------------
    # State persistence
    # ------------------------------------------------------------------

    def _load_state(self) -> None:
        """Load update history from the state JSON file."""
        try:
            if self._state_file.exists():
                raw = json.loads(self._state_file.read_text())
                self._history = [
                    TemplateVersionInfo.from_dict(e) for e in raw.get("history", [])
                ]
        except Exception as exc:
            logger.warning("Could not load template state: %s", exc)

    def _save_state(self) -> None:
        """Persist update history to the state JSON file."""
        try:
            self._state_file.parent.mkdir(parents=True, exist_ok=True)
            data = {"history": [e.to_dict() for e in self._history[-50:]]}  # keep last 50
            self._state_file.write_text(json.dumps(data, indent=2))
        except Exception as exc:
            logger.warning("Could not save template state: %s", exc)

    # ------------------------------------------------------------------
    # Version helpers
    # ------------------------------------------------------------------

    def current_version(self) -> Optional[TemplateVersionInfo]:
        """Return the most recent successful update record, or None."""
        for entry in reversed(self._history):
            if entry.success:
                return entry
        return None

    def update_history(self) -> List[TemplateVersionInfo]:
        """Return the full update history (newest last)."""
        return list(self._history)

    @staticmethod
    def _detect_installed_version() -> str:
        """
        Run ``nuclei -version`` and parse the version string.
        Returns 'unknown' if nuclei is not installed or parsing fails.
        """
        try:
            result = subprocess.run(
                ["nuclei", "-version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            # Nuclei prints e.g. "Nuclei Engine Version: v3.1.2"
            for line in result.stdout.splitlines() + result.stderr.splitlines():
                if "version" in line.lower():
                    parts = line.split()
                    # Last token is usually the version
                    for part in reversed(parts):
                        if part.startswith("v") or part[0].isdigit():
                            return part
        except Exception:
            pass
        return "unknown"

    # ------------------------------------------------------------------
    # Update
    # ------------------------------------------------------------------

    async def update(self) -> TemplateVersionInfo:
        """
        Run ``nuclei -update-templates`` asynchronously and record the result.

        Returns a :class:`TemplateVersionInfo` describing the update outcome.
        """
        logger.info("Updating Nuclei templates…")
        started_at = datetime.now(tz=timezone.utc)

        try:
            proc = await asyncio.create_subprocess_exec(
                "nuclei", "-update-templates",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self._timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                raise RuntimeError(
                    f"Template update timed out after {self._timeout}s"
                )

            success = proc.returncode == 0
            message = (stdout + stderr).decode(errors="replace").strip()
            version = self._detect_installed_version()

            info = TemplateVersionInfo(
                version=version,
                updated_at=started_at,
                success=success,
                message=message[:500],
            )

            if success:
                logger.info("Nuclei templates updated successfully (version %s)", version)
            else:
                logger.warning("Template update returned exit code %d: %s", proc.returncode, message)

        except Exception as exc:
            logger.error("Template update failed: %s", exc)
            info = TemplateVersionInfo(
                version="unknown",
                updated_at=started_at,
                success=False,
                message=str(exc),
            )

        self._history.append(info)
        self._save_state()
        return info

    # ------------------------------------------------------------------
    # Scheduler (optional APScheduler integration)
    # ------------------------------------------------------------------

    def start_scheduler(self, interval_hours: float = 24.0) -> None:
        """
        Start a background scheduler that calls :meth:`update` every
        *interval_hours* hours.

        Requires the ``apscheduler`` package to be installed::

            pip install apscheduler

        If ``apscheduler`` is not available, a warning is logged and
        scheduling is skipped.
        """
        try:
            from apscheduler.schedulers.asyncio import AsyncIOScheduler  # type: ignore
        except ImportError:
            logger.warning(
                "apscheduler not installed – scheduled template updates disabled. "
                "Install with: pip install apscheduler"
            )
            return

        if self._scheduler is not None:
            logger.warning("Scheduler already running")
            return

        self._scheduler = AsyncIOScheduler()
        self._scheduler.add_job(
            self.update,
            "interval",
            hours=interval_hours,
            id="nuclei_template_updater",
            replace_existing=True,
        )
        self._scheduler.start()
        logger.info(
            "Nuclei template auto-update scheduler started (every %.1fh)", interval_hours
        )

    def stop_scheduler(self) -> None:
        """Stop the background scheduler if it is running."""
        if self._scheduler is not None:
            self._scheduler.shutdown(wait=False)
            self._scheduler = None
            logger.info("Nuclei template updater scheduler stopped")

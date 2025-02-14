"""
Auto-Update Scheduler

Manages scheduled background jobs for refreshing:
- CVE data (cache purge + warm-up from NVD)
- CWE database (re-download from MITRE)
- CAPEC database (re-download from MITRE)
- Nuclei templates (delegates to NucleiTemplateUpdater)

Built on APScheduler (AsyncIOScheduler).  Each job records a structured
audit log entry in ``~/.univex/update_audit.jsonl``.

Usage::

    scheduler = UpdateScheduler()
    await scheduler.start()

    # Manually trigger an update
    await scheduler.run_now("cve_cache_purge")

    # Graceful shutdown
    await scheduler.stop()
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

_AUDIT_LOG_PATH = str(Path.home() / ".univex" / "update_audit.jsonl")

# Default schedules (cron-style strings, APScheduler format)
_DEFAULT_SCHEDULES: Dict[str, str] = {
    "cve_cache_purge":    "0 2 * * *",    # daily at 02:00
    "cwe_reload":         "0 3 * * 0",    # weekly Sunday 03:00
    "capec_reload":       "0 3 * * 0",    # weekly Sunday 03:00
    "nuclei_templates":   "0 4 * * *",    # daily at 04:00
}


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

def _write_audit_entry(job_name: str, status: str, detail: Optional[str] = None) -> None:
    """Append a structured audit log entry to the JSONL file."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "job": job_name,
        "status": status,
        "detail": detail,
    }
    try:
        Path(_AUDIT_LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
        with open(_AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as exc:
        logger.warning("Failed to write audit log: %s", exc)


def read_audit_log(last_n: int = 100) -> List[Dict[str, Any]]:
    """Return the last *last_n* audit log entries."""
    path = Path(_AUDIT_LOG_PATH)
    if not path.exists():
        return []
    try:
        lines = path.read_text().splitlines()
        entries = [json.loads(ln) for ln in lines if ln.strip()]
        return entries[-last_n:]
    except Exception as exc:
        logger.warning("Failed to read audit log: %s", exc)
        return []


# ---------------------------------------------------------------------------
# UpdateScheduler
# ---------------------------------------------------------------------------

class UpdateScheduler:
    """
    APScheduler-based scheduler for automatic refresh jobs.

    Each job is a named async callable.  Jobs can be triggered manually
    or run on their configured cron schedule.
    """

    def __init__(
        self,
        cve_cache: Optional[Any] = None,
        cwe_service: Optional[Any] = None,
        capec_service: Optional[Any] = None,
        nuclei_updater: Optional[Any] = None,
        schedules: Optional[Dict[str, str]] = None,
    ) -> None:
        self._cve_cache = cve_cache
        self._cwe_service = cwe_service
        self._capec_service = capec_service
        self._nuclei_updater = nuclei_updater
        self._schedules = schedules or dict(_DEFAULT_SCHEDULES)
        self._scheduler: Optional[Any] = None
        self._jobs: Dict[str, Callable] = {}
        self._register_jobs()

    # ------------------------------------------------------------------
    # Job registration
    # ------------------------------------------------------------------

    def _register_jobs(self) -> None:
        """Register all built-in update jobs."""
        self._jobs = {
            "cve_cache_purge": self._job_cve_cache_purge,
            "cwe_reload": self._job_cwe_reload,
            "capec_reload": self._job_capec_reload,
            "nuclei_templates": self._job_nuclei_templates,
        }

    # ------------------------------------------------------------------
    # Scheduler lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the APScheduler background scheduler."""
        try:
            from apscheduler.schedulers.asyncio import AsyncIOScheduler
            from apscheduler.triggers.cron import CronTrigger
        except ImportError:
            logger.warning(
                "APScheduler not installed – auto-update scheduling disabled. "
                "Install with: pip install apscheduler"
            )
            return

        self._scheduler = AsyncIOScheduler()

        for job_name, cron_expr in self._schedules.items():
            if job_name not in self._jobs:
                continue
            parts = cron_expr.split()
            if len(parts) == 5:
                minute, hour, day, month, day_of_week = parts
            else:
                logger.warning("Invalid cron expression for %s: %r", job_name, cron_expr)
                continue

            trigger = CronTrigger(
                minute=minute, hour=hour, day=day,
                month=month, day_of_week=day_of_week,
            )
            self._scheduler.add_job(
                self._wrap_job(job_name),
                trigger=trigger,
                id=job_name,
                replace_existing=True,
            )
            logger.info("Scheduled %r with cron: %s", job_name, cron_expr)

        self._scheduler.start()
        logger.info("UpdateScheduler started with %d jobs", len(self._schedules))

    async def stop(self) -> None:
        """Gracefully shut down the scheduler."""
        if self._scheduler and self._scheduler.running:
            self._scheduler.shutdown(wait=False)
            logger.info("UpdateScheduler stopped")

    # ------------------------------------------------------------------
    # Manual trigger
    # ------------------------------------------------------------------

    async def run_now(self, job_name: str) -> bool:
        """
        Immediately run a named job outside its schedule.

        Returns ``True`` on success, ``False`` on failure.
        """
        job_fn = self._jobs.get(job_name)
        if not job_fn:
            logger.warning("Unknown job: %r", job_name)
            return False

        try:
            await job_fn()
            return True
        except Exception as exc:
            logger.error("Manual job %r failed: %s", job_name, exc)
            _write_audit_entry(job_name, "failed", str(exc))
            return False

    # ------------------------------------------------------------------
    # Job definitions
    # ------------------------------------------------------------------

    async def _job_cve_cache_purge(self) -> None:
        """Purge expired CVE cache entries."""
        job = "cve_cache_purge"
        try:
            if self._cve_cache:
                deleted = await self._cve_cache.purge_expired()
                detail = f"Deleted {deleted} expired entries"
            else:
                detail = "No CVE cache configured"
            _write_audit_entry(job, "success", detail)
            logger.info("Job %r: %s", job, detail)
        except Exception as exc:
            _write_audit_entry(job, "failed", str(exc))
            raise

    async def _job_cwe_reload(self) -> None:
        """Reload CWE database."""
        job = "cwe_reload"
        try:
            if self._cwe_service:
                await self._cwe_service.load()
                detail = f"CWE database reloaded ({self._cwe_service.count()} entries)"
            else:
                detail = "No CWE service configured"
            _write_audit_entry(job, "success", detail)
            logger.info("Job %r: %s", job, detail)
        except Exception as exc:
            _write_audit_entry(job, "failed", str(exc))
            raise

    async def _job_capec_reload(self) -> None:
        """Reload CAPEC database."""
        job = "capec_reload"
        try:
            if self._capec_service:
                await self._capec_service.load()
                detail = f"CAPEC database reloaded ({self._capec_service.count()} entries)"
            else:
                detail = "No CAPEC service configured"
            _write_audit_entry(job, "success", detail)
            logger.info("Job %r: %s", job, detail)
        except Exception as exc:
            _write_audit_entry(job, "failed", str(exc))
            raise

    async def _job_nuclei_templates(self) -> None:
        """Update Nuclei templates."""
        job = "nuclei_templates"
        try:
            if self._nuclei_updater:
                result = await self._nuclei_updater.update()
                detail = f"Nuclei templates updated: {result}"
            else:
                detail = "No Nuclei updater configured"
            _write_audit_entry(job, "success", detail)
            logger.info("Job %r: %s", job, detail)
        except Exception as exc:
            _write_audit_entry(job, "failed", str(exc))
            raise

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _wrap_job(self, job_name: str) -> Callable:
        """Wrap a job to catch exceptions and write audit log."""
        job_fn = self._jobs[job_name]

        async def _wrapper() -> None:
            try:
                await job_fn()
            except Exception as exc:
                logger.error("Scheduled job %r failed: %s", job_name, exc)

        return _wrapper

    def list_jobs(self) -> List[Dict[str, str]]:
        """Return a list of registered jobs and their schedules."""
        return [
            {"name": name, "cron": self._schedules.get(name, "not scheduled")}
            for name in self._jobs
        ]

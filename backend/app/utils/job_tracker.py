"""
Background Job Tracker
Provides a unified interface for tracking background task status.

When a Prisma client is available the status updates are persisted to the
``tasks`` table; otherwise they fall through to the supplied in-memory dict
so that the existing API endpoints continue to work without a live database.
"""
import logging
from datetime import datetime
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class JobTracker:
    """
    Thin wrapper that writes task status to the database *and* to an
    optional in-memory fallback dict.

    Usage inside a background task::

        tracker = JobTracker(task_id, in_memory_store)
        await tracker.start()
        ...
        await tracker.complete({"subdomains": [...]})
        # or
        await tracker.fail("error message")
    """

    def __init__(
        self,
        task_id: str,
        in_memory: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.task_id = task_id
        self._mem = in_memory  # reference to the module-level dict, may be None

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _update_mem(self, **kwargs: Any) -> None:
        """Patch the in-memory task record if one was provided."""
        if self._mem is not None and self.task_id in self._mem:
            self._mem[self.task_id].update(
                {**kwargs, "updated_at": datetime.utcnow().isoformat()}
            )

    async def _db_update_status(
        self,
        status: str,
        started_at: Optional[datetime] = None,
        completed_at: Optional[datetime] = None,
    ) -> None:
        """Best-effort database status update – never raises."""
        try:
            from app.db.prisma_client import get_prisma
            from app.db.repositories.tasks_repo import TasksRepository

            db = await get_prisma()
            repo = TasksRepository(db)
            await repo.update_status(
                self.task_id,
                status=status,
                started_at=started_at,
                completed_at=completed_at,
            )
        except Exception as exc:
            logger.warning("DB task status update skipped (%s): %s", self.task_id, exc)

    async def _db_store_result(self, result_key: str, data: Any) -> None:
        """Best-effort database result storage – never raises."""
        try:
            from app.db.prisma_client import get_prisma
            from app.db.repositories.tasks_repo import TasksRepository

            db = await get_prisma()
            repo = TasksRepository(db)
            await repo.store_result(self.task_id, result_key, data)
        except Exception as exc:
            logger.warning("DB result store skipped (%s): %s", self.task_id, exc)

    async def _db_add_log(self, message: str, level: str = "info") -> None:
        """Best-effort database log append – never raises."""
        try:
            from app.db.prisma_client import get_prisma
            from app.db.repositories.tasks_repo import TasksRepository

            db = await get_prisma()
            repo = TasksRepository(db)
            await repo.add_log(self.task_id, message=message, level=level)
        except Exception as exc:
            logger.warning("DB log append skipped (%s): %s", self.task_id, exc)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def start(self, message: str = "Task started") -> None:
        """Mark the task as *running*."""
        self._update_mem(status="running", message=message, progress=10)
        await self._db_update_status("running", started_at=datetime.utcnow())
        await self._db_add_log(message)

    async def progress(self, percent: int, message: str = "") -> None:
        """Update the progress percentage (in-memory only)."""
        self._update_mem(progress=percent, message=message)
        if message:
            await self._db_add_log(message)

    async def complete(
        self,
        results: Optional[Any] = None,
        result_key: str = "output",
        message: str = "Task completed successfully",
    ) -> None:
        """Mark the task as *completed* and optionally store results."""
        self._update_mem(status="completed", progress=100, message=message, results=results)
        await self._db_update_status("completed", completed_at=datetime.utcnow())
        await self._db_add_log(message)
        if results is not None:
            await self._db_store_result(result_key, results)

    async def fail(self, error: str) -> None:
        """Mark the task as *failed* with an error message."""
        self._update_mem(status="failed", message=f"Task failed: {error}", error=error)
        await self._db_update_status("failed", completed_at=datetime.utcnow())
        await self._db_add_log(f"Task failed: {error}", level="error")

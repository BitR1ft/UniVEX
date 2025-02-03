"""
Task Repository
Handles all database operations for Task, TaskResult, TaskLog, and TaskMetrics.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from app.db.repositories.base import BaseRepository

if TYPE_CHECKING:
    from prisma.models import Task, TaskLog, TaskMetrics, TaskResult

logger = logging.getLogger(__name__)


class TasksRepository(BaseRepository):
    """Repository for Task CRUD, status management, and result storage."""

    def __init__(self, db: Any) -> None:
        super().__init__(db)

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    async def create_task(
        self,
        project_id: str,
        task_type: str,
        priority: int = 0,
    ) -> Task:
        """
        Create a new task record in *pending* status.

        Args:
            project_id: Owning project's ID.
            task_type: ``recon`` | ``port_scan`` | ``http_probe``.
            priority: Scheduling priority (higher = sooner).

        Returns:
            The newly created Task record.
        """
        task = await self.db.task.create(
            data={
                "project_id": project_id,
                "type": task_type,
                "status": "pending",
                "priority": priority,
            }
        )
        logger.info("Created task %s (type=%s, project=%s)", task.id, task_type, project_id)
        return task

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def get_by_id(self, task_id: str, include_relations: bool = False) -> Optional[Task]:
        """Return a task by primary key."""
        include: Dict[str, Any] = {}
        if include_relations:
            include = {
                "results": True,
                "logs": True,
                "metrics": True,
                "recon_task": True,
                "port_scan_task": True,
                "http_probe_task": True,
            }
        return await self.db.task.find_unique(where={"id": task_id}, include=include or None)

    async def get_by_project(
        self,
        project_id: str,
        skip: int = 0,
        take: int = 50,
        status: Optional[str] = None,
        task_type: Optional[str] = None,
    ) -> List[Task]:
        """
        Return tasks for a project, newest first, with optional filters.

        Args:
            project_id: Filter by project.
            skip: Pagination offset.
            take: Page size.
            status: Optional status filter.
            task_type: Optional type filter.

        Returns:
            List of Task records.
        """
        where: Dict[str, Any] = {"project_id": project_id}
        if status:
            where["status"] = status
        if task_type:
            where["type"] = task_type

        return await self.db.task.find_many(
            where=where,
            skip=skip,
            take=take,
            order={"created_at": "desc"},
        )

    async def count_by_project(
        self, project_id: str, status: Optional[str] = None
    ) -> int:
        """Return the number of tasks for a project."""
        where: Dict[str, Any] = {"project_id": project_id}
        if status:
            where["status"] = status
        return await self.db.task.count(where=where)

    # ------------------------------------------------------------------
    # Update – status lifecycle
    # ------------------------------------------------------------------

    async def update_status(
        self,
        task_id: str,
        status: str,
        started_at: Optional[datetime] = None,
        completed_at: Optional[datetime] = None,
    ) -> Optional[Task]:
        """
        Transition a task to a new status.

        Automatically sets ``started_at`` when transitioning to *running*
        and ``completed_at`` when transitioning to *completed* or *failed*,
        unless explicit timestamps are supplied.

        Args:
            task_id: Task primary key.
            status: New status value.
            started_at: Override start timestamp.
            completed_at: Override completion timestamp.

        Returns:
            Updated Task record.
        """
        now = datetime.utcnow()
        data: Dict[str, Any] = {"status": status}

        if status == "running" and started_at is None:
            data["started_at"] = now
        elif started_at is not None:
            data["started_at"] = started_at

        if status in ("completed", "failed", "cancelled") and completed_at is None:
            data["completed_at"] = now
        elif completed_at is not None:
            data["completed_at"] = completed_at

        return await self.db.task.update(where={"id": task_id}, data=data)

    # ------------------------------------------------------------------
    # Task Results
    # ------------------------------------------------------------------

    async def store_result(
        self,
        task_id: str,
        result_key: str,
        data: Any,
    ) -> TaskResult:
        """
        Store (or replace) a JSON result blob for a task.

        Args:
            task_id: Parent task ID.
            result_key: Logical name for this result (e.g. ``"subdomains"``).
            data: JSON-serialisable value.

        Returns:
            The TaskResult record.
        """
        return await self.db.taskresult.create(
            data={
                "task_id": task_id,
                "result_key": result_key,
                "data": data,
            }
        )

    async def get_results(self, task_id: str) -> List[TaskResult]:
        """Return all result records for a task."""
        return await self.db.taskresult.find_many(
            where={"task_id": task_id},
            order={"created_at": "asc"},
        )

    # ------------------------------------------------------------------
    # Task Logs
    # ------------------------------------------------------------------

    async def add_log(
        self,
        task_id: str,
        message: str,
        level: str = "info",
        extra: Optional[Dict[str, Any]] = None,
    ) -> TaskLog:
        """
        Append a log entry to a task.

        Args:
            task_id: Parent task ID.
            message: Human-readable log message.
            level: ``debug`` | ``info`` | ``warning`` | ``error``.
            extra: Optional JSON metadata.

        Returns:
            The TaskLog record.
        """
        return await self.db.tasklog.create(
            data={
                "task_id": task_id,
                "level": level,
                "message": message,
                "extra": extra,
            }
        )

    async def get_logs(
        self,
        task_id: str,
        level: Optional[str] = None,
        skip: int = 0,
        take: int = 200,
    ) -> List[TaskLog]:
        """Return paginated log entries for a task."""
        where: Dict[str, Any] = {"task_id": task_id}
        if level:
            where["level"] = level
        return await self.db.tasklog.find_many(
            where=where,
            skip=skip,
            take=take,
            order={"created_at": "asc"},
        )

    # ------------------------------------------------------------------
    # Task Metrics
    # ------------------------------------------------------------------

    async def upsert_metrics(
        self,
        task_id: str,
        duration_seconds: Optional[float] = None,
        memory_mb: Optional[float] = None,
        cpu_percent: Optional[float] = None,
        items_processed: int = 0,
        error_count: int = 0,
    ) -> TaskMetrics:
        """
        Create or update the performance metrics record for a task.

        Returns:
            The TaskMetrics record.
        """
        data: Dict[str, Any] = {
            "items_processed": items_processed,
            "error_count": error_count,
        }
        if duration_seconds is not None:
            data["duration_seconds"] = duration_seconds
        if memory_mb is not None:
            data["memory_mb"] = memory_mb
        if cpu_percent is not None:
            data["cpu_percent"] = cpu_percent

        return await self.db.taskmetrics.upsert(
            where={"task_id": task_id},
            data={
                "create": {"task_id": task_id, **data},
                "update": data,
            },
        )

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    async def delete_task(self, task_id: str) -> Optional[Task]:
        """Delete a task and all related records (cascade via schema)."""
        try:
            task = await self.db.task.delete(where={"id": task_id})
            logger.info("Deleted task %s", task_id)
            return task
        except Exception:
            return None

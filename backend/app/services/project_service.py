"""
Project Service
Orchestrates project lifecycle operations by coordinating ProjectsRepository
and TasksRepository.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from app.db.repositories.projects_repo import ProjectsRepository
from app.db.repositories.tasks_repo import TasksRepository
from app.schemas import ProjectCreate, ProjectUpdate

if TYPE_CHECKING:
    from prisma.models import Project, Task

logger = logging.getLogger(__name__)


class ProjectService:
    """Business-logic layer for project and task management."""

    def __init__(self, db: Any) -> None:
        self.projects = ProjectsRepository(db)
        self.tasks = TasksRepository(db)

    # ------------------------------------------------------------------
    # Project CRUD
    # ------------------------------------------------------------------

    async def create_project(self, user_id: str, project_data: ProjectCreate) -> Project:
        """
        Create a new project for *user_id*.

        Args:
            user_id: ID of the authenticated user.
            project_data: Validated creation payload.

        Returns:
            The created Project record.
        """
        project = await self.projects.create(
            user_id=user_id,
            name=project_data.name,
            target=project_data.target,
            description=project_data.description,
            project_type=project_data.project_type,
            enable_subdomain_enum=project_data.enable_subdomain_enum,
            enable_port_scan=project_data.enable_port_scan,
            enable_web_crawl=project_data.enable_web_crawl,
            enable_tech_detection=project_data.enable_tech_detection,
            enable_vuln_scan=project_data.enable_vuln_scan,
            enable_nuclei=project_data.enable_nuclei,
            enable_auto_exploit=project_data.enable_auto_exploit,
        )
        logger.info("Created project %s ('%s') for user %s", project.id, project.name, user_id)
        return project

    async def get_project(self, project_id: str, user_id: str) -> Optional[Project]:
        """
        Return a project if it exists and is owned by *user_id*.

        Returns:
            Project record or *None*.
        """
        project = await self.projects.get_by_id(project_id)
        if project is None:
            return None
        if project.user_id != user_id:
            return None
        return project

    async def list_projects(
        self,
        user_id: str,
        page: int = 1,
        page_size: int = 20,
        status: Optional[str] = None,
        project_type: Optional[str] = None,
        search: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Return a paginated project list with total count.

        Args:
            user_id: Filter to this owner.
            page: 1-based page number.
            page_size: Items per page.
            status: Optional status filter.
            project_type: Optional type filter.
            search: Full-text search on name/target.

        Returns:
            ``{"projects": [...], "total": int, "page": int, "page_size": int}``
        """
        skip = (page - 1) * page_size
        result = await self.projects.list_with_filters(
            user_id=user_id,
            skip=skip,
            take=page_size,
            status=status,
            project_type=project_type,
            search=search,
        )
        return {
            "projects": result["projects"],
            "total": result["total"],
            "page": page,
            "page_size": page_size,
        }

    async def update_project(
        self, project_id: str, user_id: str, update_data: ProjectUpdate
    ) -> Optional[Project]:
        """
        Partially update a project if owned by *user_id*.

        Returns:
            Updated Project or *None* if not found / not authorised.
        """
        project = await self.get_project(project_id, user_id)
        if project is None:
            return None

        status_val = update_data.status.value if update_data.status else None
        return await self.projects.update(
            project_id,
            name=update_data.name,
            description=update_data.description,
            status=status_val,
        )

    async def delete_project(self, project_id: str, user_id: str) -> bool:
        """
        Delete a project if owned by *user_id*.

        Returns:
            *True* on success, *False* if not found / not authorised.
        """
        project = await self.get_project(project_id, user_id)
        if project is None:
            return False
        deleted = await self.projects.delete(project_id)
        return deleted is not None

    # ------------------------------------------------------------------
    # Task lifecycle helpers
    # ------------------------------------------------------------------

    async def enqueue_tasks(self, project: Project) -> List[Task]:
        """
        Create the initial task set for a project based on its feature flags.

        Called after a project transitions to *running* status.

        Args:
            project: The Project record (must include feature flag fields).

        Returns:
            List of created Task records.
        """
        created: List[Task] = []

        if project.enable_subdomain_enum:
            task = await self.tasks.create_task(project.id, "recon")
            created.append(task)

        if project.enable_port_scan:
            task = await self.tasks.create_task(project.id, "port_scan")
            created.append(task)

        if project.enable_web_crawl or project.enable_tech_detection:
            task = await self.tasks.create_task(project.id, "http_probe")
            created.append(task)

        logger.info(
            "Enqueued %d tasks for project %s", len(created), project.id
        )
        return created

    async def start_project(self, project_id: str, user_id: str) -> Optional[Project]:
        """
        Transition a project to *running* and enqueue its tasks.

        Returns:
            Updated Project or *None* if not found / not authorised.
        """
        from datetime import datetime

        project = await self.get_project(project_id, user_id)
        if project is None:
            return None

        updated = await self.projects.update(
            project_id,
            status="running",
            started_at=datetime.utcnow(),
        )
        if updated:
            await self.enqueue_tasks(updated)
        return updated

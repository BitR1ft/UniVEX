"""
Project Repository
Handles all database operations for the Project model.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from app.db.repositories.base import BaseRepository

if TYPE_CHECKING:
    from prisma.models import Project

logger = logging.getLogger(__name__)


class ProjectsRepository(BaseRepository):
    """Repository for Project CRUD operations with pagination and filtering."""

    def __init__(self, db: Any) -> None:
        super().__init__(db)

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    async def create(
        self,
        user_id: str,
        name: str,
        target: str,
        description: Optional[str] = None,
        project_type: str = "full_assessment",
        enable_subdomain_enum: bool = True,
        enable_port_scan: bool = True,
        enable_web_crawl: bool = True,
        enable_tech_detection: bool = True,
        enable_vuln_scan: bool = True,
        enable_nuclei: bool = True,
        enable_auto_exploit: bool = False,
    ) -> Project:
        """
        Create a new penetration-testing project.

        Args:
            user_id: ID of the owning user.
            name: Human-readable project name.
            target: Target domain / IP / URL.
            description: Optional description.
            project_type: Assessment type (default: ``full_assessment``).
            enable_*: Feature flags for individual scan phases.

        Returns:
            The newly created Project record.
        """
        project = await self.db.project.create(
            data={
                "user_id": user_id,
                "name": name,
                "target": target,
                "description": description,
                "project_type": project_type,
                "enable_subdomain_enum": enable_subdomain_enum,
                "enable_port_scan": enable_port_scan,
                "enable_web_crawl": enable_web_crawl,
                "enable_tech_detection": enable_tech_detection,
                "enable_vuln_scan": enable_vuln_scan,
                "enable_nuclei": enable_nuclei,
                "enable_auto_exploit": enable_auto_exploit,
            }
        )
        logger.info("Created project %s for user %s", project.id, user_id)
        return project

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def get_by_id(self, project_id: str) -> Optional[Project]:
        """Return a project by primary key, or *None* if not found."""
        return await self.db.project.find_unique(where={"id": project_id})

    async def get_by_user(
        self,
        user_id: str,
        skip: int = 0,
        take: int = 20,
        status: Optional[str] = None,
    ) -> List[Project]:
        """
        Return projects owned by *user_id*, newest first.

        Args:
            user_id: Filter by owner.
            skip: Pagination offset.
            take: Page size.
            status: Optional status filter (``draft``, ``running``, …).

        Returns:
            List of Project records.
        """
        where: Dict[str, Any] = {"user_id": user_id}
        if status:
            where["status"] = status

        return await self.db.project.find_many(
            where=where,
            skip=skip,
            take=take,
            order={"created_at": "desc"},
        )

    async def count_by_user(
        self, user_id: str, status: Optional[str] = None
    ) -> int:
        """Return the total number of projects owned by *user_id*."""
        where: Dict[str, Any] = {"user_id": user_id}
        if status:
            where["status"] = status
        return await self.db.project.count(where=where)

    async def list_with_filters(
        self,
        user_id: str,
        skip: int = 0,
        take: int = 20,
        status: Optional[str] = None,
        project_type: Optional[str] = None,
        search: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Return a paginated, filtered project list together with the total
        count so callers can build pagination metadata in one call.

        Returns:
            ``{"projects": [...], "total": int}``
        """
        where: Dict[str, Any] = {"user_id": user_id}
        if status:
            where["status"] = status
        if project_type:
            where["project_type"] = project_type
        if search:
            where["OR"] = [
                {"name": {"contains": search, "mode": "insensitive"}},
                {"target": {"contains": search, "mode": "insensitive"}},
            ]

        projects = await self.db.project.find_many(
            where=where,
            skip=skip,
            take=take,
            order={"created_at": "desc"},
        )
        total = await self.db.project.count(where=where)
        return {"projects": projects, "total": total}

    # ------------------------------------------------------------------
    # Update
    # ------------------------------------------------------------------

    async def update(
        self,
        project_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[str] = None,
        started_at: Optional[Any] = None,
        completed_at: Optional[Any] = None,
    ) -> Optional[Project]:
        """
        Partially update a project record.

        Only non-None values are written.

        Returns:
            Updated Project record, or *None* if not found.
        """
        data = self._strip_none(
            {
                "name": name,
                "description": description,
                "status": status,
                "started_at": started_at,
                "completed_at": completed_at,
            }
        )
        if not data:
            return await self.get_by_id(project_id)
        return await self.db.project.update(where={"id": project_id}, data=data)

    async def update_status(self, project_id: str, status: str) -> Optional[Project]:
        """Convenience helper to update only the project status."""
        return await self.update(project_id, status=status)

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    async def delete(self, project_id: str) -> Optional[Project]:
        """
        Delete a project (and its tasks via schema cascade).

        Returns:
            The deleted Project record, or *None* if not found.
        """
        try:
            project = await self.db.project.delete(where={"id": project_id})
            logger.info("Deleted project %s", project_id)
            return project
        except Exception:
            return None

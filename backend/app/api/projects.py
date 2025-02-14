"""
projects.py – Project CRUD API endpoints (refactored to use ProjectService / Prisma)

  - POST   /projects           → ProjectService.create_project()
  - GET    /projects           → ProjectService.list_projects() (paginated + filtered)
  - GET    /projects/{id}      → ProjectService.get_project()
  - PATCH  /projects/{id}      → ProjectService.update_project()
  - DELETE /projects/{id}      → ProjectService.delete_project()
  - POST   /projects/{id}/start → ProjectService.start_project()
"""
from __future__ import annotations

import logging
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.audit import AuditAction, log_audit
from app.core.security import decode_token
from app.db.prisma_client import get_prisma
from app.schemas import (
    Message,
    ProjectCreate,
    ProjectListResponse,
    ProjectResponse,
    ProjectStatus,
    ProjectUpdate,
)
from app.services.project_service import ProjectService

logger = logging.getLogger(__name__)

router = APIRouter()
security = HTTPBearer()

# ---------------------------------------------------------------------------
# Backward-compat stub (conftest.py clears projects_db between tests)
# ---------------------------------------------------------------------------
projects_db: dict = {}


# ---------------------------------------------------------------------------
# Dependency helpers
# ---------------------------------------------------------------------------

async def get_project_service() -> ProjectService:
    """FastAPI dependency – builds a ProjectService backed by the Prisma DB."""
    db = await get_prisma()
    return ProjectService(db)


async def get_current_user_id(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
) -> str:
    """Extract and validate the bearer token; return the subject (user_id)."""
    payload = decode_token(credentials.credentials)
    user_id: str | None = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )
    return user_id


# ---------------------------------------------------------------------------
# Helper: convert Prisma Project model → ProjectResponse schema
# ---------------------------------------------------------------------------

def _to_response(project) -> ProjectResponse:
    return ProjectResponse(
        id=project.id,
        name=project.name,
        description=project.description,
        target=project.target,
        project_type=project.project_type,
        status=project.status,
        created_at=project.created_at,
        updated_at=project.updated_at,
        user_id=project.user_id,
        enable_subdomain_enum=project.enable_subdomain_enum,
        enable_port_scan=project.enable_port_scan,
        enable_web_crawl=project.enable_web_crawl,
        enable_tech_detection=project.enable_tech_detection,
        enable_vuln_scan=project.enable_vuln_scan,
        enable_nuclei=project.enable_nuclei,
        enable_auto_exploit=project.enable_auto_exploit,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    project_data: ProjectCreate,
    user_id: str = Depends(get_current_user_id),
    svc: ProjectService = Depends(get_project_service),
):
    """
    Create a new penetration testing project.

    - **name**: Project name
    - **description**: Optional description
    - **target**: Target domain, IP, or URL
    - **project_type**: Assessment type (default: `full_assessment`)
    """
    project = await svc.create_project(user_id, project_data)
    log_audit(AuditAction.PROJECT_CREATE, actor_id=user_id, target_id=project.id, target_type="project")
    return _to_response(project)


@router.get("", response_model=ProjectListResponse)
async def list_projects(
    user_id: str = Depends(get_current_user_id),
    svc: ProjectService = Depends(get_project_service),
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    status: Optional[ProjectStatus] = Query(None, description="Filter by status"),
    project_type: Optional[str] = Query(None, description="Filter by project type"),
    search: Optional[str] = Query(None, description="Full-text search on name/target"),
):
    """
    List the current user's projects with pagination and optional filters.
    """
    result = await svc.list_projects(
        user_id=user_id,
        page=page,
        page_size=page_size,
        status=status.value if status else None,
        project_type=project_type,
        search=search,
    )
    return ProjectListResponse(
        projects=[_to_response(p) for p in result["projects"]],
        total=result["total"],
        page=result["page"],
        page_size=result["page_size"],
    )


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: str,
    user_id: str = Depends(get_current_user_id),
    svc: ProjectService = Depends(get_project_service),
):
    """Return a specific project by ID (must be owned by the current user)."""
    project = await svc.get_project(project_id, user_id)
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    return _to_response(project)


@router.patch("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: str,
    project_update: ProjectUpdate,
    user_id: str = Depends(get_current_user_id),
    svc: ProjectService = Depends(get_project_service),
):
    """
    Partially update a project.

    Only **name**, **description**, and **status** can be changed after creation.
    """
    updated = await svc.update_project(project_id, user_id, project_update)
    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    log_audit(AuditAction.PROJECT_UPDATE, actor_id=user_id, target_id=project_id, target_type="project")
    return _to_response(updated)


@router.delete("/{project_id}", response_model=Message)
async def delete_project(
    project_id: str,
    user_id: str = Depends(get_current_user_id),
    svc: ProjectService = Depends(get_project_service),
):
    """Delete a project and all its tasks (cascade)."""
    deleted = await svc.delete_project(project_id, user_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    log_audit(AuditAction.PROJECT_DELETE, actor_id=user_id, target_id=project_id, target_type="project")
    return Message(message="Project deleted successfully")


@router.post("/{project_id}/start", response_model=ProjectResponse)
async def start_project(
    project_id: str,
    user_id: str = Depends(get_current_user_id),
    svc: ProjectService = Depends(get_project_service),
):
    """
    Transition a project from *draft* / *paused* to *running* and enqueue its tasks.

    The tasks created depend on the project's feature flags
    (``enable_subdomain_enum``, ``enable_port_scan``, etc.).
    """
    project = await svc.start_project(project_id, user_id)
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    log_audit(AuditAction.PROJECT_START, actor_id=user_id, target_id=project_id, target_type="project")
    return _to_response(project)

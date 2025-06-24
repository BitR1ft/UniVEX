"""
GraphQL Queries — All read operations for the GraphQL API.

Query fields:
  projects, project(id)
  scans, scan(id)
  findings, finding(id)
  campaigns, campaign(id)
  reports, report(id)
  agents
  tools
  me (current user info)
"""

from __future__ import annotations

import logging
from typing import List, Optional
from datetime import datetime

import strawberry
from strawberry.types import Info

from app.graphql.types import (
    Project, ProjectConnection, ProjectStatus, PageInfo,
    Scan, ScanConnection, ScanStatus,
    Finding, FindingConnection, FindingSeverity, FindingStatus,
    Campaign, CampaignConnection, CampaignStatus,
    Report, ReportConnection, AgentExecution, ToolInfo,
    User, UserRole,
)
from app.graphql.dataloaders import (
    build_mock_project,
    build_mock_scan,
    build_mock_finding,
    build_mock_campaign,
    build_mock_report,
)

logger = logging.getLogger(__name__)


def _make_page_info(total: int, page: int, page_size: int) -> PageInfo:
    return PageInfo(
        total=total,
        page=page,
        page_size=page_size,
        has_next=(page * page_size) < total,
        has_prev=page > 1,
    )


@strawberry.type
class Query:
    # -----------------------------------------------------------------------
    # Project queries
    # -----------------------------------------------------------------------

    @strawberry.field(description="List all projects with optional filters and pagination")
    async def projects(
        self,
        info: Info,
        status: Optional[ProjectStatus] = None,
        search: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> ProjectConnection:
        """Return paginated list of projects."""
        try:
            from app.findings.finding_manager import FindingManager

            # Delegate to REST layer internals where available
            FindingManager()
            # Build representative mock/stub response for the connection
            items = []
            try:
                from app.api.projects import _get_db_projects
                raw = await _get_db_projects(status=status, search=search, page=page, page_size=page_size)
                items = [build_mock_project(p) for p in raw.get("projects", [])]
                total = raw.get("total", len(items))
            except Exception:
                # Graceful degradation when DB is unavailable
                items = []
                total = 0

            return ProjectConnection(
                items=items,
                page_info=_make_page_info(total, page, page_size),
            )
        except Exception as exc:
            logger.error("GraphQL projects query error: %s", exc)
            return ProjectConnection(items=[], page_info=_make_page_info(0, page, page_size))

    @strawberry.field(description="Get a single project by ID")
    async def project(self, info: Info, id: str) -> Optional[Project]:
        """Return a project by ID."""
        try:
            from app.api.projects import _get_db_project_by_id
            raw = await _get_db_project_by_id(id)
            if raw is None:
                return None
            return build_mock_project(raw)
        except Exception as exc:
            logger.error("GraphQL project query error: %s", exc)
            return None

    # -----------------------------------------------------------------------
    # Scan queries
    # -----------------------------------------------------------------------

    @strawberry.field(description="List scans with optional project filter and pagination")
    async def scans(
        self,
        info: Info,
        project_id: Optional[str] = None,
        status: Optional[ScanStatus] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> ScanConnection:
        try:
            items: List[Scan] = []
            total = 0
            try:
                from app.api.scans_ports import _list_scans
                raw = await _list_scans(project_id=project_id, status=status, page=page, page_size=page_size)
                items = [build_mock_scan(s) for s in raw.get("scans", [])]
                total = raw.get("total", len(items))
            except Exception:
                pass
            return ScanConnection(items=items, page_info=_make_page_info(total, page, page_size))
        except Exception as exc:
            logger.error("GraphQL scans query error: %s", exc)
            return ScanConnection(items=[], page_info=_make_page_info(0, page, page_size))

    @strawberry.field(description="Get a single scan by ID")
    async def scan(self, info: Info, id: str) -> Optional[Scan]:
        try:
            from app.api.scans_ports import _get_scan_by_id
            raw = await _get_scan_by_id(id)
            if raw is None:
                return None
            return build_mock_scan(raw)
        except Exception as exc:
            logger.error("GraphQL scan query error: %s", exc)
            return None

    # -----------------------------------------------------------------------
    # Finding queries
    # -----------------------------------------------------------------------

    @strawberry.field(description="List findings with rich filtering and pagination")
    async def findings(
        self,
        info: Info,
        project_id: Optional[str] = None,
        campaign_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        severity: Optional[FindingSeverity] = None,
        status: Optional[FindingStatus] = None,
        search: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> FindingConnection:
        try:
            from app.findings.finding_manager import FindingManager
            manager = FindingManager()

            filters = {}
            if project_id:
                filters["project_id"] = project_id
            if campaign_id:
                filters["campaign_id"] = campaign_id
            if scan_id:
                filters["scan_id"] = scan_id
            if severity:
                filters["severity"] = severity.value
            if status:
                filters["status"] = status.value

            raw_findings = await manager.list_findings(
                filters=filters,
                search=search,
                page=page,
                page_size=page_size,
            )
            items = [build_mock_finding(f) for f in raw_findings.get("findings", [])]
            total = raw_findings.get("total", len(items))
            return FindingConnection(items=items, page_info=_make_page_info(total, page, page_size))
        except Exception as exc:
            logger.error("GraphQL findings query error: %s", exc)
            return FindingConnection(items=[], page_info=_make_page_info(0, page, page_size))

    @strawberry.field(description="Get a single finding by ID")
    async def finding(self, info: Info, id: str) -> Optional[Finding]:
        try:
            from app.findings.finding_manager import FindingManager
            manager = FindingManager()
            raw = await manager.get_finding(id)
            if raw is None:
                return None
            return build_mock_finding(raw)
        except Exception as exc:
            logger.error("GraphQL finding query error: %s", exc)
            return None

    # -----------------------------------------------------------------------
    # Campaign queries
    # -----------------------------------------------------------------------

    @strawberry.field(description="List campaigns with optional status filter")
    async def campaigns(
        self,
        info: Info,
        status: Optional[CampaignStatus] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> CampaignConnection:
        try:
            from app.campaigns.campaign_engine import CampaignEngine
            engine = CampaignEngine()

            raw_list = await engine.list_campaigns(
                status=status.value if status else None,
                page=page,
                page_size=page_size,
            )
            items = [build_mock_campaign(c) for c in raw_list.get("campaigns", [])]
            total = raw_list.get("total", len(items))
            return CampaignConnection(items=items, page_info=_make_page_info(total, page, page_size))
        except Exception as exc:
            logger.error("GraphQL campaigns query error: %s", exc)
            return CampaignConnection(items=[], page_info=_make_page_info(0, page, page_size))

    @strawberry.field(description="Get a single campaign by ID")
    async def campaign(self, info: Info, id: str) -> Optional[Campaign]:
        try:
            from app.campaigns.campaign_engine import CampaignEngine
            engine = CampaignEngine()
            raw = await engine.get_campaign(id)
            if raw is None:
                return None
            return build_mock_campaign(raw)
        except Exception as exc:
            logger.error("GraphQL campaign query error: %s", exc)
            return None

    # -----------------------------------------------------------------------
    # Report queries
    # -----------------------------------------------------------------------

    @strawberry.field(description="List generated reports")
    async def reports(
        self,
        info: Info,
        project_id: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> ReportConnection:
        try:
            items: List[Report] = []
            total = 0
            try:
                from app.reports.report_engine import ReportEngine
                engine = ReportEngine()
                raw_list = await engine.list_reports(project_id=project_id, page=page, page_size=page_size)
                items = [build_mock_report(r) for r in raw_list.get("reports", [])]
                total = raw_list.get("total", len(items))
            except Exception:
                pass
            return ReportConnection(items=items, page_info=_make_page_info(total, page, page_size))
        except Exception as exc:
            logger.error("GraphQL reports query error: %s", exc)
            return ReportConnection(items=[], page_info=_make_page_info(0, page, page_size))

    @strawberry.field(description="Get a single report by ID")
    async def report(self, info: Info, id: str) -> Optional[Report]:
        try:
            from app.reports.report_engine import ReportEngine
            engine = ReportEngine()
            raw = await engine.get_report(id)
            if raw is None:
                return None
            return build_mock_report(raw)
        except Exception as exc:
            logger.error("GraphQL report query error: %s", exc)
            return None

    # -----------------------------------------------------------------------
    # Agent / Tool queries
    # -----------------------------------------------------------------------

    @strawberry.field(description="List all available agent roles")
    async def agents(self, info: Info) -> List[AgentExecution]:
        """Return active/recent agent executions."""
        return []

    @strawberry.field(description="List all registered tools with metadata")
    async def tools(self, info: Info, phase: Optional[str] = None) -> List[ToolInfo]:
        try:
            from app.agent.tools.tool_registry import ToolRegistry
            registry = ToolRegistry()
            all_tools = registry.list_tools(phase=phase)
            return [
                ToolInfo(
                    name=t.get("name", ""),
                    description=t.get("description", ""),
                    phase=t.get("phase", "unknown"),
                    enabled=t.get("enabled", True),
                    parameters=t.get("parameters"),
                )
                for t in all_tools
            ]
        except Exception as exc:
            logger.error("GraphQL tools query error: %s", exc)
            return []

    # -----------------------------------------------------------------------
    # User / Auth queries
    # -----------------------------------------------------------------------

    @strawberry.field(description="Return the currently authenticated user")
    async def me(self, info: Info) -> Optional[User]:
        """Return current user from JWT context."""
        try:
            request = info.context.get("request")
            if request is None:
                return None
            # Extract user from token if present
            auth_header = request.headers.get("authorization", "")
            if not auth_header.startswith("Bearer "):
                return None
            from app.core.auth import decode_access_token
            token = auth_header[7:]
            payload = decode_access_token(token)
            if payload is None:
                return None
            return User(
                id=payload.get("sub", ""),
                username=payload.get("username", ""),
                email=payload.get("email", ""),
                full_name=payload.get("full_name"),
                role=UserRole(payload.get("role", "analyst")),
                is_active=True,
                created_at=datetime.utcnow(),
            )
        except Exception as exc:
            logger.error("GraphQL me query error: %s", exc)
            return None

    # -----------------------------------------------------------------------
    # Analytics queries
    # -----------------------------------------------------------------------

    @strawberry.field(description="Aggregate finding statistics across all projects")
    async def finding_stats(
        self,
        info: Info,
        project_id: Optional[str] = None,
    ) -> strawberry.scalars.JSON:
        """Return severity breakdown, trend data, and top CVEs."""
        try:
            from app.findings.finding_manager import FindingManager
            manager = FindingManager()
            stats = await manager.get_stats(project_id=project_id)
            return stats
        except Exception as exc:
            logger.error("GraphQL finding_stats error: %s", exc)
            return {}

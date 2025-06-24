"""
GraphQL Data Loaders & Object Builders

Converts raw dicts / domain objects from the REST/DB layer into Strawberry
GraphQL types without coupling the GraphQL layer to the underlying models.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

from app.graphql.types import (
    Project, ProjectStatus,
    Scan, ScanStatus,
    Finding, FindingSeverity, FindingStatus, Evidence,
    Campaign, CampaignStatus, CampaignTarget,
    Report, ReportFormat,
)


def _dt(v: Any) -> datetime:
    if isinstance(v, datetime):
        return v
    if isinstance(v, str):
        try:
            return datetime.fromisoformat(v)
        except ValueError:
            pass
    return datetime.utcnow()


def _str(v: Any, default: str = "") -> str:
    return str(v) if v is not None else default


def build_mock_project(data: Dict[str, Any]) -> Project:
    status_raw = _str(data.get("status", "active")).lower()
    try:
        status = ProjectStatus(status_raw)
    except ValueError:
        status = ProjectStatus.ACTIVE

    return Project(
        id=_str(data.get("id", "")),
        name=_str(data.get("name", "")),
        description=data.get("description"),
        target=_str(data.get("target", "")),
        project_type=_str(data.get("project_type", "web")),
        status=status,
        created_at=_dt(data.get("created_at")),
        updated_at=_dt(data.get("updated_at")),
        user_id=_str(data.get("user_id", "")),
        enable_subdomain_enum=bool(data.get("enable_subdomain_enum", False)),
        enable_port_scan=bool(data.get("enable_port_scan", False)),
        enable_web_crawl=bool(data.get("enable_web_crawl", False)),
        enable_tech_detection=bool(data.get("enable_tech_detection", False)),
        enable_vuln_scan=bool(data.get("enable_vuln_scan", False)),
        enable_nuclei=bool(data.get("enable_nuclei", False)),
        enable_auto_exploit=bool(data.get("enable_auto_exploit", False)),
    )


def build_mock_scan(data: Dict[str, Any]) -> Scan:
    status_raw = _str(data.get("status", "pending")).lower()
    try:
        status = ScanStatus(status_raw)
    except ValueError:
        status = ScanStatus.PENDING

    return Scan(
        id=_str(data.get("id", "")),
        project_id=_str(data.get("project_id", "")),
        scan_type=_str(data.get("scan_type", "unknown")),
        status=status,
        target=_str(data.get("target", "")),
        started_at=_dt(data["started_at"]) if data.get("started_at") else None,
        completed_at=_dt(data["completed_at"]) if data.get("completed_at") else None,
        created_at=_dt(data.get("created_at")),
        findings_count=int(data.get("findings_count", 0)),
        error_message=data.get("error_message"),
        metadata=data.get("metadata"),
    )


def build_mock_finding(data: Dict[str, Any]) -> Finding:
    severity_raw = _str(data.get("severity", "info")).lower()
    try:
        severity = FindingSeverity(severity_raw)
    except ValueError:
        severity = FindingSeverity.INFO

    status_raw = _str(data.get("status", "open")).lower()
    try:
        status = FindingStatus(status_raw)
    except ValueError:
        status = FindingStatus.OPEN

    raw_evidence = data.get("evidence", []) or []
    evidence = [
        Evidence(
            id=_str(e.get("id", "")),
            type=_str(e.get("type", "text")),
            content=_str(e.get("content", "")),
            filename=e.get("filename"),
            created_at=_dt(e["created_at"]) if e.get("created_at") else None,
        )
        for e in raw_evidence
    ]

    return Finding(
        id=_str(data.get("id", "")),
        title=_str(data.get("title", "")),
        severity=severity,
        status=status,
        description=_str(data.get("description", "")),
        source=_str(data.get("source", "manual")),
        cve_id=data.get("cve_id"),
        cwe_id=data.get("cwe_id"),
        owasp_category=data.get("owasp_category"),
        cvss_score=float(data.get("cvss_score", 0.0)),
        cvss_vector=data.get("cvss_vector"),
        affected_component=_str(data.get("affected_component", "")),
        affected_url=data.get("affected_url"),
        affected_parameter=data.get("affected_parameter"),
        affected_method=_str(data.get("affected_method", "GET")),
        project_id=data.get("project_id"),
        campaign_id=data.get("campaign_id"),
        scan_id=data.get("scan_id"),
        remediation=_str(data.get("remediation", "")),
        remediation_effort=_str(data.get("remediation_effort", "medium")),
        references=list(data.get("references", [])),
        tool_name=data.get("tool_name"),
        tags=list(data.get("tags", [])),
        created_at=_dt(data.get("created_at")),
        updated_at=_dt(data.get("updated_at")),
        evidence=evidence,
    )


def build_mock_campaign(data: Dict[str, Any]) -> Campaign:
    status_raw = _str(data.get("status", "pending")).lower()
    try:
        status = CampaignStatus(status_raw)
    except ValueError:
        status = CampaignStatus.PENDING

    raw_targets = data.get("targets", []) or []
    targets = [
        CampaignTarget(
            id=_str(t.get("id", "")),
            target=_str(t.get("target", "")),
            status=_str(t.get("status", "pending")),
            findings_count=int(t.get("findings_count", 0)),
        )
        for t in raw_targets
    ]

    return Campaign(
        id=_str(data.get("id", "")),
        name=_str(data.get("name", "")),
        description=data.get("description"),
        status=status,
        targets=targets,
        total_findings=int(data.get("total_findings", 0)),
        created_at=_dt(data.get("created_at")),
        updated_at=_dt(data.get("updated_at")),
        started_at=_dt(data["started_at"]) if data.get("started_at") else None,
        completed_at=_dt(data["completed_at"]) if data.get("completed_at") else None,
    )


def build_mock_report(data: Dict[str, Any]) -> Report:
    fmt_raw = _str(data.get("format", "pdf")).lower()
    try:
        fmt = ReportFormat(fmt_raw)
    except ValueError:
        fmt = ReportFormat.PDF

    return Report(
        id=_str(data.get("id", "")),
        project_id=data.get("project_id"),
        campaign_id=data.get("campaign_id"),
        format=fmt,
        title=_str(data.get("title", "Report")),
        created_at=_dt(data.get("created_at")),
        download_url=data.get("download_url"),
        findings_count=int(data.get("findings_count", 0)),
    )

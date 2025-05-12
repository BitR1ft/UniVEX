"""

Endpoints:
  POST   /api/reports/generate                 — generate a new report (HTML or PDF)
  GET    /api/reports                          — list all reports
  GET    /api/reports/{report_id}              — get report metadata
  GET    /api/reports/{report_id}/download     — download HTML or PDF content
  GET    /api/reports/{report_id}/presigned-url— get presigned MinIO download URL (24h)
  DELETE /api/reports/{report_id}              — delete a report
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.reports.report_engine import (
    Finding,
    ReportConfig,
    ReportFormat,
    ReportMetadata,
    ReportTemplate,
    ScanResult,
    Severity,
)
from app.reports.chart_generator import ChartGenerator
from app.reports.pdf_generator import PDFGenerator
from app.reports.report_engine import ReportEngine

try:
    from app.storage.artifact_store import get_artifact_store
    _MINIO_ENABLED = True
except ImportError:  # pragma: no cover
    _MINIO_ENABLED = False

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/reports", tags=["Reports"])

# ---------------------------------------------------------------------------
# In-memory report store  (report_id → StoredReport)
# ---------------------------------------------------------------------------

@dataclass
class StoredReport:
    id: str
    metadata: ReportMetadata
    config: ReportConfig
    html_content: str
    pdf_content: bytes
    created_at: datetime
    finding_count: int
    risk_level: str
    risk_score: float
    minio_pdf_url: Optional[str] = None
    minio_html_url: Optional[str] = None


_reports: Dict[str, StoredReport] = {}

# Singletons
_engine = ReportEngine()
_chart_gen = ChartGenerator()
_pdf_gen = PDFGenerator()


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class FindingRequest(BaseModel):
    """A single finding provided by the caller."""
    title: str = Field(..., description="Finding title")
    description: str = Field("", description="Detailed description")
    severity: Severity = Field(Severity.MEDIUM)
    cvss_score: float = Field(0.0, ge=0.0, le=10.0)
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    nist_controls: List[str] = Field(default_factory=list)
    pci_dss_requirements: List[str] = Field(default_factory=list)
    reproduction_steps: List[str] = Field(default_factory=list)
    evidence: Optional[str] = None
    remediation: str = ""
    affected_component: str = ""
    likelihood: str = "medium"
    business_impact: str = ""


class ScanResultRequest(BaseModel):
    """Scan result block provided by the caller."""
    target: str = Field(..., description="Target hostname or IP")
    scan_type: str = Field("", description="Type of scan performed")
    findings: List[FindingRequest] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GenerateReportRequest(BaseModel):
    """Request body for POST /api/reports/generate."""
    project_name: str = Field("Security Assessment", description="Project/client name")
    author: str = Field("Security Team", description="Report author")
    client_name: Optional[str] = None
    title: str = Field("Security Assessment Report")
    template: ReportTemplate = Field(ReportTemplate.TECHNICAL_REPORT)
    format: ReportFormat = Field(ReportFormat.HTML)
    include_charts: bool = True
    include_toc: bool = True
    scan_results: List[ScanResultRequest] = Field(default_factory=list)
    confidentiality: str = "CONFIDENTIAL"


class ReportSummary(BaseModel):
    """Summary of a stored report (returned in list / generate responses)."""
    id: str
    project_name: str
    title: str
    template: str
    format: str
    finding_count: int
    risk_level: str
    risk_score: float
    created_at: str
    author: str
    minio_pdf_url: Optional[str] = None
    minio_html_url: Optional[str] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_finding(req: FindingRequest) -> Finding:
    return Finding(
        title=req.title,
        description=req.description,
        severity=req.severity,
        cvss_score=req.cvss_score,
        cve_id=req.cve_id,
        cwe_id=req.cwe_id,
        owasp_category=req.owasp_category,
        nist_controls=req.nist_controls,
        pci_dss_requirements=req.pci_dss_requirements,
        reproduction_steps=req.reproduction_steps,
        evidence=req.evidence,
        remediation=req.remediation,
        affected_component=req.affected_component,
        likelihood=req.likelihood,
        business_impact=req.business_impact,
    )


def _to_scan_result(req: ScanResultRequest) -> ScanResult:
    return ScanResult(
        target=req.target,
        scan_type=req.scan_type,
        findings=[_to_finding(f) for f in req.findings],
        metadata=req.metadata,
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
    )


def _summary(report: StoredReport) -> ReportSummary:
    return ReportSummary(
        id=report.id,
        project_name=report.metadata.project_name,
        title=report.config.title,
        template=report.config.template.value,
        format=report.config.format.value,
        finding_count=report.finding_count,
        risk_level=report.risk_level,
        risk_score=report.risk_score,
        created_at=report.created_at.isoformat(),
        author=report.metadata.author,
        minio_pdf_url=report.minio_pdf_url,
        minio_html_url=report.minio_html_url,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/generate", response_model=ReportSummary, status_code=201)
async def generate_report(body: GenerateReportRequest, background_tasks: BackgroundTasks) -> ReportSummary:
    """
    Generate a security report from provided scan results.

    The report is stored in memory and can be downloaded via
    ``GET /api/reports/{report_id}/download``.
    """
    report_id = str(uuid.uuid4())

    # Convert request models to domain objects
    scan_results = [_to_scan_result(sr) for sr in body.scan_results]

    config = ReportConfig(
        title=body.title,
        template=body.template,
        format=body.format,
        include_charts=body.include_charts,
        include_toc=body.include_toc,
        confidentiality=body.confidentiality,
    )
    metadata = ReportMetadata(
        id=report_id,
        project_name=body.project_name,
        author=body.author,
        client_name=body.client_name,
    )

    # Collect all findings for charts
    all_findings = [f for sr in scan_results for f in sr.findings]

    # Generate charts
    chart_images: Dict[str, str] = {}
    if body.include_charts:
        try:
            chart_images = _chart_gen.generate_all(all_findings)
        except Exception as exc:
            logger.warning("Chart generation failed (non-fatal): %s", exc)

    # Render HTML
    try:
        html = _engine.generate(
            scan_results=scan_results,
            config=config,
            metadata=metadata,
            chart_images=chart_images,
        )
    except Exception as exc:
        logger.error("Report generation failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Report generation failed: {exc}")

    # Generate PDF if requested
    pdf_bytes: bytes = b""
    if body.format == ReportFormat.PDF:
        try:
            pdf_bytes = _pdf_gen.generate_pdf(html)
        except Exception as exc:
            logger.warning("PDF generation failed (will serve HTML): %s", exc)

    # Compute risk info for summary
    from app.reports.report_engine import FindingDeduplicator
    deduped = FindingDeduplicator().deduplicate(all_findings)
    risk_score = ReportEngine._calculate_risk_score(deduped)
    risk_level = ReportEngine._risk_level(risk_score)

    minio_pdf_url: Optional[str] = None
    minio_html_url: Optional[str] = None
    if _MINIO_ENABLED:
        try:
            artifact_store = get_artifact_store()
            result = await artifact_store.store_report(
                report_id=report_id,
                pdf_bytes=pdf_bytes or None,
                html_content=html,
                metadata={
                    "project-name": body.project_name,
                    "author": body.author,
                    "template": body.template.value,
                },
            )
            minio_pdf_url = result.pdf_presigned_url
            minio_html_url = result.html_presigned_url
            logger.info("Report artifacts stored in MinIO: id=%s", report_id)
        except Exception as exc:
            logger.warning("MinIO storage failed (non-fatal): %s", exc)

    stored = StoredReport(
        id=report_id,
        metadata=metadata,
        config=config,
        html_content=html,
        pdf_content=pdf_bytes,
        created_at=datetime.utcnow(),
        finding_count=len(deduped),
        risk_level=risk_level,
        risk_score=risk_score,
        minio_pdf_url=minio_pdf_url,
        minio_html_url=minio_html_url,
    )
    _reports[report_id] = stored

    logger.info(
        "Report generated: id=%s template=%s findings=%d",
        report_id, body.template.value, len(deduped)
    )
    return _summary(stored)


@router.get("", response_model=List[ReportSummary])
async def list_reports(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> List[ReportSummary]:
    """Return a paginated list of stored reports."""
    reports = list(_reports.values())
    reports.sort(key=lambda r: r.created_at, reverse=True)
    return [_summary(r) for r in reports[offset: offset + limit]]


@router.get("/{report_id}", response_model=ReportSummary)
async def get_report(report_id: str) -> ReportSummary:
    """Return metadata for a specific report."""
    report = _reports.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return _summary(report)


@router.get("/{report_id}/download")
async def download_report(
    report_id: str,
    format: Optional[ReportFormat] = Query(None, description="Override download format: html or pdf"),
) -> Response:
    """
    Download a report as HTML or PDF.

    If ``format`` is not specified the format used at generation time is used.
    If PDF was requested but WeasyPrint was unavailable, falls back to HTML.
    """
    report = _reports.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    requested = format or report.config.format

    if requested == ReportFormat.PDF and report.pdf_content:
        return Response(
            content=report.pdf_content,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="report-{report_id}.pdf"',
                "Content-Length": str(len(report.pdf_content)),
            },
        )

    # Serve HTML (fallback or explicit)
    return HTMLResponse(
        content=report.html_content,
        headers={
            "Content-Disposition": f'inline; filename="report-{report_id}.html"',
        },
    )


@router.get("/{report_id}/presigned-url")
async def get_report_presigned_url(
    report_id: str,
    format: Optional[ReportFormat] = Query(
        None, description="Format to get presigned URL for: pdf or html (default: pdf)"
    ),
) -> Dict[str, Any]:
    """
    Return a fresh presigned MinIO download URL for a stored report artifact.

    The URL is valid for 24 hours (configurable via ``MINIO_PRESIGN_EXPIRY``).
    Returns 404 if the report does not exist in the in-memory store.
    Returns 503 if MinIO is not configured.

    This endpoint is preferred over ``/download`` for large PDF reports as it
    offloads the download traffic directly to MinIO.
    """
    if not _MINIO_ENABLED:
        raise HTTPException(
            status_code=503,
            detail="MinIO artifact storage is not configured. Install miniopy-async.",
        )

    report = _reports.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    requested_format = format or report.config.format
    fmt_str = requested_format.value if hasattr(requested_format, "value") else str(requested_format)

    try:
        artifact_store = get_artifact_store()
        url = await artifact_store.get_report_download_url(
            report_id=report_id,
            format=fmt_str,
        )
    except Exception as exc:
        logger.error("Failed to generate presigned URL for %s: %s", report_id, exc)
        raise HTTPException(
            status_code=500,
            detail=f"Presigned URL generation failed: {exc}",
        )

    return {
        "report_id": report_id,
        "format": fmt_str,
        "presigned_url": url,
        "expires_in_seconds": 86400,
    }


@router.delete("/{report_id}", status_code=204, response_model=None)
async def delete_report(report_id: str) -> None:
    """Delete a stored report."""
    if report_id not in _reports:
        raise HTTPException(status_code=404, detail="Report not found")
    del _reports[report_id]
    logger.info("Report deleted: id=%s", report_id)

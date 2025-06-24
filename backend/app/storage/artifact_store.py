"""

Abstraction layer over MinIOClient that provides UniVex-specific bucket
management and a clean API for storing pentest artifacts.

Bucket structure
----------------
  univex-reports    — PDF and HTML reports
  univex-evidence   — screenshots and tool output files
  univex-scans      — raw tool output (Nuclei, Nmap, ffuf JSON results)
  univex-exports    — compliance exports (CSV, JSON)

All methods return presigned download URLs (24h expiry) so that clients
never need direct MinIO access credentials.
"""
from __future__ import annotations

import logging
import mimetypes
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.storage.minio_client import MinIOClient, get_minio_client

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Bucket constants
# ---------------------------------------------------------------------------

BUCKET_REPORTS = "univex-reports"
BUCKET_EVIDENCE = "univex-evidence"
BUCKET_SCANS = "univex-scans"
BUCKET_EXPORTS = "univex-exports"

ALL_BUCKETS = [BUCKET_REPORTS, BUCKET_EVIDENCE, BUCKET_SCANS, BUCKET_EXPORTS]


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y/%m/%d")


class ArtifactStore:
    """
    UniVex artifact storage over MinIO.

    All upload methods return a presigned download URL that expires in 24 hours
    (configurable via ``MINIO_PRESIGN_EXPIRY`` env var).

    Example::

        store = ArtifactStore()
        await store.initialize()

        url = await store.store_report(
            report_id="abc-123",
            pdf_bytes=pdf,
            html_content=html,
        )
        print(url.pdf_presigned_url)
    """

    def __init__(self, client: Optional[MinIOClient] = None) -> None:
        self._client = client or get_minio_client()

    async def initialize(self) -> None:
        """Create all UniVex buckets if they do not exist."""
        for bucket in ALL_BUCKETS:
            await self._client.ensure_bucket(bucket)
        logger.info("ArtifactStore initialized — buckets: %s", ALL_BUCKETS)

    # ------------------------------------------------------------------
    # Report storage  (univex-reports)
    # ------------------------------------------------------------------

    async def store_report(
        self,
        report_id: str,
        *,
        pdf_bytes: Optional[bytes] = None,
        html_content: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> "ReportStorageResult":
        """
        Store a report's PDF and/or HTML in ``univex-reports``.

        Returns:
            ReportStorageResult with presigned download URLs.
        """
        date_prefix = _now_utc()
        meta = {
            "report-id": report_id,
            "stored-at": datetime.now(timezone.utc).isoformat(),
            **(metadata or {}),
        }

        pdf_url: Optional[str] = None
        html_url: Optional[str] = None

        if pdf_bytes:
            pdf_key = f"{date_prefix}/{report_id}.pdf"
            await self._client.upload_bytes(
                BUCKET_REPORTS,
                pdf_key,
                pdf_bytes,
                content_type="application/pdf",
                metadata=meta,
            )
            pdf_url = await self._client.presigned_download_url(
                BUCKET_REPORTS,
                pdf_key,
                response_content_type="application/pdf",
                response_content_disposition=f'attachment; filename="report-{report_id}.pdf"',
            )

        if html_content is not None:
            html_key = f"{date_prefix}/{report_id}.html"
            html_bytes = html_content.encode("utf-8")
            await self._client.upload_bytes(
                BUCKET_REPORTS,
                html_key,
                html_bytes,
                content_type="text/html; charset=utf-8",
                metadata=meta,
            )
            html_url = await self._client.presigned_download_url(
                BUCKET_REPORTS,
                html_key,
                response_content_type="text/html; charset=utf-8",
                response_content_disposition=f'inline; filename="report-{report_id}.html"',
            )

        return ReportStorageResult(
            report_id=report_id,
            pdf_presigned_url=pdf_url,
            html_presigned_url=html_url,
        )

    async def get_report_download_url(
        self,
        report_id: str,
        format: str = "pdf",
        date_prefix: Optional[str] = None,
    ) -> str:
        """
        Return a fresh presigned download URL for an existing report.

        Args:
            report_id: The report UUID.
            format: "pdf" or "html".
            date_prefix: YYYY/MM/DD prefix (defaults to today).

        Returns:
            Fresh presigned URL.
        """
        prefix = date_prefix or _now_utc()
        ext = "pdf" if format == "pdf" else "html"
        object_name = f"{prefix}/{report_id}.{ext}"
        content_type = "application/pdf" if ext == "pdf" else "text/html; charset=utf-8"
        return await self._client.presigned_download_url(
            BUCKET_REPORTS, object_name, response_content_type=content_type
        )

    # ------------------------------------------------------------------
    # Evidence storage  (univex-evidence)
    # ------------------------------------------------------------------

    async def store_screenshot(
        self,
        campaign_id: str,
        data: bytes,
        *,
        file_extension: str = "png",
        filename: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> "EvidenceStorageResult":
        """
        Store a screenshot in ``univex-evidence``.

        Returns:
            EvidenceStorageResult with presigned URL.
        """
        date_prefix = _now_utc()
        obj_id = filename or str(uuid.uuid4())
        object_name = f"{date_prefix}/{campaign_id}/screenshots/{obj_id}.{file_extension}"
        content_type = mimetypes.guess_type(f"x.{file_extension}")[0] or "image/png"

        meta = {
            "campaign-id": campaign_id,
            "evidence-type": "screenshot",
            **(metadata or {}),
        }
        await self._client.upload_bytes(
            BUCKET_EVIDENCE, object_name, data, content_type=content_type, metadata=meta
        )
        url = await self._client.presigned_download_url(BUCKET_EVIDENCE, object_name)
        return EvidenceStorageResult(object_name=object_name, presigned_url=url)

    async def store_tool_output(
        self,
        campaign_id: str,
        tool_name: str,
        data: bytes,
        *,
        file_extension: str = "txt",
        metadata: Optional[Dict[str, str]] = None,
    ) -> "EvidenceStorageResult":
        """Store raw tool output (e.g. Nuclei results) in ``univex-evidence``."""
        date_prefix = _now_utc()
        obj_id = str(uuid.uuid4())
        object_name = f"{date_prefix}/{campaign_id}/tool-output/{tool_name}/{obj_id}.{file_extension}"
        content_type = mimetypes.guess_type(f"x.{file_extension}")[0] or "text/plain"

        meta = {
            "campaign-id": campaign_id,
            "tool-name": tool_name,
            **(metadata or {}),
        }
        await self._client.upload_bytes(
            BUCKET_EVIDENCE, object_name, data, content_type=content_type, metadata=meta
        )
        url = await self._client.presigned_download_url(BUCKET_EVIDENCE, object_name)
        return EvidenceStorageResult(object_name=object_name, presigned_url=url)

    # ------------------------------------------------------------------
    # Raw scan results  (univex-scans)
    # ------------------------------------------------------------------

    async def store_scan_result(
        self,
        session_id: str,
        tool_name: str,
        data: bytes,
        *,
        file_format: str = "json",
        metadata: Optional[Dict[str, str]] = None,
    ) -> "ScanStorageResult":
        """
        Store raw tool output JSON/XML in ``univex-scans``.

        Suitable for Nuclei JSONL, Nmap XML, ffuf JSON results.
        """
        date_prefix = _now_utc()
        obj_id = str(uuid.uuid4())
        object_name = f"{date_prefix}/{session_id}/{tool_name}/{obj_id}.{file_format}"
        content_type_map = {
            "json": "application/json",
            "jsonl": "application/jsonl",
            "xml": "application/xml",
            "txt": "text/plain",
        }
        content_type = content_type_map.get(file_format, "application/octet-stream")

        meta = {
            "session-id": session_id,
            "tool-name": tool_name,
            "file-format": file_format,
            **(metadata or {}),
        }
        await self._client.upload_bytes(
            BUCKET_SCANS, object_name, data, content_type=content_type, metadata=meta
        )
        url = await self._client.presigned_download_url(BUCKET_SCANS, object_name)
        return ScanStorageResult(object_name=object_name, presigned_url=url)

    # ------------------------------------------------------------------
    # Compliance exports  (univex-exports)
    # ------------------------------------------------------------------

    async def store_compliance_export(
        self,
        campaign_id: str,
        framework: str,
        data: bytes,
        *,
        file_format: str = "json",
        metadata: Optional[Dict[str, str]] = None,
    ) -> "ExportStorageResult":
        """
        Store a compliance export in ``univex-exports``.

        Args:
            campaign_id: Campaign UUID.
            framework: Compliance framework (e.g. soc2, pci-dss, hipaa).
            data: Serialized export bytes (JSON or CSV).
            file_format: "json" or "csv".
        """
        date_prefix = _now_utc()
        obj_id = str(uuid.uuid4())
        object_name = (
            f"{date_prefix}/{campaign_id}/{framework}/{obj_id}.{file_format}"
        )
        content_type = (
            "application/json" if file_format == "json" else "text/csv"
        )

        meta = {
            "campaign-id": campaign_id,
            "framework": framework,
            **(metadata or {}),
        }
        await self._client.upload_bytes(
            BUCKET_EXPORTS,
            object_name,
            data,
            content_type=content_type,
            metadata=meta,
        )
        url = await self._client.presigned_download_url(BUCKET_EXPORTS, object_name)
        return ExportStorageResult(object_name=object_name, presigned_url=url)

    # ------------------------------------------------------------------
    # Listing helpers
    # ------------------------------------------------------------------

    async def list_reports(self, date_prefix: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all report objects, optionally filtered by YYYY/MM/DD prefix."""
        prefix = date_prefix or ""
        return await self._client.list_objects(BUCKET_REPORTS, prefix=prefix)

    async def list_evidence(self, campaign_id: str) -> List[Dict[str, Any]]:
        """List all evidence objects for a campaign."""
        date_prefix = _now_utc()
        return await self._client.list_objects(
            BUCKET_EVIDENCE, prefix=f"{date_prefix}/{campaign_id}/"
        )

    async def list_scan_results(self, session_id: str) -> List[Dict[str, Any]]:
        """List all scan result objects for a session."""
        return await self._client.list_objects(
            BUCKET_SCANS, prefix=f"{session_id}/", recursive=True
        )

    # ------------------------------------------------------------------
    # Deletion helpers
    # ------------------------------------------------------------------

    async def delete_report(self, report_id: str, date_prefix: Optional[str] = None) -> None:
        """Delete both PDF and HTML for a report."""
        prefix = date_prefix or _now_utc()
        for ext in ("pdf", "html"):
            await self._client.delete_object(BUCKET_REPORTS, f"{prefix}/{report_id}.{ext}")

    async def delete_evidence(self, object_name: str) -> None:
        """Delete a specific evidence object."""
        await self._client.delete_object(BUCKET_EVIDENCE, object_name)

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    async def ping(self) -> bool:
        """Return True if MinIO is reachable."""
        return await self._client.ping()


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

class ReportStorageResult:
    """Result of storing a report in MinIO."""

    def __init__(
        self,
        report_id: str,
        pdf_presigned_url: Optional[str] = None,
        html_presigned_url: Optional[str] = None,
    ) -> None:
        self.report_id = report_id
        self.pdf_presigned_url = pdf_presigned_url
        self.html_presigned_url = html_presigned_url

    def as_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "pdf_url": self.pdf_presigned_url,
            "html_url": self.html_presigned_url,
        }


class EvidenceStorageResult:
    """Result of storing evidence in MinIO."""

    def __init__(self, object_name: str, presigned_url: str) -> None:
        self.object_name = object_name
        self.presigned_url = presigned_url


class ScanStorageResult:
    """Result of storing scan output in MinIO."""

    def __init__(self, object_name: str, presigned_url: str) -> None:
        self.object_name = object_name
        self.presigned_url = presigned_url


class ExportStorageResult:
    """Result of storing a compliance export in MinIO."""

    def __init__(self, object_name: str, presigned_url: str) -> None:
        self.object_name = object_name
        self.presigned_url = presigned_url


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_store: Optional[ArtifactStore] = None


def get_artifact_store(client: Optional[MinIOClient] = None) -> ArtifactStore:
    """Return the module-level ArtifactStore singleton."""
    global _store
    if _store is None or client is not None:
        _store = ArtifactStore(client=client)
    return _store


def set_artifact_store(store: ArtifactStore) -> None:
    """Override the singleton — used in tests."""
    global _store
    _store = store

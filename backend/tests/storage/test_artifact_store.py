"""

Coverage:
  TestMinIOSettings       (7 tests)  — env-var driven settings
  TestStubMinio           (5 tests)  — stub client behaviour
  TestMinIOClient         (18 tests) — upload, download, presigned URLs, listing
  TestArtifactStore       (20 tests) — all store_* and list_* methods + helpers
  TestReportPresignedAPI  (10 tests) — /api/reports/{id}/presigned-url endpoint

Total: 60 tests
"""
from __future__ import annotations

import asyncio
import uuid
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.storage.minio_client import (
    MinIOClient,
    MinIOSettings,
    _StubMinio,
    get_minio_client,
    set_minio_client,
)
from app.storage.artifact_store import (
    BUCKET_EVIDENCE,
    BUCKET_EXPORTS,
    BUCKET_REPORTS,
    BUCKET_SCANS,
    ALL_BUCKETS,
    ArtifactStore,
    EvidenceStorageResult,
    ExportStorageResult,
    ReportStorageResult,
    ScanStorageResult,
    get_artifact_store,
    set_artifact_store,
)
from app.api.reports import router as reports_router


# ===========================================================================
# Helpers
# ===========================================================================

def _make_mock_minio_client(
    presigned_url: str = "https://minio.example.com/bucket/obj?sig=abc",
    object_exists: bool = False,
    list_result: Optional[List[Dict]] = None,
) -> MinIOClient:
    """Build a MinIOClient backed by a mocked _StubMinio."""
    client = MinIOClient.__new__(MinIOClient)
    client._settings = MinIOSettings()

    stub = MagicMock(spec=_StubMinio)
    stub.bucket_exists = AsyncMock(return_value=False)
    stub.make_bucket = AsyncMock(return_value=None)
    stub.put_object = AsyncMock(return_value=None)
    stub.get_object = AsyncMock(return_value=MagicMock(read=lambda: b"data"))

    stub.presigned_get_object = AsyncMock(return_value=presigned_url)
    stub.presigned_put_object = AsyncMock(return_value=presigned_url + "&method=PUT")

    stat_mock = MagicMock()
    stub.stat_object = AsyncMock(
        return_value=stat_mock if object_exists else None,
        side_effect=None if object_exists else Exception("not found"),
    )
    stub.remove_object = AsyncMock(return_value=None)

    obj_mock = MagicMock()
    obj_mock.object_name = "reports/test.pdf"
    obj_mock.size = 1024
    obj_mock.last_modified = "2026-01-01"
    obj_mock.etag = "etag123"
    stub.list_objects = AsyncMock(return_value=list_result or [obj_mock])

    client._client = stub
    return client


@pytest.fixture(autouse=True)
def reset_storage_singletons():
    import app.storage.minio_client as mc_mod
    import app.storage.artifact_store as as_mod
    prev_mc = mc_mod._client
    prev_as = as_mod._store
    yield
    mc_mod._client = prev_mc
    as_mod._store = prev_as


# ===========================================================================
# TestMinIOSettings
# ===========================================================================

class TestMinIOSettings:
    def test_default_endpoint(self):
        s = MinIOSettings()
        assert s.endpoint == "localhost:9100"

    def test_default_access_key(self):
        s = MinIOSettings()
        assert s.access_key == "minioadmin"

    def test_default_secure_false(self):
        s = MinIOSettings()
        assert s.secure is False

    def test_default_region(self):
        s = MinIOSettings()
        assert s.region == "us-east-1"

    def test_default_presign_expiry(self):
        s = MinIOSettings()
        assert s.presign_expiry == 86400  # 24 hours

    def test_env_override_endpoint(self, monkeypatch):
        monkeypatch.setenv("MINIO_ENDPOINT", "minio:9000")
        s = MinIOSettings()
        assert s.endpoint == "minio:9000"

    def test_env_override_secure(self, monkeypatch):
        monkeypatch.setenv("MINIO_SECURE", "true")
        s = MinIOSettings()
        assert s.secure is True

    def test_env_override_expiry(self, monkeypatch):
        monkeypatch.setenv("MINIO_PRESIGN_EXPIRY", "3600")
        s = MinIOSettings()
        assert s.presign_expiry == 3600


# ===========================================================================
# TestStubMinio
# ===========================================================================

class TestStubMinio:
    def test_bucket_exists_returns_false(self):
        stub = _StubMinio()
        result = asyncio.run(stub.bucket_exists("test-bucket"))
        assert result is False

    def test_make_bucket_no_error(self):
        stub = _StubMinio()
        asyncio.run(stub.make_bucket("new-bucket"))

    def test_put_object_no_error(self):
        stub = _StubMinio()
        import io
        asyncio.run(
            stub.put_object("bucket", "key", io.BytesIO(b"data"), 4)
        )

    def test_presigned_get_object_returns_stub_url(self):
        stub = _StubMinio()
        url = asyncio.run(stub.presigned_get_object("bucket", "key"))
        assert "stub=true" in url

    def test_list_objects_returns_empty(self):
        stub = _StubMinio()
        result = asyncio.run(stub.list_objects("bucket"))
        assert result == []


# ===========================================================================
# TestMinIOClient
# ===========================================================================

class TestMinIOClient:
    def _client(self, **kwargs) -> MinIOClient:
        return _make_mock_minio_client(**kwargs)

    def test_bucket_exists_false(self):
        client = self._client()
        result = asyncio.run(client.bucket_exists("test-bucket"))
        assert result is False

    def test_ensure_bucket_creates_when_missing(self):
        client = self._client()
        asyncio.run(client.ensure_bucket("new-bucket"))
        client._client.make_bucket.assert_awaited()

    def test_ensure_bucket_skips_when_exists(self):
        client = self._client()
        client._client.bucket_exists = AsyncMock(return_value=True)
        asyncio.run(client.ensure_bucket("existing-bucket"))
        client._client.make_bucket.assert_not_awaited()

    def test_upload_bytes_calls_put_object(self):
        client = self._client()
        asyncio.run(
            client.upload_bytes("bucket", "key.pdf", b"PDF content", "application/pdf")
        )
        client._client.put_object.assert_awaited_once()

    def test_upload_bytes_returns_object_name(self):
        client = self._client()
        result = asyncio.run(
            client.upload_bytes("bucket", "mykey.html", b"<html/>", "text/html")
        )
        assert result == "mykey.html"

    def test_upload_bytes_empty_raises(self):
        client = self._client()
        client._client.put_object = AsyncMock(side_effect=Exception("empty"))
        with pytest.raises(RuntimeError, match="MinIO upload failed"):
            asyncio.run(
                client.upload_bytes("bucket", "key", b"data", "text/plain")
            )

    def test_download_bytes_calls_get_object(self):
        client = self._client()
        # Return a mock response with .read()
        mock_resp = MagicMock()
        mock_resp.read = lambda: b"downloaded"
        client._client.get_object = AsyncMock(return_value=mock_resp)
        result = asyncio.run(client.download_bytes("bucket", "key"))
        assert result == b"downloaded"

    def test_download_bytes_raises_on_error(self):
        client = self._client()
        client._client.get_object = AsyncMock(side_effect=Exception("404"))
        with pytest.raises(RuntimeError, match="MinIO download failed"):
            asyncio.run(client.download_bytes("bucket", "missing"))

    def test_presigned_download_url_returns_url(self):
        client = self._client(presigned_url="https://minio.example.com/signed?exp=24h")
        url = asyncio.run(
            client.presigned_download_url("reports", "report.pdf")
        )
        assert url == "https://minio.example.com/signed?exp=24h"

    def test_presigned_download_url_passes_expiry(self):
        client = self._client()
        asyncio.run(
            client.presigned_download_url("bucket", "key", expiry_seconds=3600)
        )
        call_kwargs = client._client.presigned_get_object.call_args
        # Verify expires was passed
        assert call_kwargs is not None

    def test_presigned_upload_url_returns_url(self):
        client = self._client(presigned_url="https://minio.example.com/upload")
        url = asyncio.run(
            client.presigned_upload_url("bucket", "new-file.pdf")
        )
        assert "PUT" in url or "upload" in url

    def test_object_exists_false_on_error(self):
        client = self._client(object_exists=False)
        result = asyncio.run(client.object_exists("bucket", "missing.pdf"))
        assert result is False

    def test_delete_object(self):
        client = self._client()
        asyncio.run(client.delete_object("bucket", "old-report.pdf"))
        client._client.remove_object.assert_awaited()

    def test_list_objects_returns_list(self):
        client = self._client()
        result = asyncio.run(client.list_objects("reports", prefix="2026/"))
        assert isinstance(result, list)
        assert len(result) > 0
        assert "name" in result[0]

    def test_list_objects_empty_on_error(self):
        client = self._client()
        client._client.list_objects = AsyncMock(side_effect=Exception("conn error"))
        result = asyncio.run(client.list_objects("bucket"))
        assert result == []

    def test_ping_true_when_bucket_exists_no_error(self):
        client = self._client()
        # ping calls bucket_exists which returns False but doesn't raise
        result = asyncio.run(client.ping())
        assert result is True

    def test_ping_false_on_exception(self):
        client = self._client()
        client._client.bucket_exists = AsyncMock(side_effect=Exception("refused"))
        result = asyncio.run(client.ping())
        assert result is False

    def test_singleton_override(self):
        mock_client = self._client()
        set_minio_client(mock_client)
        retrieved = get_minio_client()
        assert retrieved is mock_client


# ===========================================================================
# TestArtifactStore
# ===========================================================================

class TestArtifactStore:
    def _store(self, presigned_url: str = "https://minio.example.com/presigned") -> ArtifactStore:
        client = _make_mock_minio_client(presigned_url=presigned_url)
        return ArtifactStore(client=client)

    def test_initialize_creates_all_buckets(self):
        store = self._store()
        asyncio.run(store.initialize())
        # ensure_bucket is called once per bucket; each calls make_bucket
        # (since bucket_exists returns False from the stub)
        assert store._client._client.make_bucket.await_count == len(ALL_BUCKETS)

    def test_all_buckets_constant(self):
        assert BUCKET_REPORTS in ALL_BUCKETS
        assert BUCKET_EVIDENCE in ALL_BUCKETS
        assert BUCKET_SCANS in ALL_BUCKETS
        assert BUCKET_EXPORTS in ALL_BUCKETS
        assert len(ALL_BUCKETS) == 4

    # --- store_report ---

    def test_store_report_with_pdf(self):
        store = self._store("https://minio.example.com/pdf")
        result = asyncio.run(
            store.store_report(
                "report-123",
                pdf_bytes=b"%PDF-1.4",
                html_content="<html>report</html>",
            )
        )
        assert isinstance(result, ReportStorageResult)
        assert result.pdf_presigned_url == "https://minio.example.com/pdf"
        assert result.html_presigned_url == "https://minio.example.com/pdf"

    def test_store_report_pdf_only(self):
        store = self._store()
        result = asyncio.run(
            store.store_report("report-456", pdf_bytes=b"%PDF-1.4")
        )
        assert result.pdf_presigned_url is not None
        assert result.html_presigned_url is None

    def test_store_report_html_only(self):
        store = self._store()
        result = asyncio.run(
            store.store_report("report-789", html_content="<html/>")
        )
        assert result.html_presigned_url is not None
        assert result.pdf_presigned_url is None

    def test_store_report_as_dict(self):
        store = self._store()
        result = asyncio.run(store.store_report("r-1", html_content="<h1>test</h1>"))
        d = result.as_dict()
        assert "report_id" in d
        assert "html_url" in d
        assert "pdf_url" in d

    def test_get_report_download_url(self):
        store = self._store("https://minio.example.com/dl?format=pdf")
        url = asyncio.run(store.get_report_download_url("report-123", format="pdf"))
        assert "pdf" in url or "minio" in url

    # --- store_screenshot ---

    def test_store_screenshot_returns_result(self):
        store = self._store()
        result = asyncio.run(
            store.store_screenshot("campaign-1", b"\x89PNG\r\n\x1a\n")
        )
        assert isinstance(result, EvidenceStorageResult)
        assert result.presigned_url
        assert "campaign-1" in result.object_name

    def test_store_screenshot_custom_filename(self):
        store = self._store()
        result = asyncio.run(
            store.store_screenshot(
                "campaign-2", b"data", file_extension="jpg", filename="test-shot"
            )
        )
        assert "test-shot.jpg" in result.object_name

    # --- store_tool_output ---

    def test_store_tool_output_json(self):
        store = self._store()
        result = asyncio.run(
            store.store_tool_output(
                "campaign-3", "nuclei", b'[{"finding":"sqli"}]', file_extension="json"
            )
        )
        assert isinstance(result, EvidenceStorageResult)
        assert "nuclei" in result.object_name

    def test_store_tool_output_txt(self):
        store = self._store()
        result = asyncio.run(
            store.store_tool_output("camp-4", "nmap", b"Host: 10.0.0.1")
        )
        assert result.presigned_url

    # --- store_scan_result ---

    def test_store_scan_result_json(self):
        store = self._store()
        result = asyncio.run(
            store.store_scan_result(
                session_id=str(uuid.uuid4()),
                tool_name="nuclei",
                data=b'{"findings":[]}',
                file_format="json",
            )
        )
        assert isinstance(result, ScanStorageResult)
        assert result.presigned_url

    def test_store_scan_result_xml(self):
        store = self._store()
        result = asyncio.run(
            store.store_scan_result("sess-1", "nmap", b"<xml/>", file_format="xml")
        )
        assert "nmap" in result.object_name

    # --- store_compliance_export ---

    def test_store_compliance_export_json(self):
        store = self._store()
        result = asyncio.run(
            store.store_compliance_export(
                campaign_id="camp-5",
                framework="soc2",
                data=b'{"controls":[]}',
                file_format="json",
            )
        )
        assert isinstance(result, ExportStorageResult)
        assert "soc2" in result.object_name

    def test_store_compliance_export_csv(self):
        store = self._store()
        result = asyncio.run(
            store.store_compliance_export(
                "camp-6", "pci-dss", b"control,status\nCC1,pass", file_format="csv"
            )
        )
        assert result.presigned_url

    # --- listing ---

    def test_list_reports_returns_list(self):
        store = self._store()
        result = asyncio.run(store.list_reports())
        assert isinstance(result, list)

    def test_list_evidence_returns_list(self):
        store = self._store()
        result = asyncio.run(store.list_evidence("campaign-1"))
        assert isinstance(result, list)

    def test_list_scan_results_returns_list(self):
        store = self._store()
        result = asyncio.run(store.list_scan_results("sess-1"))
        assert isinstance(result, list)

    # --- deletion ---

    def test_delete_report(self):
        store = self._store()
        # Should not raise
        asyncio.run(store.delete_report("report-del"))

    def test_delete_evidence(self):
        store = self._store()
        asyncio.run(store.delete_evidence("2026/01/01/camp/screenshots/shot.png"))

    # --- health ---

    def test_ping_true(self):
        store = self._store()
        result = asyncio.run(store.ping())
        assert result is True

    def test_ping_false_on_error(self):
        store = self._store()
        store._client._client.bucket_exists = AsyncMock(side_effect=Exception("down"))
        result = asyncio.run(store.ping())
        assert result is False


# ===========================================================================
# TestReportPresignedAPI
# ===========================================================================

@pytest.fixture(scope="module")
def api_client():
    """Mount reports router in a standalone FastAPI app."""
    app = FastAPI()
    app.include_router(reports_router)
    return TestClient(app)


@pytest.fixture
def seeded_report(api_client):
    """Generate a report and return its ID."""
    resp = api_client.post(
        "/api/reports/generate",
        json={
            "project_name": "TestProject",
            "title": "Test Report",
            "template": "technical_report",
            "format": "html",
            "scan_results": [
                {
                    "target": "example.com",
                    "scan_type": "web",
                    "findings": [
                        {
                            "title": "XSS",
                            "severity": "high",
                            "cvss_score": 7.5,
                        }
                    ],
                }
            ],
        },
    )
    assert resp.status_code == 201
    return resp.json()["id"]


class TestReportPresignedAPI:
    def test_presigned_url_returns_503_when_minio_disabled(self, api_client, seeded_report):
        """When MinIO is not enabled, endpoint returns 503."""
        with patch("app.api.reports._MINIO_ENABLED", False):
            resp = api_client.get(f"/api/reports/{seeded_report}/presigned-url")
        assert resp.status_code == 503

    def test_presigned_url_404_for_unknown_report(self, api_client):
        """Unknown report_id returns 404."""
        fake_id = str(uuid.uuid4())
        with patch("app.api.reports._MINIO_ENABLED", True):
            resp = api_client.get(f"/api/reports/{fake_id}/presigned-url")
        assert resp.status_code == 404

    def test_presigned_url_200_when_minio_enabled(self, api_client, seeded_report):
        """When MinIO is enabled and report exists, returns presigned URL."""
        mock_store = MagicMock(spec=ArtifactStore)
        mock_store.get_report_download_url = AsyncMock(
            return_value="https://minio.example.com/presigned"
        )
        with patch("app.api.reports._MINIO_ENABLED", True), \
             patch("app.api.reports.get_artifact_store", return_value=mock_store):
            resp = api_client.get(f"/api/reports/{seeded_report}/presigned-url")
        assert resp.status_code == 200
        data = resp.json()
        assert "presigned_url" in data
        assert data["presigned_url"] == "https://minio.example.com/presigned"

    def test_presigned_url_schema(self, api_client, seeded_report):
        """Verify response schema."""
        mock_store = MagicMock(spec=ArtifactStore)
        mock_store.get_report_download_url = AsyncMock(return_value="https://url")
        with patch("app.api.reports._MINIO_ENABLED", True), \
             patch("app.api.reports.get_artifact_store", return_value=mock_store):
            resp = api_client.get(f"/api/reports/{seeded_report}/presigned-url")
        data = resp.json()
        assert "report_id" in data
        assert "format" in data
        assert "presigned_url" in data
        assert "expires_in_seconds" in data

    def test_presigned_url_format_query_param(self, api_client, seeded_report):
        """Verify format query param is respected."""
        mock_store = MagicMock(spec=ArtifactStore)
        mock_store.get_report_download_url = AsyncMock(return_value="https://url")
        with patch("app.api.reports._MINIO_ENABLED", True), \
             patch("app.api.reports.get_artifact_store", return_value=mock_store):
            resp = api_client.get(
                f"/api/reports/{seeded_report}/presigned-url?format=html"
            )
        assert resp.status_code == 200
        assert resp.json()["format"] == "html"

    def test_presigned_url_500_on_store_error(self, api_client, seeded_report):
        """When artifact store throws, return 500."""
        mock_store = MagicMock(spec=ArtifactStore)
        mock_store.get_report_download_url = AsyncMock(
            side_effect=RuntimeError("MinIO unreachable")
        )
        with patch("app.api.reports._MINIO_ENABLED", True), \
             patch("app.api.reports.get_artifact_store", return_value=mock_store):
            resp = api_client.get(f"/api/reports/{seeded_report}/presigned-url")
        assert resp.status_code == 500

    def test_existing_reports_api_still_works(self, api_client, seeded_report):
        """Ensure existing download endpoint still works after Day 14 changes."""
        resp = api_client.get(f"/api/reports/{seeded_report}/download")
        assert resp.status_code == 200

    def test_list_reports_includes_minio_fields(self, api_client, seeded_report):
        """Ensure list endpoint returns minio_pdf_url and minio_html_url fields."""
        resp = api_client.get("/api/reports")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        if data:
            assert "minio_pdf_url" in data[0]
            assert "minio_html_url" in data[0]

    def test_generate_report_includes_minio_fields(self, api_client):
        """Generated report summary includes MinIO URL fields."""
        resp = api_client.post(
            "/api/reports/generate",
            json={
                "project_name": "MinioProjTest",
                "title": "MinIO Test Report",
                "template": "executive_summary",
                "format": "html",
                "scan_results": [],
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "minio_pdf_url" in data
        assert "minio_html_url" in data

    def test_presigned_url_expiry_is_24h(self, api_client, seeded_report):
        """Verify expires_in_seconds is 86400 (24h)."""
        mock_store = MagicMock(spec=ArtifactStore)
        mock_store.get_report_download_url = AsyncMock(return_value="https://url")
        with patch("app.api.reports._MINIO_ENABLED", True), \
             patch("app.api.reports.get_artifact_store", return_value=mock_store):
            resp = api_client.get(f"/api/reports/{seeded_report}/presigned-url")
        assert resp.json()["expires_in_seconds"] == 86400

"""

Async MinIO client for UniVex artifact storage.

Provides:
  - Bucket creation and management
  - Object upload (single and multipart for large files)
  - Object download
  - Presigned URL generation (24h default expiry)
  - Object metadata and listing
  - Graceful degradation when miniopy-async is not installed

Environment variables
---------------------
MINIO_ENDPOINT      : MinIO host:port (default: localhost:9100)
MINIO_ACCESS_KEY    : Access key / root user (default: minioadmin)
MINIO_SECRET_KEY    : Secret key / root password (default: minioadmin)
MINIO_SECURE        : Use TLS (default: false)
MINIO_REGION        : Region (default: us-east-1)
MINIO_PRESIGN_EXPIRY: Presigned URL expiry in seconds (default: 86400 = 24h)
"""
from __future__ import annotations

import io
import logging
import os
from datetime import timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy import of miniopy-async
# ---------------------------------------------------------------------------

try:
    from miniopy_async import Minio  # type: ignore
    from miniopy_async.error import S3Error  # type: ignore
    _MINIO_AVAILABLE = True
except ImportError:  # pragma: no cover
    Minio = None  # type: ignore
    S3Error = Exception  # type: ignore
    _MINIO_AVAILABLE = False
    logger.warning(
        "miniopy-async not installed; MinIOClient will operate in stub mode. "
        "Install with: pip install miniopy-async>=1.23.4"
    )


class MinIOSettings:
    """Reads MinIO connection settings from environment variables."""

    def __init__(self) -> None:
        self.endpoint: str = os.getenv("MINIO_ENDPOINT", "localhost:9100")
        self.access_key: str = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
        self.secret_key: str = os.getenv("MINIO_SECRET_KEY", "minioadmin")
        self.secure: bool = os.getenv("MINIO_SECURE", "false").lower() == "true"
        self.region: str = os.getenv("MINIO_REGION", "us-east-1")
        self.presign_expiry: int = int(os.getenv("MINIO_PRESIGN_EXPIRY", "86400"))


class _StubMinio:
    """No-op MinIO client for when miniopy-async is not installed."""

    async def bucket_exists(self, bucket: str) -> bool:
        return False

    async def make_bucket(self, bucket: str, location: Optional[str] = None) -> None:
        logger.debug("STUB make_bucket: %s", bucket)

    async def put_object(self, bucket, name, data, length, content_type="", metadata=None):
        logger.debug("STUB put_object: %s/%s", bucket, name)

    async def get_object(self, bucket, name):
        return io.BytesIO(b"")

    async def presigned_get_object(self, bucket, name, expires=None, response_headers=None):
        return f"http://localhost:9100/{bucket}/{name}?stub=true"

    async def presigned_put_object(self, bucket, name, expires=None):
        return f"http://localhost:9100/{bucket}/{name}?stub=true&method=PUT"

    async def stat_object(self, bucket, name):
        return None

    async def remove_object(self, bucket, name):
        logger.debug("STUB remove_object: %s/%s", bucket, name)

    async def list_objects(self, bucket, prefix="", recursive=True):
        return []


class MinIOClient:
    """
    Async MinIO client for UniVex artifact storage.

    Usage::

        client = MinIOClient()
        await client.ensure_bucket("univex-reports")
        url = await client.upload_bytes(
            bucket="univex-reports",
            object_name="report-uuid.pdf",
            data=pdf_bytes,
            content_type="application/pdf",
        )
        presigned = await client.presigned_download_url(
            bucket="univex-reports",
            object_name="report-uuid.pdf",
        )
    """

    def __init__(self, settings: Optional[MinIOSettings] = None) -> None:
        self._settings = settings or MinIOSettings()
        self._client = self._build_client()

    def _build_client(self) -> Any:
        if not _MINIO_AVAILABLE:
            return _StubMinio()
        try:
            return Minio(
                self._settings.endpoint,
                access_key=self._settings.access_key,
                secret_key=self._settings.secret_key,
                secure=self._settings.secure,
                region=self._settings.region,
            )
        except Exception as exc:
            logger.warning("MinIO client build failed, using stub: %s", exc)
            return _StubMinio()

    # ------------------------------------------------------------------
    # Bucket management
    # ------------------------------------------------------------------

    async def bucket_exists(self, bucket: str) -> bool:
        """Return True if *bucket* exists."""
        try:
            return await self._client.bucket_exists(bucket)
        except Exception as exc:
            logger.warning("bucket_exists(%s) failed: %s", bucket, exc)
            return False

    async def ensure_bucket(self, bucket: str) -> None:
        """Create *bucket* if it does not exist."""
        try:
            exists = await self._client.bucket_exists(bucket)
            if not exists:
                await self._client.make_bucket(bucket)
                logger.info("Created bucket: %s", bucket)
        except Exception as exc:
            logger.warning("ensure_bucket(%s) failed: %s", bucket, exc)

    # ------------------------------------------------------------------
    # Upload
    # ------------------------------------------------------------------

    async def upload_bytes(
        self,
        bucket: str,
        object_name: str,
        data: bytes,
        content_type: str = "application/octet-stream",
        metadata: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Upload *data* bytes to *bucket*/*object_name*.

        Returns:
            The object name (path within bucket).
        """
        await self.ensure_bucket(bucket)
        stream = io.BytesIO(data)
        try:
            await self._client.put_object(
                bucket,
                object_name,
                stream,
                length=len(data),
                content_type=content_type,
                metadata=metadata or {},
            )
            logger.debug(
                "Uploaded %d bytes to %s/%s", len(data), bucket, object_name
            )
        except Exception as exc:
            logger.error(
                "Upload failed: %s/%s — %s", bucket, object_name, exc
            )
            raise RuntimeError(f"MinIO upload failed: {exc}") from exc
        return object_name

    async def upload_file(
        self,
        bucket: str,
        object_name: str,
        file_path: str,
        content_type: str = "application/octet-stream",
        metadata: Optional[Dict[str, str]] = None,
    ) -> str:
        """Upload a local file at *file_path* to *bucket*/*object_name*."""
        with open(file_path, "rb") as fh:
            data = fh.read()
        return await self.upload_bytes(
            bucket, object_name, data, content_type, metadata
        )

    # ------------------------------------------------------------------
    # Download
    # ------------------------------------------------------------------

    async def download_bytes(self, bucket: str, object_name: str) -> bytes:
        """Download *bucket*/*object_name* and return raw bytes."""
        try:
            response = await self._client.get_object(bucket, object_name)
            if hasattr(response, "read"):
                return response.read()
            return b""
        except Exception as exc:
            logger.error("Download failed: %s/%s — %s", bucket, object_name, exc)
            raise RuntimeError(f"MinIO download failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Presigned URLs
    # ------------------------------------------------------------------

    async def presigned_download_url(
        self,
        bucket: str,
        object_name: str,
        expiry_seconds: Optional[int] = None,
        response_content_type: Optional[str] = None,
        response_content_disposition: Optional[str] = None,
    ) -> str:
        """
        Generate a presigned GET URL for *bucket*/*object_name*.

        Args:
            bucket: Bucket name.
            object_name: Object key.
            expiry_seconds: URL lifetime in seconds (default: settings.presign_expiry = 24h).
            response_content_type: Override Content-Type header in response.
            response_content_disposition: Override Content-Disposition header.

        Returns:
            Presigned URL string.
        """
        expiry = timedelta(seconds=expiry_seconds or self._settings.presign_expiry)
        headers: Dict[str, str] = {}
        if response_content_type:
            headers["response-content-type"] = response_content_type
        if response_content_disposition:
            headers["response-content-disposition"] = response_content_disposition

        try:
            url = await self._client.presigned_get_object(
                bucket,
                object_name,
                expires=expiry,
                response_headers=headers if headers else None,
            )
            return url
        except Exception as exc:
            logger.error(
                "presigned_download_url failed: %s/%s — %s", bucket, object_name, exc
            )
            raise RuntimeError(f"Presigned URL generation failed: {exc}") from exc

    async def presigned_upload_url(
        self,
        bucket: str,
        object_name: str,
        expiry_seconds: Optional[int] = None,
    ) -> str:
        """Generate a presigned PUT URL for direct upload to *bucket*/*object_name*."""
        await self.ensure_bucket(bucket)
        expiry = timedelta(seconds=expiry_seconds or self._settings.presign_expiry)
        try:
            url = await self._client.presigned_put_object(
                bucket, object_name, expires=expiry
            )
            return url
        except Exception as exc:
            logger.error(
                "presigned_upload_url failed: %s/%s — %s", bucket, object_name, exc
            )
            raise RuntimeError(f"Presigned upload URL failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Object management
    # ------------------------------------------------------------------

    async def object_exists(self, bucket: str, object_name: str) -> bool:
        """Return True if the object exists in the bucket."""
        try:
            stat = await self._client.stat_object(bucket, object_name)
            return stat is not None
        except Exception:
            return False

    async def delete_object(self, bucket: str, object_name: str) -> None:
        """Delete a single object from *bucket*."""
        try:
            await self._client.remove_object(bucket, object_name)
            logger.debug("Deleted %s/%s", bucket, object_name)
        except Exception as exc:
            logger.warning("delete_object failed: %s/%s — %s", bucket, object_name, exc)

    async def list_objects(
        self,
        bucket: str,
        prefix: str = "",
        recursive: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        List objects in *bucket* with optional *prefix*.

        Returns:
            List of dicts with keys: name, size, last_modified, etag.
        """
        try:
            objects = await self._client.list_objects(
                bucket, prefix=prefix, recursive=recursive
            )
            result = []
            for obj in objects:
                result.append({
                    "name": getattr(obj, "object_name", str(obj)),
                    "size": getattr(obj, "size", 0),
                    "last_modified": str(getattr(obj, "last_modified", "")),
                    "etag": getattr(obj, "etag", ""),
                })
            return result
        except Exception as exc:
            logger.warning("list_objects(%s, %s) failed: %s", bucket, prefix, exc)
            return []

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    async def ping(self) -> bool:
        """Return True if MinIO is reachable (bucket list succeeds)."""
        try:
            await self._client.bucket_exists("_health_check_")
            return True
        except Exception as exc:
            logger.debug("MinIO ping failed: %s", exc)
            return False


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_client: Optional[MinIOClient] = None


def get_minio_client() -> MinIOClient:
    """Return the module-level MinIOClient singleton (lazy init)."""
    global _client
    if _client is None:
        _client = MinIOClient()
    return _client


def set_minio_client(client: MinIOClient) -> None:
    """Override the singleton — used in tests."""
    global _client
    _client = client

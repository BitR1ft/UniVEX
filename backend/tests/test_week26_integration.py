"""
Week 26 integration tests for auth and project endpoints.

These tests use FastAPI's dependency_overrides mechanism to inject mocked
services so that no real database connection is required.
"""
from __future__ import annotations

import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.api.auth import get_auth_service
from app.api.projects import get_project_service
from app.core.security import create_access_token


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_user(
    id: str = "user-1",
    username: str = "testuser",
    email: str = "test@example.com",
    is_active: bool = True,
    hashed_password: str = "salt:hash",
) -> MagicMock:
    user = MagicMock()
    user.id = id
    user.username = username
    user.email = email
    user.is_active = is_active
    user.full_name = "Test User"
    user.hashed_password = hashed_password
    user.created_at = datetime(2024, 1, 1, 0, 0, 0)
    return user


def make_project(
    id: str = "proj-1",
    name: str = "Test Project",
    user_id: str = "user-1",
    status: str = "draft",
) -> MagicMock:
    proj = MagicMock()
    proj.id = id
    proj.name = name
    proj.user_id = user_id
    proj.status = status
    proj.description = "desc"
    proj.target = "example.com"
    proj.project_type = "full_assessment"
    proj.enable_subdomain_enum = True
    proj.enable_port_scan = True
    proj.enable_web_crawl = True
    proj.enable_tech_detection = True
    proj.enable_vuln_scan = True
    proj.enable_nuclei = True
    proj.enable_auto_exploit = False
    proj.created_at = datetime(2024, 1, 1, 0, 0, 0)
    proj.updated_at = datetime(2024, 1, 1, 0, 0, 0)
    return proj


def _valid_token(user_id: str = "user-1") -> str:
    return create_access_token({"sub": user_id})


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestAuthIntegration:
    """Integration tests for auth endpoints (register, login, refresh, logout)."""

    @pytest.mark.asyncio
    async def test_register_returns_user(self):
        mock_user = make_user()
        mock_svc = MagicMock()
        mock_svc.register = AsyncMock(return_value=mock_user)

        async def _override():
            return mock_svc

        app.dependency_overrides[get_auth_service] = _override
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                resp = await client.post("/api/auth/register", json={
                    "email": "test@example.com",
                    "username": "testuser",
                    "password": "password123",
                })
            assert resp.status_code == 201
            assert resp.json()["username"] == "testuser"
        finally:
            app.dependency_overrides.pop(get_auth_service, None)

    @pytest.mark.asyncio
    async def test_register_duplicate_returns_400(self):
        mock_svc = MagicMock()
        mock_svc.register = AsyncMock(side_effect=ValueError("Username already registered"))

        async def _override():
            return mock_svc

        app.dependency_overrides[get_auth_service] = _override
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                resp = await client.post("/api/auth/register", json={
                    "email": "dup@example.com",
                    "username": "dup",
                    "password": "password123",
                })
            assert resp.status_code == 400
        finally:
            app.dependency_overrides.pop(get_auth_service, None)

    @pytest.mark.asyncio
    async def test_login_returns_tokens(self):
        mock_token = MagicMock()
        mock_token.access_token = "access"
        mock_token.refresh_token = "refresh"
        mock_token.token_type = "bearer"
        mock_svc = MagicMock()
        mock_svc.login = AsyncMock(return_value=mock_token)

        async def _override():
            return mock_svc

        app.dependency_overrides[get_auth_service] = _override
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                resp = await client.post("/api/auth/login", json={
                    "username": "testuser",
                    "password": "password123",
                })
            assert resp.status_code == 200
            assert "access_token" in resp.json()
        finally:
            app.dependency_overrides.pop(get_auth_service, None)

    @pytest.mark.asyncio
    async def test_login_invalid_credentials_returns_401(self):
        mock_svc = MagicMock()
        mock_svc.login = AsyncMock(side_effect=ValueError("Invalid credentials"))

        async def _override():
            return mock_svc

        app.dependency_overrides[get_auth_service] = _override
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                resp = await client.post("/api/auth/login", json={
                    "username": "wrong",
                    "password": "wrong",
                })
            assert resp.status_code == 401
        finally:
            app.dependency_overrides.pop(get_auth_service, None)

    @pytest.mark.asyncio
    async def test_me_endpoint_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/api/auth/me")
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_me_endpoint_with_valid_token(self):
        mock_user = make_user()
        mock_svc = MagicMock()
        mock_svc.get_user_by_id = AsyncMock(return_value=mock_user)

        async def _override():
            return mock_svc

        app.dependency_overrides[get_auth_service] = _override
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                resp = await client.get(
                    "/api/auth/me",
                    headers={"Authorization": f"Bearer {_valid_token()}"},
                )
            assert resp.status_code == 200
            assert resp.json()["username"] == "testuser"
        finally:
            app.dependency_overrides.pop(get_auth_service, None)

    @pytest.mark.asyncio
    async def test_register_short_password_rejected(self):
        mock_svc = MagicMock()
        mock_svc.register = AsyncMock()

        async def _override():
            return mock_svc

        app.dependency_overrides[get_auth_service] = _override
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                resp = await client.post("/api/auth/register", json={
                    "email": "test@example.com",
                    "username": "validuser",
                    "password": "short",  # < 8 chars
                })
            assert resp.status_code == 422  # Pydantic validation
        finally:
            app.dependency_overrides.pop(get_auth_service, None)

    @pytest.mark.asyncio
    async def test_register_invalid_email_rejected(self):
        mock_svc = MagicMock()
        mock_svc.register = AsyncMock()

        async def _override():
            return mock_svc

        app.dependency_overrides[get_auth_service] = _override
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                resp = await client.post("/api/auth/register", json={
                    "email": "not-an-email",
                    "username": "validuser",
                    "password": "password123",
                })
            assert resp.status_code == 422
        finally:
            app.dependency_overrides.pop(get_auth_service, None)


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestProjectsIntegration:
    """Integration tests for project CRUD endpoints."""

    @pytest.mark.asyncio
    async def test_create_project_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/api/projects", json={
                "name": "Test", "target": "example.com",
            })
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_create_project_success(self):
        mock_proj = make_project()
        mock_svc = MagicMock()
        mock_svc.create_project = AsyncMock(return_value=mock_proj)

        async def _override():
            return mock_svc

        app.dependency_overrides[get_project_service] = _override
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                resp = await client.post(
                    "/api/projects",
                    json={"name": "Test Project", "target": "example.com"},
                    headers={"Authorization": f"Bearer {_valid_token()}"},
                )
            assert resp.status_code == 201
            assert resp.json()["name"] == "Test Project"
        finally:
            app.dependency_overrides.pop(get_project_service, None)

    @pytest.mark.asyncio
    async def test_list_projects(self):
        mock_proj = make_project()
        mock_svc = MagicMock()
        mock_svc.list_projects = AsyncMock(return_value={
            "projects": [mock_proj],
            "total": 1,
            "page": 1,
            "page_size": 10,
        })

        async def _override():
            return mock_svc

        app.dependency_overrides[get_project_service] = _override
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                resp = await client.get(
                    "/api/projects",
                    headers={"Authorization": f"Bearer {_valid_token()}"},
                )
            assert resp.status_code == 200
        finally:
            app.dependency_overrides.pop(get_project_service, None)

    @pytest.mark.asyncio
    async def test_get_project_not_found(self):
        mock_svc = MagicMock()
        mock_svc.get_project = AsyncMock(return_value=None)

        async def _override():
            return mock_svc

        app.dependency_overrides[get_project_service] = _override
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                resp = await client.get(
                    "/api/projects/nonexistent",
                    headers={"Authorization": f"Bearer {_valid_token()}"},
                )
            assert resp.status_code == 404
        finally:
            app.dependency_overrides.pop(get_project_service, None)

    @pytest.mark.asyncio
    async def test_update_project(self):
        mock_proj = make_project(name="Updated")
        mock_svc = MagicMock()
        mock_svc.update_project = AsyncMock(return_value=mock_proj)

        async def _override():
            return mock_svc

        app.dependency_overrides[get_project_service] = _override
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                resp = await client.patch(
                    "/api/projects/proj-1",
                    json={"name": "Updated"},
                    headers={"Authorization": f"Bearer {_valid_token()}"},
                )
            assert resp.status_code == 200
        finally:
            app.dependency_overrides.pop(get_project_service, None)

    @pytest.mark.asyncio
    async def test_delete_project(self):
        mock_svc = MagicMock()
        mock_svc.delete_project = AsyncMock(return_value=True)

        async def _override():
            return mock_svc

        app.dependency_overrides[get_project_service] = _override
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                resp = await client.delete(
                    "/api/projects/proj-1",
                    headers={"Authorization": f"Bearer {_valid_token()}"},
                )
            assert resp.status_code == 200
        finally:
            app.dependency_overrides.pop(get_project_service, None)

    @pytest.mark.asyncio
    async def test_start_project(self):
        mock_proj = make_project(status="queued")
        mock_svc = MagicMock()
        mock_svc.start_project = AsyncMock(return_value=mock_proj)

        async def _override():
            return mock_svc

        app.dependency_overrides[get_project_service] = _override
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                resp = await client.post(
                    "/api/projects/proj-1/start",
                    headers={"Authorization": f"Bearer {_valid_token()}"},
                )
            assert resp.status_code == 200
        finally:
            app.dependency_overrides.pop(get_project_service, None)


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestMetricsEndpoint:
    @pytest.mark.asyncio
    async def test_metrics_endpoint_returns_prometheus_format(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/metrics")
        assert resp.status_code == 200
        assert "http_requests_total" in resp.text or "# HELP" in resp.text


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestHealthEndpoints:
    @pytest.mark.asyncio
    async def test_root_health_check(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/")
        assert resp.status_code == 200
        assert resp.json()["status"] == "operational"

    @pytest.mark.asyncio
    async def test_health_endpoint(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/health")
        assert resp.status_code == 200
        assert "status" in resp.json()

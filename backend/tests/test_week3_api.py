"""
Integration tests for Week 3 API refactoring.

These tests use FastAPI's dependency-override mechanism to inject a
fully-mocked service layer, so no live database is required.
"""
from __future__ import annotations

import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.api.auth import get_auth_service
from app.api.projects import get_project_service


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_user(
    id="u1",
    email="alice@example.com",
    username="alice",
    full_name="Alice Example",
    is_active=True,
):
    u = MagicMock()
    u.id = id
    u.email = email
    u.username = username
    u.full_name = full_name
    u.is_active = is_active
    u.created_at = datetime(2026, 1, 1, 0, 0, 0)
    return u


def _make_project(
    id="p1",
    user_id="u1",
    name="Alpha",
    target="example.com",
    status="draft",
):
    p = MagicMock()
    p.id = id
    p.user_id = user_id
    p.name = name
    p.target = target
    p.description = None
    p.project_type = "full_assessment"
    p.status = status
    p.created_at = datetime(2026, 1, 1)
    p.updated_at = datetime(2026, 1, 1)
    p.enable_subdomain_enum = True
    p.enable_port_scan = True
    p.enable_web_crawl = True
    p.enable_tech_detection = True
    p.enable_vuln_scan = True
    p.enable_nuclei = True
    p.enable_auto_exploit = False
    return p


def _make_auth_svc(**overrides):
    """Return a fully mocked AuthService."""
    svc = MagicMock()
    defaults = {
        "register": AsyncMock(return_value=_make_user()),
        "login": AsyncMock(return_value=MagicMock(
            access_token="acc",
            refresh_token="ref",
            token_type="bearer",
        )),
        "get_user_by_id": AsyncMock(return_value=_make_user()),
        "refresh": AsyncMock(return_value=MagicMock(
            access_token="new_acc",
            refresh_token="new_ref",
            token_type="bearer",
        )),
        "logout": AsyncMock(return_value=None),
        "logout_all": AsyncMock(return_value=None),
    }
    defaults.update(overrides)
    for k, v in defaults.items():
        setattr(svc, k, v)
    return svc


def _make_project_svc(**overrides):
    """Return a fully mocked ProjectService."""
    svc = MagicMock()
    defaults = {
        "create_project": AsyncMock(return_value=_make_project()),
        "list_projects": AsyncMock(return_value={
            "projects": [_make_project()],
            "total": 1,
            "page": 1,
            "page_size": 20,
        }),
        "get_project": AsyncMock(return_value=_make_project()),
        "update_project": AsyncMock(return_value=_make_project(name="Updated")),
        "delete_project": AsyncMock(return_value=True),
        "start_project": AsyncMock(return_value=_make_project(status="running")),
    }
    defaults.update(overrides)
    for k, v in defaults.items():
        setattr(svc, k, v)
    return svc


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def auth_client():
    """
    HTTP client with a mocked AuthService.
    The dependency override is cleared after each test.
    """
    mock_svc = _make_auth_svc()

    async def _override():
        return mock_svc

    app.dependency_overrides[get_auth_service] = _override
    transport = ASGITransport(app=app)
    yield AsyncClient(transport=transport, base_url="http://test"), mock_svc
    app.dependency_overrides.pop(get_auth_service, None)


@pytest.fixture
def project_client(valid_token):
    """
    HTTP client with a mocked ProjectService.
    Supplies a real (but short-lived) JWT so the auth dependency passes.
    """
    mock_svc = _make_project_svc()

    async def _override():
        return mock_svc

    app.dependency_overrides[get_project_service] = _override
    transport = ASGITransport(app=app)
    yield (
        AsyncClient(transport=transport, base_url="http://test"),
        mock_svc,
        valid_token,
    )
    app.dependency_overrides.pop(get_project_service, None)


@pytest.fixture
def valid_token():
    """Issue a real JWT for user_id='u1'."""
    from app.core.security import create_access_token
    return create_access_token(data={"sub": "u1", "username": "alice"})


# ===========================================================================
# Auth endpoint tests
# ===========================================================================

class TestAuthEndpoints:
    @pytest.mark.asyncio
    async def test_register_returns_201(self, auth_client):
        client, svc = auth_client
        response = await client.post(
            "/api/auth/register",
            json={
                "email": "alice@example.com",
                "username": "alice",
                "password": "Secure123!",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["username"] == "alice"
        assert "id" in data
        svc.register.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_register_returns_400_on_duplicate(self, auth_client):
        client, svc = auth_client
        svc.register = AsyncMock(side_effect=ValueError("Username already registered"))
        response = await client.post(
            "/api/auth/register",
            json={"email": "x@x.com", "username": "dup", "password": "Pass1234!"},
        )
        assert response.status_code == 400
        assert "already registered" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_login_returns_tokens(self, auth_client):
        client, svc = auth_client
        response = await client.post(
            "/api/auth/login",
            json={"username": "alice", "password": "Secure123!"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    @pytest.mark.asyncio
    async def test_login_returns_401_for_wrong_creds(self, auth_client):
        client, svc = auth_client
        svc.login = AsyncMock(side_effect=ValueError("Incorrect username or password"))
        response = await client.post(
            "/api/auth/login",
            json={"username": "alice", "password": "wrong"},
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_login_returns_403_for_inactive_user(self, auth_client):
        client, svc = auth_client
        svc.login = AsyncMock(side_effect=ValueError("User account is inactive"))
        response = await client.post(
            "/api/auth/login",
            json={"username": "alice", "password": "pass"},
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_me_returns_user_profile(self, auth_client, valid_token):
        client, svc = auth_client
        response = await client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "alice"
        svc.get_user_by_id.assert_awaited_once_with("u1")

    @pytest.mark.asyncio
    async def test_me_returns_404_for_missing_user(self, auth_client, valid_token):
        client, svc = auth_client
        svc.get_user_by_id = AsyncMock(return_value=None)
        response = await client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_refresh_returns_new_tokens(self, auth_client, valid_token):
        client, svc = auth_client
        response = await client.post(
            "/api/auth/refresh",
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data

    @pytest.mark.asyncio
    async def test_logout_returns_200(self, auth_client, valid_token):
        client, svc = auth_client
        response = await client.post(
            "/api/auth/logout",
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert response.status_code == 200
        assert "Logged out" in response.json()["message"]
        svc.logout.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_logout_all_returns_200(self, auth_client, valid_token):
        client, svc = auth_client
        response = await client.post(
            "/api/auth/logout-all",
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert response.status_code == 200
        svc.logout_all.assert_awaited_once_with("u1")


# ===========================================================================
# Project endpoint tests
# ===========================================================================

class TestProjectEndpoints:
    @pytest.mark.asyncio
    async def test_create_project_returns_201(self, project_client):
        client, svc, token = project_client
        response = await client.post(
            "/api/projects",
            headers={"Authorization": f"Bearer {token}"},
            json={"name": "Alpha", "target": "example.com"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Alpha"
        svc.create_project.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_list_projects_returns_paginated(self, project_client):
        client, svc, token = project_client
        response = await client.get(
            "/api/projects",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "projects" in data
        assert data["total"] == 1

    @pytest.mark.asyncio
    async def test_get_project_returns_project(self, project_client):
        client, svc, token = project_client
        response = await client.get(
            "/api/projects/p1",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        assert response.json()["id"] == "p1"

    @pytest.mark.asyncio
    async def test_get_project_returns_404_when_not_found(self, project_client):
        client, svc, token = project_client
        svc.get_project = AsyncMock(return_value=None)
        response = await client.get(
            "/api/projects/p999",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_update_project(self, project_client):
        client, svc, token = project_client
        response = await client.patch(
            "/api/projects/p1",
            headers={"Authorization": f"Bearer {token}"},
            json={"name": "Updated"},
        )
        assert response.status_code == 200
        assert response.json()["name"] == "Updated"
        svc.update_project.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_delete_project_returns_message(self, project_client):
        client, svc, token = project_client
        response = await client.delete(
            "/api/projects/p1",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        assert "deleted" in response.json()["message"]

    @pytest.mark.asyncio
    async def test_delete_project_returns_404_when_not_found(self, project_client):
        client, svc, token = project_client
        svc.delete_project = AsyncMock(return_value=False)
        response = await client.delete(
            "/api/projects/p999",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_start_project_returns_running_status(self, project_client):
        client, svc, token = project_client
        response = await client.post(
            "/api/projects/p1/start",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "running"
        svc.start_project.assert_awaited_once_with("p1", "u1")


# ===========================================================================
# Health / Readiness endpoint tests
# ===========================================================================

class TestHealthEndpoints:
    @pytest.mark.asyncio
    async def test_root_returns_operational(self):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/")
        assert response.status_code == 200
        assert response.json()["status"] == "operational"

    @pytest.mark.asyncio
    async def test_health_returns_json(self):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "services" in data
        assert "database" in data["services"]

    @pytest.mark.asyncio
    async def test_readiness_returns_json(self):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/readiness")
        # Either 200 (all services up) or 503 (services not ready in test env)
        assert response.status_code in (200, 503)
        data = response.json()
        assert "status" in data
        assert "checks" in data

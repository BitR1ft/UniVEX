"""
Unit Tests for Service Layer (Week 2 – Day 13)

These tests mock the underlying repositories so no live database or
Prisma client is required.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _user(id="u1", username="alice", email="alice@example.com", is_active=True):
    u = MagicMock()
    u.id = id
    u.username = username
    u.email = email
    u.is_active = is_active
    return u


def _project(id="p1", user_id="u1", status="draft"):
    p = MagicMock()
    p.id = id
    p.user_id = user_id
    p.status = status
    p.name = "Test"
    p.enable_subdomain_enum = True
    p.enable_port_scan = True
    p.enable_web_crawl = True
    p.enable_tech_detection = True
    return p


def _task(id="t1", project_id="p1", task_type="recon"):
    t = MagicMock()
    t.id = id
    t.project_id = project_id
    t.type = task_type
    return t


def _make_auth_service():
    """Build an AuthService with repo dependencies fully mocked."""
    from app.services.auth_service import AuthService

    # Patch the repo constructors so __init__ gets mocked repos
    users_mock = MagicMock()
    sessions_mock = MagicMock()
    for method in [
        "get_by_username", "get_by_email", "get_by_id",
        "create_user", "authenticate",
    ]:
        setattr(users_mock, method, AsyncMock())
    for method in ["create_session", "revoke_session", "revoke_all_user_sessions", "is_valid"]:
        setattr(sessions_mock, method, AsyncMock())

    svc = AuthService.__new__(AuthService)
    svc.users = users_mock
    svc.sessions = sessions_mock
    return svc


def _make_project_service():
    """Build a ProjectService with repo dependencies fully mocked."""
    from app.services.project_service import ProjectService

    projects_mock = MagicMock()
    tasks_mock = MagicMock()
    for method in [
        "create", "get_by_id", "get_by_user", "count_by_user",
        "list_with_filters", "update", "update_status", "delete",
    ]:
        setattr(projects_mock, method, AsyncMock())
    for method in ["create_task"]:
        setattr(tasks_mock, method, AsyncMock())

    svc = ProjectService.__new__(ProjectService)
    svc.projects = projects_mock
    svc.tasks = tasks_mock
    return svc


# ===========================================================================
# AuthService
# ===========================================================================

class TestAuthService:
    @pytest.mark.asyncio
    async def test_register_raises_on_duplicate_username(self):
        from app.schemas import UserCreate

        svc = _make_auth_service()
        svc.users.get_by_username = AsyncMock(return_value=_user())

        user_data = UserCreate(
            email="new@example.com",
            username="alice",
            password="Password1!",
        )
        with pytest.raises(ValueError, match="Username already registered"):
            await svc.register(user_data)

    @pytest.mark.asyncio
    async def test_register_raises_on_duplicate_email(self):
        from app.schemas import UserCreate

        svc = _make_auth_service()
        svc.users.get_by_username = AsyncMock(return_value=None)
        svc.users.get_by_email = AsyncMock(return_value=_user())

        user_data = UserCreate(
            email="alice@example.com",
            username="newuser",
            password="Password1!",
        )
        with pytest.raises(ValueError, match="Email already registered"):
            await svc.register(user_data)

    @pytest.mark.asyncio
    async def test_register_succeeds(self):
        from app.schemas import UserCreate

        svc = _make_auth_service()
        svc.users.get_by_username = AsyncMock(return_value=None)
        svc.users.get_by_email = AsyncMock(return_value=None)
        expected = _user()
        svc.users.create_user = AsyncMock(return_value=expected)

        user_data = UserCreate(
            email="new@example.com",
            username="newuser",
            password="Password1!",
        )
        result = await svc.register(user_data)
        assert result is expected

    @pytest.mark.asyncio
    async def test_login_raises_for_wrong_credentials(self):
        svc = _make_auth_service()
        svc.users.authenticate = AsyncMock(return_value=None)

        with pytest.raises(ValueError, match="Incorrect username or password"):
            await svc.login("alice", "wrong")

    @pytest.mark.asyncio
    async def test_login_raises_for_inactive_user(self):
        svc = _make_auth_service()
        svc.users.authenticate = AsyncMock(return_value=_user(is_active=False))

        with pytest.raises(ValueError, match="inactive"):
            await svc.login("alice", "pass")

    @pytest.mark.asyncio
    async def test_login_returns_tokens(self):
        svc = _make_auth_service()
        svc.users.authenticate = AsyncMock(return_value=_user())
        svc.sessions.create_session = AsyncMock(return_value=MagicMock())

        with (
            patch("app.services.auth_service.create_access_token", return_value="access"),
            patch("app.services.auth_service.create_refresh_token", return_value="refresh"),
        ):
            token = await svc.login("alice", "correct")

        assert token.access_token == "access"
        assert token.refresh_token == "refresh"
        assert token.token_type == "bearer"
        svc.sessions.create_session.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_logout_revokes_session(self):
        svc = _make_auth_service()
        svc.sessions.revoke_session = AsyncMock(return_value=None)

        await svc.logout("mytoken")
        svc.sessions.revoke_session.assert_awaited_once_with("mytoken")

    @pytest.mark.asyncio
    async def test_logout_all_revokes_all(self):
        svc = _make_auth_service()
        svc.sessions.revoke_all_user_sessions = AsyncMock(return_value=3)

        await svc.logout_all("u1")
        svc.sessions.revoke_all_user_sessions.assert_awaited_once_with("u1")


# ===========================================================================
# ProjectService
# ===========================================================================

class TestProjectService:
    @pytest.mark.asyncio
    async def test_create_project(self):
        from app.schemas import ProjectCreate

        svc = _make_project_service()
        expected = _project()
        svc.projects.create = AsyncMock(return_value=expected)

        data = ProjectCreate(name="My Project", target="example.com")
        result = await svc.create_project("u1", data)
        assert result is expected
        svc.projects.create.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_get_project_returns_none_if_not_found(self):
        svc = _make_project_service()
        svc.projects.get_by_id = AsyncMock(return_value=None)

        result = await svc.get_project("p1", "u1")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_project_returns_none_for_wrong_owner(self):
        svc = _make_project_service()
        svc.projects.get_by_id = AsyncMock(return_value=_project(user_id="other"))

        result = await svc.get_project("p1", "u1")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_project_returns_project_for_owner(self):
        svc = _make_project_service()
        p = _project(user_id="u1")
        svc.projects.get_by_id = AsyncMock(return_value=p)

        result = await svc.get_project("p1", "u1")
        assert result is p

    @pytest.mark.asyncio
    async def test_delete_project_returns_false_for_non_owner(self):
        svc = _make_project_service()
        svc.projects.get_by_id = AsyncMock(return_value=_project(user_id="other"))

        result = await svc.delete_project("p1", "u1")
        assert result is False

    @pytest.mark.asyncio
    async def test_delete_project_returns_true_on_success(self):
        svc = _make_project_service()
        p = _project(user_id="u1")
        svc.projects.get_by_id = AsyncMock(return_value=p)
        svc.projects.delete = AsyncMock(return_value=p)

        result = await svc.delete_project("p1", "u1")
        assert result is True

    @pytest.mark.asyncio
    async def test_enqueue_tasks_creates_correct_task_types(self):
        svc = _make_project_service()
        p = _project()
        svc.tasks.create_task = AsyncMock(return_value=_task())

        tasks = await svc.enqueue_tasks(p)

        # With all flags True: recon + port_scan + http_probe
        assert svc.tasks.create_task.call_count == 3
        types_called = [
            call.args[1] if call.args else call.kwargs.get("task_type")
            for call in svc.tasks.create_task.call_args_list
        ]
        assert "recon" in types_called
        assert "port_scan" in types_called
        assert "http_probe" in types_called

    @pytest.mark.asyncio
    async def test_list_projects_applies_pagination(self):
        svc = _make_project_service()
        svc.projects.list_with_filters = AsyncMock(
            return_value={"projects": [_project()], "total": 1}
        )

        result = await svc.list_projects("u1", page=2, page_size=10)

        assert result["page"] == 2
        assert result["page_size"] == 10
        _, kwargs = svc.projects.list_with_filters.call_args
        assert kwargs.get("skip") == 10  # (2-1)*10
        assert kwargs.get("take") == 10


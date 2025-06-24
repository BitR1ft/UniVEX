"""
Unit Tests for Repository Layer (Week 2)

These tests use MagicMock to replace the Prisma client so no live database
connection is required.  They verify that:
  - Each repository method calls the correct Prisma model accessor
  - Correct data is passed to create / update / delete calls
  - Helper utilities (strip_none, paginate) work as expected
"""
import pytest
from datetime import datetime, timedelta
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

from app.db.repositories.base import BaseRepository
from app.db.repositories.users_repo import UsersRepository
from app.db.repositories.projects_repo import ProjectsRepository
from app.db.repositories.tasks_repo import TasksRepository
from app.db.repositories.sessions_repo import SessionsRepository


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_db() -> MagicMock:
    """Return a MagicMock Prisma client with async accessors pre-configured."""
    db = MagicMock()
    for model in ("user", "project", "task", "taskresult", "tasklog", "taskmetrics", "session"):
        mock_model = MagicMock()
        for method in (
            "create", "find_unique", "find_many", "update", "delete",
            "count", "update_many", "delete_many", "upsert",
        ):
            setattr(mock_model, method, AsyncMock())
        setattr(db, model, mock_model)
    return db


def _user(id="u1", username="alice", email="alice@example.com"):
    u = MagicMock()
    u.id = id
    u.username = username
    u.email = email
    u.is_active = True
    u.hashed_password = "salt:hash"
    return u


def _project(id="p1", user_id="u1", status="draft"):
    p = MagicMock()
    p.id = id
    p.user_id = user_id
    p.status = status
    p.enable_subdomain_enum = True
    p.enable_port_scan = True
    p.enable_web_crawl = True
    p.enable_tech_detection = True
    return p


def _task(id="t1", project_id="p1", task_type="recon", status="pending"):
    t = MagicMock()
    t.id = id
    t.project_id = project_id
    t.type = task_type
    t.status = status
    return t


# ===========================================================================
# BaseRepository
# ===========================================================================

class TestBaseRepository:
    def test_strip_none_removes_none_values(self):
        data = {"a": 1, "b": None, "c": "x", "d": None}
        result = BaseRepository._strip_none(data)
        assert result == {"a": 1, "c": "x"}

    def test_strip_none_empty_dict(self):
        assert BaseRepository._strip_none({}) == {}

    def test_paginate_first_page(self):
        items = list(range(10))
        assert BaseRepository._paginate(items, 0, 3) == [0, 1, 2]

    def test_paginate_second_page(self):
        items = list(range(10))
        assert BaseRepository._paginate(items, 3, 3) == [3, 4, 5]

    def test_paginate_beyond_end(self):
        items = list(range(5))
        assert BaseRepository._paginate(items, 4, 10) == [4]


# ===========================================================================
# UsersRepository
# ===========================================================================

class TestUsersRepository:
    @pytest.mark.asyncio
    async def test_create_user(self):
        db = _make_db()
        expected = _user()
        db.user.create.return_value = expected

        with patch("app.db.repositories.users_repo.get_password_hash", return_value="hashed"):
            repo = UsersRepository(db)
            result = await repo.create_user(
                email="alice@example.com",
                username="alice",
                password="secret",
            )

        db.user.create.assert_awaited_once()
        call_data = db.user.create.call_args.kwargs["data"]
        assert call_data["email"] == "alice@example.com"
        assert call_data["hashed_password"] == "hashed"
        assert result is expected

    @pytest.mark.asyncio
    async def test_get_by_id(self):
        db = _make_db()
        expected = _user()
        db.user.find_unique.return_value = expected

        repo = UsersRepository(db)
        result = await repo.get_by_id("u1")

        db.user.find_unique.assert_awaited_once_with(where={"id": "u1"})
        assert result is expected

    @pytest.mark.asyncio
    async def test_get_by_email(self):
        db = _make_db()
        db.user.find_unique.return_value = _user()

        repo = UsersRepository(db)
        await repo.get_by_email("alice@example.com")

        db.user.find_unique.assert_awaited_once_with(where={"email": "alice@example.com"})

    @pytest.mark.asyncio
    async def test_get_by_username(self):
        db = _make_db()
        db.user.find_unique.return_value = _user()

        repo = UsersRepository(db)
        await repo.get_by_username("alice")

        db.user.find_unique.assert_awaited_once_with(where={"username": "alice"})

    @pytest.mark.asyncio
    async def test_update_user_only_sends_non_none_fields(self):
        db = _make_db()
        db.user.update.return_value = _user()

        repo = UsersRepository(db)
        await repo.update_user("u1", full_name="Alice Smith")

        call_data = db.user.update.call_args.kwargs["data"]
        assert "full_name" in call_data
        assert "email" not in call_data
        assert "is_active" not in call_data

    @pytest.mark.asyncio
    async def test_update_user_no_changes_returns_current(self):
        db = _make_db()
        db.user.find_unique.return_value = _user()

        repo = UsersRepository(db)
        result = await repo.update_user("u1")

        db.user.update.assert_not_awaited()
        db.user.find_unique.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_delete_user(self):
        db = _make_db()
        db.user.delete.return_value = _user()

        repo = UsersRepository(db)
        result = await repo.delete_user("u1")

        db.user.delete.assert_awaited_once_with(where={"id": "u1"})
        assert result is not None

    @pytest.mark.asyncio
    async def test_authenticate_returns_none_for_wrong_password(self):
        db = _make_db()
        db.user.find_unique.return_value = _user()

        with patch("app.db.repositories.users_repo.verify_password", return_value=False):
            repo = UsersRepository(db)
            result = await repo.authenticate("alice", "wrong")

        assert result is None

    @pytest.mark.asyncio
    async def test_authenticate_returns_user_for_correct_password(self):
        db = _make_db()
        expected = _user()
        db.user.find_unique.return_value = expected

        with patch("app.db.repositories.users_repo.verify_password", return_value=True):
            repo = UsersRepository(db)
            result = await repo.authenticate("alice", "correct")

        assert result is expected

    @pytest.mark.asyncio
    async def test_authenticate_returns_none_for_unknown_user(self):
        db = _make_db()
        db.user.find_unique.return_value = None

        repo = UsersRepository(db)
        result = await repo.authenticate("nobody", "pass")

        assert result is None


# ===========================================================================
# ProjectsRepository
# ===========================================================================

class TestProjectsRepository:
    @pytest.mark.asyncio
    async def test_create_project(self):
        db = _make_db()
        expected = _project()
        db.project.create.return_value = expected

        repo = ProjectsRepository(db)
        result = await repo.create(
            user_id="u1",
            name="Test Project",
            target="example.com",
        )

        db.project.create.assert_awaited_once()
        data = db.project.create.call_args.kwargs["data"]
        assert data["user_id"] == "u1"
        assert data["name"] == "Test Project"
        assert result is expected

    @pytest.mark.asyncio
    async def test_get_by_id(self):
        db = _make_db()
        db.project.find_unique.return_value = _project()

        repo = ProjectsRepository(db)
        await repo.get_by_id("p1")

        db.project.find_unique.assert_awaited_once_with(where={"id": "p1"})

    @pytest.mark.asyncio
    async def test_get_by_user_applies_status_filter(self):
        db = _make_db()
        db.project.find_many.return_value = []

        repo = ProjectsRepository(db)
        await repo.get_by_user("u1", status="running")

        where = db.project.find_many.call_args.kwargs["where"]
        assert where["user_id"] == "u1"
        assert where["status"] == "running"

    @pytest.mark.asyncio
    async def test_update_status(self):
        db = _make_db()
        db.project.update.return_value = _project(status="running")

        repo = ProjectsRepository(db)
        result = await repo.update_status("p1", "running")

        db.project.update.assert_awaited_once()
        data = db.project.update.call_args.kwargs["data"]
        assert data["status"] == "running"

    @pytest.mark.asyncio
    async def test_delete_project(self):
        db = _make_db()
        db.project.delete.return_value = _project()

        repo = ProjectsRepository(db)
        result = await repo.delete("p1")

        db.project.delete.assert_awaited_once_with(where={"id": "p1"})
        assert result is not None

    @pytest.mark.asyncio
    async def test_list_with_filters_returns_dict(self):
        db = _make_db()
        db.project.find_many.return_value = [_project()]
        db.project.count.return_value = 1

        repo = ProjectsRepository(db)
        result = await repo.list_with_filters("u1")

        assert "projects" in result
        assert "total" in result
        assert result["total"] == 1


# ===========================================================================
# TasksRepository
# ===========================================================================

class TestTasksRepository:
    @pytest.mark.asyncio
    async def test_create_task(self):
        db = _make_db()
        db.task.create.return_value = _task()

        repo = TasksRepository(db)
        result = await repo.create_task("p1", "recon")

        db.task.create.assert_awaited_once()
        data = db.task.create.call_args.kwargs["data"]
        assert data["project_id"] == "p1"
        assert data["type"] == "recon"
        assert data["status"] == "pending"

    @pytest.mark.asyncio
    async def test_update_status_sets_started_at_for_running(self):
        db = _make_db()
        db.task.update.return_value = _task(status="running")

        repo = TasksRepository(db)
        await repo.update_status("t1", "running")

        data = db.task.update.call_args.kwargs["data"]
        assert data["status"] == "running"
        assert "started_at" in data

    @pytest.mark.asyncio
    async def test_update_status_sets_completed_at_for_completed(self):
        db = _make_db()
        db.task.update.return_value = _task(status="completed")

        repo = TasksRepository(db)
        await repo.update_status("t1", "completed")

        data = db.task.update.call_args.kwargs["data"]
        assert "completed_at" in data

    @pytest.mark.asyncio
    async def test_store_result(self):
        db = _make_db()
        db.taskresult.create.return_value = MagicMock()

        repo = TasksRepository(db)
        await repo.store_result("t1", "subdomains", ["a.example.com"])

        db.taskresult.create.assert_awaited_once()
        data = db.taskresult.create.call_args.kwargs["data"]
        assert data["task_id"] == "t1"
        assert data["result_key"] == "subdomains"

    @pytest.mark.asyncio
    async def test_add_log(self):
        db = _make_db()
        db.tasklog.create.return_value = MagicMock()

        repo = TasksRepository(db)
        await repo.add_log("t1", "Task started", level="info")

        db.tasklog.create.assert_awaited_once()
        data = db.tasklog.create.call_args.kwargs["data"]
        assert data["task_id"] == "t1"
        assert data["message"] == "Task started"
        assert data["level"] == "info"

    @pytest.mark.asyncio
    async def test_upsert_metrics(self):
        db = _make_db()
        db.taskmetrics.upsert.return_value = MagicMock()

        repo = TasksRepository(db)
        await repo.upsert_metrics("t1", duration_seconds=5.0, items_processed=10)

        db.taskmetrics.upsert.assert_awaited_once()
        call = db.taskmetrics.upsert.call_args.kwargs
        assert call["where"] == {"task_id": "t1"}

    @pytest.mark.asyncio
    async def test_get_by_project_with_filters(self):
        db = _make_db()
        db.task.find_many.return_value = [_task()]

        repo = TasksRepository(db)
        await repo.get_by_project("p1", status="running", task_type="recon")

        where = db.task.find_many.call_args.kwargs["where"]
        assert where["project_id"] == "p1"
        assert where["status"] == "running"
        assert where["type"] == "recon"


# ===========================================================================
# SessionsRepository
# ===========================================================================

class TestSessionsRepository:
    def _session(self, revoked=False, expired=False):
        s = MagicMock()
        s.id = "sess1"
        s.user_id = "u1"
        s.token = "tok"
        s.is_revoked = revoked
        s.expires_at = (
            datetime.utcnow() - timedelta(hours=1)
            if expired
            else datetime.utcnow() + timedelta(days=7)
        )
        return s

    @pytest.mark.asyncio
    async def test_create_session(self):
        db = _make_db()
        db.session.create.return_value = self._session()

        repo = SessionsRepository(db)
        result = await repo.create_session("u1", "mytoken")

        db.session.create.assert_awaited_once()
        data = db.session.create.call_args.kwargs["data"]
        assert data["user_id"] == "u1"
        assert data["token"] == "mytoken"
        assert "expires_at" in data

    @pytest.mark.asyncio
    async def test_get_by_token(self):
        db = _make_db()
        db.session.find_unique.return_value = self._session()

        repo = SessionsRepository(db)
        await repo.get_by_token("mytoken")

        db.session.find_unique.assert_awaited_once_with(where={"token": "mytoken"})

    @pytest.mark.asyncio
    async def test_is_valid_returns_true_for_valid_session(self):
        db = _make_db()
        db.session.find_unique.return_value = self._session()

        repo = SessionsRepository(db)
        assert await repo.is_valid("tok") is True

    @pytest.mark.asyncio
    async def test_is_valid_returns_false_for_revoked(self):
        db = _make_db()
        db.session.find_unique.return_value = self._session(revoked=True)

        repo = SessionsRepository(db)
        assert await repo.is_valid("tok") is False

    @pytest.mark.asyncio
    async def test_is_valid_returns_false_for_expired(self):
        db = _make_db()
        db.session.find_unique.return_value = self._session(expired=True)

        repo = SessionsRepository(db)
        assert await repo.is_valid("tok") is False

    @pytest.mark.asyncio
    async def test_is_valid_returns_false_for_missing_session(self):
        db = _make_db()
        db.session.find_unique.return_value = None

        repo = SessionsRepository(db)
        assert await repo.is_valid("tok") is False

    @pytest.mark.asyncio
    async def test_revoke_session(self):
        db = _make_db()
        db.session.find_unique.return_value = self._session()
        db.session.update.return_value = self._session(revoked=True)

        repo = SessionsRepository(db)
        result = await repo.revoke_session("tok")

        db.session.update.assert_awaited_once()
        data = db.session.update.call_args.kwargs["data"]
        assert data["is_revoked"] is True

    @pytest.mark.asyncio
    async def test_revoke_session_returns_none_if_not_found(self):
        db = _make_db()
        db.session.find_unique.return_value = None

        repo = SessionsRepository(db)
        result = await repo.revoke_session("nonexistent")

        assert result is None
        db.session.update.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_revoke_all_user_sessions(self):
        db = _make_db()
        db.session.update_many.return_value = 3

        repo = SessionsRepository(db)
        count = await repo.revoke_all_user_sessions("u1")

        assert count == 3
        db.session.update_many.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_cleanup_expired(self):
        db = _make_db()
        db.session.delete_many.return_value = 5

        repo = SessionsRepository(db)
        count = await repo.cleanup_expired()

        assert count == 5
        db.session.delete_many.assert_awaited_once()

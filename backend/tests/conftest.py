"""
Pytest configuration

Week 3 note: auth.py and projects.py now delegate to AuthService /
ProjectService via Prisma.  The in-memory `users_db` and `projects_db` stubs
still exist for backward-compat, but are not used by the live endpoints.
Integration tests override the FastAPI dependencies to inject mock services.
"""
import pytest


@pytest.fixture(autouse=True)
def reset_databases():
    """
    Clear the legacy in-memory stub dicts between tests.

    These dicts are no longer used by the refactored endpoints, but test
    modules that were written against the old API may still reference them.
    Gracefully skips when the database layer is unavailable (e.g., in
    isolated unit-test environments without database drivers installed).
    """
    try:
        from app.api import auth, projects

        auth.users_db.clear()
        projects.projects_db.clear()

        yield

        auth.users_db.clear()
        projects.projects_db.clear()
    except Exception:
        yield

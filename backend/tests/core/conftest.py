"""Core module test configuration — no database imports required."""
import pytest


@pytest.fixture
def reset_databases():
    """Override parent conftest: core tests don't use the legacy DB stubs."""
    yield

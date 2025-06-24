"""MCP test configuration"""

import pytest


# Override the reset_databases fixture from parent conftest
@pytest.fixture
def reset_databases():
    """No-op override of parent reset_databases fixture for MCP tests"""
    yield  # MCP tests don't need database setup


@pytest.fixture(scope="session", autouse=True)
def setup_mcp_tests():
    """Setup for MCP tests without database dependencies"""
    # No database setup needed for MCP tests
    yield

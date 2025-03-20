"""
MCP (Model Context Protocol) Package

Contains MCP server implementations for tool integration.
"""

from .base_server import MCPServer, MCPTool, MCPClient, ToolRegistry, _RateLimiter
from .protocol import (
    ErrorCode,
    InitializeResult,
    ToolCallResult,
    get_compliance_report,
    COMPLIANCE_CHECKLIST,
)
from .phase_control import (
    PhaseAccessController,
    PhaseRestrictionMiddleware,
    get_phase_permissions,
    validate_tool_phase,
    PHASE_PERMISSIONS,
)
from .testing import (
    MCPServerTestClient,
    MockMCPServer,
    MCPProtocolValidator,
    ProtocolComplianceTestCase,
    assert_rpc_ok,
    assert_rpc_error,
    build_rpc_request,
)

__all__ = [
    # base
    "MCPServer", "MCPTool", "MCPClient", "ToolRegistry", "_RateLimiter",
    # protocol
    "ErrorCode", "InitializeResult", "ToolCallResult",
    "get_compliance_report", "COMPLIANCE_CHECKLIST",
    # phase control
    "PhaseAccessController", "PhaseRestrictionMiddleware",
    "get_phase_permissions", "validate_tool_phase", "PHASE_PERMISSIONS",
    # testing
    "MCPServerTestClient", "MockMCPServer", "MCPProtocolValidator",
    "ProtocolComplianceTestCase", "assert_rpc_ok", "assert_rpc_error", "build_rpc_request",
]

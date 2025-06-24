"""Tests for MCP base server and client"""

import pytest
from app.mcp.base_server import MCPServer, MCPTool, MCPClient
from typing import Dict, Any, List


class MockMCPServer(MCPServer):
    """Mock MCP server for testing"""
    
    def __init__(self):
        super().__init__(
            name="TestServer",
            description="Test MCP Server",
            port=9000
        )
    
    def get_tools(self) -> List[MCPTool]:
        return [
            MCPTool(
                name="test_tool",
                description="A test tool",
                parameters={
                    "type": "object",
                    "properties": {
                        "input": {"type": "string"}
                    },
                    "required": ["input"]
                }
            )
        ]
    
    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if tool_name == "test_tool":
            return {
                "success": True,
                "output": f"Processed: {params.get('input', '')}"
            }
        return {"success": False, "error": "Unknown tool"}


class TestMCPServer:
    """Test MCPServer base class"""
    
    def test_server_initialization(self):
        """Test server initialization"""
        server = MockMCPServer()
        assert server.name == "TestServer"
        assert server.description == "Test MCP Server"
        assert server.port == 9000
    
    def test_get_tools(self):
        """Test tool retrieval"""
        server = MockMCPServer()
        tools = server.get_tools()
        assert len(tools) == 1
        assert tools[0].name == "test_tool"
        assert tools[0].description == "A test tool"
    
    @pytest.mark.asyncio
    async def test_execute_tool(self):
        """Test tool execution"""
        server = MockMCPServer()
        result = await server.execute_tool("test_tool", {"input": "hello"})
        assert result["success"] is True
        assert "hello" in result["output"]
    
    @pytest.mark.asyncio
    async def test_execute_unknown_tool(self):
        """Test execution of unknown tool"""
        server = MockMCPServer()
        result = await server.execute_tool("unknown_tool", {})
        assert result["success"] is False
        assert "error" in result


class TestMCPTool:
    """Test MCPTool model"""
    
    def test_tool_creation(self):
        """Test MCPTool creation"""
        tool = MCPTool(
            name="test",
            description="Test tool",
            parameters={"type": "object"}
        )
        assert tool.name == "test"
        assert tool.description == "Test tool"
        assert tool.parameters["type"] == "object"
    
    def test_tool_validation(self):
        """Test tool parameter validation"""
        from pydantic import ValidationError
        
        with pytest.raises(ValidationError):
            # Missing required fields (name and description are both required)
            MCPTool()


class TestMCPClient:
    """Test MCPClient"""
    
    def test_client_initialization(self):
        """Test client initialization"""
        client = MCPClient("http://localhost:9000")
        assert client.server_url == "http://localhost:9000"
        assert client._request_id == 0
    
    def test_get_next_id(self):
        """Test request ID generation"""
        client = MCPClient("http://localhost:9000")
        id1 = client._get_next_id()
        id2 = client._get_next_id()
        assert id1 == "1"
        assert id2 == "2"

"""Tests for tool registry"""

import pytest
from app.agent.tools.tool_registry import ToolRegistry, create_default_registry, get_global_registry
from app.agent.tools.echo_tool import EchoTool
from app.agent.tools.calculator_tool import CalculatorTool
from app.agent.state.agent_state import Phase


class TestToolRegistry:
    """Test ToolRegistry class"""
    
    def test_registry_initialization(self):
        """Test registry initialization"""
        registry = ToolRegistry()
        assert len(registry.list_all_tools()) == 0
    
    def test_register_tool(self):
        """Test tool registration"""
        registry = ToolRegistry()
        tool = EchoTool()
        registry.register_tool(tool)
        
        assert "echo" in registry.list_all_tools()
        assert registry.get_tool("echo") is not None
    
    def test_register_tool_with_phases(self):
        """Test tool registration with phase restrictions"""
        registry = ToolRegistry()
        tool = EchoTool()
        registry.register_tool(tool, allowed_phases=[Phase.INFORMATIONAL])
        
        assert registry.is_tool_allowed("echo", Phase.INFORMATIONAL)
        assert not registry.is_tool_allowed("echo", Phase.EXPLOITATION)
    
    def test_unregister_tool(self):
        """Test tool unregistration"""
        registry = ToolRegistry()
        tool = EchoTool()
        registry.register_tool(tool)
        
        assert "echo" in registry.list_all_tools()
        registry.unregister_tool("echo")
        assert "echo" not in registry.list_all_tools()
    
    def test_get_tools_for_phase(self):
        """Test getting tools for specific phase"""
        registry = ToolRegistry()
        
        echo_tool = EchoTool()
        calc_tool = CalculatorTool()
        
        registry.register_tool(echo_tool, allowed_phases=[Phase.INFORMATIONAL])
        registry.register_tool(calc_tool, allowed_phases=[Phase.EXPLOITATION])
        
        info_tools = registry.get_tools_for_phase(Phase.INFORMATIONAL)
        assert "echo" in info_tools
        assert "calculator" not in info_tools
        
        exploit_tools = registry.get_tools_for_phase(Phase.EXPLOITATION)
        assert "calculator" in exploit_tools
        assert "echo" not in exploit_tools
    
    def test_get_tool_metadata(self):
        """Test getting tool metadata"""
        registry = ToolRegistry()
        tool = EchoTool()
        registry.register_tool(tool, allowed_phases=[Phase.INFORMATIONAL])
        
        metadata = registry.get_tool_metadata("echo")
        assert metadata is not None
        assert metadata["name"] == "echo"
        assert metadata["description"] == tool.description
        assert Phase.INFORMATIONAL.value in metadata["allowed_phases"]
    
    def test_get_all_tool_metadata(self):
        """Test getting all tool metadata"""
        registry = ToolRegistry()
        registry.register_tool(EchoTool())
        registry.register_tool(CalculatorTool())
        
        metadata_list = registry.get_all_tool_metadata()
        assert len(metadata_list) == 2
    
    def test_get_all_tool_metadata_filtered(self):
        """Test getting metadata filtered by phase"""
        registry = ToolRegistry()
        registry.register_tool(EchoTool(), allowed_phases=[Phase.INFORMATIONAL])
        registry.register_tool(CalculatorTool(), allowed_phases=[Phase.EXPLOITATION])
        
        info_metadata = registry.get_all_tool_metadata(Phase.INFORMATIONAL)
        assert len(info_metadata) == 1
        assert info_metadata[0]["name"] == "echo"


class TestDefaultRegistry:
    """Test default registry creation"""
    
    def test_create_default_registry(self):
        """Test creating default registry"""
        registry = create_default_registry()
        
        # Should have multiple tools
        tools = registry.list_all_tools()
        assert len(tools) > 0
        
        # Should have basic tools
        assert "echo" in tools
        assert "calculator" in tools
    
    def test_default_registry_phase_restrictions(self):
        """Test that default registry has proper phase restrictions"""
        registry = create_default_registry()
        
        # Echo should be available in all phases
        assert registry.is_tool_allowed("echo", Phase.INFORMATIONAL)
        assert registry.is_tool_allowed("echo", Phase.EXPLOITATION)
        
        # Metasploit should only be in exploitation
        if "metasploit_search" in registry.list_all_tools():
            assert not registry.is_tool_allowed("metasploit_search", Phase.INFORMATIONAL)
            assert registry.is_tool_allowed("metasploit_search", Phase.EXPLOITATION)
    
    def test_get_global_registry(self):
        """Test getting global registry singleton"""
        registry1 = get_global_registry()
        registry2 = get_global_registry()
        
        # Should be the same instance
        assert registry1 is registry2
        
        # Should have tools
        assert len(registry1.list_all_tools()) > 0

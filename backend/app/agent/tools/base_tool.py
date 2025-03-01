"""
Base Tool Abstract Class

Defines the interface for all tools that can be used by the agent.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any
from pydantic import BaseModel, Field


class ToolMetadata(BaseModel):
    """Metadata for a tool"""
    name: str = Field(..., description="Tool name")
    description: str = Field(..., description="What the tool does")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Tool parameter schema")


class BaseTool(ABC):
    """
    Abstract base class for all agent tools.
    
    Tools are functions that the agent can invoke to interact with
    the environment (scan networks, exploit vulnerabilities, etc.)
    """
    
    def __init__(self):
        self._metadata = self._define_metadata()
    
    @abstractmethod
    def _define_metadata(self) -> ToolMetadata:
        """Define tool metadata (name, description, parameters)"""
        pass
    
    @abstractmethod
    async def execute(self, **kwargs) -> str:
        """
        Execute the tool with given parameters.
        
        Returns:
            str: Tool output as a string (will be truncated if too long)
        """
        pass
    
    @property
    def metadata(self) -> ToolMetadata:
        """Get tool metadata"""
        return self._metadata
    
    @property
    def name(self) -> str:
        """Get tool name"""
        return self._metadata.name
    
    @property
    def description(self) -> str:
        """Get tool description"""
        return self._metadata.description
    
    def to_langchain_tool(self):
        """Convert to LangChain tool format"""
        from langchain_core.tools import StructuredTool
        
        return StructuredTool.from_function(
            func=self.execute,
            name=self.name,
            description=self.description,
        )

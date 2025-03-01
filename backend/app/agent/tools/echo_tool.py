"""
Mock Echo Tool

Simple tool that echoes back the input. Used for testing the agent.
"""

from .base_tool import BaseTool, ToolMetadata
from .error_handling import with_timeout


class EchoTool(BaseTool):
    """Simple echo tool for testing"""
    
    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="echo",
            description="Echoes back the input message. Useful for testing the agent's tool invocation.",
            parameters={
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "The message to echo back"
                    }
                },
                "required": ["message"]
            }
        )
    
    @with_timeout(timeout_seconds=10)
    async def execute(self, message: str, **kwargs) -> str:
        """Echo the message back"""
        return f"Echo: {message}"

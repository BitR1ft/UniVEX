"""
Mock Calculator Tool

Simple calculator tool for testing agent math operations.
"""

from .base_tool import BaseTool, ToolMetadata
from .error_handling import with_timeout, ToolExecutionError


class CalculatorTool(BaseTool):
    """Calculator tool for basic arithmetic"""
    
    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="calculator",
            description="Performs basic arithmetic operations (add, subtract, multiply, divide). Use this when you need to do calculations.",
            parameters={
                "type": "object",
                "properties": {
                    "operation": {
                        "type": "string",
                        "enum": ["add", "subtract", "multiply", "divide"],
                        "description": "The arithmetic operation to perform"
                    },
                    "a": {
                        "type": "number",
                        "description": "First operand"
                    },
                    "b": {
                        "type": "number",
                        "description": "Second operand"
                    }
                },
                "required": ["operation", "a", "b"]
            }
        )
    
    @with_timeout(timeout_seconds=5)
    async def execute(self, operation: str, a: float, b: float, **kwargs) -> str:
        """Perform arithmetic operation"""
        try:
            if operation == "add":
                result = a + b
            elif operation == "subtract":
                result = a - b
            elif operation == "multiply":
                result = a * b
            elif operation == "divide":
                if b == 0:
                    raise ToolExecutionError("Cannot divide by zero")
                result = a / b
            else:
                raise ToolExecutionError(f"Unknown operation: {operation}")
            
            return f"Result: {a} {operation} {b} = {result}"
        except Exception as e:
            raise ToolExecutionError(f"Calculator error: {str(e)}")

"""
SimpleJSON Agent — Lightweight Structured JSON Response Agent

A lightweight agent for producing and validating structured JSON responses
without a full reasoning chain; used for data extraction and API calls.
"""

from __future__ import annotations

import json
import logging
from enum import Enum
from typing import Any, Dict, List, Optional

from app.agent.agents import BaseAgent, MultiAgentState
from app.agent.state.agent_state import Phase
from app.agent.tools.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)


class SchemaType(str, Enum):
    """Predefined schema types for structured output."""

    FINDING = "finding"
    TARGET_INFO = "target_info"
    SCAN_RESULT = "scan_result"
    TOOL_OUTPUT = "tool_output"
    CUSTOM = "custom"


class SimpleJSONAgent(BaseAgent):
    """
    Lightweight agent that returns validated JSON without a full reasoning chain.

    Used for structured data extraction, schema validation, and type-safe
    API responses.  Operates without multi-step ReAct loops.
    """

    AGENT_NAME = "simple_json"
    PREFERRED_TOOLS: List[str] = ["web_search", "query_graph"]

    # Predefined schemas for common data structures
    PREDEFINED_SCHEMAS: Dict[str, Dict[str, Any]] = {
        "finding": {
            "type": "object",
            "required": ["type", "severity"],
            "properties": {
                "type": {"type": "string"},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "tool": {"type": "string"},
                "output": {"type": "string"},
                "description": {"type": "string"},
                "cve_references": {"type": "array"},
                "owasp_mapping": {"type": "string"},
                "cvss_score": {"type": "number"},
                "cwe_id": {"type": "string"},
            },
        },
        "target_info": {
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string"},
                "ip": {"type": "string"},
                "domain": {"type": "string"},
                "ports": {"type": "array"},
                "services": {"type": "array"},
                "os": {"type": "string"},
                "os_type": {"type": "string"},
                "lhost": {"type": "string"},
                "lport": {"type": "integer"},
            },
        },
        "scan_result": {
            "type": "object",
            "required": ["tool", "status"],
            "properties": {
                "tool": {"type": "string"},
                "status": {"type": "string"},
                "output": {"type": "string"},
                "findings": {"type": "array"},
                "duration_seconds": {"type": "number"},
                "timestamp": {"type": "string"},
            },
        },
        "tool_output": {
            "type": "object",
            "required": ["tool_name", "raw_output"],
            "properties": {
                "tool_name": {"type": "string"},
                "raw_output": {"type": "string"},
                "parsed": {"type": "object"},
                "exit_code": {"type": "integer"},
                "error": {"type": "string"},
            },
        },
    }

    def __init__(
        self,
        registry: ToolRegistry,
        llm: Any = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(registry, llm, config)

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    def get_phase(self) -> Phase:
        return Phase.INFORMATIONAL

    def _build_system_prompt(self) -> str:
        tool_names = ", ".join(self.get_tool_names()) or "none"
        return (
            "You are the SimpleJSON Agent, a lightweight agent specialised in "
            "structured data extraction and JSON schema validation.\n\n"
            "Your responsibilities:\n"
            "  1. Extract structured JSON data from unstructured text.\n"
            "  2. Validate JSON objects against predefined schemas.\n"
            "  3. Coerce field types to match schema requirements.\n"
            "  4. Return well-formed, schema-compliant JSON responses.\n"
            "  5. Handle partial data gracefully with sensible defaults.\n\n"
            f"Available tools: {tool_names}.\n\n"
            "Always return valid JSON. Do not add commentary outside of JSON."
        )

    async def run(
        self, state: MultiAgentState, task: str
    ) -> Dict[str, Any]:
        """
        Extract and return structured JSON based on the task.

        Args:
            state: Shared multi-agent state.
            task:  Extraction or query task description.

        Returns:
            ``{"agent": "simple_json", "result": dict, "valid": bool,
               "schema_type": str}``
        """
        logger.info("SimpleJSONAgent task: %s", task[:80])

        schema_type = self._infer_schema_type(task)
        schema = self.PREDEFINED_SCHEMAS.get(schema_type.value, {})

        context: Dict[str, Any] = {
            "target_info": state.get("target_info") or {},
            "agent_results": state.get("agent_results") or {},
        }

        result = self.structured_query(task, schema, context)
        valid = self.validate_schema(result, schema) if schema else True

        return {
            "agent": self.AGENT_NAME,
            "result": result,
            "valid": valid,
            "schema_type": schema_type.value,
        }

    # ------------------------------------------------------------------
    # Domain-specific methods
    # ------------------------------------------------------------------

    def extract_json(self, text: str, schema: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract and validate JSON from an arbitrary text string.

        Args:
            text:   Text that may contain JSON (possibly embedded in markdown).
            schema: JSON schema to validate against.

        Returns:
            Extracted and validated dict.
        """
        # Try to parse the text directly as JSON
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return self._coerce_types(data, schema)
        except (json.JSONDecodeError, ValueError):
            pass

        # Try to extract JSON from code blocks
        import re
        json_block = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if json_block:
            try:
                data = json.loads(json_block.group(1))
                if isinstance(data, dict):
                    return self._coerce_types(data, schema)
            except (json.JSONDecodeError, ValueError):
                pass

        # Try to find any JSON object in the text
        brace_match = re.search(r"\{[^{}]*\}", text, re.DOTALL)
        if brace_match:
            try:
                data = json.loads(brace_match.group(0))
                if isinstance(data, dict):
                    return self._coerce_types(data, schema)
            except (json.JSONDecodeError, ValueError):
                pass

        # Return an empty dict satisfying schema defaults
        return self._build_default(schema)

    def validate_schema(self, data: Dict[str, Any], schema: Dict[str, Any]) -> bool:
        """
        Validate a dict against a JSON schema definition.

        Args:
            data:   Dict to validate.
            schema: Schema dict with ``required`` and ``properties`` keys.

        Returns:
            True if valid, False otherwise.
        """
        if not schema:
            return True

        required = schema.get("required", [])
        properties = schema.get("properties", {})

        # Check all required fields are present
        for field in required:
            if field not in data:
                logger.debug("Schema validation: missing required field '%s'", field)
                return False

        # Check enum constraints
        for field, prop_schema in properties.items():
            if field in data and "enum" in prop_schema:
                if data[field] not in prop_schema["enum"]:
                    logger.debug("Schema validation: '%s' value not in enum", field)
                    return False

        return True

    def structured_query(
        self,
        prompt: str,
        output_schema: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Produce a structured response conforming to the output schema.

        Args:
            prompt:        Query description.
            output_schema: JSON schema for the desired output.
            context:       Additional context data.

        Returns:
            Schema-conformant dict.
        """
        # Build a synthetic response from available context
        result = self._build_default(output_schema)

        # Populate with context data where schema fields match
        target_info = context.get("target_info", {})
        for key, value in target_info.items():
            if key in output_schema.get("properties", {}):
                result[key] = value

        return self._coerce_types(result, output_schema)

    def _coerce_types(self, data: Dict[str, Any], schema: Dict[str, Any]) -> Dict[str, Any]:
        """
        Coerce field types to match the schema definition.

        Args:
            data:   Input dict to coerce.
            schema: Schema with ``properties`` type definitions.

        Returns:
            Dict with coerced field values.
        """
        if not schema:
            return data

        properties = schema.get("properties", {})
        coerced = dict(data)

        type_coercions = {
            "string": str,
            "integer": int,
            "number": float,
            "boolean": bool,
        }

        for field, prop_schema in properties.items():
            if field not in coerced:
                continue
            expected_type = prop_schema.get("type")
            coerce_fn = type_coercions.get(expected_type)
            if coerce_fn is None:
                continue
            try:
                coerced[field] = coerce_fn(coerced[field])
            except (ValueError, TypeError):
                pass  # Leave as-is if coercion fails

        return coerced

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _infer_schema_type(self, task: str) -> SchemaType:
        """Infer the appropriate schema type from the task description."""
        task_lower = task.lower()
        if "finding" in task_lower or "vulnerability" in task_lower:
            return SchemaType.FINDING
        if "target" in task_lower:
            return SchemaType.TARGET_INFO
        if "scan" in task_lower or "result" in task_lower:
            return SchemaType.SCAN_RESULT
        if "tool" in task_lower or "output" in task_lower:
            return SchemaType.TOOL_OUTPUT
        return SchemaType.CUSTOM

    def _build_default(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Build a default dict satisfying the schema's required fields."""
        required = schema.get("required", [])
        properties = schema.get("properties", {})

        default_values: Dict[str, Any] = {
            "string": "",
            "integer": 0,
            "number": 0.0,
            "boolean": False,
            "array": [],
            "object": {},
        }

        result: Dict[str, Any] = {}
        for field in required:
            prop = properties.get(field, {})
            field_type = prop.get("type", "string")
            enum_vals = prop.get("enum")
            result[field] = enum_vals[0] if enum_vals else default_values.get(field_type, "")

        return result


__all__ = ["SimpleJSONAgent", "SchemaType"]

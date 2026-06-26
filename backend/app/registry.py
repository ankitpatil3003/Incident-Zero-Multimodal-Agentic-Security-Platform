"""
Typed MCP tool registry with JSON schema validation.

Enforces predictable agent behavior: every tool must declare its input schema
and output signals upfront. The orchestrator uses this to validate tool calls
and the correlator uses output_signals to know what to expect.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# Path to the JSON schema defining valid tool registrations
_SCHEMA_PATH = Path(__file__).resolve().parent.parent.parent / "schemas" / "tool_registry.json"


class ToolSpec:
    """Immutable specification for a registered MCP tool."""

    __slots__ = ("name", "description", "input_schema", "output_signals", "handler")

    def __init__(
        self,
        name: str,
        description: str,
        input_schema: Dict[str, Any],
        output_signals: List[str],
        handler: Callable[..., Dict[str, Any]],
    ) -> None:
        self.name = name
        self.description = description
        self.input_schema = input_schema
        self.output_signals = output_signals
        self.handler = handler

    def validate_input(self, params: Dict[str, Any]) -> List[str]:
        """Check that required input keys are present. Returns list of errors."""
        required = self.input_schema.get("required", [])
        properties = self.input_schema.get("properties", {})
        errors: List[str] = []

        for key in required:
            if key not in params:
                errors.append(f"Missing required input: '{key}'")

        for key, value in params.items():
            if key not in properties:
                continue
            prop_spec = properties[key]
            expected_type = prop_spec.get("type")
            if expected_type and not _type_matches(value, expected_type):
                errors.append(
                    f"Input '{key}' expected type '{expected_type}', got '{type(value).__name__}'"
                )

        return errors

    def validate_output(self, result: Dict[str, Any]) -> List[str]:
        """Check that the ToolResult envelope has the required keys."""
        errors: List[str] = []
        for key in ("tool_name", "artifacts", "evidence", "signals"):
            if key not in result:
                errors.append(f"Missing required output key: '{key}'")
        if result.get("tool_name") != self.name:
            errors.append(
                f"Output tool_name '{result.get('tool_name')}' doesn't match '{self.name}'"
            )
        return errors


class ToolRegistry:
    """Registry of available MCP tools. Singleton used by the orchestrator."""

    def __init__(self) -> None:
        self._tools: Dict[str, ToolSpec] = {}

    def register(
        self,
        name: str,
        description: str,
        input_schema: Dict[str, Any],
        output_signals: List[str],
        handler: Callable[..., Dict[str, Any]],
    ) -> ToolSpec:
        """Register a new MCP tool. Raises ValueError on duplicate names."""
        if name in self._tools:
            raise ValueError(f"Tool '{name}' is already registered")

        spec = ToolSpec(
            name=name,
            description=description,
            input_schema=input_schema,
            output_signals=output_signals,
            handler=handler,
        )
        self._tools[name] = spec
        logger.info("Registered MCP tool: %s", name)
        return spec

    def get(self, name: str) -> Optional[ToolSpec]:
        return self._tools.get(name)

    def list_tools(self) -> List[ToolSpec]:
        return list(self._tools.values())

    def invoke(self, name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate input, call handler, validate output.
        Returns ToolResult or raises ValueError on validation failure.
        """
        spec = self.get(name)
        if spec is None:
            raise ValueError(f"Unknown tool: '{name}'")

        # Validate input
        input_errors = spec.validate_input(params)
        if input_errors:
            raise ValueError(f"Input validation failed for '{name}': {input_errors}")

        # Call handler
        result = spec.handler(**params)

        # Validate output
        output_errors = spec.validate_output(result)
        if output_errors:
            logger.warning("Output validation issues for '%s': %s", name, output_errors)

        return result

    def to_function_call_schema(self) -> List[Dict[str, Any]]:
        """
        Export all tools as LLM function-calling schema.
        Used when the orchestrator needs the LLM to select which tools to invoke.
        """
        schemas = []
        for spec in self._tools.values():
            schemas.append(
                {
                    "type": "function",
                    "function": {
                        "name": spec.name,
                        "description": spec.description,
                        "parameters": spec.input_schema,
                    },
                }
            )
        return schemas


# Singleton
tool_registry = ToolRegistry()


def _type_matches(value: Any, expected: str) -> bool:
    """Check if a Python value matches a JSON schema type string."""
    type_map = {
        "string": str,
        "integer": int,
        "number": (int, float),
        "boolean": bool,
        "array": list,
        "object": dict,
    }
    expected_types = type_map.get(expected)
    if expected_types is None:
        return True  # unknown type — don't block
    return isinstance(value, expected_types)

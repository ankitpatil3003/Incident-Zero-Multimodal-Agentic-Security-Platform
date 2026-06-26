"""
Shared type definitions and helpers for all MCP tool outputs.

Every MCP tool returns a ToolResult — a standardized envelope containing:
  - tool_name: identifier for the tool that produced the result
  - artifacts: tool-specific extracted data (summaries, parsed structures)
  - evidence: list of evidence items linked to findings
  - signals: cross-tool correlation hints (runtime_proof, secret_exposure, etc.)
  - errors: list of non-fatal errors encountered during processing
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


# --- Evidence item schema ---

EVIDENCE_KINDS = {"code", "log", "runtime", "ocr", "image_text", "screenshot", "diagram", "other"}


def build_evidence(
    evidence_id: str,
    kind: str,
    file_path: str = "",
    line: int = 0,
    snippet: str = "",
    note: str = "",
) -> Dict[str, Any]:
    """Build a single evidence item with validated kind."""
    return {
        "id": evidence_id,
        "kind": kind if kind in EVIDENCE_KINDS else "other",
        "file_path": file_path,
        "line": line,
        "snippet": snippet,
        "note": note,
    }


# --- ToolResult envelope ---


def build_tool_result(
    tool_name: str,
    artifacts: Dict[str, Any],
    evidence: List[Dict[str, Any]],
    signals: Dict[str, Any],
    errors: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Build the standardized ToolResult envelope.

    All MCP tools must return this shape. The orchestrator and correlator
    depend on these keys being present.
    """
    return {
        "tool_name": tool_name,
        "artifacts": artifacts,
        "evidence": evidence,
        "signals": signals,
        "errors": errors if errors else None,
    }


def build_error_result(
    tool_name: str,
    error: str,
    detail: str = "",
) -> Dict[str, Any]:
    """Shorthand for returning a ToolResult with only an error."""
    errors = [{"error": error, "detail": detail}] if detail else [{"error": error}]
    return build_tool_result(
        tool_name=tool_name,
        artifacts={},
        evidence=[],
        signals={},
        errors=errors,
    )

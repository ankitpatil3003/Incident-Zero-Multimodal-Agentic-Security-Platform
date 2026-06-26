"""
Shared type definitions and helpers for all MCP tool outputs.

Every MCP tool returns a ToolResult — a standardized envelope containing:
  - tool_name: identifier for the tool that produced the result
  - artifacts: tool-specific extracted data (summaries, parsed structures)
  - evidence: list of evidence items linked to findings
  - signals: cross-tool correlation hints (runtime_proof, secret_exposure, etc.)
  - errors: list of non-fatal errors encountered during processing

Security:
  - Secret values in evidence snippets are automatically masked
  - Full credentials are never exposed in API responses
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


# --- Secret masking ---

# Patterns that match secret values to be redacted in evidence snippets.
_SECRET_MASK_PATTERNS = [
    # key = "value" or key = 'value'
    re.compile(
        r"""((?:password|secret|token|api_key|apikey|api[-_]?secret|"""
        r"""access_key|private_key|auth|credential|db_pass|database_url)"""
        r"""\s*[=:]\s*['"])([^'"]{4,})(['"])""",
        re.IGNORECASE,
    ),
    # AWS-style keys: AKIA followed by 16+ chars
    re.compile(r"(AKIA)([A-Z0-9]{16,})"),
    # Bearer tokens
    re.compile(r"(Bearer\s+)([A-Za-z0-9_\-\.]{8,})", re.IGNORECASE),
    # Generic hex/base64 tokens after common prefixes
    re.compile(
        r"""((?:ghp_|gho_|ghu_|ghs_|ghr_|sk-|sk_live_|rk_live_|pk_live_|"""
        r"""sk_test_|rk_test_|pk_test_|xox[bprsao]-))([A-Za-z0-9_\-]{8,})"""
    ),
]

_MASK_VISIBLE_CHARS = 3
_MASK_PLACEHOLDER = "***"


def mask_secrets(text: str) -> str:
    """Replace secret values in text with masked versions.

    Keeps the first and last few characters visible so the user
    can identify which secret it is, without exposing the full value.
    """
    if not text:
        return text

    result = text
    for pattern in _SECRET_MASK_PATTERNS:
        def _replacer(m: re.Match) -> str:
            groups = m.groups()
            if len(groups) == 3:
                prefix, value, suffix = groups
                masked = _mask_value(value)
                return f"{prefix}{masked}{suffix}"
            elif len(groups) == 2:
                prefix, value = groups
                masked = _mask_value(value)
                return f"{prefix}{masked}"
            return m.group(0)

        result = pattern.sub(_replacer, result)
    return result


def _mask_value(value: str) -> str:
    """Mask a secret value, keeping a few chars visible at each end."""
    if len(value) <= _MASK_VISIBLE_CHARS * 2 + 3:
        return _MASK_PLACEHOLDER
    start = value[:_MASK_VISIBLE_CHARS]
    end = value[-_MASK_VISIBLE_CHARS:]
    return f"{start}{_MASK_PLACEHOLDER}{end}"


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
    """Build a single evidence item with validated kind.

    Secrets in snippet and note fields are automatically masked
    so that full credential values are never exposed in API responses.
    """
    return {
        "id": evidence_id,
        "kind": kind if kind in EVIDENCE_KINDS else "other",
        "file_path": file_path,
        "line": line,
        "snippet": mask_secrets(snippet),
        "note": mask_secrets(note),
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

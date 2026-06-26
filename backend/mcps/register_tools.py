"""
Wire all 5 MCP tools into the tool_registry singleton.

Import this module at app startup to make all tools available
for orchestrator invocation and LLM function-calling export.
"""

from __future__ import annotations

from backend.app.registry import tool_registry
from backend.mcps.codescan.scanner import scan_repo
from backend.mcps.log_reasoner.run import analyze_log
from backend.mcps.screenshot_analyzer.run import analyze_screenshot
from backend.mcps.diagram_extractor.run import extract_diagram
from backend.mcps.patcher.generator import generate_patches


def register_all_tools() -> None:
    """Register all MCP tools. Safe to call multiple times (skips duplicates)."""

    _register_if_missing(
        name="CodeScan",
        description=(
            "Scan a source code repository for vulnerabilities including "
            "hardcoded secrets, SQL injection, and weak cryptography."
        ),
        input_schema={
            "required": ["repo_path"],
            "properties": {
                "repo_path": {"type": "string", "description": "Path to repository root"},
            },
        },
        output_signals=[
            "has_secrets", "has_sqli", "has_weak_crypto",
            "finding_types", "max_severity",
        ],
        handler=lambda **kwargs: scan_repo(**kwargs),
    )

    _register_if_missing(
        name="LogReasoner",
        description=(
            "Analyze log files for errors, authentication failures, "
            "suspicious activity, and network issues."
        ),
        input_schema={
            "required": ["log_path"],
            "properties": {
                "log_path": {"type": "string", "description": "Path to log file"},
            },
        },
        output_signals=[
            "has_errors", "has_auth_failures", "has_suspicious_activity",
            "has_network_issues", "categories_found", "max_severity",
        ],
        handler=lambda **kwargs: analyze_log(**kwargs),
    )

    _register_if_missing(
        name="ScreenshotAnalyzer",
        description=(
            "Analyze screenshots for exposed secrets, error messages, "
            "PII, and network information using OCR and pattern detection."
        ),
        input_schema={
            "required": ["screenshot_path"],
            "properties": {
                "screenshot_path": {"type": "string", "description": "Path to screenshot image"},
            },
        },
        output_signals=[
            "has_secret_exposure", "has_error_exposure",
            "has_pii_exposure", "has_network_info",
            "categories_found", "max_severity",
        ],
        handler=lambda **kwargs: analyze_screenshot(**kwargs),
    )

    _register_if_missing(
        name="DiagramExtractor",
        description=(
            "Extract architecture components, protocols, ports, and data flows "
            "from network/architecture diagram images."
        ),
        input_schema={
            "required": ["diagram_path"],
            "properties": {
                "diagram_path": {"type": "string", "description": "Path to diagram image"},
            },
        },
        output_signals=[
            "has_components", "has_protocols", "has_ports", "has_flows",
            "component_names", "protocol_names",
        ],
        handler=lambda **kwargs: extract_diagram(**kwargs),
    )

    _register_if_missing(
        name="Patcher",
        description=(
            "Generate fix suggestions and unified diffs from vulnerability "
            "findings produced by other MCP tools."
        ),
        input_schema={
            "required": ["findings"],
            "properties": {
                "findings": {
                    "type": "array",
                    "description": "List of evidence dicts from other tools",
                },
            },
        },
        output_signals=[
            "has_patches", "patch_count", "types_patched", "all_auto_fixable",
        ],
        handler=lambda **kwargs: generate_patches(**kwargs),
    )


def _register_if_missing(name: str, **kwargs) -> None:  # type: ignore[no-untyped-def]
    """Register a tool only if not already registered."""
    if tool_registry.get(name) is None:
        tool_registry.register(name=name, **kwargs)

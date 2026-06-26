"""
CodeScan MCP tool — walks a repository directory, applies vulnerability rules,
and returns a ToolResult envelope with findings.

Uses the local-first pattern:
  - Local: regex-based rule matching (always runs, no API needed)
  - LLM: optional Mistral augmentation to reduce false positives (future Sprint)
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Tuple

from backend.mcps.common.types import build_tool_result, build_error_result
from backend.mcps.common.local_extract import local_first
from backend.mcps.codescan.rules import VULNERABILITY_RULES, VulnerabilityRule
from backend.mcps.codescan.evidence_extractor import extract_evidence

logger = logging.getLogger(__name__)

# Extensions we scan (skip binaries, images, etc.)
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb",
    ".rs", ".c", ".cpp", ".h", ".cs", ".php", ".sh", ".bash",
    ".yaml", ".yml", ".toml", ".json", ".xml", ".env", ".cfg",
    ".ini", ".conf", ".tf", ".hcl",
}

# Directories to always skip
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".mypy_cache", ".pytest_cache", "dist", "build", ".next",
}

# Max file size to scan (1 MB)
MAX_FILE_SIZE = 1_048_576

TOOL_NAME = "CodeScan"


def scan_repo(repo_path: str) -> Dict[str, Any]:
    """
    Main entry point. Scans a repository and returns a ToolResult.

    Args:
        repo_path: path to the repository root directory

    Returns:
        ToolResult envelope with findings
    """
    if not os.path.isdir(repo_path):
        return build_error_result(TOOL_NAME, "repo_not_found", f"Path not found: {repo_path}")

    def local_fn() -> Dict[str, Any]:
        return _local_scan(repo_path)

    def llm_fn(local_result: Dict[str, Any]) -> Dict[str, Any]:
        # LLM augmentation deferred to Sprint 5 orchestrator integration.
        # For now, return empty — local_first merges gracefully.
        return {"artifacts": {}, "evidence": [], "signals": {}}

    merged = local_first(local_fn, llm_fn)

    return build_tool_result(
        tool_name=TOOL_NAME,
        artifacts=merged["artifacts"],
        evidence=merged["evidence"],
        signals=merged["signals"],
        errors=merged.get("errors"),
    )


def _local_scan(repo_path: str) -> Dict[str, Any]:
    """Walk repo, apply rules, build evidence."""
    matches: List[Tuple[VulnerabilityRule, Dict[str, Any], str]] = []
    files_scanned = 0
    files_skipped = 0

    for dirpath, dirnames, filenames in os.walk(repo_path):
        # Prune skipped directories in-place
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        for filename in filenames:
            ext = os.path.splitext(filename)[1].lower()
            if ext not in SCANNABLE_EXTENSIONS:
                files_skipped += 1
                continue

            full_path = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(full_path, repo_path)

            try:
                size = os.path.getsize(full_path)
                if size > MAX_FILE_SIZE:
                    files_skipped += 1
                    continue

                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except (OSError, PermissionError) as exc:
                logger.warning("Cannot read %s: %s", rel_path, exc)
                files_skipped += 1
                continue

            files_scanned += 1

            for rule in VULNERABILITY_RULES:
                rule_matches = rule.check(content, rel_path)
                for m in rule_matches:
                    matches.append((rule, m, rel_path))

    result = extract_evidence(matches)

    # Add scan metadata to artifacts
    result["artifacts"]["files_scanned"] = files_scanned
    result["artifacts"]["files_skipped"] = files_skipped
    result["artifacts"]["rules_applied"] = len(VULNERABILITY_RULES)

    return result

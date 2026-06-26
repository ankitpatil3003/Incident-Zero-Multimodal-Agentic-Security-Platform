"""
LogReasoner MCP tool — parses log files using regex patterns to detect
errors, auth failures, and suspicious activity, then optionally augments
with Mistral LLM for root-cause reasoning.

Uses the local-first pattern:
  - Local: regex pattern matching for known log signatures
  - LLM: Mistral text model for root-cause analysis of detected anomalies
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from backend.mcps.common.types import build_tool_result, build_error_result, build_evidence
from backend.mcps.common.local_extract import local_first

logger = logging.getLogger(__name__)

TOOL_NAME = "LogReasoner"

# Max log file size (5 MB)
MAX_LOG_SIZE = 5_242_880


# --- Pattern definitions ---

class LogPattern:
    """A named regex pattern for detecting log anomalies."""

    __slots__ = ("pattern_id", "category", "severity", "description", "regex")

    def __init__(
        self,
        pattern_id: str,
        category: str,
        severity: str,
        description: str,
        regex: re.Pattern[str],
    ) -> None:
        self.pattern_id = pattern_id
        self.category = category
        self.severity = severity
        self.description = description
        self.regex = regex


LOG_PATTERNS: List[LogPattern] = [
    # --- Errors ---
    LogPattern(
        "ERR_EXCEPTION", "error", "high",
        "Unhandled exception or traceback",
        re.compile(r"(?:Traceback|Exception|Error|FATAL|CRITICAL)\b.*", re.IGNORECASE),
    ),
    LogPattern(
        "ERR_SEGFAULT", "error", "high",
        "Segmentation fault detected",
        re.compile(r"segfault|segmentation fault|SIGSEGV", re.IGNORECASE),
    ),
    LogPattern(
        "ERR_OOM", "error", "high",
        "Out of memory condition",
        re.compile(r"out of memory|OOM|MemoryError|Cannot allocate", re.IGNORECASE),
    ),
    # --- Auth failures ---
    LogPattern(
        "AUTH_FAIL", "auth", "high",
        "Authentication failure",
        re.compile(
            r"(?:authentication|auth|login)\s+(?:failed|failure|denied|invalid|error)",
            re.IGNORECASE,
        ),
    ),
    LogPattern(
        "AUTH_BRUTE", "auth", "high",
        "Possible brute force — repeated failed attempts",
        re.compile(r"(?:too many|multiple|repeated)\s+(?:failed|invalid)\s+(?:attempt|login)", re.IGNORECASE),
    ),
    LogPattern(
        "AUTH_PRIVILEGE", "auth", "high",
        "Privilege escalation attempt",
        re.compile(r"(?:privilege|permission)\s+(?:escalat|denied|unauthorized)", re.IGNORECASE),
    ),
    # --- Suspicious activity ---
    LogPattern(
        "SUSP_INJECTION", "suspicious", "high",
        "Possible injection attack in request",
        re.compile(
            r"(?:SQL\s*injection|<script|UNION\s+SELECT|eval\(|exec\(|os\.system)",
            re.IGNORECASE,
        ),
    ),
    LogPattern(
        "SUSP_PATH_TRAVERSAL", "suspicious", "medium",
        "Path traversal attempt",
        re.compile(r"\.\./\.\.|%2e%2e|directory traversal", re.IGNORECASE),
    ),
    LogPattern(
        "SUSP_UNUSUAL_PORT", "suspicious", "medium",
        "Connection on unusual port",
        re.compile(r"(?:port|connection)\s+(?:4444|5555|6666|31337|1337)\b"),
    ),
    # --- Network ---
    LogPattern(
        "NET_TIMEOUT", "network", "medium",
        "Connection timeout or refused",
        re.compile(r"(?:connection|connect)\s+(?:timed?\s*out|refused|reset)", re.IGNORECASE),
    ),
    LogPattern(
        "NET_SSL_ERROR", "network", "medium",
        "SSL/TLS error",
        re.compile(r"(?:SSL|TLS)\s+(?:error|handshake|certificate|verify)", re.IGNORECASE),
    ),
]


# --- Main entry point ---

def analyze_log(log_path: str) -> Dict[str, Any]:
    """
    Analyze a log file and return a ToolResult.

    Args:
        log_path: path to the log file

    Returns:
        ToolResult envelope with findings
    """
    if not os.path.isfile(log_path):
        return build_error_result(TOOL_NAME, "file_not_found", f"Log file not found: {log_path}")

    try:
        size = os.path.getsize(log_path)
        if size > MAX_LOG_SIZE:
            return build_error_result(
                TOOL_NAME, "file_too_large",
                f"Log file is {size} bytes (max {MAX_LOG_SIZE})",
            )

        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except (OSError, PermissionError) as exc:
        return build_error_result(TOOL_NAME, "read_error", str(exc))

    lines = content.splitlines()

    def local_fn() -> Dict[str, Any]:
        return _local_analyze(lines, log_path)

    def llm_fn(local_result: Dict[str, Any]) -> Dict[str, Any]:
        # LLM root-cause analysis deferred to Sprint 5 orchestrator integration.
        return {"artifacts": {}, "evidence": [], "signals": {}}

    merged = local_first(local_fn, llm_fn)

    return build_tool_result(
        tool_name=TOOL_NAME,
        artifacts=merged["artifacts"],
        evidence=merged["evidence"],
        signals=merged["signals"],
        errors=merged.get("errors"),
    )


def _local_analyze(lines: List[str], log_path: str) -> Dict[str, Any]:
    """Apply log patterns line-by-line, build evidence and signals."""
    matches: List[Tuple[LogPattern, int, str]] = []  # (pattern, line_num, line_text)
    category_counts: Dict[str, int] = {}
    severity_counts: Dict[str, int] = {}

    for line_idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue

        for pattern in LOG_PATTERNS:
            if pattern.regex.search(stripped):
                matches.append((pattern, line_idx + 1, stripped))
                category_counts[pattern.category] = category_counts.get(pattern.category, 0) + 1
                severity_counts[pattern.severity] = severity_counts.get(pattern.severity, 0) + 1
                break  # one pattern per line

    evidence: List[Dict[str, Any]] = []
    for idx, (pattern, line_num, line_text) in enumerate(matches):
        evidence.append(
            build_evidence(
                evidence_id=f"lr-{idx:04d}-{pattern.pattern_id}",
                kind="log",
                file_path=log_path,
                line=line_num,
                snippet=line_text[:200],
                note=f"[{pattern.severity.upper()}] {pattern.pattern_id}: {pattern.description}",
            )
        )

    categories_found = set(category_counts.keys())

    artifacts = {
        "total_findings": len(matches),
        "total_lines_analyzed": len(lines),
        "findings_by_category": category_counts,
        "findings_by_severity": severity_counts,
    }

    signals = {
        "has_errors": "error" in categories_found,
        "has_auth_failures": "auth" in categories_found,
        "has_suspicious_activity": "suspicious" in categories_found,
        "has_network_issues": "network" in categories_found,
        "categories_found": sorted(categories_found),
        "max_severity": _max_severity(severity_counts),
    }

    needs_llm = len(matches) > 0

    return {
        "artifacts": artifacts,
        "evidence": evidence,
        "signals": signals,
        "needs_llm": needs_llm,
    }


_SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1}


def _max_severity(by_severity: Dict[str, int]) -> str:
    if not by_severity:
        return "none"
    return max(by_severity.keys(), key=lambda s: _SEVERITY_ORDER.get(s, 0))

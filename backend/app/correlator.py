"""
Cross-tool finding correlator.

Takes ToolResult outputs from multiple MCP tools and produces a unified
list of correlated findings. Correlation logic:

1. Group evidence by file_path — findings from multiple tools about the
   same file are likely related.
2. Severity bumping — when two or more tools independently flag the same
   file, bump the combined finding's severity (medium → high).
3. Cross-signal correlation — if CodeScan finds hardcoded secrets AND
   ScreenshotAnalyzer detects secret exposure, that's corroborating evidence.
4. Deduplication — evidence items with the same ID are merged, not duplicated.
5. Multimodal payload — each correlated finding carries evidence from all
   contributing tools, preserving the full audit trail.

Security notes:
  - File paths in evidence are kept as-is for traceability but never used
    to serve files directly (that goes through the API's path traversal guards).
  - Severity bumping is capped at "critical" to prevent unbounded escalation.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

SEVERITY_LEVELS = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_NAMES = {v: k for k, v in SEVERITY_LEVELS.items()}


def correlate_findings(tool_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Merge findings from multiple ToolResult outputs into correlated findings.

    Args:
        tool_results: list of ToolResult dicts from MCP tool invocations

    Returns:
        dict with:
          - findings: list of correlated finding dicts
          - summary: aggregated statistics
          - cross_tool_correlations: list of detected cross-tool links
    """
    if not tool_results:
        return _empty_result()

    # Step 1: Extract all evidence items grouped by source file
    file_evidence_map: Dict[str, List[Dict[str, Any]]] = {}
    all_signals: Dict[str, Any] = {}
    tool_names: List[str] = []
    total_evidence = 0

    for tr in tool_results:
        tool_name = tr.get("tool_name", "unknown")
        tool_names.append(tool_name)
        evidence_items = tr.get("evidence", [])
        signals = tr.get("signals", {})

        # Merge signals with tool name prefix for traceability
        for key, val in signals.items():
            prefixed = f"{tool_name}.{key}"
            all_signals[prefixed] = val

        for ev in evidence_items:
            total_evidence += 1
            file_path = ev.get("file_path", "__global__")
            file_evidence_map.setdefault(file_path, []).append(
                {**ev, "_source_tool": tool_name}
            )

    # Step 2: Build correlated findings per file
    findings: List[Dict[str, Any]] = []
    seen_evidence_ids: Set[str] = set()

    for file_path, evidence_list in file_evidence_map.items():
        # Deduplicate evidence by ID
        deduped: List[Dict[str, Any]] = []
        for ev in evidence_list:
            eid = ev.get("id", "")
            if eid and eid in seen_evidence_ids:
                continue
            if eid:
                seen_evidence_ids.add(eid)
            deduped.append(ev)

        if not deduped:
            continue

        # Determine contributing tools
        contributing_tools = sorted({ev["_source_tool"] for ev in deduped})

        # Compute base severity from evidence notes
        base_severity = _compute_base_severity(deduped)

        # Severity bumping: cross-tool corroboration increases severity
        corroborated = len(contributing_tools) > 1
        final_severity = _bump_severity(base_severity) if corroborated else base_severity

        # Extract finding types from evidence
        finding_types = _extract_finding_types(deduped)

        # Clean _source_tool from evidence before output
        clean_evidence = [{k: v for k, v in ev.items() if k != "_source_tool"} for ev in deduped]

        finding = {
            "id": f"finding-{len(findings):04d}",
            "file_path": file_path,
            "severity": final_severity,
            "corroborated": corroborated,
            "contributing_tools": contributing_tools,
            "finding_types": finding_types,
            "evidence_count": len(clean_evidence),
            "evidence": clean_evidence,
        }
        findings.append(finding)

    # Sort findings by severity (critical first)
    findings.sort(key=lambda f: SEVERITY_LEVELS.get(f["severity"], 0), reverse=True)

    # Step 3: Detect cross-tool correlations
    cross_correlations = _detect_cross_correlations(all_signals, tool_names)

    summary = {
        "total_findings": len(findings),
        "total_evidence": total_evidence,
        "tools_invoked": sorted(set(tool_names)),
        "severity_breakdown": _severity_breakdown(findings),
        "corroborated_count": sum(1 for f in findings if f["corroborated"]),
        "cross_tool_correlations": len(cross_correlations),
    }

    return {
        "findings": findings,
        "summary": summary,
        "cross_tool_correlations": cross_correlations,
        "signals": all_signals,
    }


def _empty_result() -> Dict[str, Any]:
    return {
        "findings": [],
        "summary": {
            "total_findings": 0,
            "total_evidence": 0,
            "tools_invoked": [],
            "severity_breakdown": {},
            "corroborated_count": 0,
            "cross_tool_correlations": 0,
        },
        "cross_tool_correlations": [],
        "signals": {},
    }


def _compute_base_severity(evidence_list: List[Dict[str, Any]]) -> str:
    """Determine the highest severity from evidence notes."""
    max_level = 0
    for ev in evidence_list:
        note = ev.get("note", "")
        for sev_name, sev_level in SEVERITY_LEVELS.items():
            if sev_name.upper() in note.upper():
                max_level = max(max_level, sev_level)
    return SEVERITY_NAMES.get(max_level, "info")


def _bump_severity(severity: str) -> str:
    """Increase severity by one level for cross-tool corroboration. Capped at critical."""
    current = SEVERITY_LEVELS.get(severity, 0)
    bumped = min(current + 1, SEVERITY_LEVELS["critical"])
    return SEVERITY_NAMES.get(bumped, "critical")


def _extract_finding_types(evidence_list: List[Dict[str, Any]]) -> List[str]:
    """Extract unique finding type keywords from evidence notes."""
    types: Set[str] = set()
    type_keywords = {
        "hardcoded_secret", "sql_injection", "weak_cryptography",
        "secret_exposure", "error_exposure", "pii_exposure",
        "auth", "suspicious", "network",
    }
    for ev in evidence_list:
        note = ev.get("note", "").lower()
        eid = ev.get("id", "").lower()
        for keyword in type_keywords:
            if keyword in note or keyword in eid:
                types.add(keyword)
    return sorted(types)


def _severity_breakdown(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count findings per severity level."""
    breakdown: Dict[str, int] = {}
    for f in findings:
        sev = f["severity"]
        breakdown[sev] = breakdown.get(sev, 0) + 1
    return breakdown


# --- Cross-tool correlation rules ---

# Each rule: (signal_a, signal_b, correlation_description)
_CORRELATION_RULES: List[Tuple[str, str, str]] = [
    (
        "CodeScan.has_secrets",
        "ScreenshotAnalyzer.has_secret_exposure",
        "Hardcoded secrets in code AND secrets visible in screenshots — "
        "likely exposed credentials requiring immediate rotation",
    ),
    (
        "CodeScan.has_sqli",
        "LogReasoner.has_suspicious_activity",
        "SQL injection vectors in code AND suspicious activity in logs — "
        "possible active exploitation",
    ),
    (
        "LogReasoner.has_auth_failures",
        "LogReasoner.has_suspicious_activity",
        "Authentication failures combined with suspicious activity — "
        "possible brute force or credential stuffing attack",
    ),
    (
        "CodeScan.has_secrets",
        "LogReasoner.has_auth_failures",
        "Hardcoded credentials in code AND auth failures in logs — "
        "leaked credentials may be under active attack",
    ),
    (
        "DiagramExtractor.has_components",
        "CodeScan.has_sqli",
        "Architecture components identified AND SQL injection in code — "
        "attack surface mapped with exploitable entry points",
    ),
]


def _detect_cross_correlations(
    signals: Dict[str, Any],
    tool_names: List[str],
) -> List[Dict[str, Any]]:
    """Check cross-tool signal pairs for known correlation patterns."""
    correlations: List[Dict[str, Any]] = []

    for signal_a, signal_b, description in _CORRELATION_RULES:
        val_a = signals.get(signal_a)
        val_b = signals.get(signal_b)

        if val_a and val_b:
            correlations.append(
                {
                    "signals": [signal_a, signal_b],
                    "description": description,
                    "severity_impact": "elevated",
                }
            )

    return correlations

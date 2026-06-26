"""
Converts raw rule matches into structured Evidence items and aggregated artifacts.

Takes a list of (rule, match) pairs from the scanner and produces:
  - evidence: list of build_evidence() dicts (one per match)
  - artifacts: summary dict with finding counts, severity breakdown, file list
  - signals: correlation hints (has_secrets, has_sqli, has_weak_crypto, finding_types)
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from backend.mcps.common.types import build_evidence
from backend.mcps.codescan.rules import VulnerabilityRule


def extract_evidence(
    matches: List[Tuple[VulnerabilityRule, Dict[str, Any], str]],
) -> Dict[str, Any]:
    """
    Build evidence, artifacts, and signals from scanner matches.

    Args:
        matches: list of (rule, match_dict, file_path) tuples

    Returns:
        dict with keys: evidence, artifacts, signals, needs_llm
    """
    evidence: List[Dict[str, Any]] = []
    findings_by_type: Dict[str, int] = {}
    findings_by_severity: Dict[str, int] = {}
    affected_files: set[str] = set()

    for idx, (rule, match, file_path) in enumerate(matches):
        eid = f"cs-{idx:04d}-{rule.rule_id}"

        evidence.append(
            build_evidence(
                evidence_id=eid,
                kind="code",
                file_path=file_path,
                line=match["line_number"],
                snippet=match["snippet"],
                note=f"[{rule.severity.upper()}] {rule.rule_id}: {match['message']}",
            )
        )

        findings_by_type[rule.vulnerability_type] = (
            findings_by_type.get(rule.vulnerability_type, 0) + 1
        )
        findings_by_severity[rule.severity] = (
            findings_by_severity.get(rule.severity, 0) + 1
        )
        affected_files.add(file_path)

    finding_types = set(findings_by_type.keys())

    artifacts = {
        "total_findings": len(matches),
        "findings_by_type": findings_by_type,
        "findings_by_severity": findings_by_severity,
        "affected_files": sorted(affected_files),
    }

    signals = {
        "has_secrets": "hardcoded_secret" in finding_types,
        "has_sqli": "sql_injection" in finding_types,
        "has_weak_crypto": "weak_cryptography" in finding_types,
        "finding_types": sorted(finding_types),
        "max_severity": _max_severity(findings_by_severity),
    }

    # Request LLM augmentation only when there are findings worth analyzing
    needs_llm = len(matches) > 0

    return {
        "artifacts": artifacts,
        "evidence": evidence,
        "signals": signals,
        "needs_llm": needs_llm,
    }


_SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1}


def _max_severity(by_severity: Dict[str, int]) -> str:
    """Return the highest severity present, or 'none'."""
    if not by_severity:
        return "none"
    return max(by_severity.keys(), key=lambda s: _SEVERITY_ORDER.get(s, 0))

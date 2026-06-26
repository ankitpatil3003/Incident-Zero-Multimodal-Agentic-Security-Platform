"""
Patcher MCP tool — generates fix suggestions and unified diffs
from vulnerability findings produced by other MCP tools.

Uses template-based patch generation: each vulnerability type has a
known remediation pattern that produces a concrete code fix.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from backend.mcps.common.types import build_tool_result, build_error_result, build_evidence

logger = logging.getLogger(__name__)

TOOL_NAME = "Patcher"


# --- Patch templates ---
# Maps vulnerability_type → remediation function

def _fix_hardcoded_secret(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a fix that replaces hardcoded secrets with env var lookups."""
    snippet = finding.get("snippet", "")
    file_path = finding.get("file_path", "unknown")

    # Extract the variable name from the snippet
    var_name = "SECRET"
    for part in snippet.split("=")[0].split():
        clean = part.strip().rstrip(":").upper()
        if clean:
            var_name = clean
            break

    env_var = var_name.upper().replace(" ", "_")

    original = snippet.strip()
    fixed = f'{var_name.lower()} = os.environ.get("{env_var}")'

    return {
        "patch_id": f"patch-{finding.get('evidence_id', 'unknown')}",
        "file_path": file_path,
        "vulnerability_type": "hardcoded_secret",
        "description": f"Replace hardcoded secret with environment variable `{env_var}`",
        "original": original,
        "fixed": fixed,
        "diff": _make_unified_diff(file_path, original, fixed),
        "confidence": 0.85,
        "requires_review": True,
    }


def _fix_sql_injection(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a fix suggesting parameterized queries."""
    snippet = finding.get("snippet", "")
    file_path = finding.get("file_path", "unknown")

    return {
        "patch_id": f"patch-{finding.get('evidence_id', 'unknown')}",
        "file_path": file_path,
        "vulnerability_type": "sql_injection",
        "description": "Use parameterized queries instead of string interpolation",
        "original": snippet.strip(),
        "fixed": "# TODO: Replace with parameterized query\n"
                 "# cursor.execute(\"SELECT * FROM table WHERE col = %s\", (value,))",
        "diff": _make_unified_diff(
            file_path,
            snippet.strip(),
            "# TODO: Replace with parameterized query\n"
            "# cursor.execute(\"SELECT * FROM table WHERE col = %s\", (value,))",
        ),
        "confidence": 0.80,
        "requires_review": True,
    }


def _fix_weak_crypto(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a fix replacing weak hashes with SHA-256."""
    snippet = finding.get("snippet", "")
    file_path = finding.get("file_path", "unknown")

    fixed = snippet
    if "md5" in snippet.lower():
        fixed = snippet.replace("md5", "sha256").replace("MD5", "SHA256")
    elif "sha1" in snippet.lower():
        fixed = snippet.replace("sha1", "sha256").replace("SHA1", "SHA256")

    return {
        "patch_id": f"patch-{finding.get('evidence_id', 'unknown')}",
        "file_path": file_path,
        "vulnerability_type": "weak_cryptography",
        "description": "Replace weak hash (MD5/SHA-1) with SHA-256",
        "original": snippet.strip(),
        "fixed": fixed.strip(),
        "diff": _make_unified_diff(file_path, snippet.strip(), fixed.strip()),
        "confidence": 0.90,
        "requires_review": False,
    }


# Registry of fix generators
_FIX_GENERATORS = {
    "hardcoded_secret": _fix_hardcoded_secret,
    "sql_injection": _fix_sql_injection,
    "weak_cryptography": _fix_weak_crypto,
}


# --- Main entry point ---

def generate_patches(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate patches from a list of findings (evidence items from other tools).

    Each finding dict should have:
      - evidence_id: str
      - file_path: str
      - snippet: str
      - note: str (contains vulnerability type info)

    Args:
        findings: list of evidence dicts from CodeScan or other tools

    Returns:
        ToolResult envelope with generated patches
    """
    if not findings:
        return build_tool_result(
            tool_name=TOOL_NAME,
            artifacts={"total_patches": 0, "patches": []},
            evidence=[],
            signals={"has_patches": False, "patch_count": 0},
        )

    patches: List[Dict[str, Any]] = []
    evidence: List[Dict[str, Any]] = []
    types_patched: set[str] = set()
    skipped = 0

    for finding in findings:
        vuln_type = _infer_vulnerability_type(finding)
        generator = _FIX_GENERATORS.get(vuln_type)

        if generator is None:
            skipped += 1
            continue

        try:
            patch = generator(finding)
            patches.append(patch)
            types_patched.add(vuln_type)

            evidence.append(
                build_evidence(
                    evidence_id=patch["patch_id"],
                    kind="code",
                    file_path=patch["file_path"],
                    snippet=patch["diff"][:200],
                    note=f"Patch generated: {patch['description']}",
                )
            )
        except Exception as exc:
            logger.warning("Failed to generate patch for %s: %s", finding.get("evidence_id"), exc)
            skipped += 1

    artifacts = {
        "total_patches": len(patches),
        "patches": patches,
        "types_patched": sorted(types_patched),
        "skipped": skipped,
    }

    signals = {
        "has_patches": len(patches) > 0,
        "patch_count": len(patches),
        "types_patched": sorted(types_patched),
        "all_auto_fixable": all(not p["requires_review"] for p in patches),
    }

    return build_tool_result(
        tool_name=TOOL_NAME,
        artifacts=artifacts,
        evidence=evidence,
        signals=signals,
    )


def _infer_vulnerability_type(finding: Dict[str, Any]) -> str:
    """Infer the vulnerability type from the finding's note or evidence_id."""
    note = finding.get("note", "").lower()
    eid = finding.get("evidence_id", "").lower()

    if "secret" in note or "secret" in eid:
        return "hardcoded_secret"
    if "sql" in note or "sqli" in eid:
        return "sql_injection"
    if "crypto" in note or "md5" in note or "sha1" in note or "crypto" in eid:
        return "weak_cryptography"

    return "unknown"


def _make_unified_diff(file_path: str, original: str, fixed: str) -> str:
    """Generate a minimal unified diff string."""
    lines = [
        f"--- a/{file_path}",
        f"+++ b/{file_path}",
        "@@ -1 +1 @@",
    ]
    for line in original.splitlines():
        lines.append(f"-{line}")
    for line in fixed.splitlines():
        lines.append(f"+{line}")
    return "\n".join(lines)

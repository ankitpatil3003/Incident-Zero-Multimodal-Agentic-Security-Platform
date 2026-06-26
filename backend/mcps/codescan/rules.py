"""
Regex-based vulnerability detection rules for CodeScan MCP.

Each rule defines:
  - rule_id: unique identifier
  - vulnerability_type: category (hardcoded_secret, sql_injection, weak_cryptography)
  - severity: high | medium | low
  - confidence: base confidence score (0.0–1.0)
  - description: what the rule detects
  - patterns: list of compiled regex patterns
  - file_filter: optional file extension filter (None = all scannable files)
  - check(): applies patterns to file content, returns list of matches
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Pattern


@dataclass
class VulnerabilityRule:
    rule_id: str
    vulnerability_type: str
    severity: str
    confidence: float
    description: str
    patterns: List[Pattern[str]]
    file_filter: Optional[List[str]] = None

    def check(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """
        Apply rule patterns against file content.
        Returns list of match dicts with line_number, snippet, message, confidence.
        """
        if self.file_filter:
            if not any(file_path.endswith(ext) for ext in self.file_filter):
                return []

        matches: List[Dict[str, Any]] = []
        lines = content.splitlines()

        for line_idx, line in enumerate(lines):
            for pattern in self.patterns:
                match = pattern.search(line)
                if match is None:
                    continue

                # Skip comments
                stripped = line.lstrip()
                if stripped.startswith("#") or stripped.startswith("//"):
                    continue

                matches.append(
                    {
                        "line_number": line_idx + 1,
                        "snippet": line.rstrip()[:200],
                        "message": self.description,
                        "confidence": self.confidence,
                        "pattern_used": pattern.pattern,
                    }
                )
                break  # one match per line per rule is enough

        return matches


# --- Rule definitions ---

VULNERABILITY_RULES: List[VulnerabilityRule] = [
    # --- Hardcoded secrets ---
    VulnerabilityRule(
        rule_id="SECRET_ASSIGNMENT",
        vulnerability_type="hardcoded_secret",
        severity="high",
        confidence=0.85,
        description="Hardcoded secret or API key assigned to a variable",
        patterns=[
            re.compile(
                r"""(?:password|passwd|secret|api_?key|token|auth)\s*=\s*['"][^'"]{8,}['"]""",
                re.IGNORECASE,
            ),
        ],
    ),
    VulnerabilityRule(
        rule_id="SECRET_AWS_KEY",
        vulnerability_type="hardcoded_secret",
        severity="high",
        confidence=0.95,
        description="AWS access key ID found in source code",
        patterns=[
            re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        ],
    ),
    VulnerabilityRule(
        rule_id="SECRET_GITHUB_TOKEN",
        vulnerability_type="hardcoded_secret",
        severity="high",
        confidence=0.95,
        description="GitHub personal access token found in source code",
        patterns=[
            re.compile(r"\bghp_[A-Za-z0-9]{36,}\b"),
        ],
    ),
    VulnerabilityRule(
        rule_id="SECRET_STRIPE_KEY",
        vulnerability_type="hardcoded_secret",
        severity="high",
        confidence=0.95,
        description="Stripe secret key found in source code",
        patterns=[
            re.compile(r"\b(?:sk_live|sk_test)_[A-Za-z0-9]{20,}\b"),
        ],
    ),
    VulnerabilityRule(
        rule_id="SECRET_GENERIC_KEY",
        vulnerability_type="hardcoded_secret",
        severity="medium",
        confidence=0.70,
        description="Generic API key pattern found in source code",
        patterns=[
            re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
        ],
    ),
    # --- SQL injection ---
    VulnerabilityRule(
        rule_id="SQLI_PYTHON_FSTRING",
        vulnerability_type="sql_injection",
        severity="high",
        confidence=0.85,
        description="SQL query built with f-string interpolation (Python)",
        patterns=[
            re.compile(
                r"""f['"].*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*\{""",
                re.IGNORECASE,
            ),
        ],
        file_filter=[".py"],
    ),
    VulnerabilityRule(
        rule_id="SQLI_PYTHON_FORMAT",
        vulnerability_type="sql_injection",
        severity="high",
        confidence=0.80,
        description="SQL query built with .format() or % string formatting",
        patterns=[
            re.compile(
                r"""['"].*(?:SELECT|INSERT|UPDATE|DELETE)\b.*['"].*\.format\(""",
                re.IGNORECASE,
            ),
            re.compile(
                r"""['"].*(?:SELECT|INSERT|UPDATE|DELETE)\b.*%s""",
                re.IGNORECASE,
            ),
        ],
        file_filter=[".py"],
    ),
    VulnerabilityRule(
        rule_id="SQLI_JS_TEMPLATE",
        vulnerability_type="sql_injection",
        severity="high",
        confidence=0.85,
        description="SQL query built with template literal interpolation (JS/TS)",
        patterns=[
            re.compile(
                r"""`.*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*\$\{""",
                re.IGNORECASE,
            ),
        ],
        file_filter=[".js", ".jsx", ".ts", ".tsx"],
    ),
    VulnerabilityRule(
        rule_id="SQLI_STRING_CONCAT",
        vulnerability_type="sql_injection",
        severity="medium",
        confidence=0.65,
        description="SQL query built with string concatenation",
        patterns=[
            re.compile(
                r"""['"].*(?:SELECT|INSERT|UPDATE|DELETE)\b.*['"]\s*\+""",
                re.IGNORECASE,
            ),
        ],
    ),
    # --- Weak cryptography ---
    VulnerabilityRule(
        rule_id="CRYPTO_MD5",
        vulnerability_type="weak_cryptography",
        severity="medium",
        confidence=0.75,
        description="MD5 hash usage detected — cryptographically broken for security",
        patterns=[
            re.compile(r"""(?:hashlib\.md5|MD5|md5\()"""),
        ],
    ),
    VulnerabilityRule(
        rule_id="CRYPTO_SHA1",
        vulnerability_type="weak_cryptography",
        severity="medium",
        confidence=0.70,
        description="SHA-1 hash usage detected — deprecated for security purposes",
        patterns=[
            re.compile(r"""(?:hashlib\.sha1|SHA1|sha1\()"""),
        ],
    ),
]

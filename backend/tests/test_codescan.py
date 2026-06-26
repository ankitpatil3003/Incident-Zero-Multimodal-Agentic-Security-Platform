"""
Tests for CodeScan MCP tool — rules engine, evidence extractor, and scanner.
"""

import os
from pathlib import Path

import pytest

from backend.mcps.codescan.rules import VulnerabilityRule, VULNERABILITY_RULES
from backend.mcps.codescan.evidence_extractor import extract_evidence, _max_severity
from backend.mcps.codescan.scanner import scan_repo, TOOL_NAME

FIXTURES_DIR = str(Path(__file__).resolve().parent.parent.parent / "fixtures" / "vulnerable_repo")


# --- VulnerabilityRule.check() tests ---


class TestRuleCheck:
    def test_detects_hardcoded_password(self):
        content = 'password = "SuperSecretPassword123!"'
        rule = _find_rule("SECRET_ASSIGNMENT")
        matches = rule.check(content, "app.py")
        assert len(matches) == 1
        assert matches[0]["line_number"] == 1

    def test_detects_aws_key(self):
        content = "key = AKIAIOSFODNN7EXAMPLE"
        rule = _find_rule("SECRET_AWS_KEY")
        matches = rule.check(content, "config.py")
        assert len(matches) == 1

    def test_detects_github_token(self):
        content = 'token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234"'
        rule = _find_rule("SECRET_GITHUB_TOKEN")
        matches = rule.check(content, "ci.py")
        assert len(matches) == 1

    def test_detects_sqli_fstring(self):
        content = 'query = f"SELECT * FROM users WHERE id = {user_id}"'
        rule = _find_rule("SQLI_PYTHON_FSTRING")
        matches = rule.check(content, "db.py")
        assert len(matches) == 1

    def test_detects_sqli_js_template(self):
        content = "const q = `SELECT * FROM users WHERE id = ${userId}`;"
        rule = _find_rule("SQLI_JS_TEMPLATE")
        matches = rule.check(content, "db.js")
        assert len(matches) == 1

    def test_file_filter_skips_wrong_extension(self):
        content = 'query = f"SELECT * FROM users WHERE id = {user_id}"'
        rule = _find_rule("SQLI_PYTHON_FSTRING")
        # Rule has file_filter=[".py"], so .js should be skipped
        matches = rule.check(content, "file.js")
        assert len(matches) == 0

    def test_detects_md5(self):
        content = "digest = hashlib.md5(data).hexdigest()"
        rule = _find_rule("CRYPTO_MD5")
        matches = rule.check(content, "hash.py")
        assert len(matches) == 1

    def test_skips_comments(self):
        content = '# password = "not_a_real_secret_12345"'
        rule = _find_rule("SECRET_ASSIGNMENT")
        matches = rule.check(content, "app.py")
        assert len(matches) == 0

    def test_no_match_on_clean_code(self):
        content = "x = 42\nreturn x + 1"
        for rule in VULNERABILITY_RULES:
            matches = rule.check(content, "clean.py")
            assert len(matches) == 0, f"Rule {rule.rule_id} false-positive on clean code"


# --- Evidence extractor tests ---


class TestEvidenceExtractor:
    def test_empty_matches(self):
        result = extract_evidence([])
        assert result["artifacts"]["total_findings"] == 0
        assert result["evidence"] == []
        assert result["signals"]["has_secrets"] is False
        assert result["needs_llm"] is False

    def test_builds_evidence_from_matches(self):
        rule = _find_rule("SECRET_ASSIGNMENT")
        match = {
            "line_number": 5,
            "snippet": 'password = "secret123456789"',
            "message": rule.description,
            "confidence": rule.confidence,
            "pattern_used": "test",
        }
        result = extract_evidence([(rule, match, "app.py")])
        assert result["artifacts"]["total_findings"] == 1
        assert len(result["evidence"]) == 1
        assert result["evidence"][0]["kind"] == "code"
        assert result["signals"]["has_secrets"] is True
        assert result["needs_llm"] is True

    def test_severity_aggregation(self):
        rules_and_matches = []
        for rule_id in ("SECRET_ASSIGNMENT", "CRYPTO_MD5"):
            rule = _find_rule(rule_id)
            match = {
                "line_number": 1,
                "snippet": "test",
                "message": rule.description,
                "confidence": rule.confidence,
                "pattern_used": "test",
            }
            rules_and_matches.append((rule, match, "app.py"))

        result = extract_evidence(rules_and_matches)
        assert result["signals"]["max_severity"] == "high"
        assert "hardcoded_secret" in result["signals"]["finding_types"]
        assert "weak_cryptography" in result["signals"]["finding_types"]


class TestMaxSeverity:
    def test_high_wins(self):
        assert _max_severity({"high": 1, "medium": 2}) == "high"

    def test_empty_returns_none(self):
        assert _max_severity({}) == "none"

    def test_medium_only(self):
        assert _max_severity({"medium": 3}) == "medium"


# --- Full scanner tests ---


class TestScanRepo:
    def test_scan_fixture_repo_finds_vulnerabilities(self):
        result = scan_repo(FIXTURES_DIR)
        assert result["tool_name"] == TOOL_NAME
        assert result["artifacts"]["total_findings"] > 0
        assert result["artifacts"]["files_scanned"] >= 2
        assert len(result["evidence"]) > 0

    def test_scan_finds_secrets(self):
        result = scan_repo(FIXTURES_DIR)
        assert result["signals"]["has_secrets"] is True

    def test_scan_finds_sqli(self):
        result = scan_repo(FIXTURES_DIR)
        assert result["signals"]["has_sqli"] is True

    def test_scan_finds_weak_crypto(self):
        result = scan_repo(FIXTURES_DIR)
        assert result["signals"]["has_weak_crypto"] is True

    def test_scan_nonexistent_dir(self):
        result = scan_repo("/nonexistent/path")
        assert result["errors"] is not None
        assert any("repo_not_found" in e["error"] for e in result["errors"])

    def test_scan_empty_dir(self, tmp_path):
        result = scan_repo(str(tmp_path))
        assert result["artifacts"]["total_findings"] == 0
        assert result["evidence"] == []

    def test_affected_files_listed(self):
        result = scan_repo(FIXTURES_DIR)
        affected = result["artifacts"]["affected_files"]
        assert any("app.py" in f for f in affected)


# --- Helper ---

def _find_rule(rule_id: str) -> VulnerabilityRule:
    for rule in VULNERABILITY_RULES:
        if rule.rule_id == rule_id:
            return rule
    raise ValueError(f"Rule {rule_id} not found")

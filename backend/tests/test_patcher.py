"""
Tests for Patcher MCP tool — template-based patch generation.
"""

import pytest

from backend.mcps.patcher.generator import (
    generate_patches,
    _infer_vulnerability_type,
    _make_unified_diff,
    TOOL_NAME,
)


class TestInferVulnerabilityType:
    def test_secret_from_note(self):
        assert _infer_vulnerability_type({"note": "[HIGH] SECRET_ASSIGNMENT: Hardcoded secret"}) == "hardcoded_secret"

    def test_sqli_from_note(self):
        assert _infer_vulnerability_type({"note": "SQL injection via f-string"}) == "sql_injection"

    def test_crypto_from_note(self):
        assert _infer_vulnerability_type({"note": "weak cryptography MD5"}) == "weak_cryptography"

    def test_crypto_from_evidence_id(self):
        assert _infer_vulnerability_type({"evidence_id": "cs-0001-CRYPTO_MD5", "note": ""}) == "weak_cryptography"

    def test_unknown(self):
        assert _infer_vulnerability_type({"note": "something else", "evidence_id": "x"}) == "unknown"


class TestMakeUnifiedDiff:
    def test_basic_diff(self):
        diff = _make_unified_diff("app.py", "old line", "new line")
        assert "--- a/app.py" in diff
        assert "+++ b/app.py" in diff
        assert "-old line" in diff
        assert "+new line" in diff

    def test_multiline_diff(self):
        diff = _make_unified_diff("f.py", "line1\nline2", "fix1\nfix2")
        assert "-line1" in diff
        assert "+fix1" in diff


class TestGeneratePatches:
    def test_empty_findings(self):
        result = generate_patches([])
        assert result["tool_name"] == TOOL_NAME
        assert result["artifacts"]["total_patches"] == 0
        assert result["signals"]["has_patches"] is False

    def test_patches_hardcoded_secret(self):
        findings = [
            {
                "evidence_id": "cs-0001-SECRET_ASSIGNMENT",
                "file_path": "app.py",
                "snippet": 'password = "SuperSecret123!"',
                "note": "[HIGH] SECRET_ASSIGNMENT: Hardcoded secret",
            }
        ]
        result = generate_patches(findings)
        assert result["artifacts"]["total_patches"] == 1
        patch = result["artifacts"]["patches"][0]
        assert patch["vulnerability_type"] == "hardcoded_secret"
        assert "os.environ" in patch["fixed"]
        assert patch["requires_review"] is True

    def test_patches_sql_injection(self):
        findings = [
            {
                "evidence_id": "cs-0002-SQLI_PYTHON_FSTRING",
                "file_path": "db.py",
                "snippet": 'f"SELECT * FROM users WHERE id = {user_id}"',
                "note": "[HIGH] SQLI: SQL injection via f-string",
            }
        ]
        result = generate_patches(findings)
        assert result["artifacts"]["total_patches"] == 1
        patch = result["artifacts"]["patches"][0]
        assert patch["vulnerability_type"] == "sql_injection"
        assert "parameterized" in patch["description"]

    def test_patches_weak_crypto(self):
        findings = [
            {
                "evidence_id": "cs-0003-CRYPTO_MD5",
                "file_path": "hash.py",
                "snippet": "hashlib.md5(data).hexdigest()",
                "note": "[MEDIUM] CRYPTO_MD5: weak cryptography",
            }
        ]
        result = generate_patches(findings)
        assert result["artifacts"]["total_patches"] == 1
        patch = result["artifacts"]["patches"][0]
        assert "sha256" in patch["fixed"]
        assert patch["requires_review"] is False

    def test_skips_unknown_types(self):
        findings = [
            {
                "evidence_id": "unknown-001",
                "file_path": "x.py",
                "snippet": "something",
                "note": "unrecognized issue",
            }
        ]
        result = generate_patches(findings)
        assert result["artifacts"]["total_patches"] == 0
        assert result["artifacts"]["skipped"] == 1

    def test_multiple_findings(self):
        findings = [
            {
                "evidence_id": "cs-0001-SECRET_ASSIGNMENT",
                "file_path": "app.py",
                "snippet": 'password = "SuperSecret123!"',
                "note": "[HIGH] SECRET_ASSIGNMENT: Hardcoded secret",
            },
            {
                "evidence_id": "cs-0003-CRYPTO_MD5",
                "file_path": "hash.py",
                "snippet": "hashlib.md5(data).hexdigest()",
                "note": "[MEDIUM] CRYPTO_MD5: weak cryptography",
            },
        ]
        result = generate_patches(findings)
        assert result["artifacts"]["total_patches"] == 2
        assert "hardcoded_secret" in result["signals"]["types_patched"]
        assert "weak_cryptography" in result["signals"]["types_patched"]

    def test_evidence_created_for_patches(self):
        findings = [
            {
                "evidence_id": "cs-0001-SECRET_ASSIGNMENT",
                "file_path": "app.py",
                "snippet": 'token = "sk-abc12345678901234567"',
                "note": "[HIGH] SECRET: Hardcoded secret",
            }
        ]
        result = generate_patches(findings)
        assert len(result["evidence"]) == 1
        assert result["evidence"][0]["kind"] == "code"


class TestToolRegistration:
    def test_register_all_tools(self):
        from backend.mcps.register_tools import register_all_tools
        from backend.app.registry import ToolRegistry

        reg = ToolRegistry()
        # Monkey-patch the singleton temporarily
        import backend.mcps.register_tools as rt
        original = rt.tool_registry
        rt.tool_registry = reg
        try:
            register_all_tools()
            names = [t.name for t in reg.list_tools()]
            assert "CodeScan" in names
            assert "LogReasoner" in names
            assert "ScreenshotAnalyzer" in names
            assert "DiagramExtractor" in names
            assert "Patcher" in names
            assert len(names) == 5
        finally:
            rt.tool_registry = original

    def test_function_call_schema_export(self):
        from backend.mcps.register_tools import register_all_tools
        from backend.app.registry import ToolRegistry

        reg = ToolRegistry()
        import backend.mcps.register_tools as rt
        original = rt.tool_registry
        rt.tool_registry = reg
        try:
            register_all_tools()
            schemas = reg.to_function_call_schema()
            assert len(schemas) == 5
            for s in schemas:
                assert s["type"] == "function"
                assert "name" in s["function"]
                assert "parameters" in s["function"]
        finally:
            rt.tool_registry = original

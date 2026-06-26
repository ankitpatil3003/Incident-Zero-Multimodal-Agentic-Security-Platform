"""
Tests for LogReasoner MCP tool — pattern matching and analysis.
"""

from pathlib import Path

import pytest

from backend.mcps.log_reasoner.run import (
    analyze_log,
    LogPattern,
    LOG_PATTERNS,
    TOOL_NAME,
    _local_analyze,
    _max_severity,
)

FIXTURE_LOG = str(Path(__file__).resolve().parent.parent.parent / "fixtures" / "sample.log")


# --- LogPattern tests ---


class TestLogPatterns:
    def test_detects_traceback(self):
        line = "ERROR Traceback (most recent call last): ValueError"
        pattern = _find_pattern("ERR_EXCEPTION")
        assert pattern.regex.search(line)

    def test_detects_auth_failure(self):
        line = "authentication failed for user admin"
        pattern = _find_pattern("AUTH_FAIL")
        assert pattern.regex.search(line)

    def test_detects_brute_force(self):
        line = "too many failed login attempts from 192.168.1.50"
        pattern = _find_pattern("AUTH_BRUTE")
        assert pattern.regex.search(line)

    def test_detects_sqli_in_log(self):
        line = "SQL injection attempt detected"
        pattern = _find_pattern("SUSP_INJECTION")
        assert pattern.regex.search(line)

    def test_detects_path_traversal(self):
        line = "../../etc/passwd"
        pattern = _find_pattern("SUSP_PATH_TRAVERSAL")
        assert pattern.regex.search(line)

    def test_detects_oom(self):
        line = "MemoryError: Cannot allocate 2GB buffer"
        pattern = _find_pattern("ERR_OOM")
        assert pattern.regex.search(line)

    def test_detects_ssl_error(self):
        line = "SSL certificate verify error for api.example.com"
        pattern = _find_pattern("NET_SSL_ERROR")
        assert pattern.regex.search(line)

    def test_no_match_on_clean_line(self):
        line = "INFO  Request completed in 250ms"
        for pattern in LOG_PATTERNS:
            assert not pattern.regex.search(line), (
                f"Pattern {pattern.pattern_id} false-positive on clean log line"
            )


# --- Local analysis tests ---


class TestLocalAnalyze:
    def test_fixture_log_finds_multiple_categories(self):
        lines = Path(FIXTURE_LOG).read_text().splitlines()
        result = _local_analyze(lines, FIXTURE_LOG)
        cats = result["signals"]["categories_found"]
        assert "error" in cats
        assert "auth" in cats
        assert "suspicious" in cats

    def test_evidence_has_correct_kind(self):
        lines = Path(FIXTURE_LOG).read_text().splitlines()
        result = _local_analyze(lines, FIXTURE_LOG)
        for ev in result["evidence"]:
            assert ev["kind"] == "log"

    def test_empty_log(self):
        result = _local_analyze([], "empty.log")
        assert result["artifacts"]["total_findings"] == 0
        assert result["needs_llm"] is False


# --- Full analyzer tests ---


class TestAnalyzeLog:
    def test_fixture_log_returns_tool_result(self):
        result = analyze_log(FIXTURE_LOG)
        assert result["tool_name"] == TOOL_NAME
        assert result["artifacts"]["total_findings"] > 0
        assert len(result["evidence"]) > 0

    def test_signals_populated(self):
        result = analyze_log(FIXTURE_LOG)
        assert result["signals"]["has_errors"] is True
        assert result["signals"]["has_auth_failures"] is True
        assert result["signals"]["has_suspicious_activity"] is True
        assert result["signals"]["max_severity"] == "high"

    def test_nonexistent_file(self):
        result = analyze_log("/nonexistent/log.txt")
        assert result["errors"] is not None
        assert any("file_not_found" in e["error"] for e in result["errors"])

    def test_empty_file(self, tmp_path):
        empty = tmp_path / "empty.log"
        empty.write_text("")
        result = analyze_log(str(empty))
        assert result["artifacts"]["total_findings"] == 0
        assert result["evidence"] == []

    def test_total_lines_counted(self):
        result = analyze_log(FIXTURE_LOG)
        assert result["artifacts"]["total_lines_analyzed"] == 14


class TestMaxSeverityLog:
    def test_high_wins(self):
        assert _max_severity({"high": 1, "medium": 2}) == "high"

    def test_empty_returns_none(self):
        assert _max_severity({}) == "none"


# --- Helper ---

def _find_pattern(pattern_id: str) -> LogPattern:
    for p in LOG_PATTERNS:
        if p.pattern_id == pattern_id:
            return p
    raise ValueError(f"Pattern {pattern_id} not found")

"""
Tests for the cross-tool correlator.
"""

from backend.app.correlator import (
    correlate_findings,
    _compute_base_severity,
    _bump_severity,
    _extract_finding_types,
    _detect_cross_correlations,
    _severity_breakdown,
)
from backend.mcps.common.types import build_tool_result, build_evidence


class TestCorrelateFindings:
    def test_empty_input(self):
        result = correlate_findings([])
        assert result["findings"] == []
        assert result["summary"]["total_findings"] == 0

    def test_single_tool_single_file(self):
        tr = build_tool_result(
            "CodeScan",
            {"total_findings": 1},
            [build_evidence("e1", "code", file_path="app.py", note="[HIGH] SECRET")],
            {"has_secrets": True},
        )
        result = correlate_findings([tr])
        assert result["summary"]["total_findings"] == 1
        assert result["findings"][0]["file_path"] == "app.py"
        assert result["findings"][0]["corroborated"] is False

    def test_cross_tool_corroboration(self):
        tr1 = build_tool_result(
            "CodeScan",
            {},
            [build_evidence("e1", "code", file_path="app.py", note="[HIGH] SECRET")],
            {"has_secrets": True},
        )
        tr2 = build_tool_result(
            "ScreenshotAnalyzer",
            {},
            [build_evidence("e2", "screenshot", file_path="app.py", note="[HIGH] SECRET visible")],
            {"has_secret_exposure": True},
        )
        result = correlate_findings([tr1, tr2])
        # Both tools flagged app.py → should be corroborated
        app_finding = next(f for f in result["findings"] if f["file_path"] == "app.py")
        assert app_finding["corroborated"] is True
        assert len(app_finding["contributing_tools"]) == 2
        assert app_finding["evidence_count"] == 2

    def test_severity_bumping_on_corroboration(self):
        tr1 = build_tool_result(
            "CodeScan",
            {},
            [build_evidence("e1", "code", file_path="app.py", note="[MEDIUM] CRYPTO_MD5")],
            {},
        )
        tr2 = build_tool_result(
            "LogReasoner",
            {},
            [build_evidence("e2", "log", file_path="app.py", note="[MEDIUM] error")],
            {},
        )
        result = correlate_findings([tr1, tr2])
        app_finding = next(f for f in result["findings"] if f["file_path"] == "app.py")
        # Medium + corroboration → should bump to high
        assert app_finding["severity"] == "high"

    def test_deduplication_by_evidence_id(self):
        ev = build_evidence("e1", "code", file_path="app.py", note="[HIGH] SECRET")
        tr1 = build_tool_result("CodeScan", {}, [ev], {})
        tr2 = build_tool_result("CodeScan", {}, [ev], {})  # same evidence
        result = correlate_findings([tr1, tr2])
        app_finding = next(f for f in result["findings"] if f["file_path"] == "app.py")
        # e1 should appear only once
        assert app_finding["evidence_count"] == 1

    def test_multiple_files_separate_findings(self):
        tr = build_tool_result(
            "CodeScan",
            {},
            [
                build_evidence("e1", "code", file_path="app.py", note="[HIGH] SECRET"),
                build_evidence("e2", "code", file_path="db.py", note="[HIGH] SQLI"),
            ],
            {},
        )
        result = correlate_findings([tr])
        assert result["summary"]["total_findings"] == 2
        file_paths = {f["file_path"] for f in result["findings"]}
        assert "app.py" in file_paths
        assert "db.py" in file_paths

    def test_findings_sorted_by_severity(self):
        tr = build_tool_result(
            "CodeScan",
            {},
            [
                build_evidence("e1", "code", file_path="low.py", note="[LOW] info"),
                build_evidence("e2", "code", file_path="high.py", note="[HIGH] SECRET"),
            ],
            {},
        )
        result = correlate_findings([tr])
        # High severity should come first
        assert result["findings"][0]["file_path"] == "high.py"


class TestCrossToolCorrelations:
    def test_detects_secrets_and_screenshot_correlation(self):
        signals = {
            "CodeScan.has_secrets": True,
            "ScreenshotAnalyzer.has_secret_exposure": True,
        }
        correlations = _detect_cross_correlations(signals, ["CodeScan", "ScreenshotAnalyzer"])
        assert len(correlations) >= 1
        assert any("credential" in c["description"].lower() for c in correlations)

    def test_no_correlation_when_signals_missing(self):
        signals = {"CodeScan.has_secrets": True}
        correlations = _detect_cross_correlations(signals, ["CodeScan"])
        # No matching pair → no correlations
        secret_correlations = [
            c for c in correlations
            if "ScreenshotAnalyzer.has_secret_exposure" in c["signals"]
        ]
        assert len(secret_correlations) == 0

    def test_no_correlation_when_signals_false(self):
        signals = {
            "CodeScan.has_secrets": False,
            "ScreenshotAnalyzer.has_secret_exposure": True,
        }
        correlations = _detect_cross_correlations(signals, ["CodeScan", "ScreenshotAnalyzer"])
        secret_correlations = [
            c for c in correlations
            if "CodeScan.has_secrets" in c["signals"]
        ]
        assert len(secret_correlations) == 0


class TestHelpers:
    def test_compute_base_severity(self):
        evidence = [{"note": "[HIGH] SECRET"}, {"note": "[MEDIUM] CRYPTO"}]
        assert _compute_base_severity(evidence) == "high"

    def test_compute_base_severity_empty(self):
        assert _compute_base_severity([]) == "info"

    def test_bump_severity(self):
        assert _bump_severity("medium") == "high"
        assert _bump_severity("high") == "critical"
        assert _bump_severity("critical") == "critical"  # capped

    def test_extract_finding_types(self):
        evidence = [
            {"note": "hardcoded_secret detected", "id": "cs-0001-SECRET"},
            {"note": "sql_injection found", "id": "cs-0002-SQLI"},
        ]
        types = _extract_finding_types(evidence)
        assert "hardcoded_secret" in types
        assert "sql_injection" in types

    def test_severity_breakdown(self):
        findings = [
            {"severity": "high"},
            {"severity": "high"},
            {"severity": "medium"},
        ]
        bd = _severity_breakdown(findings)
        assert bd == {"high": 2, "medium": 1}

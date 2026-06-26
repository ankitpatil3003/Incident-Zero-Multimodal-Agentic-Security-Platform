"""
Tests for ScreenshotAnalyzer MCP tool.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from backend.mcps.screenshot_analyzer.run import (
    analyze_screenshot,
    _local_analyze,
    _get_image_info,
    TextPattern,
    TEXT_PATTERNS,
    TOOL_NAME,
    _max_severity,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"
SAMPLE_SCREENSHOT = str(FIXTURES_DIR / "sample_screenshot.png")


class TestTextPatterns:
    def test_detects_password(self):
        p = _find_pattern("SCR_SECRET")
        assert p.regex.search("password = SuperSecret123!")

    def test_detects_aws_key(self):
        p = _find_pattern("SCR_AWS_KEY")
        assert p.regex.search("AKIAIOSFODNN7EXAMPLE")

    def test_detects_private_ip(self):
        p = _find_pattern("SCR_PRIVATE_IP")
        assert p.regex.search("192.168.1.100")

    def test_detects_error(self):
        p = _find_pattern("SCR_ERROR")
        assert p.regex.search("Traceback (most recent call last)")

    def test_detects_url(self):
        p = _find_pattern("SCR_URL")
        assert p.regex.search("https://api.example.com/v1/users")

    def test_detects_email(self):
        p = _find_pattern("SCR_EMAIL")
        assert p.regex.search("admin@example.com")

    def test_no_match_on_clean(self):
        for p in TEXT_PATTERNS:
            assert not p.regex.search("Hello World"), (
                f"Pattern {p.pattern_id} false-positive on 'Hello World'"
            )


class TestGetImageInfo:
    def test_reads_png_info(self):
        info = _get_image_info(SAMPLE_SCREENSHOT)
        assert info["width"] == 400
        assert info["height"] == 200
        assert info["format"] == "PNG"

    def test_nonexistent_file(self):
        info = _get_image_info("/nonexistent/file.png")
        assert info["width"] == 0


class TestLocalAnalyze:
    @patch("backend.mcps.screenshot_analyzer.run._try_ocr", return_value=None)
    def test_no_ocr_returns_empty_findings(self, mock_ocr):
        result = _local_analyze(SAMPLE_SCREENSHOT)
        assert result["artifacts"]["total_findings"] == 0
        assert result["artifacts"]["ocr_extracted"] is False

    @patch("backend.mcps.screenshot_analyzer.run._try_ocr")
    def test_ocr_text_detects_secrets(self, mock_ocr):
        mock_ocr.return_value = "password = SuperSecret123!\nHello World"
        result = _local_analyze(SAMPLE_SCREENSHOT)
        assert result["artifacts"]["total_findings"] >= 1
        assert result["signals"]["has_secret_exposure"] is True

    @patch("backend.mcps.screenshot_analyzer.run._try_ocr")
    def test_ocr_text_detects_errors(self, mock_ocr):
        mock_ocr.return_value = "Traceback (most recent call last)\nValueError: bad"
        result = _local_analyze(SAMPLE_SCREENSHOT)
        assert result["signals"]["has_error_exposure"] is True

    @patch("backend.mcps.screenshot_analyzer.run._try_ocr")
    def test_ocr_text_detects_private_ip(self, mock_ocr):
        mock_ocr.return_value = "Server at 192.168.1.100"
        result = _local_analyze(SAMPLE_SCREENSHOT)
        assert result["signals"]["has_network_info"] is True


class TestAnalyzeScreenshot:
    def test_nonexistent_file(self):
        result = analyze_screenshot("/nonexistent/image.png")
        assert result["errors"] is not None
        assert any("file_not_found" in e["error"] for e in result["errors"])

    def test_unsupported_format(self, tmp_path):
        f = tmp_path / "test.gif"
        f.write_bytes(b"GIF89a")
        result = analyze_screenshot(str(f))
        assert result["errors"] is not None
        assert any("unsupported_format" in e["error"] for e in result["errors"])

    @patch("backend.mcps.screenshot_analyzer.run._try_ocr", return_value=None)
    def test_valid_image_returns_tool_result(self, mock_ocr):
        result = analyze_screenshot(SAMPLE_SCREENSHOT)
        assert result["tool_name"] == TOOL_NAME
        assert "image_info" in result["artifacts"]
        assert result["artifacts"]["image_info"]["width"] == 400


class TestMaxSeverityScreenshot:
    def test_high_wins(self):
        assert _max_severity({"high": 1, "low": 2}) == "high"

    def test_empty(self):
        assert _max_severity({}) == "none"


# --- Helper ---

def _find_pattern(pattern_id: str) -> TextPattern:
    for p in TEXT_PATTERNS:
        if p.pattern_id == pattern_id:
            return p
    raise ValueError(f"Pattern {pattern_id} not found")

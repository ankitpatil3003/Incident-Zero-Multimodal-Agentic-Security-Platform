"""
Tests for DiagramExtractor MCP tool.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from backend.mcps.diagram_extractor.run import (
    extract_diagram,
    _local_extract,
    _get_image_info,
    COMPONENT_PATTERNS,
    PROTOCOL_PATTERN,
    PORT_PATTERN,
    FLOW_PATTERN,
    TOOL_NAME,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"
SAMPLE_IMAGE = str(FIXTURES_DIR / "sample_screenshot.png")


class TestPatterns:
    def test_detects_api_gateway(self):
        assert COMPONENT_PATTERNS.search("API Gateway")

    def test_detects_database(self):
        assert COMPONENT_PATTERNS.search("Database")

    def test_detects_kubernetes(self):
        assert COMPONENT_PATTERNS.search("Kubernetes cluster")

    def test_detects_redis(self):
        assert COMPONENT_PATTERNS.search("Redis cache layer")

    def test_detects_https_protocol(self):
        assert PROTOCOL_PATTERN.search("HTTPS")

    def test_detects_grpc_protocol(self):
        assert PROTOCOL_PATTERN.search("gRPC endpoint")

    def test_detects_port(self):
        m = PORT_PATTERN.search("port:5432")
        assert m and m.group(1) == "5432"

    def test_detects_arrow_flow(self):
        assert FLOW_PATTERN.search("Service A -> Service B")

    def test_detects_unicode_arrow(self):
        assert FLOW_PATTERN.search("Client → Server")

    def test_no_component_in_plain_text(self):
        assert not COMPONENT_PATTERNS.search("Hello World 123")


class TestLocalExtract:
    @patch("backend.mcps.diagram_extractor.run._try_ocr", return_value=None)
    def test_no_ocr_returns_empty(self, mock_ocr):
        result = _local_extract(SAMPLE_IMAGE)
        assert result["artifacts"]["component_count"] == 0
        assert result["artifacts"]["ocr_extracted"] is False

    @patch("backend.mcps.diagram_extractor.run._try_ocr")
    def test_extracts_components(self, mock_ocr):
        mock_ocr.return_value = "API Gateway -> Load Balancer\nDatabase: PostgreSQL"
        result = _local_extract(SAMPLE_IMAGE)
        components = result["artifacts"]["components_detected"]
        assert "API Gateway" in components
        assert "Load Balancer" in components
        assert "Database" in components

    @patch("backend.mcps.diagram_extractor.run._try_ocr")
    def test_extracts_protocols(self, mock_ocr):
        mock_ocr.return_value = "Protocol: HTTPS, gRPC"
        result = _local_extract(SAMPLE_IMAGE)
        assert "HTTPS" in result["artifacts"]["protocols_detected"]
        assert "GRPC" in result["artifacts"]["protocols_detected"]

    @patch("backend.mcps.diagram_extractor.run._try_ocr")
    def test_extracts_ports(self, mock_ocr):
        mock_ocr.return_value = "Database port:5432"
        result = _local_extract(SAMPLE_IMAGE)
        assert "5432" in result["artifacts"]["ports_detected"]

    @patch("backend.mcps.diagram_extractor.run._try_ocr")
    def test_detects_flows(self, mock_ocr):
        mock_ocr.return_value = "Client -> Server -> Database"
        result = _local_extract(SAMPLE_IMAGE)
        assert result["artifacts"]["has_flow_indicators"] is True
        assert result["signals"]["has_flows"] is True

    @patch("backend.mcps.diagram_extractor.run._try_ocr")
    def test_evidence_created_for_components(self, mock_ocr):
        mock_ocr.return_value = "API Gateway\nRedis"
        result = _local_extract(SAMPLE_IMAGE)
        assert len(result["evidence"]) == 2
        assert all(e["kind"] == "diagram" for e in result["evidence"])


class TestExtractDiagram:
    def test_nonexistent_file(self):
        result = extract_diagram("/nonexistent/diagram.png")
        assert result["errors"] is not None
        assert any("file_not_found" in e["error"] for e in result["errors"])

    def test_unsupported_format(self, tmp_path):
        f = tmp_path / "test.gif"
        f.write_bytes(b"GIF89a")
        result = extract_diagram(str(f))
        assert result["errors"] is not None

    @patch("backend.mcps.diagram_extractor.run._try_ocr", return_value=None)
    def test_valid_image_returns_tool_result(self, mock_ocr):
        result = extract_diagram(SAMPLE_IMAGE)
        assert result["tool_name"] == TOOL_NAME
        assert "image_info" in result["artifacts"]


class TestGetImageInfoDiagram:
    def test_reads_image(self):
        info = _get_image_info(SAMPLE_IMAGE)
        assert info["width"] == 400
        assert info["height"] == 200

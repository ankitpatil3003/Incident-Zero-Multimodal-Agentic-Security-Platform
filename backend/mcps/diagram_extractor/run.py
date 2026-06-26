"""
DiagramExtractor MCP tool — extracts architecture information from
diagram images (network diagrams, architecture diagrams, flow charts).

Uses the local-first pattern:
  - Local: Image metadata extraction + OCR text for label detection,
           regex-based extraction of component names, protocols, ports
  - LLM: Mistral vision model for semantic diagram understanding (future Sprint)
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional, Set

from backend.mcps.common.types import build_tool_result, build_error_result, build_evidence
from backend.mcps.common.local_extract import local_first

logger = logging.getLogger(__name__)

TOOL_NAME = "DiagramExtractor"

MAX_IMAGE_SIZE = 10_485_760
SUPPORTED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".webp"}


# --- Patterns for extracting architecture info from OCR text ---

# Common infrastructure component keywords
COMPONENT_PATTERNS = re.compile(
    r"\b("
    r"API\s*Gateway|Load\s*Balancer|Firewall|WAF|CDN|DNS|Proxy|"
    r"Database|DB|Redis|Kafka|RabbitMQ|Queue|Cache|S3|Bucket|"
    r"Docker|Container|Kubernetes|K8s|Pod|Node|Cluster|"
    r"Lambda|Function|Serverless|EC2|VM|Instance|"
    r"VPC|Subnet|NAT|IGW|Route\s*53|CloudFront|"
    r"Auth|OAuth|SSO|LDAP|Active\s*Directory|IAM|"
    r"ELB|ALB|NLB|Nginx|Apache|HAProxy|"
    r"MySQL|PostgreSQL|MongoDB|DynamoDB|Elasticsearch|"
    r"SQS|SNS|EventBridge|Pub\s*/?\s*Sub|"
    r"CI\s*/?\s*CD|Jenkins|GitHub\s*Actions|GitLab|"
    r"Monitoring|Prometheus|Grafana|CloudWatch|Datadog"
    r")\b",
    re.IGNORECASE,
)

# Protocol and port patterns
PROTOCOL_PATTERN = re.compile(
    r"\b(HTTPS?|gRPC|WebSocket|WSS?|TCP|UDP|AMQP|MQTT|SSH|FTP|SMTP)\b",
    re.IGNORECASE,
)

PORT_PATTERN = re.compile(
    r"\b(?:port|:)\s*(\d{2,5})\b",
    re.IGNORECASE,
)

# Arrow/flow indicators in text
FLOW_PATTERN = re.compile(
    r"(->|→|=>|──>|-->|←|<-|<--|<──)",
)


# --- Main entry point ---

def extract_diagram(diagram_path: str) -> Dict[str, Any]:
    """
    Analyze an architecture diagram and return a ToolResult.

    Args:
        diagram_path: path to the diagram image file

    Returns:
        ToolResult envelope with extracted architecture info
    """
    if not os.path.isfile(diagram_path):
        return build_error_result(
            TOOL_NAME, "file_not_found", f"Diagram not found: {diagram_path}"
        )

    ext = os.path.splitext(diagram_path)[1].lower()
    if ext not in SUPPORTED_EXTENSIONS:
        return build_error_result(
            TOOL_NAME, "unsupported_format", f"Unsupported image format: {ext}"
        )

    try:
        size = os.path.getsize(diagram_path)
        if size > MAX_IMAGE_SIZE:
            return build_error_result(
                TOOL_NAME, "file_too_large",
                f"Image is {size} bytes (max {MAX_IMAGE_SIZE})",
            )
    except OSError as exc:
        return build_error_result(TOOL_NAME, "read_error", str(exc))

    def local_fn() -> Dict[str, Any]:
        return _local_extract(diagram_path)

    def llm_fn(local_result: Dict[str, Any]) -> Dict[str, Any]:
        # Vision model semantic extraction deferred to Sprint 5.
        return {"artifacts": {}, "evidence": [], "signals": {}}

    merged = local_first(local_fn, llm_fn)

    return build_tool_result(
        tool_name=TOOL_NAME,
        artifacts=merged["artifacts"],
        evidence=merged["evidence"],
        signals=merged["signals"],
        errors=merged.get("errors"),
    )


def _local_extract(diagram_path: str) -> Dict[str, Any]:
    """Extract architecture info from image metadata and OCR text."""
    image_info = _get_image_info(diagram_path)
    ocr_text = _try_ocr(diagram_path)

    components: Set[str] = set()
    protocols: Set[str] = set()
    ports: Set[str] = set()
    has_flows = False
    evidence: List[Dict[str, Any]] = []

    if ocr_text:
        # Extract components
        for match in COMPONENT_PATTERNS.finditer(ocr_text):
            components.add(match.group(1).strip())

        # Extract protocols
        for match in PROTOCOL_PATTERN.finditer(ocr_text):
            protocols.add(match.group(1).upper())

        # Extract ports
        for match in PORT_PATTERN.finditer(ocr_text):
            port = match.group(1)
            if 1 <= int(port) <= 65535:
                ports.add(port)

        # Check for flow indicators
        has_flows = bool(FLOW_PATTERN.search(ocr_text))

        # Build evidence for each detected component
        for idx, component in enumerate(sorted(components)):
            evidence.append(
                build_evidence(
                    evidence_id=f"diag-{idx:04d}-component",
                    kind="diagram",
                    file_path=diagram_path,
                    snippet=component,
                    note=f"Architecture component detected: {component}",
                )
            )

    artifacts = {
        "components_detected": sorted(components),
        "protocols_detected": sorted(protocols),
        "ports_detected": sorted(ports),
        "has_flow_indicators": has_flows,
        "component_count": len(components),
        "ocr_extracted": ocr_text is not None,
        "ocr_text_length": len(ocr_text) if ocr_text else 0,
        "image_info": image_info,
    }

    signals = {
        "has_components": len(components) > 0,
        "has_protocols": len(protocols) > 0,
        "has_ports": len(ports) > 0,
        "has_flows": has_flows,
        "component_names": sorted(components),
        "protocol_names": sorted(protocols),
    }

    needs_llm = ocr_text is not None and len(ocr_text) > 0

    return {
        "artifacts": artifacts,
        "evidence": evidence,
        "signals": signals,
        "needs_llm": needs_llm,
    }


def _get_image_info(path: str) -> Dict[str, Any]:
    """Extract basic image metadata using Pillow."""
    try:
        from PIL import Image

        with Image.open(path) as img:
            return {
                "width": img.width,
                "height": img.height,
                "format": img.format or "unknown",
                "mode": img.mode,
            }
    except Exception as exc:
        logger.warning("Could not read image info for %s: %s", path, exc)
        return {"width": 0, "height": 0, "format": "unknown", "mode": "unknown"}


def _try_ocr(diagram_path: str) -> Optional[str]:
    """Attempt OCR via Mistral OCR API. Returns extracted text or None."""
    try:
        from backend.mcps.common.mistral_client import call_ocr
        from backend.app.config import settings

        if not settings.mistral_api_key:
            logger.info("No MISTRAL_API_KEY — skipping OCR for %s", diagram_path)
            return None

        result = call_ocr(diagram_path, model=settings.mistral_ocr_model)
        if result["ok"] and result["data"]:
            return "\n".join(result["data"])
        return None
    except Exception as exc:
        logger.warning("OCR failed for %s: %s", diagram_path, exc)
        return None

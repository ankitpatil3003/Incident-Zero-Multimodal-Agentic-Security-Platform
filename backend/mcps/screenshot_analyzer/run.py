"""
ScreenshotAnalyzer MCP tool — extracts text from screenshots using OCR,
detects secrets/IPs/URLs/errors in the extracted text, and optionally
augments with Mistral vision model for contextual analysis.

Uses the local-first pattern:
  - Local: Pillow preprocessing + Mistral OCR for text extraction,
           then regex-based detection on the extracted text
  - LLM: Mistral vision model for contextual screenshot analysis (future Sprint)
"""

from __future__ import annotations

import base64
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from backend.mcps.common.types import build_tool_result, build_error_result, build_evidence
from backend.mcps.common.local_extract import local_first

logger = logging.getLogger(__name__)

TOOL_NAME = "ScreenshotAnalyzer"

# Max image size (10 MB)
MAX_IMAGE_SIZE = 10_485_760

SUPPORTED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".webp"}


# --- Detection patterns applied to OCR-extracted text ---

class TextPattern:
    """A regex pattern for detecting interesting content in OCR text."""

    __slots__ = ("pattern_id", "category", "severity", "description", "regex")

    def __init__(
        self,
        pattern_id: str,
        category: str,
        severity: str,
        description: str,
        regex: re.Pattern[str],
    ) -> None:
        self.pattern_id = pattern_id
        self.category = category
        self.severity = severity
        self.description = description
        self.regex = regex


TEXT_PATTERNS: List[TextPattern] = [
    TextPattern(
        "SCR_SECRET", "secret_exposure", "high",
        "Possible secret or credential visible in screenshot",
        re.compile(
            r"(?:password|passwd|secret|api_?key|token|auth)\s*[:=]\s*\S+",
            re.IGNORECASE,
        ),
    ),
    TextPattern(
        "SCR_AWS_KEY", "secret_exposure", "high",
        "AWS access key visible in screenshot",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    TextPattern(
        "SCR_PRIVATE_IP", "network_info", "medium",
        "Private IP address visible in screenshot",
        re.compile(r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"),
    ),
    TextPattern(
        "SCR_ERROR", "error_exposure", "medium",
        "Error message or stack trace visible in screenshot",
        re.compile(r"(?:Traceback|Exception|Error|FATAL|stack\s*trace)\b", re.IGNORECASE),
    ),
    TextPattern(
        "SCR_URL", "network_info", "low",
        "URL visible in screenshot",
        re.compile(r"https?://[^\s\"'<>]{5,}"),
    ),
    TextPattern(
        "SCR_EMAIL", "pii_exposure", "medium",
        "Email address visible in screenshot",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    ),
]


# --- Main entry point ---

def analyze_screenshot(screenshot_path: str) -> Dict[str, Any]:
    """
    Analyze a screenshot image and return a ToolResult.

    Args:
        screenshot_path: path to the image file

    Returns:
        ToolResult envelope with findings
    """
    if not os.path.isfile(screenshot_path):
        return build_error_result(
            TOOL_NAME, "file_not_found", f"Image not found: {screenshot_path}"
        )

    ext = os.path.splitext(screenshot_path)[1].lower()
    if ext not in SUPPORTED_EXTENSIONS:
        return build_error_result(
            TOOL_NAME, "unsupported_format", f"Unsupported image format: {ext}"
        )

    try:
        size = os.path.getsize(screenshot_path)
        if size > MAX_IMAGE_SIZE:
            return build_error_result(
                TOOL_NAME, "file_too_large",
                f"Image is {size} bytes (max {MAX_IMAGE_SIZE})",
            )
    except OSError as exc:
        return build_error_result(TOOL_NAME, "read_error", str(exc))

    def local_fn() -> Dict[str, Any]:
        return _local_analyze(screenshot_path)

    def llm_fn(local_result: Dict[str, Any]) -> Dict[str, Any]:
        # Vision model augmentation deferred to Sprint 5 orchestrator integration.
        return {"artifacts": {}, "evidence": [], "signals": {}}

    merged = local_first(local_fn, llm_fn)

    return build_tool_result(
        tool_name=TOOL_NAME,
        artifacts=merged["artifacts"],
        evidence=merged["evidence"],
        signals=merged["signals"],
        errors=merged.get("errors"),
    )


def _local_analyze(screenshot_path: str) -> Dict[str, Any]:
    """
    Preprocess image and extract text via OCR, then run detection patterns.

    OCR is attempted via Mistral OCR API. If unavailable (no API key),
    falls back to image metadata only.
    """
    image_info = _get_image_info(screenshot_path)
    ocr_text = _try_ocr(screenshot_path)

    evidence: List[Dict[str, Any]] = []
    category_counts: Dict[str, int] = {}
    severity_counts: Dict[str, int] = {}

    if ocr_text:
        lines = ocr_text.splitlines()
        for line_idx, line in enumerate(lines):
            stripped = line.strip()
            if not stripped:
                continue
            for pattern in TEXT_PATTERNS:
                if pattern.regex.search(stripped):
                    evidence.append(
                        build_evidence(
                            evidence_id=f"scr-{len(evidence):04d}-{pattern.pattern_id}",
                            kind="screenshot",
                            file_path=screenshot_path,
                            line=line_idx + 1,
                            snippet=stripped[:200],
                            note=f"[{pattern.severity.upper()}] {pattern.pattern_id}: "
                                 f"{pattern.description}",
                        )
                    )
                    category_counts[pattern.category] = (
                        category_counts.get(pattern.category, 0) + 1
                    )
                    severity_counts[pattern.severity] = (
                        severity_counts.get(pattern.severity, 0) + 1
                    )
                    break  # one pattern per line

    categories_found = set(category_counts.keys())

    artifacts = {
        "total_findings": len(evidence),
        "ocr_text_length": len(ocr_text) if ocr_text else 0,
        "ocr_extracted": ocr_text is not None,
        "image_info": image_info,
        "findings_by_category": category_counts,
        "findings_by_severity": severity_counts,
    }

    signals = {
        "has_secret_exposure": "secret_exposure" in categories_found,
        "has_error_exposure": "error_exposure" in categories_found,
        "has_pii_exposure": "pii_exposure" in categories_found,
        "has_network_info": "network_info" in categories_found,
        "categories_found": sorted(categories_found),
        "max_severity": _max_severity(severity_counts),
    }

    needs_llm = len(evidence) > 0 or (ocr_text is not None and len(ocr_text) > 0)

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


def _try_ocr(screenshot_path: str) -> Optional[str]:
    """
    Attempt OCR via Mistral OCR API. Returns extracted text or None.

    Falls back gracefully if no API key is configured.
    """
    try:
        from backend.mcps.common.mistral_client import call_ocr
        from backend.app.config import settings

        if not settings.mistral_api_key:
            logger.info("No MISTRAL_API_KEY — skipping OCR for %s", screenshot_path)
            return None

        result = call_ocr(screenshot_path, model=settings.mistral_ocr_model)
        if result["ok"] and result["data"]:
            # data is a list of text chunks from OCR
            return "\n".join(result["data"])
        return None
    except Exception as exc:
        logger.warning("OCR failed for %s: %s", screenshot_path, exc)
        return None


_SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1}


def _max_severity(by_severity: Dict[str, int]) -> str:
    if not by_severity:
        return "none"
    return max(by_severity.keys(), key=lambda s: _SEVERITY_ORDER.get(s, 0))

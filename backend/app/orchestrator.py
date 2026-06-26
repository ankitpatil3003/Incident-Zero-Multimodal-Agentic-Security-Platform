"""
Pipeline orchestrator — runs MCP tools in sequence and assembles results.

Pipeline stages:
  1. INGEST  — validate inputs, emit "evidence received" event
  2. SCAN    — run applicable MCP tools (CodeScan, LogReasoner,
               ScreenshotAnalyzer, DiagramExtractor) based on available inputs
  3. CORRELATE — merge findings across tools, detect cross-tool patterns
  4. GRAPH   — build attack graph from correlated findings
  5. PATCH   — generate fix suggestions from correlated evidence
  6. FINALIZE — assemble result bundle, emit "done" event

Security notes:
  - Input paths are validated before tool invocation (existence, type, size)
  - Each tool runs in a try/except — one tool failure doesn't crash the pipeline
  - No user-supplied paths are used without validation
  - Pipeline errors are logged but never expose internal paths to the API response
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from .store import job_store
from .correlator import correlate_findings
from .graph import build_attack_graph

logger = logging.getLogger(__name__)

# Maximum input file size for safety (50 MB)
_MAX_INPUT_FILE_SIZE = 50 * 1024 * 1024

# Allowed image extensions for screenshot/diagram inputs
_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".webp"}


def run_job(job_id: str) -> None:
    """Execute the analysis pipeline for a given job."""
    job = job_store.get_job(job_id)
    if job is None:
        return

    try:
        _run_pipeline(job_id)
    except Exception as exc:
        logger.exception("Pipeline failed for job %s", job_id)
        job_store.add_event(
            job, stage="finalize", message=f"Pipeline failed: {exc}", status="error"
        )
        job.status = "error"
        job.result = _error_result(job_id, str(exc), job.timeline)


def _run_pipeline(job_id: str) -> None:
    """Core pipeline logic — separated for testability."""
    job = job_store.get_job(job_id)
    if job is None:
        return

    tool_results: List[Dict[str, Any]] = []

    # --- Stage: SCAN ---
    # Run each tool if its input is available and valid.
    # Each tool call is isolated — failure in one does not block others.

    # CodeScan
    if job.repo_path:
        job_store.add_event(job, stage="scan", message="CodeScan started", status="in_progress")
        result = _safe_invoke_codescan(job.repo_path)
        if result:
            tool_results.append(result)
            finding_count = result.get("artifacts", {}).get("total_findings", 0)
            job_store.add_event(
                job, stage="scan",
                message=f"CodeScan completed — {finding_count} findings",
                status="done",
            )
        else:
            job_store.add_event(
                job, stage="scan", message="CodeScan skipped (invalid input)", status="done"
            )

    # LogReasoner
    if job.log_path:
        job_store.add_event(
            job, stage="scan", message="LogReasoner started", status="in_progress"
        )
        result = _safe_invoke_log_reasoner(job.log_path)
        if result:
            tool_results.append(result)
            finding_count = result.get("artifacts", {}).get("total_findings", 0)
            job_store.add_event(
                job, stage="scan",
                message=f"LogReasoner completed — {finding_count} findings",
                status="done",
            )
        else:
            job_store.add_event(
                job, stage="scan", message="LogReasoner skipped (invalid input)", status="done"
            )

    # ScreenshotAnalyzer
    if job.screenshot_path:
        job_store.add_event(
            job, stage="scan", message="ScreenshotAnalyzer started", status="in_progress"
        )
        result = _safe_invoke_screenshot_analyzer(job.screenshot_path)
        if result:
            tool_results.append(result)
            finding_count = result.get("artifacts", {}).get("total_findings", 0)
            job_store.add_event(
                job, stage="scan",
                message=f"ScreenshotAnalyzer completed — {finding_count} findings",
                status="done",
            )
        else:
            job_store.add_event(
                job, stage="scan",
                message="ScreenshotAnalyzer skipped (invalid input)", status="done",
            )

    # DiagramExtractor
    if job.diagram_path:
        job_store.add_event(
            job, stage="scan", message="DiagramExtractor started", status="in_progress"
        )
        result = _safe_invoke_diagram_extractor(job.diagram_path)
        if result:
            tool_results.append(result)
            component_count = result.get("artifacts", {}).get("component_count", 0)
            job_store.add_event(
                job, stage="scan",
                message=f"DiagramExtractor completed — {component_count} components",
                status="done",
            )
        else:
            job_store.add_event(
                job, stage="scan",
                message="DiagramExtractor skipped (invalid input)", status="done",
            )

    # --- Stage: CORRELATE ---
    job_store.add_event(
        job, stage="correlate", message="Correlating findings", status="in_progress"
    )
    correlated = correlate_findings(tool_results)
    finding_count = correlated["summary"]["total_findings"]
    correlation_count = correlated["summary"]["cross_tool_correlations"]
    job_store.add_event(
        job, stage="correlate",
        message=f"Correlation complete — {finding_count} findings, "
                f"{correlation_count} cross-tool correlations",
        status="done",
    )

    # --- Stage: GRAPH ---
    job_store.add_event(
        job, stage="graph", message="Building attack graph", status="in_progress"
    )
    graph = build_attack_graph(correlated)
    node_count = graph["stats"]["node_count"]
    path_count = len(graph["top_paths"])
    job_store.add_event(
        job, stage="graph",
        message=f"Attack graph built — {node_count} nodes, {path_count} attack paths",
        status="done",
    )

    # --- Stage: PATCH ---
    job_store.add_event(
        job, stage="patch", message="Generating patches", status="in_progress"
    )
    patches_result = _safe_invoke_patcher(correlated["findings"])
    patch_count = 0
    if patches_result:
        patch_count = patches_result.get("artifacts", {}).get("total_patches", 0)
    job_store.add_event(
        job, stage="patch",
        message=f"Patch generation complete — {patch_count} patches",
        status="done",
    )

    # --- Stage: FINALIZE ---
    job_store.add_event(
        job, stage="finalize", message="Assembling result bundle", status="in_progress"
    )

    job.status = "done"
    job.result = {
        "job_id": job.job_id,
        "status": "done",
        "findings": correlated["findings"],
        "summary": correlated["summary"],
        "cross_tool_correlations": correlated["cross_tool_correlations"],
        "graph": graph,
        "patches": patches_result.get("artifacts", {}).get("patches", []) if patches_result else [],
        "timeline": job.timeline,
    }

    job_store.add_event(
        job, stage="finalize", message="Result bundle ready", status="done"
    )


# --- Safe tool invocation wrappers ---
# Each wrapper validates input, catches exceptions, and returns None on failure.


def _safe_invoke_codescan(repo_path: str) -> Optional[Dict[str, Any]]:
    """Validate and invoke CodeScan."""
    if not _validate_directory(repo_path):
        logger.warning("CodeScan: invalid repo path: %s", repo_path)
        return None
    try:
        from backend.mcps.codescan.scanner import scan_repo

        result = scan_repo(repo_path)
        if result.get("errors") and not result.get("evidence"):
            logger.warning("CodeScan returned errors only: %s", result["errors"])
        return result
    except Exception as exc:
        logger.exception("CodeScan failed: %s", exc)
        return None


def _safe_invoke_log_reasoner(log_path: str) -> Optional[Dict[str, Any]]:
    """Validate and invoke LogReasoner."""
    if not _validate_file(log_path):
        logger.warning("LogReasoner: invalid log path: %s", log_path)
        return None
    try:
        from backend.mcps.log_reasoner.run import analyze_log

        return analyze_log(log_path)
    except Exception as exc:
        logger.exception("LogReasoner failed: %s", exc)
        return None


def _safe_invoke_screenshot_analyzer(
    screenshot_path: str,
) -> Optional[Dict[str, Any]]:
    """Validate and invoke ScreenshotAnalyzer."""
    if not _validate_image_file(screenshot_path):
        logger.warning("ScreenshotAnalyzer: invalid path: %s", screenshot_path)
        return None
    try:
        from backend.mcps.screenshot_analyzer.run import analyze_screenshot

        return analyze_screenshot(screenshot_path)
    except Exception as exc:
        logger.exception("ScreenshotAnalyzer failed: %s", exc)
        return None


def _safe_invoke_diagram_extractor(
    diagram_path: str,
) -> Optional[Dict[str, Any]]:
    """Validate and invoke DiagramExtractor."""
    if not _validate_image_file(diagram_path):
        logger.warning("DiagramExtractor: invalid path: %s", diagram_path)
        return None
    try:
        from backend.mcps.diagram_extractor.run import extract_diagram

        return extract_diagram(diagram_path)
    except Exception as exc:
        logger.exception("DiagramExtractor failed: %s", exc)
        return None


def _safe_invoke_patcher(
    findings: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Extract evidence from findings and invoke Patcher."""
    if not findings:
        return None
    try:
        from backend.mcps.patcher.generator import generate_patches

        # Flatten evidence from all correlated findings
        all_evidence: List[Dict[str, Any]] = []
        for finding in findings:
            for ev in finding.get("evidence", []):
                all_evidence.append({**ev, "file_path": finding.get("file_path", "")})

        if not all_evidence:
            return None

        return generate_patches(all_evidence)
    except Exception as exc:
        logger.exception("Patcher failed: %s", exc)
        return None


# --- Input validation helpers ---


def _validate_directory(path: str) -> bool:
    """Check that path exists and is a directory."""
    if not path or not path.strip():
        return False
    p = Path(path)
    return p.is_dir()


def _validate_file(path: str) -> bool:
    """Check that path exists, is a file, and is within size limits."""
    if not path or not path.strip():
        return False
    p = Path(path)
    if not p.is_file():
        return False
    try:
        size = p.stat().st_size
        if size > _MAX_INPUT_FILE_SIZE:
            logger.warning("File too large (%d bytes): %s", size, path)
            return False
    except OSError:
        return False
    return True


def _validate_image_file(path: str) -> bool:
    """Check that path is a valid image file."""
    if not _validate_file(path):
        return False
    ext = Path(path).suffix.lower()
    if ext not in _IMAGE_EXTENSIONS:
        logger.warning("Not an allowed image extension (%s): %s", ext, path)
        return False
    return True


def _error_result(
    job_id: str,
    error_msg: str,
    timeline: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build the error result structure."""
    return {
        "job_id": job_id,
        "status": "error",
        "findings": [],
        "summary": {
            "total_findings": 0,
            "total_evidence": 0,
            "tools_invoked": [],
            "severity_breakdown": {},
            "corroborated_count": 0,
            "cross_tool_correlations": 0,
        },
        "cross_tool_correlations": [],
        "graph": {"nodes": [], "edges": [], "top_paths": [], "stats": {
            "node_count": 0, "edge_count": 0, "entry_nodes": 0,
            "vuln_nodes": 0, "impact_nodes": 0, "max_risk_score": 0,
        }},
        "patches": [],
        "timeline": timeline,
        "error": error_msg,
    }

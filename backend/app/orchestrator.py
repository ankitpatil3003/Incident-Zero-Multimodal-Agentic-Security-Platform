"""
Pipeline orchestrator — runs MCP tools in sequence and assembles results.

Stub implementation for Sprint 1. Full pipeline built in Sprint 5.
"""

from .store import job_store


def run_job(job_id: str) -> None:
    """Execute the analysis pipeline for a given job."""
    job = job_store.get_job(job_id)
    if job is None:
        return

    try:
        # Sprint 5: CodeScan → LogReasoner → ScreenshotAnalyzer → DiagramExtractor
        #           → Correlator → AttackGraph → Patcher
        job_store.add_event(job, stage="scan", message="CodeScan started", status="in_progress")
        job_store.add_event(job, stage="scan", message="CodeScan completed (stub)", status="done")
        job_store.add_event(
            job, stage="finalize", message="Result bundle ready", status="done"
        )

        job.status = "done"
        job.result = {
            "job_id": job.job_id,
            "status": "done",
            "findings": [],
            "graph": {"nodes": [], "edges": [], "top_paths": []},
            "patches": [],
            "manual_fix_recommendations": [],
            "timeline": job.timeline,
            "summary": "Stub pipeline — no MCP tools active yet.",
        }
    except Exception as exc:
        job_store.add_event(
            job, stage="finalize", message=f"Pipeline failed: {exc}", status="error"
        )
        job.status = "error"
        job.result = {
            "job_id": job.job_id,
            "status": "error",
            "findings": [],
            "graph": {"nodes": [], "edges": [], "top_paths": []},
            "patches": [],
            "manual_fix_recommendations": [],
            "timeline": job.timeline,
            "summary": str(exc),
        }

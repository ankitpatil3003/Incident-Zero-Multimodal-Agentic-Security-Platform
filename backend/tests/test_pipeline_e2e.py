"""
End-to-end pipeline integration tests.

These tests run the full orchestrator pipeline against fixture data
to verify that all stages (scan → correlate → graph → patch) work together.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from backend.app.orchestrator import (
    _run_pipeline,
    _validate_directory,
    _validate_file,
    _validate_image_file,
    _safe_invoke_codescan,
    _safe_invoke_log_reasoner,
    _safe_invoke_patcher,
)
from backend.app.store import JobStore

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"
VULNERABLE_REPO = str(FIXTURES_DIR / "vulnerable_repo")
SAMPLE_LOG = str(FIXTURES_DIR / "sample.log")
SAMPLE_SCREENSHOT = str(FIXTURES_DIR / "sample_screenshot.png")


# --- Input validation tests ---


class TestInputValidation:
    def test_validate_directory_valid(self):
        assert _validate_directory(VULNERABLE_REPO) is True

    def test_validate_directory_nonexistent(self):
        assert _validate_directory("/nonexistent/path") is False

    def test_validate_directory_empty(self):
        assert _validate_directory("") is False
        assert _validate_directory("  ") is False

    def test_validate_file_valid(self):
        assert _validate_file(SAMPLE_LOG) is True

    def test_validate_file_nonexistent(self):
        assert _validate_file("/nonexistent/file.log") is False

    def test_validate_file_is_directory(self):
        assert _validate_file(VULNERABLE_REPO) is False

    def test_validate_image_file_valid(self):
        assert _validate_image_file(SAMPLE_SCREENSHOT) is True

    def test_validate_image_file_wrong_ext(self):
        assert _validate_image_file(SAMPLE_LOG) is False


# --- Individual tool invocation tests ---


class TestSafeToolInvocation:
    def test_codescan_returns_findings(self):
        result = _safe_invoke_codescan(VULNERABLE_REPO)
        assert result is not None
        assert result["tool_name"] == "CodeScan"
        assert result["artifacts"]["total_findings"] > 0

    def test_codescan_invalid_path_returns_none(self):
        result = _safe_invoke_codescan("/nonexistent")
        assert result is None

    def test_log_reasoner_returns_findings(self):
        result = _safe_invoke_log_reasoner(SAMPLE_LOG)
        assert result is not None
        assert result["tool_name"] == "LogReasoner"
        assert result["artifacts"]["total_findings"] > 0

    def test_log_reasoner_invalid_path_returns_none(self):
        result = _safe_invoke_log_reasoner("/nonexistent.log")
        assert result is None

    def test_patcher_returns_patches(self):
        # Create realistic findings for patcher
        findings = [
            {
                "id": "finding-0000",
                "file_path": "app.py",
                "evidence": [
                    {
                        "id": "cs-0001-SECRET_ASSIGNMENT",
                        "kind": "code",
                        "snippet": 'password = "SuperSecret123!"',
                        "note": "[HIGH] SECRET_ASSIGNMENT: Hardcoded secret",
                    }
                ],
            }
        ]
        result = _safe_invoke_patcher(findings)
        assert result is not None
        assert result["artifacts"]["total_patches"] >= 1

    def test_patcher_empty_findings_returns_none(self):
        result = _safe_invoke_patcher([])
        assert result is None


# --- Full pipeline tests ---


class TestFullPipeline:
    def _make_job(
        self,
        store: JobStore,
        repo_path: str = None,
        log_path: str = None,
        screenshot_path: str = None,
        diagram_path: str = None,
    ):
        return store.create_job(
            repo_path=repo_path,
            log_path=log_path,
            screenshot_path=screenshot_path,
            diagram_path=diagram_path,
        )

    def test_codescan_only_pipeline(self):
        store = JobStore()
        job = self._make_job(store, repo_path=VULNERABLE_REPO)

        # Monkey-patch the orchestrator to use our store
        with patch("backend.app.orchestrator.job_store", store):
            _run_pipeline(job.job_id)

        assert job.status == "done"
        assert job.result["status"] == "done"
        assert len(job.result["findings"]) > 0
        assert job.result["graph"]["stats"]["node_count"] > 0
        assert len(job.result["patches"]) > 0

    def test_codescan_and_log_pipeline(self):
        store = JobStore()
        job = self._make_job(store, repo_path=VULNERABLE_REPO, log_path=SAMPLE_LOG)

        with patch("backend.app.orchestrator.job_store", store):
            _run_pipeline(job.job_id)

        assert job.status == "done"
        tools_invoked = job.result["summary"]["tools_invoked"]
        assert "CodeScan" in tools_invoked
        assert "LogReasoner" in tools_invoked
        assert job.result["summary"]["total_findings"] > 0

    @patch("backend.mcps.screenshot_analyzer.run._try_ocr", return_value=None)
    def test_full_pipeline_all_inputs(self, mock_ocr):
        store = JobStore()
        job = self._make_job(
            store,
            repo_path=VULNERABLE_REPO,
            log_path=SAMPLE_LOG,
            screenshot_path=SAMPLE_SCREENSHOT,
            diagram_path=SAMPLE_SCREENSHOT,  # reuse for testing
        )

        with patch("backend.app.orchestrator.job_store", store):
            _run_pipeline(job.job_id)

        assert job.status == "done"
        tools_invoked = job.result["summary"]["tools_invoked"]
        assert "CodeScan" in tools_invoked
        assert "LogReasoner" in tools_invoked
        # Screenshot/Diagram may or may not produce findings without OCR

    def test_no_inputs_still_completes(self):
        store = JobStore()
        job = self._make_job(store)

        with patch("backend.app.orchestrator.job_store", store):
            _run_pipeline(job.job_id)

        assert job.status == "done"
        assert job.result["summary"]["total_findings"] == 0
        assert job.result["graph"]["stats"]["node_count"] == 0

    def test_pipeline_produces_correct_result_structure(self):
        store = JobStore()
        job = self._make_job(store, repo_path=VULNERABLE_REPO)

        with patch("backend.app.orchestrator.job_store", store):
            _run_pipeline(job.job_id)

        result = job.result
        # Required top-level keys
        assert "job_id" in result
        assert "status" in result
        assert "findings" in result
        assert "summary" in result
        assert "graph" in result
        assert "patches" in result
        assert "timeline" in result

        # Graph structure
        graph = result["graph"]
        assert "nodes" in graph
        assert "edges" in graph
        assert "top_paths" in graph
        assert "stats" in graph

        # Summary structure
        summary = result["summary"]
        assert "total_findings" in summary
        assert "total_evidence" in summary
        assert "tools_invoked" in summary
        assert "severity_breakdown" in summary

    def test_timeline_has_all_stages(self):
        store = JobStore()
        job = self._make_job(store, repo_path=VULNERABLE_REPO, log_path=SAMPLE_LOG)

        with patch("backend.app.orchestrator.job_store", store):
            _run_pipeline(job.job_id)

        stages = {event["stage"] for event in job.timeline}
        assert "ingest" in stages
        assert "scan" in stages
        assert "correlate" in stages
        assert "graph" in stages
        assert "patch" in stages
        assert "finalize" in stages

    def test_attack_paths_are_valid(self):
        store = JobStore()
        job = self._make_job(store, repo_path=VULNERABLE_REPO)

        with patch("backend.app.orchestrator.job_store", store):
            _run_pipeline(job.job_id)

        for path in job.result["graph"]["top_paths"]:
            assert path["risk_score"] > 0
            assert path["length"] >= 3
            # Path should start with entry and end with impact
            assert path["path"][0]["type"] == "entry"
            assert path["path"][-1]["type"] == "impact"

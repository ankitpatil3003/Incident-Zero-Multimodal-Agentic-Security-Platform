"""
Tests for the attack graph builder.
"""

from backend.app.graph import (
    build_attack_graph,
    _sanitize_node_id,
    _build_vuln_label,
    _entry_type,
    _entry_label,
    _empty_graph,
)
from backend.app.correlator import correlate_findings
from backend.mcps.common.types import build_tool_result, build_evidence


class TestBuildAttackGraph:
    def test_empty_input(self):
        result = build_attack_graph({"findings": [], "cross_tool_correlations": []})
        assert result == _empty_graph()

    def test_single_finding_produces_3_layer_graph(self):
        """A single finding should create: entry → vuln → impact."""
        correlated = {
            "findings": [
                {
                    "id": "finding-0000",
                    "file_path": "app.py",
                    "severity": "high",
                    "corroborated": False,
                    "contributing_tools": ["CodeScan"],
                    "finding_types": ["hardcoded_secret"],
                    "evidence_count": 1,
                    "evidence": [{"id": "e1", "kind": "code"}],
                }
            ],
            "cross_tool_correlations": [],
        }
        graph = build_attack_graph(correlated)
        assert graph["stats"]["entry_nodes"] >= 1
        assert graph["stats"]["vuln_nodes"] == 1
        assert graph["stats"]["impact_nodes"] >= 1
        assert graph["stats"]["edge_count"] >= 2
        assert len(graph["top_paths"]) >= 1

    def test_corroborated_finding_has_higher_risk(self):
        """Corroborated findings should have boosted risk scores."""
        correlated = {
            "findings": [
                {
                    "id": "finding-0000",
                    "file_path": "app.py",
                    "severity": "high",
                    "corroborated": True,
                    "contributing_tools": ["CodeScan", "LogReasoner"],
                    "finding_types": ["hardcoded_secret"],
                    "evidence_count": 2,
                    "evidence": [],
                }
            ],
            "cross_tool_correlations": [],
        }
        graph = build_attack_graph(correlated)
        vuln_nodes = [n for n in graph["nodes"] if n["node_type"] == "vulnerability"]
        assert len(vuln_nodes) == 1
        # Corroborated high = 0.8 + 0.1 = 0.9
        assert vuln_nodes[0]["risk_score"] == 0.9

    def test_multiple_finding_types_create_multiple_impacts(self):
        correlated = {
            "findings": [
                {
                    "id": "finding-0000",
                    "file_path": "db.py",
                    "severity": "high",
                    "corroborated": False,
                    "contributing_tools": ["CodeScan"],
                    "finding_types": ["sql_injection", "hardcoded_secret"],
                    "evidence_count": 2,
                    "evidence": [],
                }
            ],
            "cross_tool_correlations": [],
        }
        graph = build_attack_graph(correlated)
        # sql_injection → data_breach, rce; hardcoded_secret → credential_theft, unauthorized_access
        assert graph["stats"]["impact_nodes"] >= 3

    def test_top_paths_ranked_by_score(self):
        correlated = {
            "findings": [
                {
                    "id": "finding-0000",
                    "file_path": "a.py",
                    "severity": "high",
                    "corroborated": False,
                    "contributing_tools": ["CodeScan"],
                    "finding_types": ["sql_injection"],
                    "evidence_count": 1,
                    "evidence": [],
                },
                {
                    "id": "finding-0001",
                    "file_path": "b.py",
                    "severity": "low",
                    "corroborated": False,
                    "contributing_tools": ["CodeScan"],
                    "finding_types": ["weak_cryptography"],
                    "evidence_count": 1,
                    "evidence": [],
                },
            ],
            "cross_tool_correlations": [],
        }
        graph = build_attack_graph(correlated)
        if len(graph["top_paths"]) >= 2:
            # First path should have higher or equal score
            assert graph["top_paths"][0]["risk_score"] >= graph["top_paths"][1]["risk_score"]

    def test_impact_nodes_not_duplicated(self):
        """Multiple findings leading to the same impact should share the impact node."""
        correlated = {
            "findings": [
                {
                    "id": "finding-0000",
                    "file_path": "a.py",
                    "severity": "high",
                    "corroborated": False,
                    "contributing_tools": ["CodeScan"],
                    "finding_types": ["hardcoded_secret"],
                    "evidence_count": 1,
                    "evidence": [],
                },
                {
                    "id": "finding-0001",
                    "file_path": "b.py",
                    "severity": "high",
                    "corroborated": False,
                    "contributing_tools": ["ScreenshotAnalyzer"],
                    "finding_types": ["secret_exposure"],
                    "evidence_count": 1,
                    "evidence": [],
                },
            ],
            "cross_tool_correlations": [],
        }
        graph = build_attack_graph(correlated)
        impact_ids = [n["id"] for n in graph["nodes"] if n["node_type"] == "impact"]
        # credential_theft should appear only once
        assert len(impact_ids) == len(set(impact_ids))


class TestIntegrationWithCorrelator:
    def test_full_pipeline_codescan_to_graph(self):
        """Simulate CodeScan → correlate → graph."""
        tr = build_tool_result(
            "CodeScan",
            {"total_findings": 2},
            [
                build_evidence("e1", "code", file_path="app.py",
                               note="[HIGH] SECRET_ASSIGNMENT: Hardcoded secret"),
                build_evidence("e2", "code", file_path="db.py",
                               note="[HIGH] SQLI: sql_injection via f-string"),
            ],
            {"has_secrets": True, "has_sqli": True},
        )
        correlated = correlate_findings([tr])
        graph = build_attack_graph(correlated)

        assert graph["stats"]["node_count"] > 0
        assert graph["stats"]["vuln_nodes"] == 2
        assert len(graph["top_paths"]) > 0
        # Every path should have entry → vuln → impact (length 3)
        for path in graph["top_paths"]:
            assert path["length"] == 3
            assert path["path"][0]["type"] == "entry"
            assert path["path"][1]["type"] == "vulnerability"
            assert path["path"][2]["type"] == "impact"


class TestHelpers:
    def test_sanitize_node_id(self):
        assert _sanitize_node_id("vuln_finding-0001") == "vuln_finding-0001"
        assert _sanitize_node_id("path/../../../etc") == "path_.._.._.._etc"
        assert _sanitize_node_id("<script>alert(1)</script>") == "_script_alert_1___script_"

    def test_sanitize_node_id_length_limit(self):
        long_id = "a" * 200
        assert len(_sanitize_node_id(long_id)) == 100

    def test_build_vuln_label(self):
        label = _build_vuln_label(["hardcoded_secret", "sql_injection"], "app.py")
        assert "Hardcoded Secret" in label
        assert "app.py" in label

    def test_entry_type_mapping(self):
        assert _entry_type(["sql_injection"]) == "external_input"
        assert _entry_type(["hardcoded_secret"]) == "leaked_credential"
        assert _entry_type(["auth"]) == "authentication"
        assert _entry_type(["network"]) == "network_access"
        assert _entry_type(["error_exposure"]) == "unknown_entry"

    def test_entry_label(self):
        label = _entry_label(["hardcoded_secret"])
        assert "Leaked" in label

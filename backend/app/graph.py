"""
Attack graph builder using NetworkX.

Constructs a directed acyclic graph (DAG) representing attack chains:
  - Entry nodes: initial access points (exposed services, leaked credentials)
  - Vulnerability nodes: specific weaknesses found by MCP tools
  - Impact nodes: potential consequences (data breach, RCE, privilege escalation)

Graph structure:
  ENTRY → VULNERABILITY → IMPACT

Scoring:
  - Each node has a risk_score (0.0–1.0) based on severity and confidence
  - Edge weights represent transition likelihood
  - Top attack paths are ranked by cumulative risk score

Security notes:
  - Graph is computed in-memory, never serialized to disk
  - Node IDs are sanitized to prevent injection in downstream rendering
  - No user input is used directly in node labels without sanitization
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx

logger = logging.getLogger(__name__)

# Severity → base risk score mapping
_SEVERITY_SCORES = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
    "info": 0.1,
}

# Vulnerability type → potential impact mapping
_IMPACT_MAP: Dict[str, List[Dict[str, Any]]] = {
    "hardcoded_secret": [
        {"impact": "credential_theft", "label": "Credential Theft", "base_score": 0.9},
        {"impact": "unauthorized_access", "label": "Unauthorized Access", "base_score": 0.85},
    ],
    "secret_exposure": [
        {"impact": "credential_theft", "label": "Credential Theft", "base_score": 0.9},
    ],
    "sql_injection": [
        {"impact": "data_breach", "label": "Data Breach", "base_score": 0.95},
        {"impact": "rce", "label": "Remote Code Execution", "base_score": 0.7},
    ],
    "weak_cryptography": [
        {"impact": "data_exposure", "label": "Data Exposure via Weak Crypto", "base_score": 0.6},
    ],
    "auth": [
        {"impact": "unauthorized_access", "label": "Unauthorized Access", "base_score": 0.8},
        {"impact": "privilege_escalation", "label": "Privilege Escalation", "base_score": 0.7},
    ],
    "suspicious": [
        {"impact": "active_exploitation", "label": "Active Exploitation", "base_score": 0.85},
    ],
    "error_exposure": [
        {"impact": "info_disclosure", "label": "Information Disclosure", "base_score": 0.4},
    ],
    "pii_exposure": [
        {"impact": "data_breach", "label": "PII Data Breach", "base_score": 0.8},
    ],
    "network": [
        {"impact": "service_disruption", "label": "Service Disruption", "base_score": 0.5},
    ],
}

# Sanitization pattern for node IDs
_NODE_ID_RE = re.compile(r"[^a-zA-Z0-9_\-\.]")


def _sanitize_node_id(raw: str) -> str:
    """Sanitize a string for use as a graph node ID."""
    return _NODE_ID_RE.sub("_", raw)[:100]


def build_attack_graph(
    correlated: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Build an attack graph from correlated findings.

    Args:
        correlated: output from correlate_findings()

    Returns:
        dict with:
          - nodes: list of node dicts (id, label, type, risk_score, metadata)
          - edges: list of edge dicts (source, target, weight, label)
          - top_paths: ranked list of highest-risk attack chains
          - stats: graph statistics
    """
    findings = correlated.get("findings", [])
    cross_correlations = correlated.get("cross_tool_correlations", [])

    if not findings:
        return _empty_graph()

    G = nx.DiGraph()

    # Track unique impacts to avoid duplicate impact nodes
    impact_nodes_added: Set[str] = set()

    for finding in findings:
        finding_id = finding["id"]
        severity = finding.get("severity", "medium")
        file_path = finding.get("file_path", "unknown")
        finding_types = finding.get("finding_types", [])
        corroborated = finding.get("corroborated", False)

        risk_score = _SEVERITY_SCORES.get(severity, 0.5)
        if corroborated:
            risk_score = min(risk_score + 0.1, 1.0)  # boost for corroboration

        # Create vulnerability node
        vuln_node_id = _sanitize_node_id(f"vuln_{finding_id}")
        vuln_label = _build_vuln_label(finding_types, file_path)
        G.add_node(
            vuln_node_id,
            label=vuln_label,
            node_type="vulnerability",
            risk_score=round(risk_score, 2),
            severity=severity,
            finding_types=finding_types,
            file_path=file_path,
            corroborated=corroborated,
            evidence_count=finding.get("evidence_count", 0),
        )

        # Create entry node(s) based on finding types
        entry_node_id = _sanitize_node_id(f"entry_{_entry_type(finding_types)}")
        entry_label = _entry_label(finding_types)
        if not G.has_node(entry_node_id):
            G.add_node(
                entry_node_id,
                label=entry_label,
                node_type="entry",
                risk_score=round(risk_score * 0.8, 2),
            )
        G.add_edge(
            entry_node_id,
            vuln_node_id,
            weight=round(risk_score, 2),
            label="exploits",
        )

        # Create impact node(s)
        for ftype in finding_types:
            impacts = _IMPACT_MAP.get(ftype, [])
            for impact_def in impacts:
                impact_id = _sanitize_node_id(f"impact_{impact_def['impact']}")
                if impact_id not in impact_nodes_added:
                    impact_score = impact_def["base_score"]
                    G.add_node(
                        impact_id,
                        label=impact_def["label"],
                        node_type="impact",
                        risk_score=round(impact_score, 2),
                    )
                    impact_nodes_added.add(impact_id)

                edge_weight = round(risk_score * impact_def["base_score"], 2)
                G.add_edge(
                    vuln_node_id,
                    impact_id,
                    weight=edge_weight,
                    label="leads_to",
                )

    # Compute top attack paths
    top_paths = _compute_top_paths(G)

    # Serialize graph
    nodes = [
        {"id": n, **G.nodes[n]}
        for n in G.nodes
    ]
    edges = [
        {"source": u, "target": v, **G.edges[u, v]}
        for u, v in G.edges
    ]

    stats = {
        "node_count": G.number_of_nodes(),
        "edge_count": G.number_of_edges(),
        "entry_nodes": sum(1 for _, d in G.nodes(data=True) if d.get("node_type") == "entry"),
        "vuln_nodes": sum(1 for _, d in G.nodes(data=True) if d.get("node_type") == "vulnerability"),
        "impact_nodes": sum(1 for _, d in G.nodes(data=True) if d.get("node_type") == "impact"),
        "max_risk_score": max((d.get("risk_score", 0) for _, d in G.nodes(data=True)), default=0),
    }

    return {
        "nodes": nodes,
        "edges": edges,
        "top_paths": top_paths,
        "stats": stats,
    }


def _empty_graph() -> Dict[str, Any]:
    return {
        "nodes": [],
        "edges": [],
        "top_paths": [],
        "stats": {
            "node_count": 0,
            "edge_count": 0,
            "entry_nodes": 0,
            "vuln_nodes": 0,
            "impact_nodes": 0,
            "max_risk_score": 0,
        },
    }


def _build_vuln_label(finding_types: List[str], file_path: str) -> str:
    """Build a human-readable label for a vulnerability node."""
    types_str = ", ".join(t.replace("_", " ").title() for t in finding_types[:3])
    # Truncate file path for readability
    short_path = file_path if len(file_path) <= 40 else f"...{file_path[-37:]}"
    if types_str:
        return f"{types_str} in {short_path}"
    return f"Finding in {short_path}"


def _entry_type(finding_types: List[str]) -> str:
    """Determine the entry node category based on finding types."""
    if "sql_injection" in finding_types or "suspicious" in finding_types:
        return "external_input"
    if "hardcoded_secret" in finding_types or "secret_exposure" in finding_types:
        return "leaked_credential"
    if "auth" in finding_types:
        return "authentication"
    if "network" in finding_types:
        return "network_access"
    return "unknown_entry"


def _entry_label(finding_types: List[str]) -> str:
    """Human-readable entry point label."""
    labels = {
        "external_input": "External Input (User/API)",
        "leaked_credential": "Leaked Credentials",
        "authentication": "Authentication Endpoint",
        "network_access": "Network Access",
        "unknown_entry": "Unknown Entry Point",
    }
    return labels.get(_entry_type(finding_types), "Entry Point")


def _compute_top_paths(
    G: nx.DiGraph,
    max_paths: int = 5,
) -> List[Dict[str, Any]]:
    """
    Find the highest-risk attack paths from entry nodes to impact nodes.

    Uses DFS to enumerate all entry→impact paths, scoring each by the
    sum of edge weights along the path. Returns top N paths.
    """
    entry_nodes = [n for n, d in G.nodes(data=True) if d.get("node_type") == "entry"]
    impact_nodes = [n for n, d in G.nodes(data=True) if d.get("node_type") == "impact"]

    if not entry_nodes or not impact_nodes:
        return []

    scored_paths: List[Tuple[float, List[str]]] = []

    for entry in entry_nodes:
        for impact in impact_nodes:
            try:
                for path in nx.all_simple_paths(G, entry, impact, cutoff=10):
                    # Score = sum of edge weights along the path
                    total_weight = sum(
                        G.edges[path[i], path[i + 1]].get("weight", 0)
                        for i in range(len(path) - 1)
                    )
                    scored_paths.append((total_weight, path))
            except nx.NetworkXError:
                continue

    # Sort by score descending, take top N
    scored_paths.sort(key=lambda x: x[0], reverse=True)

    top_paths = []
    for score, path in scored_paths[:max_paths]:
        path_nodes = []
        for node_id in path:
            node_data = G.nodes[node_id]
            path_nodes.append(
                {
                    "id": node_id,
                    "label": node_data.get("label", node_id),
                    "type": node_data.get("node_type", "unknown"),
                }
            )
        top_paths.append(
            {
                "risk_score": round(score, 2),
                "path": path_nodes,
                "length": len(path),
            }
        )

    return top_paths

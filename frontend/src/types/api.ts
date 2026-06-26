/**
 * Shared TypeScript types matching the backend API response shapes.
 * These are the contracts between frontend and backend.
 */

// --- Evidence ---

export type EvidenceKind =
  | "code"
  | "log"
  | "runtime"
  | "ocr"
  | "image_text"
  | "screenshot"
  | "diagram"
  | "other";

export interface Evidence {
  id: string;
  kind: EvidenceKind;
  file_path: string;
  line: number;
  snippet: string;
  note: string;
}

// --- Findings ---

export interface Finding {
  id: string;
  file_path: string;
  severity: Severity;
  corroborated: boolean;
  contributing_tools: string[];
  finding_types: string[];
  evidence_count: number;
  evidence: Evidence[];
}

export type Severity = "critical" | "high" | "medium" | "low" | "info" | "none";

// --- Attack Graph ---

export interface GraphNode {
  id: string;
  label: string;
  node_type: "entry" | "vulnerability" | "impact";
  risk_score: number;
  severity?: Severity;
  finding_types?: string[];
  file_path?: string;
  corroborated?: boolean;
  evidence_count?: number;
}

export interface GraphEdge {
  source: string;
  target: string;
  weight: number;
  label: string;
}

export interface AttackPath {
  risk_score: number;
  path: { id: string; label: string; type: string }[];
  length: number;
}

export interface AttackGraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  top_paths: AttackPath[];
  stats: {
    node_count: number;
    edge_count: number;
    entry_nodes: number;
    vuln_nodes: number;
    impact_nodes: number;
    max_risk_score: number;
  };
}

// --- Patches ---

export interface Patch {
  patch_id: string;
  file_path: string;
  vulnerability_type: string;
  description: string;
  original: string;
  fixed: string;
  diff: string;
  confidence: number;
  requires_review: boolean;
}

// --- Cross-tool Correlations ---

export interface CrossCorrelation {
  signals: string[];
  description: string;
  severity_impact: string;
}

// --- Timeline ---

export interface TimelineEvent {
  ts: string;
  stage: string;
  message: string;
  status: string;
}

// --- Summary ---

export interface Summary {
  total_findings: number;
  total_evidence: number;
  tools_invoked: string[];
  severity_breakdown: Record<string, number>;
  corroborated_count: number;
  cross_tool_correlations: number;
}

// --- API Responses ---

export interface AnalyzeResponse {
  job_id: string;
  status: string;
}

export interface JobStatusResponse {
  job_id: string;
  status: string;
  timeline: TimelineEvent[];
}

export interface JobResultResponse {
  job_id: string;
  status: string;
  findings: Finding[];
  summary: Summary;
  cross_tool_correlations: CrossCorrelation[];
  graph: AttackGraphData;
  patches: Patch[];
  timeline: TimelineEvent[];
  error?: string;
}

export interface JobInputsResponse {
  job_id: string;
  repo_path: string | null;
  log_path: string | null;
  screenshot_path: string | null;
  diagram_path: string | null;
}

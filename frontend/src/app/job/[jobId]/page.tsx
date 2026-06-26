"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { getJobResult, ApiError } from "@/lib/api-client";
import { useJobEvents } from "@/hooks/useJobEvents";
import type { JobResultResponse, Finding, Severity } from "@/types/api";
import { AttackGraph } from "@/components/AttackGraph";
import { EvidenceViewer } from "@/components/EvidenceViewer";
import { PatchViewer } from "@/components/PatchViewer";

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
  none: 5,
};

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5)
  );
}

export default function JobPage() {
  const params = useParams();
  const jobId = typeof params.jobId === "string" ? params.jobId : null;

  const { events, status: sseStatus } = useJobEvents(jobId);
  const [result, setResult] = useState<JobResultResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [activeTab, setActiveTab] = useState<"findings" | "graph" | "patches">("findings");

  // Fetch full result once SSE says done/error, or on mount for completed jobs
  useEffect(() => {
    if (!jobId) return;

    async function fetchResult() {
      try {
        const data = await getJobResult(jobId!);
        setResult(data);
        if (data.error) {
          setError(data.error);
        }
      } catch (err) {
        if (err instanceof ApiError) {
          setError(`Failed to load results (${err.status})`);
        } else {
          setError("Failed to load results");
        }
      }
    }

    // On mount, always try fetching (job might already be done)
    fetchResult();
  }, [jobId]);

  // Re-fetch when SSE signals completion
  useEffect(() => {
    if (!jobId) return;
    if (sseStatus === "done" || sseStatus === "error") {
      getJobResult(jobId).then(setResult).catch(() => {});
    }
  }, [jobId, sseStatus]);

  if (!jobId) {
    return <p>Invalid job ID.</p>;
  }

  const isRunning = sseStatus === "connecting" || sseStatus === "streaming";
  const findings = result?.findings ?? [];
  const sorted = sortFindings(findings);

  return (
    <div>
      <div className="page-header">
        <div className="page-header-row">
          <div>
            <h1 className="page-title">
              Job <code className="job-id">{jobId}</code>
            </h1>
            <p className="page-subtitle">
              {isRunning ? "Analysis in progress..." : result?.status ?? "Loading..."}
            </p>
          </div>
          <Link href="/" className="btn btn-secondary">
            Back
          </Link>
        </div>
      </div>

      {/* Timeline / live events */}
      {events.length > 0 && (
        <div className="card timeline-card">
          <div className="card-title">Timeline</div>
          <ul className="timeline">
            {events.map((ev, i) => (
              <li key={i} className="timeline-item">
                <span
                  className={`status-dot status-dot--${ev.status}`}
                />
                <span className="timeline-stage">{ev.stage}</span>
                <span className="timeline-message">{ev.message}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {error && <p className="form-error">{error}</p>}

      {/* Summary stats */}
      {result?.summary && (
        <div className="summary-grid">
          <div className="summary-stat card">
            <div className="summary-stat-value">
              {result.summary.total_findings}
            </div>
            <div className="summary-stat-label">Findings</div>
          </div>
          <div className="summary-stat card">
            <div className="summary-stat-value">
              {result.summary.total_evidence}
            </div>
            <div className="summary-stat-label">Evidence</div>
          </div>
          <div className="summary-stat card">
            <div className="summary-stat-value">
              {result.summary.corroborated_count}
            </div>
            <div className="summary-stat-label">Corroborated</div>
          </div>
          <div className="summary-stat card">
            <div className="summary-stat-value">
              {result.summary.cross_tool_correlations}
            </div>
            <div className="summary-stat-label">Cross-tool</div>
          </div>
        </div>
      )}

      {/* Tab navigation */}
      {result && result.status === "done" && (
        <>
          <div className="tab-bar">
            <button
              className={`tab-btn${activeTab === "findings" ? " tab-btn--active" : ""}`}
              onClick={() => setActiveTab("findings")}
            >
              Findings ({findings.length})
            </button>
            <button
              className={`tab-btn${activeTab === "graph" ? " tab-btn--active" : ""}`}
              onClick={() => setActiveTab("graph")}
            >
              Attack Graph
            </button>
            <button
              className={`tab-btn${activeTab === "patches" ? " tab-btn--active" : ""}`}
              onClick={() => setActiveTab("patches")}
            >
              Patches ({result.patches?.length ?? 0})
            </button>
          </div>

          {/* Findings tab */}
          {activeTab === "findings" && (
            <div className="findings-section">
              {sorted.length === 0 ? (
                <p className="empty-state-text">No findings.</p>
              ) : (
                <div className="findings-list">
                  {sorted.map((f) => (
                    <button
                      key={f.id}
                      className={`finding-row card${
                        selectedFinding?.id === f.id ? " finding-row--selected" : ""
                      }`}
                      onClick={() =>
                        setSelectedFinding(
                          selectedFinding?.id === f.id ? null : f
                        )
                      }
                    >
                      <div className="finding-row-header">
                        <span className={`badge badge-${f.severity}`}>
                          {f.severity}
                        </span>
                        <code className="finding-file">{f.file_path}</code>
                        {f.corroborated && (
                          <span className="badge badge-info" title="Corroborated across tools">
                            corroborated
                          </span>
                        )}
                      </div>
                      <div className="finding-row-meta">
                        <span>{f.evidence_count} evidence</span>
                        <span>{f.contributing_tools.join(", ")}</span>
                      </div>
                    </button>
                  ))}
                </div>
              )}

              {selectedFinding && (
                <EvidenceViewer
                  finding={selectedFinding}
                  jobId={jobId}
                  onClose={() => setSelectedFinding(null)}
                />
              )}
            </div>
          )}

          {/* Graph tab */}
          {activeTab === "graph" && result.graph && (
            <AttackGraph data={result.graph} />
          )}

          {/* Patches tab */}
          {activeTab === "patches" && (
            <PatchViewer patches={result.patches ?? []} />
          )}
        </>
      )}
    </div>
  );
}

"use client";

import { evidenceFileUrl } from "@/lib/api-client";
import type { Finding, Evidence } from "@/types/api";

interface EvidenceViewerProps {
  finding: Finding;
  jobId: string;
  onClose: () => void;
}

/**
 * Side panel that displays evidence items for a selected finding.
 * Screenshots are rendered as images via the backend evidence endpoint.
 * Code/log evidence is displayed as formatted snippets.
 */
export function EvidenceViewer({ finding, jobId, onClose }: EvidenceViewerProps) {
  return (
    <div className="evidence-panel card">
      <div className="evidence-panel-header">
        <div>
          <span className={`badge badge-${finding.severity}`}>
            {finding.severity}
          </span>
          <code className="evidence-panel-file">{finding.file_path}</code>
        </div>
        <button
          className="btn btn-secondary btn-sm"
          onClick={onClose}
          aria-label="Close evidence panel"
        >
          Close
        </button>
      </div>

      {finding.corroborated && (
        <p className="evidence-corroborated">
          Corroborated across: {finding.contributing_tools.join(", ")}
        </p>
      )}

      <div className="evidence-list">
        {finding.evidence.length === 0 ? (
          <p className="empty-state-text">No evidence items.</p>
        ) : (
          finding.evidence.map((ev) => (
            <EvidenceItem key={ev.id} evidence={ev} jobId={jobId} />
          ))
        )}
      </div>
    </div>
  );
}

// --- Evidence item ---

function EvidenceItem({
  evidence,
  jobId,
}: {
  evidence: Evidence;
  jobId: string;
}) {
  const isScreenshot = evidence.kind === "screenshot" || evidence.kind === "image_text";

  return (
    <div className="evidence-item">
      <div className="evidence-item-header">
        <span className="evidence-kind-badge">{evidence.kind}</span>
        {evidence.line > 0 && (
          <span className="evidence-line">line {evidence.line}</span>
        )}
      </div>

      {evidence.note && (
        <p className="evidence-note">{evidence.note}</p>
      )}

      {evidence.snippet && (
        <pre className="evidence-snippet">
          <code>{evidence.snippet}</code>
        </pre>
      )}

      {isScreenshot && (
        <div className="evidence-screenshot">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img
            src={evidenceFileUrl(jobId, evidence.id)}
            alt={`Evidence ${evidence.id}`}
            className="evidence-screenshot-img"
            loading="lazy"
          />
        </div>
      )}
    </div>
  );
}

"use client";

import { useState } from "react";
import type { Patch } from "@/types/api";

interface PatchViewerProps {
  patches: Patch[];
}

/**
 * Displays generated patches as unified diffs with copy-to-clipboard.
 */
export function PatchViewer({ patches }: PatchViewerProps) {
  if (patches.length === 0) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">⬡</div>
        <p className="empty-state-text">No patches generated.</p>
      </div>
    );
  }

  return (
    <div className="patches-list">
      {patches.map((patch) => (
        <PatchCard key={patch.patch_id} patch={patch} />
      ))}
    </div>
  );
}

// --- Individual patch card ---

function PatchCard({ patch }: { patch: Patch }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(patch.diff);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API may not be available
    }
  }

  return (
    <div className="patch-card card">
      <div className="patch-card-header">
        <div>
          <code className="patch-file">{patch.file_path}</code>
          <span className="patch-vuln-type">{patch.vulnerability_type}</span>
        </div>
        <div className="patch-card-actions">
          {patch.requires_review && (
            <span className="badge badge-medium">needs review</span>
          )}
          <span className="patch-confidence">
            {(patch.confidence * 100).toFixed(0)}% confidence
          </span>
        </div>
      </div>

      <p className="patch-description">{patch.description}</p>

      <div className="patch-diff-container">
        <div className="patch-diff-header">
          <span>Unified Diff</span>
          <button
            className="btn btn-secondary btn-sm"
            onClick={handleCopy}
          >
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
        <pre className="patch-diff">
          <code>
            {patch.diff.split("\n").map((line, i) => (
              <span
                key={i}
                className={
                  line.startsWith("+")
                    ? "diff-add"
                    : line.startsWith("-")
                    ? "diff-remove"
                    : line.startsWith("@@")
                    ? "diff-hunk"
                    : ""
                }
              >
                {line}
                {"\n"}
              </span>
            ))}
          </code>
        </pre>
      </div>
    </div>
  );
}

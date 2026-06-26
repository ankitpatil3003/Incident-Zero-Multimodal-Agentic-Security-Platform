"use client";

import { useState, useRef, FormEvent } from "react";
import { useRouter } from "next/navigation";
import { submitAnalysisWithFiles, ApiError } from "@/lib/api-client";
import { persistJobId } from "@/app/page";

/** Max file size enforced client-side (50 MB, matches backend). */
const MAX_FILE_SIZE = 50 * 1024 * 1024;

const ALLOWED_LOG_EXTENSIONS = [".log", ".txt", ".json", ".csv"];
const ALLOWED_IMAGE_EXTENSIONS = [".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".webp"];

function validateFileExtension(file: File, allowed: string[]): string | null {
  const ext = file.name.slice(file.name.lastIndexOf(".")).toLowerCase();
  if (!allowed.includes(ext)) {
    return `"${file.name}" has disallowed extension. Allowed: ${allowed.join(", ")}`;
  }
  return null;
}

function validateFileSize(file: File): string | null {
  if (file.size > MAX_FILE_SIZE) {
    return `"${file.name}" exceeds 50 MB limit`;
  }
  return null;
}

export default function UploadPage() {
  const router = useRouter();
  const [repoPath, setRepoPath] = useState("");
  const [logFile, setLogFile] = useState<File | null>(null);
  const [screenshotFile, setScreenshotFile] = useState<File | null>(null);
  const [diagramFile, setDiagramFile] = useState<File | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const logRef = useRef<HTMLInputElement>(null);
  const screenshotRef = useRef<HTMLInputElement>(null);
  const diagramRef = useRef<HTMLInputElement>(null);

  function handleFileSelect(
    e: React.ChangeEvent<HTMLInputElement>,
    allowed: string[],
    setter: (f: File | null) => void
  ) {
    setError(null);
    const file = e.target.files?.[0] ?? null;
    if (!file) {
      setter(null);
      return;
    }
    const extErr = validateFileExtension(file, allowed);
    if (extErr) {
      setError(extErr);
      e.target.value = "";
      return;
    }
    const sizeErr = validateFileSize(file);
    if (sizeErr) {
      setError(sizeErr);
      e.target.value = "";
      return;
    }
    setter(file);
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);

    const trimmedRepo = repoPath.trim();
    if (!trimmedRepo && !logFile && !screenshotFile && !diagramFile) {
      setError("Provide at least one input: repo path, log file, screenshot, or diagram.");
      return;
    }

    setSubmitting(true);
    try {
      const res = await submitAnalysisWithFiles({
        repo_path: trimmedRepo || undefined,
        log_file: logFile ?? undefined,
        screenshot_file: screenshotFile ?? undefined,
        diagram_file: diagramFile ?? undefined,
      });
      persistJobId(res.job_id);
      router.push(`/job/${res.job_id}`);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(`Server error (${err.status}): ${err.body}`);
      } else {
        setError("Failed to submit. Is the backend running?");
      }
      setSubmitting(false);
    }
  }

  function clearFile(
    setter: (f: File | null) => void,
    ref: React.RefObject<HTMLInputElement | null>
  ) {
    setter(null);
    if (ref.current) ref.current.value = "";
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">New Scan</h1>
        <p className="page-subtitle">
          Upload evidence for security analysis
        </p>
      </div>

      <form onSubmit={handleSubmit} className="upload-form card">
        {/* Repo path */}
        <div className="form-group">
          <label className="form-label" htmlFor="repo-path">
            Repository path (local directory)
          </label>
          <input
            id="repo-path"
            type="text"
            className="form-input"
            placeholder="/path/to/repo"
            value={repoPath}
            onChange={(e) => setRepoPath(e.target.value)}
            autoComplete="off"
          />
        </div>

        {/* Log file */}
        <div className="form-group">
          <label className="form-label" htmlFor="log-file">
            Log file
            <span className="form-hint"> ({ALLOWED_LOG_EXTENSIONS.join(", ")})</span>
          </label>
          <div className="file-input-row">
            <input
              id="log-file"
              ref={logRef}
              type="file"
              accept={ALLOWED_LOG_EXTENSIONS.join(",")}
              className="form-input file-input"
              onChange={(e) => handleFileSelect(e, ALLOWED_LOG_EXTENSIONS, setLogFile)}
            />
            {logFile && (
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => clearFile(setLogFile, logRef)}
              >
                Clear
              </button>
            )}
          </div>
        </div>

        {/* Screenshot */}
        <div className="form-group">
          <label className="form-label" htmlFor="screenshot-file">
            Screenshot
            <span className="form-hint"> ({ALLOWED_IMAGE_EXTENSIONS.join(", ")})</span>
          </label>
          <div className="file-input-row">
            <input
              id="screenshot-file"
              ref={screenshotRef}
              type="file"
              accept={ALLOWED_IMAGE_EXTENSIONS.join(",")}
              className="form-input file-input"
              onChange={(e) =>
                handleFileSelect(e, ALLOWED_IMAGE_EXTENSIONS, setScreenshotFile)
              }
            />
            {screenshotFile && (
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => clearFile(setScreenshotFile, screenshotRef)}
              >
                Clear
              </button>
            )}
          </div>
        </div>

        {/* Diagram */}
        <div className="form-group">
          <label className="form-label" htmlFor="diagram-file">
            Architecture diagram
            <span className="form-hint"> ({ALLOWED_IMAGE_EXTENSIONS.join(", ")})</span>
          </label>
          <div className="file-input-row">
            <input
              id="diagram-file"
              ref={diagramRef}
              type="file"
              accept={ALLOWED_IMAGE_EXTENSIONS.join(",")}
              className="form-input file-input"
              onChange={(e) =>
                handleFileSelect(e, ALLOWED_IMAGE_EXTENSIONS, setDiagramFile)
              }
            />
            {diagramFile && (
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => clearFile(setDiagramFile, diagramRef)}
              >
                Clear
              </button>
            )}
          </div>
        </div>

        {error && <p className="form-error">{error}</p>}

        <button
          type="submit"
          className="btn btn-primary"
          disabled={submitting}
        >
          {submitting ? "Submitting..." : "Start Analysis"}
        </button>
      </form>
    </div>
  );
}

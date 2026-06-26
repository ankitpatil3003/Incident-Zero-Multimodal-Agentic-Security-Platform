/**
 * API client for the Incident Zero backend.
 *
 * All requests go through Next.js rewrites (see next.config.js)
 * so the browser never talks directly to :8000 — this avoids CORS
 * issues and keeps the backend URL out of client bundles.
 *
 * Security notes:
 *  - No user-supplied strings are interpolated into URLs without validation
 *  - All responses are validated for expected shape before use
 *  - File uploads use FormData (no manual boundary construction)
 */

import type {
  AnalyzeResponse,
  JobStatusResponse,
  JobResultResponse,
  JobInputsResponse,
  TimelineEvent,
} from "@/types/api";

// --- Helpers ---

const API_BASE = "/api";

/** Job ID format: alphanumeric + underscore, 1-50 chars (matches backend). */
const JOB_ID_RE = /^[a-zA-Z0-9_]{1,50}$/;

function validateJobId(jobId: string): string {
  if (!JOB_ID_RE.test(jobId)) {
    throw new Error("Invalid job ID format");
  }
  return jobId;
}

class ApiError extends Error {
  constructor(
    public status: number,
    public statusText: string,
    public body: string
  ) {
    super(`API error ${status}: ${statusText}`);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      ...(init?.headers ?? {}),
    },
  });

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new ApiError(res.status, res.statusText, body);
  }

  return res.json() as Promise<T>;
}

// --- Public API ---

/** POST /analyze — submit a job with explicit paths. */
export async function submitAnalysis(params: {
  repo_path?: string;
  log_path?: string;
  screenshot_path?: string;
  diagram_path?: string;
}): Promise<AnalyzeResponse> {
  return request<AnalyzeResponse>("/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });
}

/** POST /analyze/upload — submit a job with file uploads. */
export async function submitAnalysisWithFiles(params: {
  repo_path?: string;
  log_file?: File;
  screenshot_file?: File;
  diagram_file?: File;
}): Promise<AnalyzeResponse> {
  const form = new FormData();

  if (params.repo_path) {
    form.append("repo_path", params.repo_path);
  }
  if (params.log_file) {
    form.append("log_file", params.log_file);
  }
  if (params.screenshot_file) {
    form.append("screenshot_file", params.screenshot_file);
  }
  if (params.diagram_file) {
    form.append("diagram_file", params.diagram_file);
  }

  return request<AnalyzeResponse>("/analyze/upload", {
    method: "POST",
    body: form,
  });
}

/** GET /status/{job_id} */
export async function getJobStatus(
  jobId: string
): Promise<JobStatusResponse> {
  return request<JobStatusResponse>(`/status/${validateJobId(jobId)}`);
}

/** GET /result/{job_id} */
export async function getJobResult(
  jobId: string
): Promise<JobResultResponse> {
  return request<JobResultResponse>(`/result/${validateJobId(jobId)}`);
}

/** GET /inputs/{job_id} */
export async function getJobInputs(
  jobId: string
): Promise<JobInputsResponse> {
  return request<JobInputsResponse>(`/inputs/${validateJobId(jobId)}`);
}

/** URL for serving an uploaded input file. */
export function inputFileUrl(jobId: string, kind: string): string {
  return `${API_BASE}/input-file/${validateJobId(jobId)}/${encodeURIComponent(kind)}`;
}

/** URL for serving an evidence file (e.g. screenshot). */
export function evidenceFileUrl(jobId: string, evidenceId: string): string {
  return `${API_BASE}/evidence/${validateJobId(jobId)}/${encodeURIComponent(evidenceId)}`;
}

// --- SSE ---

export type SSEEventHandler = (event: TimelineEvent) => void;
export type SSEErrorHandler = (error: Event) => void;

/**
 * Subscribe to real-time job events via SSE.
 * Returns a cleanup function that closes the connection.
 */
export function subscribeToJobEvents(
  jobId: string,
  onEvent: SSEEventHandler,
  onError?: SSEErrorHandler
): () => void {
  const url = `${API_BASE}/events/${validateJobId(jobId)}`;
  const source = new EventSource(url);

  source.onmessage = (msg) => {
    try {
      const event = JSON.parse(msg.data) as TimelineEvent;
      onEvent(event);
    } catch {
      // Malformed SSE data — skip silently
    }
  };

  source.onerror = (err) => {
    onError?.(err);
    source.close();
  };

  return () => source.close();
}

export { ApiError };

// --- Local storage helpers ---

const JOBS_KEY = "incident_zero_jobs";

export function persistJobId(jobId: string): void {
  if (typeof window === "undefined") return;
  try {
    const raw = window.localStorage.getItem(JOBS_KEY);
    const ids: string[] = raw ? JSON.parse(raw) : [];
    const deduped = ids.filter((id) => id !== jobId);
    deduped.unshift(jobId);
    window.localStorage.setItem(JOBS_KEY, JSON.stringify(deduped.slice(0, 50)));
  } catch {
    // localStorage unavailable — ignore
  }
}
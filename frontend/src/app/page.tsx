"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { getJobStatus, ApiError } from "@/lib/api-client";
import type { JobStatusResponse } from "@/types/api";

/** Local storage key for persisting known job IDs across page reloads. */
const JOBS_KEY = "incident_zero_jobs";

function loadJobIds(): string[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(JOBS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

/** Save a new job ID to the persisted list (most recent first, max 50). */
export function persistJobId(jobId: string): void {
  const ids = loadJobIds().filter((id) => id !== jobId);
  ids.unshift(jobId);
  const trimmed = ids.slice(0, 50);
  window.localStorage.setItem(JOBS_KEY, JSON.stringify(trimmed));
}

interface JobRow {
  jobId: string;
  status: string;
  lastStage: string;
  lastMessage: string;
  loading: boolean;
  error: string | null;
}

export default function DashboardPage() {
  const [jobs, setJobs] = useState<JobRow[]>([]);
  const [loaded, setLoaded] = useState(false);

  const fetchJobs = useCallback(async () => {
    const ids = loadJobIds();
    if (ids.length === 0) {
      setJobs([]);
      setLoaded(true);
      return;
    }

    const rows: JobRow[] = ids.map((id) => ({
      jobId: id,
      status: "unknown",
      lastStage: "",
      lastMessage: "",
      loading: true,
      error: null,
    }));
    setJobs(rows);

    const settled = await Promise.allSettled(
      ids.map((id) => getJobStatus(id))
    );

    const updated = ids.map((id, i) => {
      const result = settled[i];
      if (result.status === "fulfilled") {
        const data = result.value;
        const last =
          data.timeline.length > 0
            ? data.timeline[data.timeline.length - 1]
            : null;
        return {
          jobId: id,
          status: data.status,
          lastStage: last?.stage ?? "",
          lastMessage: last?.message ?? "",
          loading: false,
          error: null,
        };
      }
      return {
        jobId: id,
        status: "unknown",
        lastStage: "",
        lastMessage:
          result.reason instanceof ApiError
            ? result.reason.message
            : "Failed to fetch",
        loading: false,
        error: "unreachable",
      };
    });

    setJobs(updated);
    setLoaded(true);
  }, []);

  useEffect(() => {
    fetchJobs();
  }, [fetchJobs]);

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Dashboard</h1>
        <p className="page-subtitle">Recent security analysis jobs</p>
      </div>

      {!loaded ? (
        <p className="empty-state-text">Loading...</p>
      ) : jobs.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-icon">⬡</div>
          <p className="empty-state-text">
            No jobs yet.{" "}
            <Link href="/upload">Start a new scan</Link> to begin.
          </p>
        </div>
      ) : (
        <div className="jobs-list">
          {jobs.map((job) => (
            <Link
              key={job.jobId}
              href={`/job/${job.jobId}`}
              className="job-card card"
            >
              <div className="job-card-header">
                <code className="job-id">{job.jobId}</code>
                <span
                  className={`status-dot status-dot--${job.status}`}
                  title={job.status}
                />
              </div>
              {job.loading ? (
                <p className="job-card-detail">Loading...</p>
              ) : job.error ? (
                <p className="job-card-detail job-card-error">
                  {job.lastMessage}
                </p>
              ) : (
                <p className="job-card-detail">
                  {job.lastStage && (
                    <span className="job-stage">{job.lastStage}</span>
                  )}
                  {job.lastMessage}
                </p>
              )}
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}

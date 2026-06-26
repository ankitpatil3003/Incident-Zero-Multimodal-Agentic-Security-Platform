"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import { subscribeToJobEvents } from "@/lib/api-client";
import type { TimelineEvent } from "@/types/api";

interface UseJobEventsResult {
  events: TimelineEvent[];
  status: "connecting" | "streaming" | "done" | "error" | "disconnected";
  lastEvent: TimelineEvent | null;
}

/**
 * Custom hook that subscribes to SSE events for a job.
 *
 * Automatically reconnects once on error. Stops listening
 * when the job reaches "done" or "error" status.
 */
export function useJobEvents(jobId: string | null): UseJobEventsResult {
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [status, setStatus] = useState<UseJobEventsResult["status"]>("connecting");
  const [lastEvent, setLastEvent] = useState<TimelineEvent | null>(null);
  const retriedRef = useRef(false);

  const connect = useCallback(() => {
    if (!jobId) return () => {};

    setStatus("connecting");

    const cleanup = subscribeToJobEvents(
      jobId,
      (event) => {
        setEvents((prev) => [...prev, event]);
        setLastEvent(event);
        setStatus("streaming");

        if (event.status === "done" || event.status === "error") {
          setStatus(event.status);
        }
      },
      () => {
        // On SSE error, retry once
        if (!retriedRef.current) {
          retriedRef.current = true;
          setStatus("connecting");
          // Delay retry slightly
          setTimeout(() => connect(), 1000);
        } else {
          setStatus("disconnected");
        }
      }
    );

    return cleanup;
  }, [jobId]);

  useEffect(() => {
    retriedRef.current = false;
    setEvents([]);
    setLastEvent(null);

    const cleanup = connect();
    return cleanup;
  }, [connect]);

  return { events, status, lastEvent };
}

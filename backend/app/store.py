"""
In-memory job store with pub/sub for SSE event streaming.

Jobs are ephemeral — lost on server restart. This is intentional for v1;
a persistent backend (Postgres, Redis) is a future enhancement.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4


@dataclass
class Job:
    job_id: str
    status: str
    repo_path: Optional[str]
    log_path: Optional[str]
    screenshot_path: Optional[str]
    diagram_path: Optional[str]
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    result: Dict[str, Any] = field(default_factory=dict)


class JobStore:
    """Thread-safe (GIL) in-memory store with async pub/sub per job."""

    def __init__(self) -> None:
        self._jobs: Dict[str, Job] = {}
        self._subscribers: Dict[str, List[asyncio.Queue[Dict[str, Any]]]] = {}

    def create_job(
        self,
        repo_path: Optional[str] = None,
        log_path: Optional[str] = None,
        screenshot_path: Optional[str] = None,
        diagram_path: Optional[str] = None,
    ) -> Job:
        job_id = f"job_{uuid4().hex[:8]}"
        job = Job(
            job_id=job_id,
            status="running",
            repo_path=repo_path,
            log_path=log_path,
            screenshot_path=screenshot_path,
            diagram_path=diagram_path,
        )
        self._jobs[job_id] = job
        self.add_event(job, stage="ingest", message="Evidence received", status="done")
        return job

    def get_job(self, job_id: str) -> Optional[Job]:
        return self._jobs.get(job_id)

    def add_event(self, job: Job, stage: str, message: str, status: str) -> None:
        event: Dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "stage": stage,
            "message": message,
            "status": status,
        }
        job.timeline.append(event)
        for queue in self._subscribers.get(job.job_id, []):
            queue.put_nowait(event)

    def subscribe(self, job_id: str) -> asyncio.Queue[Dict[str, Any]]:
        queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()
        self._subscribers.setdefault(job_id, []).append(queue)
        return queue

    def unsubscribe(self, job_id: str, queue: asyncio.Queue[Dict[str, Any]]) -> None:
        queues = self._subscribers.get(job_id)
        if not queues:
            return
        try:
            queues.remove(queue)
        except ValueError:
            return
        if not queues:
            self._subscribers.pop(job_id, None)


# Singleton — imported by main.py and orchestrator.py
job_store = JobStore()

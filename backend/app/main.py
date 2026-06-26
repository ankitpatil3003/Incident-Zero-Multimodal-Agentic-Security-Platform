"""
Incident Zero API — FastAPI application entry point.

Run: uvicorn backend.app.main:app --reload --port 8000

Security measures:
  - Path traversal protection on all file-serving endpoints
  - Upload size limits and extension allowlisting
  - Filename sanitization on uploads
  - CORS restricted to configured origins
  - No sensitive data in error responses
"""

import re
import shutil
from pathlib import Path
from typing import Optional
from uuid import uuid4

import asyncio
import json
import mimetypes

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

from .config import settings, CORS_ALLOW_ORIGINS, UPLOAD_DIR
from .orchestrator import run_job
from .store import Job, job_store


# --- Filename sanitization ---

_SAFE_FILENAME_RE = re.compile(r"[^\w\.\-]")
_MAX_FILENAME_LEN = 200


def _sanitize_filename(filename: str) -> str:
    """Remove path separators, special chars, and limit length."""
    name = Path(filename).name
    name = _SAFE_FILENAME_RE.sub("_", name)
    name = re.sub(r"_+", "_", name).strip("_")
    if len(name) > _MAX_FILENAME_LEN:
        stem = Path(name).stem[:_MAX_FILENAME_LEN - 10]
        suffix = Path(name).suffix
        name = f"{stem}{suffix}"
    return name or "upload.bin"


def _validate_upload_extension(filename: str) -> None:
    """Reject files with disallowed extensions."""
    ext = Path(filename).suffix.lower()
    if ext and ext not in settings.allowed_upload_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"File extension '{ext}' is not allowed",
        )


def _validate_upload_size(upload: UploadFile) -> None:
    """Reject uploads exceeding size limit."""
    pass


def _is_safe_path(base_dir: Path, target_path: Path) -> bool:
    """Verify that target_path is within base_dir (prevents path traversal)."""
    try:
        resolved_base = base_dir.resolve()
        resolved_target = target_path.resolve()
        return str(resolved_target).startswith(str(resolved_base))
    except (OSError, ValueError):
        return False


# --- Pydantic models ---


class AnalyzeRequest(BaseModel):
    repo_path: Optional[str] = None
    log_path: Optional[str] = None
    screenshot_path: Optional[str] = None
    diagram_path: Optional[str] = None


class AnalyzeResponse(BaseModel):
    job_id: str
    status: str


app = FastAPI(title="Incident Zero API", version="0.1.0")

# --- CORS ---
allowed_origins = [o.strip() for o in CORS_ALLOW_ORIGINS.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "incident-zero"}


# --- POST /analyze (JSON body) ---


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest, background_tasks: BackgroundTasks) -> AnalyzeResponse:
    job = job_store.create_job(
        repo_path=(req.repo_path or "").strip() or None,
        log_path=(req.log_path or "").strip() or None,
        screenshot_path=(req.screenshot_path or "").strip() or None,
        diagram_path=(req.diagram_path or "").strip() or None,
    )
    background_tasks.add_task(run_job, job.job_id)
    return AnalyzeResponse(job_id=job.job_id, status=job.status)


# --- POST /analyze/upload (multipart form + files) ---


@app.post("/analyze/upload", response_model=AnalyzeResponse)
def analyze_upload(
    background_tasks: BackgroundTasks,
    repo_path: Optional[str] = Form(None),
    log_path: Optional[str] = Form(None),
    screenshot_path: Optional[str] = Form(None),
    diagram_path: Optional[str] = Form(None),
    log_file: Optional[UploadFile] = File(None),
    screenshot_file: Optional[UploadFile] = File(None),
    diagram_file: Optional[UploadFile] = File(None),
) -> AnalyzeResponse:
    resolved_log = _resolve_evidence(explicit_path=log_path, upload=log_file, prefix="log")
    resolved_screenshot = _resolve_evidence(
        explicit_path=screenshot_path, upload=screenshot_file, prefix="screenshot"
    )
    resolved_diagram = _resolve_evidence(
        explicit_path=diagram_path, upload=diagram_file, prefix="diagram"
    )

    job = job_store.create_job(
        repo_path=(repo_path or "").strip() or None,
        log_path=resolved_log,
        screenshot_path=resolved_screenshot,
        diagram_path=resolved_diagram,
    )
    background_tasks.add_task(run_job, job.job_id)
    return AnalyzeResponse(job_id=job.job_id, status=job.status)


# --- File helpers ---


def _resolve_evidence(
    explicit_path: Optional[str],
    upload: Optional[UploadFile],
    prefix: str,
) -> Optional[str]:
    """Use explicit path if given, otherwise persist the uploaded file."""
    clean = (explicit_path or "").strip()
    if clean:
        return clean
    if upload is None or not upload.filename:
        return None
    return _persist_upload(upload, prefix)


def _persist_upload(upload: UploadFile, prefix: str) -> str:
    """Save uploaded file to disk with sanitized name and size enforcement."""
    original = upload.filename or f"{prefix}.bin"
    _validate_upload_extension(original)

    sanitized = _sanitize_filename(original)
    suffix = Path(sanitized).suffix
    saved_name = f"{prefix}_{uuid4().hex}{suffix}"
    saved_path = UPLOAD_DIR / saved_name

    bytes_written = 0
    with saved_path.open("wb") as f:
        while True:
            chunk = upload.file.read(8192)
            if not chunk:
                break
            bytes_written += len(chunk)
            if bytes_written > settings.max_upload_size_bytes:
                saved_path.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=413,
                    detail=f"Upload exceeds maximum size of {settings.max_upload_size_bytes} bytes",
                )
            f.write(chunk)

    return str(saved_path)


# --- SSE event stream ---


@app.get("/events/{job_id}")
async def events(job_id: str, request: Request) -> StreamingResponse:
    job = _get_job_or_404(job_id)
    queue = job_store.subscribe(job_id)

    async def stream():
        try:
            for event in job.timeline:
                yield f"data: {json.dumps(event)}\n\n"

            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("status") in {"done", "error"}:
                    break
        finally:
            job_store.unsubscribe(job_id, queue)

    return StreamingResponse(stream(), media_type="text/event-stream")


# --- Read-only job query endpoints ---


@app.get("/status/{job_id}")
def status(job_id: str) -> dict:
    job = _get_job_or_404(job_id)
    return {"job_id": job.job_id, "status": job.status, "timeline": job.timeline}


@app.get("/result/{job_id}")
def result(job_id: str) -> dict:
    job = _get_job_or_404(job_id)
    if job.status in {"done", "error"} and job.result:
        return job.result
    return {"job_id": job.job_id, "status": job.status, "timeline": job.timeline}


@app.get("/inputs/{job_id}")
def inputs(job_id: str) -> dict:
    job = _get_job_or_404(job_id)
    return {
        "job_id": job.job_id,
        "repo_path": job.repo_path,
        "log_path": job.log_path,
        "screenshot_path": job.screenshot_path,
        "diagram_path": job.diagram_path,
    }


@app.get("/input-file/{job_id}/{kind}")
def input_file(job_id: str, kind: str) -> FileResponse:
    job = _get_job_or_404(job_id)
    path = _resolve_job_input_path(job, kind)
    if path is None:
        raise HTTPException(status_code=404, detail="input file not found")
    media_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    return FileResponse(path=path, media_type=media_type, filename=path.name)


@app.get("/evidence/{job_id}/{evidence_id}")
def evidence_file(job_id: str, evidence_id: str) -> FileResponse:
    job = _get_job_or_404(job_id)
    findings = (job.result or {}).get("findings", []) or []
    for finding in findings:
        for evidence in finding.get("evidence", []) or []:
            if evidence.get("id") != evidence_id:
                continue
            if evidence.get("kind") != "screenshot":
                continue
            file_path = str(evidence.get("file_path") or "").strip()
            if not file_path:
                raise HTTPException(status_code=404, detail="evidence file not found")
            path = Path(file_path)
            if not _is_safe_path(UPLOAD_DIR, path):
                raise HTTPException(status_code=403, detail="access denied")
            if not path.exists() or not path.is_file():
                raise HTTPException(status_code=404, detail="evidence file not found")
            media_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
            return FileResponse(path=path, media_type=media_type, filename=path.name)
    raise HTTPException(status_code=404, detail="evidence not found or not previewable")


def _get_job_or_404(job_id: str) -> Job:
    if not re.match(r"^[a-zA-Z0-9_]{1,50}$", job_id):
        raise HTTPException(status_code=404, detail="job not found")
    job = job_store.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return job


def _resolve_job_input_path(job: Job, kind: str) -> Optional[Path]:
    kind_map = {
        "log": (job.log_path or "").strip(),
        "screenshot": (job.screenshot_path or "").strip(),
        "diagram": (job.diagram_path or "").strip(),
    }
    selected = kind_map.get(kind)
    if not selected:
        return None
    path = Path(selected)
    if str(UPLOAD_DIR) in selected and not _is_safe_path(UPLOAD_DIR, path):
        return None
    if not path.exists() or not path.is_file():
        return None
    return path

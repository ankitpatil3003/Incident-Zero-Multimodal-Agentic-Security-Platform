"""
Sprint 1 API tests — covers every endpoint in main.py.

Run: cd backend && python -m pytest tests/test_api.py -v
"""

import pytest
from httpx import ASGITransport, AsyncClient

from backend.app.main import app
from backend.app.store import job_store


@pytest.fixture(autouse=True)
def _clear_store():
    """Reset the job store between tests."""
    job_store._jobs.clear()
    job_store._subscribers.clear()


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_health(client: AsyncClient):
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "incident-zero"


@pytest.mark.asyncio
async def test_analyze_creates_job(client: AsyncClient):
    resp = await client.post("/analyze", json={"repo_path": "/tmp/test-repo"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["job_id"].startswith("job_")
    assert data["status"] == "running"


@pytest.mark.asyncio
async def test_analyze_upload_creates_job(client: AsyncClient):
    resp = await client.post(
        "/analyze/upload",
        data={"repo_path": "/tmp/test-repo"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["job_id"].startswith("job_")


@pytest.mark.asyncio
async def test_status_returns_timeline(client: AsyncClient):
    resp = await client.post("/analyze", json={"repo_path": "/tmp/test-repo"})
    job_id = resp.json()["job_id"]

    resp = await client.get(f"/status/{job_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["job_id"] == job_id
    assert isinstance(data["timeline"], list)
    assert len(data["timeline"]) >= 1


@pytest.mark.asyncio
async def test_status_404_for_unknown_job(client: AsyncClient):
    resp = await client.get("/status/job_nonexistent")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_result_returns_status_while_running(client: AsyncClient):
    resp = await client.post("/analyze", json={"repo_path": "/tmp/test-repo"})
    job_id = resp.json()["job_id"]

    resp = await client.get(f"/result/{job_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert "job_id" in data or "status" in data


@pytest.mark.asyncio
async def test_inputs_returns_paths(client: AsyncClient):
    resp = await client.post(
        "/analyze",
        json={"repo_path": "/tmp/repo", "log_path": "/tmp/app.log"},
    )
    job_id = resp.json()["job_id"]

    resp = await client.get(f"/inputs/{job_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["repo_path"] == "/tmp/repo"
    assert data["log_path"] == "/tmp/app.log"
    assert data["screenshot_path"] is None


@pytest.mark.asyncio
async def test_input_file_404_when_no_file(client: AsyncClient):
    resp = await client.post("/analyze", json={"repo_path": "/tmp/repo"})
    job_id = resp.json()["job_id"]

    resp = await client.get(f"/input-file/{job_id}/log")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_evidence_404_for_unknown_job(client: AsyncClient):
    resp = await client.get("/evidence/job_fake/e_fake")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_events_404_for_unknown_job(client: AsyncClient):
    """SSE endpoint returns 404 for unknown job."""
    resp = await client.get("/events/job_nonexistent")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_sse_pubsub_mechanism():
    """Verify the pub/sub mechanism that powers SSE delivery."""
    job = job_store.create_job(repo_path="/tmp/repo")
    queue = job_store.subscribe(job.job_id)

    job_store.add_event(job, stage="test", message="hello", status="done")
    event = queue.get_nowait()
    assert event["stage"] == "test"
    assert event["message"] == "hello"

    job_store.unsubscribe(job.job_id, queue)

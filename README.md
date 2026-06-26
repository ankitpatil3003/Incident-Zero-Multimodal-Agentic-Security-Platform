# Incident Zero

**Multimodal Agentic Security Platform**

An end-to-end agentic pipeline that accepts code repositories, log files, screenshots, and architecture diagrams, runs specialized MCP (Model Context Protocol) security tools, correlates findings across modalities, builds interactive attack graphs, and generates deterministic security patches.

## Architecture

```
User uploads evidence (repo + logs + screenshots + diagrams)
  │
  ├─→ FastAPI saves files, creates Job, starts background pipeline
  │
  ├─→ Orchestrator runs MCP tools sequentially:
  │     ├─ CodeScan(repo_path)           → vulnerability findings
  │     ├─ LogReasoner(log_path)         → log pattern analysis
  │     ├─ ScreenshotAnalyzer(image)     → OCR + secret detection
  │     └─ DiagramExtractor(image)       → component extraction
  │
  ├─→ Cross-tool Correlator:
  │     ├─ Deduplicates findings by (type, file, line)
  │     ├─ Bumps severity on cross-tool corroboration
  │     └─ Detects multi-signal attack patterns
  │
  ├─→ Attack Graph Builder (NetworkX):
  │     ├─ Creates entry → vulnerability → impact DAG
  │     └─ Ranks top attack paths by cumulative risk
  │
  ├─→ Patcher generates unified diffs for fixable vulnerabilities
  │
  └─→ Results streamed via SSE, served via REST API
```

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI, Python 3.11+ |
| Frontend | Next.js 14, TypeScript, ReactFlow |
| AI Provider | Mistral AI (free tier — $0 cost) |
| Graph Engine | NetworkX |
| Image Processing | Pillow |
| Real-time | Server-Sent Events (SSE) |
| Containerization | Docker, Docker Compose |

## MCP Tools

All five tools follow the **local-first pattern**: regex/heuristic extraction always runs; LLM augmentation is optional and gracefully degrades.

| Tool | Input | What It Detects |
|---|---|---|
| CodeScan | Repo directory | Hardcoded secrets, SQL injection, weak crypto |
| LogReasoner | Log file | Error patterns, auth failures, suspicious activity |
| ScreenshotAnalyzer | Screenshot image | Exposed secrets, IPs, URLs in screenshots |
| DiagramExtractor | Architecture diagram | Infrastructure components, protocols, data flows |
| Patcher | Findings list | Generates fix diffs (secret removal, parameterized queries) |

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 20+
- (Optional) Docker and Docker Compose
- (Optional) Mistral API key for LLM features (works without it via local-first extraction)

### Local Development

```bash
# Clone
git clone https://github.com/your-username/Incident-Zero-Multimodal-Agentic-Security-Platform.git
cd Incident-Zero-Multimodal-Agentic-Security-Platform

# Backend
cd backend
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
cd ..

# Environment
cp .env.example .env
# Edit .env to add MISTRAL_API_KEY (optional)

# Start backend
uvicorn backend.app.main:app --reload --port 8000

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
```

The frontend runs on `http://localhost:3000` and proxies API calls to the backend on `:8000`.

### Docker

```bash
cp .env.example .env
# Edit .env to add MISTRAL_API_KEY (optional)

# Single container (backend only)
docker build -t incident-zero .
docker run -p 8000:8000 --env-file .env incident-zero

# Full stack (backend + frontend)
docker compose up --build
```

### Running Tests

```bash
cd backend
python -m pytest tests/ -v
```

All 194+ tests run without external dependencies (Mistral API calls are mocked).

## API Reference

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/analyze` | Submit analysis job (JSON body with paths) |
| `POST` | `/analyze/upload` | Submit with file uploads (multipart form) |
| `GET` | `/status/{job_id}` | Poll job status and timeline |
| `GET` | `/events/{job_id}` | SSE stream of real-time pipeline events |
| `GET` | `/result/{job_id}` | Full result bundle (findings, graph, patches) |
| `GET` | `/inputs/{job_id}` | Input metadata for a job |
| `GET` | `/input-file/{job_id}/{kind}` | Download uploaded evidence file |
| `GET` | `/evidence/{job_id}/{evidence_id}` | Serve evidence artifact |
| `GET` | `/health` | Health check |

### Example: Submit a scan

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"repo_path": "/path/to/repo", "log_path": "/path/to/app.log"}'
```

Response:
```json
{"job_id": "job_a1b2c3d4", "status": "running"}
```

### Example: Stream events

```bash
curl -N http://localhost:8000/events/job_a1b2c3d4
```

### Example: Get results

```bash
curl http://localhost:8000/result/job_a1b2c3d4
```

## Project Structure

```
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI app + endpoints
│   │   ├── store.py           # Job dataclass + in-memory store
│   │   ├── orchestrator.py    # Pipeline runner
│   │   ├── correlator.py      # Cross-tool finding merger
│   │   ├── graph.py           # Attack graph builder (NetworkX)
│   │   ├── registry.py        # MCP tool registry
│   │   └── config.py          # Settings + env loading
│   ├── mcps/
│   │   ├── common/            # Shared types, Mistral client, local-first
│   │   ├── codescan/          # CodeScan tool
│   │   ├── log_reasoner/      # LogReasoner tool
│   │   ├── screenshot_analyzer/  # ScreenshotAnalyzer tool
│   │   ├── diagram_extractor/ # DiagramExtractor tool
│   │   └── patcher/           # Patcher tool
│   └── tests/                 # 194+ pytest tests
├── frontend/
│   └── src/
│       ├── app/               # Next.js pages (dashboard, upload, job results)
│       ├── components/        # AttackGraph, EvidenceViewer, PatchViewer, Sidebar
│       ├── hooks/             # useJobEvents SSE hook
│       ├── lib/               # API client
│       └── types/             # TypeScript API types
├── schemas/                   # JSON schema for tool registry
├── fixtures/                  # Test fixtures (vulnerable repo, sample log/screenshot)
├── Dockerfile                 # Multi-stage build (backend + frontend)
├── Dockerfile.frontend        # Standalone frontend container
├── docker-compose.yml         # Full stack orchestration
└── PROJECT_BLUEPRINT.md       # Detailed sprint plan and architecture
```

## Security

- Path traversal guards on all file-serving endpoints
- Upload size limits (50 MB) with chunked enforcement
- Filename sanitization and extension allowlisting
- Job ID format validation (prevents injection)
- Secret masking in all MCP tool outputs (credentials never exposed in API responses)
- CORS restricted to configured origins
- Non-root Docker containers
- Mistral rate-limit handling with exponential backoff

## Cost

**$0.** The platform runs entirely on Mistral's free tier (1 req/s). Local-first extraction means every tool produces findings even without LLM access.

## License

MIT

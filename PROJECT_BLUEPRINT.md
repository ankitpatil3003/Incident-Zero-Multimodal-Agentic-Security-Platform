# Incident Zero — Enterprise Project Blueprint

## 1. Project Overview

**Product**: Multimodal Agentic Security Platform  
**Stack**: FastAPI, Next.js 14, Mistral AI, Custom MCP, OCR, SSE  
**Cost Target**: $0 (Mistral free tier: 1 req/s, sufficient for dev)  
**Timeline**: 8 sprints (~4 weeks if daily commits)

An end-to-end agentic pipeline that accepts images, PDFs, and text evidence, runs OCR extraction and LLM-driven attack-graph generation, and outputs structured root-cause analysis.

---

## 2. Team Roles & Ownership

| Role | Alias | Owns | Approves |
|---|---|---|---|
| **Product Manager** | PM | PRD, sprint scope, acceptance criteria, backlog priority | Feature completeness, UX flows |
| **Backend Engineer 1** | BE-1 | FastAPI core, orchestrator, job store, SSE, API contracts | Backend PRs |
| **Backend Engineer 2** | BE-2 | All 5 MCP servers, Mistral client, correlator, attack graph | MCP PRs |
| **Frontend/Design Engineer** | FE | Next.js app, ReactFlow viz, upload UX, responsive design | Frontend PRs |
| **DevOps Engineer** | OPS | Repo setup, CI/CD, Docker, env config, deploy scripts | Infra PRs |
| **QA / Bug-Finder** | QA | Test plans, integration tests, edge cases, regression | Test coverage gates |
| **Security Reviewer** | SEC | Threat model review, input validation audit, secret handling | Security sign-off |

### RACI per Sprint Phase

| Activity | PM | BE-1 | BE-2 | FE | OPS | QA | SEC |
|---|---|---|---|---|---|---|---|
| Sprint planning | A | C | C | C | C | I | I |
| API design | C | R | C | C | I | I | I |
| MCP implementation | I | C | R | I | I | C | C |
| Frontend build | C | I | I | R | I | C | I |
| Testing | I | C | C | C | I | R | C |
| Deployment | I | I | I | I | R | C | I |
| Security review | I | C | C | C | I | I | R |

*R = Responsible, A = Accountable, C = Consulted, I = Informed*

---

## 3. Scope & Constraints

### What This Platform Does
1. Accepts multimodal evidence: code repos (local paths), log files, screenshots, architecture diagrams
2. Runs 5 specialized MCP tools in parallel where possible
3. Correlates findings across modalities (code + logs + screenshots + diagrams)
4. Builds an interactive attack graph showing exploit chains
5. Generates deterministic security patches with diffs
6. Streams progress to the frontend via SSE in real-time

### What This Platform Does NOT Do
- No remote repo cloning (local paths only in v1)
- No persistent database (in-memory job store in v1)
- No user auth (single-user mode in v1)
- No production deployment (local dev only in v1)
- No fine-tuned models (Mistral API as-is)

### Hard Constraints
- **Cost**: $0 — Mistral free tier only (1 req/s rate limit)
- **No code copying**: All MCP tools are written from scratch, referencing the architecture pattern only
- **Typed contracts**: Every MCP tool input/output follows strict JSON schema
- **Zero unstructured fallback**: If LLM returns invalid JSON, the tool returns a structured error, never raw text

### Known Limitations
- Free-tier rate limiting means multi-MCP jobs are sequential, not parallel
- OCR accuracy depends on image quality; no pre-processing beyond resize
- Attack graph is heuristic (entry → vuln → impact), not a true threat model
- Patcher only handles `hardcoded-secret` and `sql-injection` vulnerability types
- In-memory store means all jobs are lost on server restart

---

## 4. Tech Stack Decisions

| Layer | Choice | Why |
|---|---|---|
| Backend framework | FastAPI 0.104+ | Async-native, Pydantic validation, auto OpenAPI docs |
| Python version | 3.11+ | Performance, modern typing |
| AI provider | Mistral (free tier) | Text + Vision + OCR in one provider, $0 cost |
| Frontend framework | Next.js 14 | App router, SSR, TypeScript-first |
| Graph visualization | ReactFlow 11 | Purpose-built for node/edge graphs, drag/zoom/pan |
| Real-time | SSE (Server-Sent Events) | Simpler than WebSocket for one-directional event streams |
| Graph computation | NetworkX | Lightweight, pure Python, perfect for attack path analysis |
| Image processing | Pillow | Resize/normalize images before OCR |
| Validation | Pydantic v2 | Runtime type safety on all API boundaries |

---

## 5. Sprint Plan (Commit-by-Commit)

### Sprint 0: Foundation (OPS + PM)
*Goal: Repo skeleton, tooling, CI, project governance*

| # | Commit Message | Owner | Files |
|---|---|---|---|
| 1 | `chore: initialize monorepo structure` | OPS | `backend/`, `frontend/`, `schemas/`, `fixtures/`, `diagrams/` |
| 2 | `chore: add backend dependencies and pyproject.toml` | OPS | `backend/pyproject.toml`, `backend/requirements.txt` |
| 3 | `chore: scaffold Next.js 14 frontend` | OPS | `frontend/package.json`, `frontend/tsconfig.json`, `frontend/next.config.js` |
| 4 | `chore: add .env.example and config loader` | OPS | `.env.example`, `backend/app/config.py` |
| 5 | `docs: add PROJECT_BLUEPRINT.md` | PM | `PROJECT_BLUEPRINT.md` |
| 6 | `chore: add pre-commit hooks (black, flake8, mypy)` | OPS | `.pre-commit-config.yaml` |

### Sprint 1: API Core (BE-1)
*Goal: FastAPI app boots, job lifecycle works, SSE streams events*

| # | Commit Message | Owner | Files |
|---|---|---|---|
| 7 | `feat: add Job dataclass and in-memory JobStore` | BE-1 | `backend/app/store.py` |
| 8 | `feat: add FastAPI app with CORS and health endpoint` | BE-1 | `backend/app/main.py` |
| 9 | `feat: add POST /analyze endpoint with background tasks` | BE-1 | `backend/app/main.py` |
| 10 | `feat: add POST /analyze/upload with file upload support` | BE-1 | `backend/app/main.py` |
| 11 | `feat: add GET /status/{job_id} and GET /result/{job_id}` | BE-1 | `backend/app/main.py` |
| 12 | `feat: add GET /events/{job_id} SSE endpoint` | BE-1 | `backend/app/main.py` |
| 13 | `test: add API endpoint tests with pytest` | QA | `backend/tests/test_api.py` |

### Sprint 2: MCP Tool Registry (BE-2)
*Goal: Typed tool registry with JSON schema validation, shared utilities*

| # | Commit Message | Owner | Files |
|---|---|---|---|
| 14 | `feat: add MCP shared types (ToolResult schema)` | BE-2 | `backend/mcps/common/types.py` |
| 15 | `feat: add Mistral client wrapper (text, vision, OCR)` | BE-2 | `backend/mcps/common/mistral_client.py` |
| 16 | `feat: add local-first extraction pattern` | BE-2 | `backend/mcps/common/local_extract.py` |
| 17 | `feat: add tool registry with JSON schema validation` | BE-2 | `backend/app/registry.py`, `schemas/tool_registry.json` |
| 18 | `test: add Mistral client unit tests with mocks` | QA | `backend/tests/test_mistral_client.py` |

### Sprint 3: MCP Tools — CodeScan + LogReasoner (BE-2)
*Goal: First two investigative tools producing structured findings*

| # | Commit Message | Owner | Files |
|---|---|---|---|
| 19 | `feat: add CodeScan vulnerability rules engine` | BE-2 | `backend/mcps/codescan/rules.py` |
| 20 | `feat: add CodeScan evidence extractor` | BE-2 | `backend/mcps/codescan/evidence_extractor.py` |
| 21 | `feat: add CodeScan scanner (main entry point)` | BE-2 | `backend/mcps/codescan/scanner.py` |
| 22 | `feat: add LogReasoner with pattern matching + LLM` | BE-2 | `backend/mcps/log_reasoner/run.py` |
| 23 | `test: add CodeScan tests with fixture repos` | QA | `backend/tests/test_codescan.py`, `fixtures/vulnerable_repo/` |
| 24 | `test: add LogReasoner tests with fixture logs` | QA | `backend/tests/test_log_reasoner.py`, `fixtures/sample.log` |

### Sprint 4: MCP Tools — Screenshot + Diagram + Patcher (BE-2)
*Goal: Complete the remaining 3 MCP tools*

| # | Commit Message | Owner | Files |
|---|---|---|---|
| 25 | `feat: add ScreenshotAnalyzer with OCR + vision` | BE-2 | `backend/mcps/screenshot_analyzer/run.py` |
| 26 | `feat: add DiagramExtractor with vision model` | BE-2 | `backend/mcps/diagram_extractor/run.py` |
| 27 | `feat: add Patcher with template-based diff generation` | BE-2 | `backend/mcps/patcher/generator.py` |
| 28 | `feat: add GitHub PR bundle builder for Patcher` | BE-2 | `backend/mcps/patcher/github.py` |
| 29 | `test: add screenshot and diagram tests with fixtures` | QA | `backend/tests/test_screenshot.py`, `fixtures/sample_screenshot.png` |

### Sprint 5: Orchestrator + Correlation + Attack Graph (BE-1 + BE-2)
*Goal: Pipeline runs end-to-end, correlates findings, builds graph*

| # | Commit Message | Owner | Files |
|---|---|---|---|
| 30 | `feat: add cross-tool correlator with finding merge` | BE-2 | `backend/app/correlator.py` |
| 31 | `feat: add attack graph builder (NetworkX)` | BE-2 | `backend/app/graph.py` |
| 32 | `feat: add orchestrator pipeline (scan → correlate → graph → patch)` | BE-1 | `backend/app/orchestrator.py` |
| 33 | `feat: add input-file and evidence-file serving endpoints` | BE-1 | `backend/app/main.py` |
| 34 | `test: add end-to-end pipeline integration test` | QA | `backend/tests/test_pipeline_e2e.py` |

### Sprint 6: Frontend (FE)
*Goal: Working UI — dashboard, upload, results, attack graph*

| # | Commit Message | Owner | Files |
|---|---|---|---|
| 35 | `feat: add app layout with navigation` | FE | `frontend/src/app/layout.tsx`, `frontend/src/app/page.tsx` |
| 36 | `feat: add dashboard page with recent jobs` | FE | `frontend/src/app/dashboard/page.tsx` |
| 37 | `feat: add upload page with multi-file form` | FE | `frontend/src/app/upload/page.tsx` |
| 38 | `feat: add SSE hook for real-time job events` | FE | `frontend/src/hooks/useJobEvents.ts` |
| 39 | `feat: add job results page with findings list` | FE | `frontend/src/app/job/[id]/page.tsx` |
| 40 | `feat: add interactive attack graph with ReactFlow` | FE | `frontend/src/components/AttackGraph.tsx` |
| 41 | `feat: add evidence viewer with screenshot preview` | FE | `frontend/src/components/EvidenceViewer.tsx` |
| 42 | `feat: add patch diff viewer` | FE | `frontend/src/components/PatchViewer.tsx` |
| 43 | `style: add responsive CSS and dark mode support` | FE | `frontend/src/app/globals.css` |

### Sprint 7: Integration + Hardening (QA + SEC + OPS)
*Goal: Everything works together, edge cases handled, security reviewed*

| # | Commit Message | Owner | Files |
|---|---|---|---|
| 44 | `test: add frontend component tests` | QA | `frontend/__tests__/` |
| 45 | `fix: handle large file uploads gracefully` | BE-1 | `backend/app/main.py` |
| 46 | `fix: handle Mistral rate-limit errors with backoff` | BE-2 | `backend/mcps/common/mistral_client.py` |
| 47 | `security: add input validation and path traversal guards` | SEC | `backend/app/main.py`, `backend/mcps/codescan/scanner.py` |
| 48 | `security: mask secrets in all MCP tool outputs` | SEC | `backend/mcps/common/types.py` |
| 49 | `chore: add Dockerfile and docker-compose.yml` | OPS | `Dockerfile`, `docker-compose.yml` |
| 50 | `docs: update README with setup and usage guide` | PM | `README.md` |

---

## 6. API Contract Summary

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/analyze` | Submit analysis job (JSON body) |
| `POST` | `/analyze/upload` | Submit with file uploads (multipart) |
| `GET` | `/status/{job_id}` | Poll job status + timeline |
| `GET` | `/events/{job_id}` | SSE stream of real-time events |
| `GET` | `/result/{job_id}` | Full result (findings, graph, patches) |
| `GET` | `/inputs/{job_id}` | Input metadata for a job |
| `GET` | `/input-file/{job_id}/{kind}` | Download uploaded evidence file |
| `GET` | `/evidence/{job_id}/{evidence_id}` | Serve evidence artifact (screenshot) |

### Job Lifecycle

```
POST /analyze → job_id (status: "running")
    ↓ Background task
  Stage: ingest → scan → correlate → graph → patch → finalize
    ↓ SSE events per stage
GET /result/{job_id} → full result bundle (status: "done" | "error")
```

### ToolResult Schema (every MCP returns this)

```json
{
  "tool_name": "string",
  "artifacts": {},
  "evidence": [{"id": "", "kind": "", "file_path": "", "line": 0, "snippet": "", "note": ""}],
  "signals": {},
  "errors": [{"error": "", "detail": ""}] | null
}
```

---

## 7. MCP Tool Design (Custom — Not Copied)

Each MCP follows the **local-first** pattern:
1. **Local extraction**: Parse the input with regex/heuristics → produce structured findings
2. **LLM augmentation**: If `needs_llm=true`, send selected chunks to Mistral for deeper analysis
3. **Merge**: Combine local + LLM results into a single `ToolResult`

This pattern ensures the pipeline works even when the LLM is unavailable (rate-limited, network down).

### Tool Specifications

| Tool | Input | Local Phase | LLM Phase | Output Signals |
|---|---|---|---|---|
| CodeScan | repo path | Regex rules for secrets, SQLi, weak crypto | None (deterministic) | finding type, severity, CWE |
| LogReasoner | log file | Error/auth/suspicious pattern matching | Root cause analysis | runtime_proof, sql_injection_suspected |
| ScreenshotAnalyzer | image file | OCR → entity/secret extraction | Structured interpretation | secret_exposure_detected, endpoint_guess |
| DiagramExtractor | image file | None | Vision model: components, connections, zones | entry_points, trust_zones |
| Patcher | findings[] | Template-based diff generation | None (deterministic) | patch count, manual recommendations |

---

## 8. Data Flow (End-to-End)

```
User uploads evidence (repo path + log + screenshot + diagram)
  │
  ├─→ FastAPI saves files, creates Job, starts background task
  │
  ├─→ Orchestrator runs MCP tools sequentially:
  │     ├─ CodeScan(repo_path)           → findings[]
  │     ├─ LogReasoner(log_path)         → evidence[] + signals{}
  │     ├─ ScreenshotAnalyzer(image)     → evidence[] + signals{}
  │     └─ DiagramExtractor(image)       → artifacts{} + signals{}
  │
  ├─→ Correlator merges all tool results:
  │     ├─ Deduplicates findings by (type, file, line)
  │     ├─ Attaches multimodal evidence to matching findings
  │     ├─ Bumps severity when runtime proof exists
  │     └─ Synthesizes new findings from multimodal signals
  │
  ├─→ Attack Graph Builder:
  │     ├─ Creates entry → vulnerability → impact chains
  │     └─ Scores and ranks top-3 attack paths
  │
  ├─→ Patcher generates diffs for supported vulnerability types
  │
  └─→ Result bundle returned via /result/{job_id}
       SSE events streamed throughout via /events/{job_id}
```

---

## 9. Directory Structure

```
incident-zero/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── config.py          # env loading
│   │   ├── main.py            # FastAPI app + endpoints
│   │   ├── store.py           # Job dataclass + JobStore
│   │   ├── orchestrator.py    # pipeline runner
│   │   ├── correlator.py      # cross-tool finding merger
│   │   ├── graph.py           # attack graph builder
│   │   └── registry.py        # MCP tool registry
│   ├── mcps/
│   │   ├── common/
│   │   │   ├── __init__.py
│   │   │   ├── types.py       # ToolResult schema
│   │   │   ├── mistral_client.py  # Mistral API wrapper
│   │   │   └── local_extract.py   # local-first pattern
│   │   ├── codescan/
│   │   │   ├── __init__.py
│   │   │   ├── scanner.py
│   │   │   ├── rules.py
│   │   │   └── evidence_extractor.py
│   │   ├── log_reasoner/
│   │   │   ├── __init__.py
│   │   │   └── run.py
│   │   ├── screenshot_analyzer/
│   │   │   ├── __init__.py
│   │   │   └── run.py
│   │   ├── diagram_extractor/
│   │   │   ├── __init__.py
│   │   │   └── run.py
│   │   └── patcher/
│   │       ├── __init__.py
│   │       ├── generator.py
│   │       └── github.py
│   ├── tests/
│   │   ├── test_api.py
│   │   ├── test_codescan.py
│   │   ├── test_log_reasoner.py
│   │   ├── test_screenshot.py
│   │   ├── test_mistral_client.py
│   │   └── test_pipeline_e2e.py
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   │   ├── layout.tsx
│   │   │   ├── page.tsx
│   │   │   ├── globals.css
│   │   │   ├── dashboard/page.tsx
│   │   │   ├── upload/page.tsx
│   │   │   └── job/[id]/page.tsx
│   │   ├── components/
│   │   │   ├── AttackGraph.tsx
│   │   │   ├── EvidenceViewer.tsx
│   │   │   └── PatchViewer.tsx
│   │   └── hooks/
│   │       └── useJobEvents.ts
│   ├── package.json
│   ├── tsconfig.json
│   └── next.config.js
├── schemas/
│   └── tool_registry.json
├── fixtures/
│   ├── vulnerable_repo/
│   ├── sample.log
│   └── sample_screenshot.png
├── diagrams/
├── .env.example
├── .gitignore
├── docker-compose.yml
├── Dockerfile
├── LICENSE
├── README.md
└── PROJECT_BLUEPRINT.md
```

---

## 10. Cost Analysis

| Resource | Cost | Notes |
|---|---|---|
| Mistral API (free tier) | $0 | 1 req/s, sufficient for dev/demo |
| GitHub (public repo) | $0 | Free for public repos |
| Local dev server | $0 | Runs on your machine |
| Docker (optional) | $0 | Docker Desktop free for personal use |
| **Total** | **$0** | |

If you later need higher throughput, Mistral's paid tier starts at ~$0.2/1M tokens for `mistral-small`.

---

## 11. Definition of Done (per Sprint)

- [ ] All commits pass linting (black, flake8, mypy)
- [ ] All new code has corresponding tests
- [ ] Tests pass in CI (pytest for backend, type-check for frontend)
- [ ] API contracts match the schema in this document
- [ ] No secrets or credentials in committed code
- [ ] Each commit is atomic and independently valid (doesn't break the build)

---

## 12. How to Start

**Next step**: Begin Sprint 0 — run the first 6 commits to set up the repo skeleton, tooling, and configuration. Tell me to start Sprint 0 and I'll create each file commit-by-commit.

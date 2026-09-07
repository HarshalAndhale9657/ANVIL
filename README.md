
<div align="center">

# A.E.G.I.S.

### Autonomous Exploit Generation and Intelligent Security

An autonomous, fail-closed red-team engine that discovers, exploits, verifies, and patches security vulnerabilities — then opens a Pull Request with the fix — all with zero human intervention and full end-to-end observability.

---

[🌐 Live Demo](https://aegis-frontend-azure.vercel.app) | [🏗️ Architecture](#system-architecture) | [🚀 Getting Started](#getting-started) | [⚙️ How It Works](#how-it-works) | [📚 Research](#research--inspiration)

---

</div>

## Table of Contents

- [Problem Statement](#problem-statement)
- [The Solution](#the-solution)
- [📊 Benchmark Results](#-benchmark-results)
- [🌟 Powered by Omium AI](#-powered-by-omium-ai)
- [System Architecture](#system-architecture)
- [Key Differentiators](#key-differentiators)
- [How It Works](#how-it-works)
  - [End-to-End Pipeline Flow](#end-to-end-pipeline-flow)
  - [Colored Petri Net (CPN) Execution Model](#colored-petri-net-cpn-execution-model)
  - [Agent Breakdown](#agent-breakdown)
  - [SSE Event Lifecycle](#sse-event-lifecycle)
- [Research & Inspiration](#research--inspiration)
- [Evaluation Criteria Alignment](#evaluation-criteria-alignment)
- [Technical Stack](#technical-stack)
- [Project Structure](#project-structure)
- [Fail-Closed Safety Mechanisms](#fail-closed-safety-mechanisms)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Step 1 — Configure the Backend](#step-1--configure-the-backend)
  - [Step 2 — Start the Backend](#step-2--start-the-backend)
  - [Step 3 — Start the Frontend](#step-3--start-the-frontend)
  - [One-Command Launch](#one-command-launch)
- [API Reference](#api-reference)
- [Observability and Tracing](#observability-and-tracing)
- [Data Contracts](#data-contracts)
- [Future Scope and Scalability](#future-scope-and-scalability)
- [Contributors](#contributors)
- [License](#license)

---

## Problem Statement

Modern software teams ship code at velocity, but security remediation remains painfully manual. Existing vulnerability scanners generate reports that sit in backlogs for weeks. When AI-powered agents attempt autonomous fixing, they face three critical failure modes:

1. **Hallucination** — LLM agents fabricate vulnerability findings or generate patches that introduce new bugs, with no mechanism to distinguish real exploits from imagined ones.
2. **Death Spirals** — Agents without deterministic routing enter infinite retry loops, consuming resources without converging on a solution.
3. **Black-Box Execution** — Without production-grade observability, teams cannot audit what the agent did, why it made a decision, or where it failed — making autonomous agents a liability rather than an asset.

These problems are not hypothetical. They are the primary reasons security teams distrust autonomous agents in production environments.

---

## The Solution

A.E.G.I.S. eliminates all three failure modes through a mathematically grounded architecture:

- **A Colored Petri Net (CPN) execution engine** replaces free-form agent chaining with deterministic, graph-based orchestration. The LLM is never consulted for routing decisions — pure Python `if/else` logic governs all state transitions.
- **A dedicated Verifier Agent** (zero LLM dependency) acts as a cryptographic checkpoint: exploit output must contain deterministic proof markers (`FLAG{...}` or `EXPLOIT_SUCCESS`) before the pipeline advances. This is the anti-hallucination gate.
- **Full W3C Trace Context propagation** via the Omium SDK across every asynchronous boundary (FastAPI to background threads), producing a single connected distributed trace for the entire pipeline. Every decision, every token, every sandbox execution is auditable.

The result: a system that autonomously clones a GitHub repository, scans its source code, generates and executes exploit payloads in a sandboxed environment, deterministically verifies exploitation, generates a security patch **whose correctness is proven by re-running the exploit against the patched code inside a sealed container**, and opens a Pull Request — all visible in real-time through Server-Sent Events streamed to a production-quality web dashboard.

---

## 📊 Benchmark Results

A.E.G.I.S. ships with an [evaluation harness](backend/evaluation/) that runs the **real pipeline** against a corpus of known-vulnerable apps and scores it against ground truth. First run — 6 vulnerability classes, real GPT-4o pipeline, patches validated by re-running the exploit inside a `--network none` container:

| Metric | Rate | Count |
|--------|------|-------|
| **Detected** | **100%** | 6 / 6 |
| **Exploited** (sandbox-confirmed) | **83%** | 5 / 6 |
| **Verified** (deterministic gate) | **83%** | 5 / 6 |
| **Patched** (live re-exploit-validated) | **50%** | 3 / 6 |

Classes: insecure deserialization · path traversal · SQL injection · SSTI/XSS · command injection · SSRF.

The **patch rate is strict on purpose**: a fix counts only if the patched app *still starts* **and** the original exploit *no longer succeeds*, re-checked inside a sealed container. In this run the gate **rejected a generated SSTI patch that imported `flask.escape`** (removed in Flask 2.1 — the app wouldn't even start) which the static check had *passed*, and refused other ineffective fixes: the pipeline ships **no patch rather than a broken one** (fail-closed). A tool reporting "100% patched" on this corpus would be lying — this is the number that is actually true. The lone exploit miss, SSRF, is *detected* but not exploited because proving SSRF impact needs a reachable internal target an offline harness can't provide.

Reproduce: `cd backend && python -m evaluation.run_eval` (add `--no-patch` for the cheaper detection/exploit/verify pass). Full breakdown: [`backend/evaluation/RESULTS.md`](backend/evaluation/RESULTS.md).

---

## 🌟 Powered by Omium AI

A.E.G.I.S. is deeply integrated with the **Omium SDK**, which was an absolute game-changer for building this project quickly and reliably. Developing a multi-agent orchestration engine with strict execution gates is notoriously difficult to debug. **Omium AI** transformed our development experience by:

- **Uncovering Hidden Bugs:** We used Omium to trace execution paths across background threads and asynchronous boundaries. When our orchestration engine initially suffered from race conditions or infinite retry loops, Omium's distributed tracing instantly pinpointed the failing transitions, saving us hours of manual debugging.
- **Auditing LLM Decisions:** By attaching structured attributes (`llm.prompt_tokens`, `agent.decision_rationale`) to Omium spans, we could visualize exactly *why* our agents failed on specific payload generations, allowing us to rapidly iterate on prompt engineering.
- **Monitoring Pipeline Failures:** Omium helped us identify race conditions between our SSE real-time streaming and background SQLite checkpoints. The end-to-end observability made the invisible visible.

Without Omium, tracking the state of an autonomous red-team agent across a FastAPI backend, background workers, and sandboxed subprocesses would have been a massive black box. **Omium is the observability backbone of A.E.G.I.S.**

---

## System Architecture

<img width="1600" height="1064" alt="image" src="https://github.com/user-attachments/assets/ca0dac52-c9d6-4161-a55b-10bde5a4be78" />

---

## Key Differentiators

### Production-Grade Observability (Omium SDK + W3C Trace Context)

A.E.G.I.S. does not operate as a black box. Every pipeline execution emits structured OpenTelemetry spans with rich attributes — `cpn.transition`, `cpn.step`, `cpn.retry_count`, `llm.prompt_tokens`, `sandbox.stdout_length`, `verification.result`, and `patch.confidence`. The Omium SDK exports traces via OTLP gRPC to `ingest.monium.yandex.cloud:443`.

Critically, **W3C Trace Context is propagated across asynchronous boundaries** (from the FastAPI request handler into `asyncio.to_thread` and through the CPN engine), ensuring the entire multi-agent pipeline — from the initial HTTP request to the final GitHub PR — appears as a single, connected distributed trace. This is not bolted-on logging; it is first-class, standards-compliant observability.

### Fail-Closed and Deterministic Architecture

The Verifier Agent is intentionally **not an LLM**. It is pure deterministic Python that performs three cryptographic checks:
1. `vulnerability_confirmed` must be `True`
2. `sandbox_stdout` must contain `EXPLOIT_SUCCESS` or `FLAG{`
3. If `extracted_secret` is set, a strict regex (`FLAG\{[A-Za-z0-9_\-]+\}`) must match in stdout

If any check fails, the pipeline retries the exploit (up to 3 attempts) or halts at a terminal error state. The LLM cannot talk its way past verification. This is the anti-hallucination checkpoint that prevents false positives from reaching the patch stage.

### Deterministic Graph Routing via Colored Petri Net

Unlike agent frameworks that use LLMs for routing (introducing non-determinism at the orchestration layer), A.E.G.I.S. uses a formal Colored Petri Net with 10 places and 5 transitions. All routing decisions are encoded as Python guard conditions. The LLM is confined to its designated role — generating analysis, payloads, and patches — never deciding what happens next.

### Real-World Integration, Not Mock Services

A.E.G.I.S. operates against real APIs:
- **GitHub REST API** via PyGithub — clone repos, create branches, push commits, open Pull Requests using the authenticated user's OAuth token
- **GitHub OAuth 2.0** — full authorization code flow with signed HttpOnly cookies
- **OpenAI GPT-4o** — structured JSON output with Pydantic validation for all agent responses
- **Real-time SSE streaming** — not polling, not WebSocket emulation, but proper `text/event-stream` via `sse-starlette`

### How AEGIS Outperforms Existing Security Agents

While many AI security tools stop at static analysis or simple patch generation, ANVIL solves the fundamental flaws of first-generation AI agents:

| Feature | Existing AI Security Agents | **AEGIS (Our Agent)** |
|---------|---------------------------|-----------------------|
| **Orchestration** | **Non-deterministic LLM routing** (ReAct/Chain-of-Thought). Prone to infinite loops, getting stuck, and unpredictable execution paths. | **Colored Petri Net (CPN)**. 100% deterministic, mathematically sound state machine with hard retry limits. The LLM does the thinking; Python does the routing. |
| **Verification** | **LLM-based validation** ("Did this patch work? Yes!"). High risk of hallucinated success where the agent lies to itself. | **Cryptographic Verification Gate**. Pure deterministic Python checking for sandbox execution stdout markers (`FLAG{...}`). Zero LLM hallucination surface. |
| **Execution** | **Theoretical patching**. Agents generate fixes based on assumed vulnerabilities without proving exploitability. | **Live Sandbox Exploitation**. ANVIL writes an actual Python exploit, fires it at an isolated sandbox, and *proves* the vulnerability exists before patching. |
| **Observability** | **Black-box execution**. Terminal logs only. Impossible to trace token usage, exact prompts, or decision trees across distributed boundaries. | **Omium SDK + W3C Trace Context**. Every action emits structured OpenTelemetry spans. The entire async pipeline is a single, visualizable distributed trace. |
| **Safety** | **Runaway execution**. Agents can hallucinate dangerous system commands (`rm -rf`) if given execution access. | **AST-Validated Sandbox**. Fail-closed code execution filtering dangerous imports and calls, combined with a SHA-256 circuit breaker for exploit deduplication. |

---

## How It Works

### End-to-End Pipeline Flow

```
User authenticates via GitHub OAuth
        |
        v
User enters repository URL and clicks "Start Scan"
        |
        v
POST /api/scan --> Pipeline Runner (asyncio.to_thread)
        |
        v
    [1] Clone repository via GitHub API (authenticated HTTPS)
        |
        v
    [2] Recon Agent: GPT-4o analyzes source code for vulnerabilities
        |
        v
    [3] Exploit Agent: GPT-4o generates Python exploit payload
        |               --> AST validation (block dangerous imports/calls)
        |               --> Sandboxed subprocess (env allowlist, timeout, per-scan breaker)
        |
        v
    [4] Verifier Agent: Deterministic stdout analysis (NO LLM)
        |         |
        |     [FAIL] --> Retry (up to 3x) --> back to [3]
        |
        v
    [5] Patcher Agent: GPT-4o generates security fix, then PROVES it:
        |   LIVE RE-EXPLOIT GATE — apply the fix to a throwaway copy, relaunch the
        |   app in a --network none container, re-run the exploit; accept ONLY if
        |   the app still starts AND the exploit now fails
        |         |
        |     [REJECTED] --> feed the failure back to the LLM, regenerate (<=3x);
        |                    fail-closed (NO PR) if none pass
        |         |
        |     [ACCEPTED] --> create fix/ branch, push patched files, open Pull Request
        |
        v
    SSE event: "completed" with PR URL --> Frontend renders results
```

### Colored Petri Net (CPN) Execution Model

The CPN is the formal orchestration backbone. It defines a bipartite graph of **Places** (system states) and **Transitions** (agent actions), with the `MasterState` Pydantic model serving as the "coloured token" that flows through the net.

```mermaid
stateDiagram-v2
    [*] --> ingress
    ingress --> recon_ready: T1 — Initialize
    recon_ready --> exploit_ready: T2 — Vulnerabilities Found
    recon_ready --> end_safe: T2 — No Vulnerabilities (Clean Repo)
    exploit_ready --> exploit_done: T3 — Exploit Executed
    exploit_done --> patch_ready: T4 — Exploit Verified
    exploit_done --> exploit_ready: T4 — Verification Failed (retry, max 3)
    exploit_done --> end_error: T4 — Max Retries Exceeded
    patch_ready --> patch_done: T5 — PR Created
    exploit_ready --> end_error: T3 — Exploit Generation Failed
    patch_ready --> end_error: T5 — Patch Failed

    end_safe --> [*]
    end_error --> [*]
    patch_done --> [*]
```

**Terminal places**: `patch_done` (success), `end_safe` (no vulnerabilities), `end_error` (pipeline failure)

**Safety limits**: 20-step absolute maximum prevents infinite graph traversal. 3-retry circuit breaker at verification prevents exploit-verify death spirals.

### Agent Breakdown

| Agent | Role | LLM | Key Mechanism |
|-------|------|-----|---------------|
| **Recon Agent** | Analyze cloned source code for security vulnerabilities | GPT-4o | Structured JSON output validated against `ReconOutput` schema; deterministic fallback if LLM returns invalid data |
| **Exploit Agent** | Generate + run a standalone Python exploit | GPT-4o | AST-validated sandbox (import/call filtering, fail-closed env allowlist, timeout, per-scan SHA-256 circuit breaker); deterministic exploit templates as fallback; auto-launches the target app to exploit it live |
| **Verifier Agent** | Deterministically confirm exploitation | None | Pure Python — requires the `EXPLOIT_SUCCESS` marker **plus real, non-failure evidence**; rejects hallucinated or failed exploits. Zero LLM, zero hallucination surface |
| **Patcher Agent** | Generate a fix, **prove it**, open a GitHub PR | GPT-4o | Self-correcting: static gate → **live re-exploit gate** (relaunch the patched app in a sealed `--network none` container and re-run the exploit — accept only if it still starts **and** the exploit now fails) → on rejection, feed the failure back and regenerate (≤3 attempts); **fail-closed** (no PR) if none pass. Then create `fix/` branch, push, open PR |

### SSE Event Lifecycle

```
queued --> cloning --> recon --> exploit --> verify --> patch --> pushing --> completed
                                              ^                   |
                                              |   retry loop      |
                                              +----(max 3x)-------+
```

Each event payload:
```json
{
  "scan_id": "a1b2c3d4e5f6",
  "stage": "verify",
  "status": "running",
  "message": "Verifying exploit (deterministic)...",
  "detail": null,
  "pr_url": null,
  "vuln_count": 2,
  "progress_pct": 60
}
```

---

## Evaluation Criteria Alignment

This section maps A.E.G.I.S.'s architecture directly to the hackathon evaluation rubric to demonstrate maximum alignment with each scoring criterion.

| Criterion | How A.E.G.I.S. Addresses It |
|-----------|----------------------|
| **Autonomy** | The entire pipeline — from repository cloning through vulnerability discovery, exploitation, verification, patching, and Pull Request creation — executes without any human intervention. The user provides a repo URL; A.E.G.I.S. delivers a fix PR. Zero manual steps. |
| **Observability** | Every CPN transition, LLM call, sandbox execution, and verification decision emits structured OpenTelemetry spans via the Omium SDK. W3C Trace Context propagation across async boundaries produces a single connected trace for the full pipeline. This is not logging — it is production-grade distributed tracing. |
| **Reliability** | The fail-closed architecture prevents runaway execution: AST-validated sandbox blocks dangerous code before execution; deterministic Verifier rejects hallucinated results; SHA-256 circuit breaker prevents identical payload retries; 3-retry cap prevents death spirals; 20-step CPN limit prevents infinite traversal; SQLite WAL checkpointing after every transition enables crash recovery. |
| **Real-World Integration** | A.E.G.I.S. operates against live GitHub repositories using the GitHub REST API (OAuth, clone, branch, commit, PR) and OpenAI GPT-4o. No mock services, no simulated APIs. |
| **Technical Complexity** | Multi-agent CPN orchestration, AST-based code sandboxing, W3C trace propagation across async boundaries, real-time SSE streaming, signed cookie authentication, and strict Pydantic v2 inter-agent contracts — all integrated into a cohesive, production-quality system. |

---

## Technical Stack

### Frontend
| Technology | Purpose |
|-----------|---------|
| React 18 | Component-based UI with hooks |
| Vite 5 | Development server with HMR |
| CSS Modules | Scoped, maintainable styling |
| Server-Sent Events (SSE) | Real-time pipeline progress streaming |
| Petri Net Visualizer | Visual CPN state representation |
| Diff Viewer | Side-by-side patch visualization |

### Backend and Orchestration
| Technology | Purpose |
|-----------|---------|
| FastAPI | Async HTTP API with automatic OpenAPI docs |
| Python 3.11+ (asyncio) | Async pipeline execution via `asyncio.to_thread` |
| Colored Petri Net Engine | Deterministic multi-agent orchestration (custom) |
| SQLite (WAL mode) | Durable state checkpoints after every CPN transition |
| asyncio (background task + per-scan `asyncio.Queue`) | In-process pipeline execution and real-time SSE event streaming |
| Pydantic v2 | Strict JSON schema enforcement on all inter-agent data |
| AST Sandbox | Fail-closed code execution with import/call filtering |

### Integrations
| Service | Purpose |
|---------|---------|
| OpenAI GPT-4o | LLM backbone for Recon, Exploit, and Patcher agents |
| GitHub REST API (PyGithub) | Repository operations: clone, branch, commit, Pull Request |
| GitHub OAuth 2.0 | User authentication with signed HttpOnly cookies |
| Omium SDK (OTLP gRPC) | Distributed tracing with W3C Trace Context propagation |
| sse-starlette | Server-Sent Events for real-time frontend updates |

---

## Project Structure

```
anvil/
|
+-- frontend/                        # React + Vite dashboard
|   +-- src/
|       +-- components/
|       |   +-- NavBar.jsx           # Navigation with auth state
|       |   +-- HeroSection.jsx      # Landing page hero
|       |   +-- GitHubConnect.jsx     # OAuth connection flow
|       |   +-- RepoInput.jsx        # Repository URL input + scan trigger
|       |   +-- PetriNet.jsx         # Real-time CPN state visualizer
|       |   +-- Terminal.jsx         # Live SSE event terminal
|       |   +-- DiffViewer.jsx       # Side-by-side patch diff
|       |   +-- ScanComplete.jsx     # Results summary with PR link
|       |   +-- Architecture.jsx     # System architecture display
|       |   +-- Footer.jsx           # Footer component
|       +-- hooks/                   # Custom React hooks (SSE, auth)
|       +-- api/                     # API client functions
|       +-- App.jsx                  # Root component + routing
|       +-- index.css                # Global design system
|
+-- backend/
|   +-- app/
|   |   +-- main.py                  # FastAPI application + CORS + router mount
|   |   +-- api.py                   # Scan REST endpoints + SSE streaming
|   |   +-- auth.py                  # GitHub OAuth router (4 endpoints)
|   |   +-- pipeline.py             # Async pipeline runner + event emitter
|   |   +-- graph.py                 # CPN engine: Places, Transitions, routing
|   |   +-- sandbox.py              # AST-validated subprocess sandbox
|   |   +-- container_runtime.py    # Sealed --network none Docker isolation
|   |   +-- patch_validator.py      # Live re-exploit gate (host + container)
|   |   +-- schemas.py              # Pydantic v2 data contracts
|   |   +-- db.py                    # SQLite WAL checkpointing + execution log
|   |   +-- config.py               # Central configuration (env vars)
|   |   +-- telemetry.py            # Omium/OTLP exporter + W3C propagation
|   |   +-- github_service.py       # GitHub API: clone, branch, PR
|   |   +-- agents/
|   |       +-- recon.py            # Agent 1: Source code vulnerability analysis
|   |       +-- exploiter.py        # Agent 2: Exploit generation + sandbox
|   |       +-- verifier.py         # Verifier: Deterministic (NO LLM)
|   |       +-- patcher.py          # Agent 3: Fix + self-correcting re-exploit gate + PR
|   +-- docker/anvil-sandbox.Dockerfile  # Sealed sandbox base image
|   +-- evaluation/                  # Benchmark harness + known-vuln corpus + RESULTS.md
|   +-- tests/                       # sandbox / verifier / CPN / gate / container / eval (pytest)
|   +-- requirements.txt            # Python dependencies
|   +-- .env.example                 # Environment variable template
|
+-- start.sh                        # One-command launcher (backend + frontend)
```

---

## Fail-Closed Safety Mechanisms

A.E.G.I.S. enforces security at every layer. If any validation step fails, the system **refuses to proceed** (fail-closed).

| Layer | Mechanism | Implementation | What It Prevents |
|-------|-----------|---------------|-----------------|
| Sandbox | AST Import Filtering | Blocks `shutil`, `ctypes`, `subprocess`, `multiprocessing`, `signal`, `importlib` before execution | Dangerous system-level imports in LLM-generated code |
| Sandbox | AST Call Filtering | Blocks `os.remove`, `os.system`, `os.fork`, `eval`, `exec`, `subprocess.run` | Destructive operations and arbitrary code execution |
| Sandbox | Env Allowlist | Only PATH / TLS / proxy vars forwarded; every secret dropped (fail-closed allowlist) | Environment variable / credential leakage into LLM-generated code |
| Sandbox | Hard Timeout | Configurable `timeout` on subprocess execution | Infinite loops and resource exhaustion |
| Sandbox | SHA-256 Dedup | Per-scan hash circuit breaker blocks a payload after repeated failures | Retrying the same broken exploit indefinitely |
| Patch | Live Re-Exploit Gate | Relaunch the patched app + re-run the exploit; accept only if it still STARTS and the exploit now FAILS | Ineffective or app-breaking patches that static analysis waves through |
| Isolation | Sealed Container | `--network none` + memory/pid/cpu caps + non-root + ephemeral (host fallback) | Untrusted target/exploit code reaching the host or the internet |
| CPN | Max Steps | 20-step absolute limit on graph traversal | Infinite state machine loops |
| CPN | Retry Circuit Breaker | Maximum 3 retries at the verification gate | Exploit-Verify death spiral |
| Schemas | Pydantic v2 Strict Mode | All inter-agent data validated against typed contracts | Context poisoning and malformed data propagation |
| State | SQLite WAL Checkpoints | Full state serialized after every CPN transition | Data loss on crash; enables recovery |
| Auth | Signed HttpOnly Cookies | `itsdangerous.URLSafeSerializer` with configurable secret | Session hijacking and token theft |

---

## Getting Started

### Prerequisites

| Requirement | Check | Install |
|------------|-------|---------|
| Python 3.11+ | `python3 --version` | [python.org](https://www.python.org/downloads/) |
| Node.js 20+ | `node --version` | [nodejs.org](https://nodejs.org/) |
| OpenAI API Key | — | [platform.openai.com](https://platform.openai.com/api-keys) |
| GitHub OAuth App | — | [github.com/settings/developers](https://github.com/settings/developers) |

When creating the GitHub OAuth App, set:
- **Homepage URL**: `http://localhost:5173`
- **Authorization callback URL**: `http://localhost:8000/api/auth/callback`

---

### Step 1 — Configure the Backend

```bash
cd backend
cp .env.example .env
```

Edit `backend/.env` and fill in your credentials:

```env
OPENAI_API_KEY=sk-your-key-here
GITHUB_CLIENT_ID=your_client_id
GITHUB_CLIENT_SECRET=your_client_secret
SESSION_SECRET=run: python -c "import secrets; print(secrets.token_hex(32))"
```

All other values (SQLite path, Omium endpoint) have sensible defaults.

> **Tip:** Generate a secure session secret with: `python -c "import secrets; print(secrets.token_hex(32))"`

---

### Step 2 — Start the Backend

```bash
cd backend
python -m venv .venv

# Activate the virtual environment
# macOS/Linux:  source .venv/bin/activate
# Windows:      .venv\Scripts\activate

pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

The API documentation will be available at: `http://localhost:8000/docs`

---

### Step 3 — Start the Frontend

Open a new terminal:

```bash
cd frontend
npm install
npm run dev
```

The application will be available at: `http://localhost:5173`

---

### One-Command Launch

Alternatively, use the included launcher script that starts the backend and frontend in one step:

```bash
chmod +x start.sh
./start.sh
```

---

## API Reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/api/auth/github` | No | Redirect to GitHub OAuth authorization |
| `GET` | `/api/auth/callback` | No | OAuth code exchange, sets signed cookie |
| `GET` | `/api/auth/me` | Yes | Returns authenticated GitHub user profile |
| `POST` | `/api/auth/logout` | No | Clears session cookie |
| `POST` | `/api/scan` | Yes | Start scan `{"repo_url": "...", "base_branch": "main"}` |
| `GET` | `/api/scan/{id}/stream` | No | SSE stream of real-time `ScanEvent` objects |
| `GET` | `/api/scan/{id}` | No | Full `ScanResult` for a completed scan |
| `GET` | `/api/scans` | Yes | List all scans for current session |
| `GET` | `/health` | No | Health check endpoint |

---

## Observability and Tracing

A.E.G.I.S. exports distributed traces via the Omium SDK using the OTLP gRPC protocol. Every span includes structured attributes:

| Span Category | Attributes |
|--------------|------------|
| CPN Engine | `cpn.transition`, `cpn.step`, `cpn.retry_count`, `cpn.final_node`, `cpn.total_steps` |
| LLM Calls | `llm.prompt_tokens`, `llm.completion_tokens`, `agent.decision_rationale` |
| Sandbox | `tool.execution_status`, `sandbox.stdout_length` |
| Verification | `verification.result` (`VERIFIED` / `REJECTED`) |
| Patch | `patch.branch`, `patch.confidence` |

**W3C Trace Context Propagation**: The `traceparent` header is injected at the FastAPI ingress and extracted across async boundaries, ensuring the full pipeline (HTTP request, background thread, CPN transitions, agent executions) appears as one connected trace.

```
FastAPI Request --> trace_operation("scan_pipeline")
    --> asyncio.to_thread --> trace_operation("cpn_engine_run")
        --> trace_operation("transition:t2_run_recon")
        --> trace_operation("transition:t3_run_exploit")
        --> trace_operation("transition:t4_verify")
        --> trace_operation("transition:t5_run_patch")
```

---

## Data Contracts

All inter-agent communication is governed by strict Pydantic v2 schemas. No free-form text passes between agents.

| Schema | Producer | Consumer | Fields |
|--------|----------|----------|--------|
| `WebhookPayload` | API Layer | Pipeline | `target_url`, `deployment_id`, `repo_url` |
| `ReconOutput` | Recon Agent | Exploit Agent | `target_url`, `detected_framework`, `vulnerable_endpoints[]` |
| `ExploitOutput` | Exploit Agent | Verifier | `vulnerability_confirmed`, `exploit_payload_used`, `sandbox_stdout`, `extracted_secret` |
| `VerificationResult` | Verifier | Patcher (gate) | `verified`, `reason`, `expected_pattern`, `actual_value` |
| `PatchOutput` | Patcher Agent | Results | `file_modified`, `unified_diff`, `pr_url`, `confidence_score` |
| `MasterState` | CPN Engine | All Agents | The coloured token: carries all accumulated state through the net |
| `ScanEvent` | Pipeline | Frontend (SSE) | `scan_id`, `stage`, `status`, `message`, `pr_url`, `progress_pct` |

---

## Future Scope and Scalability

A.E.G.I.S. was designed as a production-capable foundation, not a hackathon prototype. The architecture supports the following V2 enhancements:

| Enhancement | Description |
|------------|-------------|
| **CI/CD Pipeline Integration** | Trigger scans automatically on push/PR events via GitHub Webhooks, integrating A.E.G.I.S. into existing DevSecOps workflows |
| **Multi-Platform Support** | Extend GitHub integration to GitLab, Bitbucket, and Azure DevOps using a provider abstraction layer |
| **Expanded Skill Repository** | Add detection modules for OWASP Top 10 categories beyond path traversal: SQL injection, XSS, SSRF, insecure deserialization |
| **Parallel Multi-Vulnerability Scanning** | Fork the CPN into parallel sub-nets, one per vulnerability, enabling simultaneous exploitation and patching |
| **Persistent Scan History** | Replace in-memory scan registry with PostgreSQL for multi-session, multi-user scan history and analytics |
| **Role-Based Access Control** | Extend OAuth to support team-based access with repository-level permissions |
| **Custom Policy Engine** | Allow teams to define which vulnerability classes trigger auto-patching vs. manual review |
| **Container-Based Sandbox** | Upgrade from AST-validated subprocess to gVisor or Firecracker micro-VMs for stronger isolation |

---

## Research & Inspiration

A.E.G.I.S. draws on ideas from several areas of academic and industry research. Below are the key works that influenced our architecture and design decisions.

### Colored Petri Nets for Multi-Agent Orchestration

| Reference | Relevance to A.E.G.I.S. |
|-----------|------------------------|
| **K. Jensen & L.M. Kristensen**, *Coloured Petri Nets: Modelling and Validation of Concurrent Systems*, Springer, 2009. | The foundational text on CPN theory. Our CPN engine directly implements the coloured token model described here — using a `MasterState` Pydantic object as the token flowing through a bipartite place-transition graph. |
| **Hübner et al.**, *"Using Coloured Petri Nets for Testing Multi-Agent Systems"*, MDPI, 2020. | Introduced the CPN4M framework for mapping organizational agent specifications (Moise+) to CPN models. Inspired our approach of encoding all routing decisions as Python guard conditions rather than LLM-driven routing. |
| **Marzougui et al.**, *"Colored Petri Nets Based Modeling and Simulation of Multi-Agent Systems"*, AIRCC, 2014. | Demonstrated the use of Hierarchical CPNs for modeling individual agent behaviors and composing them into verifiable system models — directly relevant to our 10-place, 5-transition CPN design. |

### Autonomous Vulnerability Detection & Red-Teaming

| Reference | Relevance to A.E.G.I.S. |
|-----------|------------------------|
| **Fang et al.**, *"Teams of LLM Agents can Exploit Zero-Day Vulnerabilities"* (HPTSA), arXiv, 2024. | Demonstrated that hierarchical planning with specialized sub-agents (exploration, exploitation, triage) outperforms monolithic agent architectures. This directly influenced our four-agent pipeline design (Recon → Exploit → Verify → Patch). |
| **Deng et al.**, *"PentestGPT: An LLM-empowered Automatic Penetration Testing Tool"*, USENIX Security, 2024. | Highlighted the limitations of single-agent penetration testing and the need for structured task decomposition — a gap we address with our CPN-based orchestration. |
| **Gioacchini et al.**, *"AutoPenBench: Benchmarking Generative Agents for Penetration Testing"*, arXiv, 2024. | Established benchmarks for evaluating autonomous penetration testing agents. Validated our design choice of deterministic verification gates to prevent LLM hallucination in security-critical pipelines. |
| **DARPA AI Cyber Challenge (AIxCC)**, 2024–2025. | The first large-scale competition for autonomous AI cyber-defense systems. Reinforced the importance of fail-closed architectures and the need for cryptographic proof of exploitation before patching — core tenets of A.E.G.I.S. |

### Observability & Distributed Tracing

| Reference | Relevance to A.E.G.I.S. |
|-----------|------------------------|
| **W3C Trace Context Specification**, W3C Recommendation, 2021. | The standard we implement for propagating trace context (`traceparent` header) across async boundaries, enabling the entire pipeline to appear as a single connected trace. |
| **OpenTelemetry Specification**, CNCF, 2023. | Our telemetry layer uses the OTLP gRPC protocol and structured span attributes, following OpenTelemetry semantic conventions for LLM and agent operations. |

---

## Contributors

- [Aniket Krishna Ingale](https://github.com/DevOpsDreamer)
- [Sumeet Ravindra Gite](https://github.com/Sumeet2386)
- [Harshal Andhale](https://github.com/HarshalAndhale9657)
- [Ansh Jaiswal](https://github.com/Ansh-1019)

---

## License

This project was built for the Multi-Agent Autonomy Hackathon (PS3 Track).

---

<div align="center">

**Built with a focus on autonomy, reliability, and full observability.**

A.E.G.I.S. — Because vulnerabilities should not wait for humans.

</div>

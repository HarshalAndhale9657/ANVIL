"""
FastAPI application — entry point for the Anvil web app.

Serves the API routes for GitHub OAuth, scan management, and SSE streaming.
The frontend (Vite app) will be served separately or proxied.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import router as api_router
from app.auth import router as auth_router
from app.config import FRONTEND_URL
from app.telemetry import init_telemetry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_telemetry()
    logger.info("Anvil API server ready")
    yield
    # Shutdown (nothing to tear down yet)


app = FastAPI(
    title="Anvil — Autonomous Security Remediation",
    description=(
        "Multi-agent CPN pipeline that scans GitHub repos for vulnerabilities, "
        "generates exploits, verifies them, and creates Pull Requests with fixes."
    ),
    version="2.0.0",
    lifespan=lifespan,
)

# ── CORS — allow the Vite dev server to call the API ─────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",   # Vite default
        "http://localhost:3000",   # alternate
        "http://localhost:8000",   # same-origin
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000",
        FRONTEND_URL,
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Mount routers ────────────────────────────────────────────────────────────
app.include_router(auth_router)
app.include_router(api_router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "anvil"}


# ── Legacy webhook endpoint (kept for backward compatibility) ────────────────

@app.post("/webhook", status_code=202, tags=["legacy"])
async def receive_webhook_legacy(payload: dict):
    """
    Legacy webhook endpoint. For new integrations, use POST /api/scan instead.
    """
    import uuid
    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=202,
        content={
            "status": "accepted",
            "message": "Legacy webhook received. Use POST /api/scan for the web app.",
            "trace_id": uuid.uuid4().hex,
        },
    )

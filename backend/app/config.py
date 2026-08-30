"""
Central configuration for the Autonomous Red-Team Engine.
All secrets and environment toggles live here.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from the project root (one level above app/)
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

# ── LLM Provider ──────────────────────────────────────────────────────────────
OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
LLM_MODEL: str = os.getenv("LLM_MODEL", "gpt-4o")
LLM_TEMPERATURE: float = float(os.getenv("LLM_TEMPERATURE", "0.0"))

# ── SQLite ────────────────────────────────────────────────────────────────────
SQLITE_DB_PATH: str = os.getenv("SQLITE_DB_PATH", "master_state.db")

# ── Sandbox ───────────────────────────────────────────────────────────────────
SANDBOX_TIMEOUT_SECONDS: int = int(os.getenv("SANDBOX_TIMEOUT_SECONDS", "15"))
SANDBOX_MAX_RETRIES: int = int(os.getenv("SANDBOX_MAX_RETRIES", "3"))

# ── Patch Validation ──────────────────────────────────────────────────────────
# When enabled, generated patches must pass the live re-exploit gate (launch the
# patched app + re-run the exploit) before a PR is opened. Kill switch for
# environments where launching the target app is not possible.
LIVE_PATCH_GATE: bool = os.getenv("LIVE_PATCH_GATE", "true").lower() in ("true", "1", "yes")

# How many times the patcher may regenerate a fix, feeding each rejection
# (ineffective / breaks-startup) back to the model, before giving up (no PR).
PATCH_MAX_ATTEMPTS: int = int(os.getenv("PATCH_MAX_ATTEMPTS", "3"))

# ── Omium / OpenTelemetry ─────────────────────────────────────────────────────
OMIUM_API_KEY: str = os.getenv("OMIUM_API_KEY", "")
OMIUM_ENDPOINT: str = os.getenv(
    "OMIUM_ENDPOINT",
    "https://api.omium.ai",
)
SERVICE_NAME: str = os.getenv("SERVICE_NAME", "red-team-engine")

# ── GitHub OAuth ──────────────────────────────────────────────────────────────
GITHUB_CLIENT_ID: str = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET: str = os.getenv("GITHUB_CLIENT_SECRET", "")
GITHUB_REDIRECT_URI: str = os.getenv(
    "GITHUB_REDIRECT_URI", "http://localhost:8000/api/auth/callback"
)

# ── Session / Security ───────────────────────────────────────────────────────
SESSION_SECRET: str = os.getenv("SESSION_SECRET", "change-me-in-production-32bytes!")

# ── Scan Workspace ───────────────────────────────────────────────────────────
SCAN_TEMP_DIR: str = os.getenv("SCAN_TEMP_DIR", str(Path(__file__).resolve().parent.parent / "scans"))

# ── Web App URL ──────────────────────────────────────────────────────────────
FRONTEND_URL: str = os.getenv("FRONTEND_URL", "http://localhost:5173")

"""
Central configuration for the Autonomous Red-Team Engine.
All secrets and environment toggles live here.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from the project root (one level above app/)
load_dotenv(Path(__file__).resolve().parent.parent / ".env")


def _env_bool(name: str, default: str) -> bool:
    return os.getenv(name, default).strip().lower() in ("true", "1", "yes")


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

# ── Agentic exploit ───────────────────────────────────────────────────────────
# When on, the exploiter uses a tool-using loop (probe the live target via HTTP /
# read source, observe, refine) to generate the exploit, instead of one-shot
# prompting. It still emits a standalone script run in the AST sandbox, so the
# verify/patch contract is unchanged. Off by default (extra LLM calls per scan).
AGENTIC_EXPLOIT: bool = os.getenv("AGENTIC_EXPLOIT", "false").lower() in ("true", "1", "yes")
AGENTIC_EXPLOIT_MAX_STEPS: int = int(os.getenv("AGENTIC_EXPLOIT_MAX_STEPS", "8"))

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
_DEFAULT_SESSION_SECRET = "change-me-in-production-32bytes!"
SESSION_SECRET: str = os.getenv("SESSION_SECRET", _DEFAULT_SESSION_SECRET)

# Session cookie attributes. Production serves the API same-origin behind the
# frontend (Vercel rewrites /api/* to the backend), so SameSite=Lax + Secure is
# correct there. Only a split-origin deployment (frontend and API on different
# sites) needs SameSite=None — and those third-party cookies are blocked by
# Safari, Firefox, Brave and every browser's private mode, so avoid it.
COOKIE_SECURE: bool = _env_bool("COOKIE_SECURE", "false")
COOKIE_SAMESITE: str = os.getenv("COOKIE_SAMESITE", "lax").lower()
if COOKIE_SAMESITE not in ("lax", "strict", "none"):
    raise ValueError(f"COOKIE_SAMESITE must be lax|strict|none, got {COOKIE_SAMESITE!r}")
if COOKIE_SAMESITE == "none" and not COOKIE_SECURE:
    raise ValueError("COOKIE_SAMESITE=none requires COOKIE_SECURE=true (browsers reject it otherwise)")
# A Secure cookie means a real deployment: refuse to start with the public
# placeholder secret, which would let anyone forge session cookies.
if COOKIE_SECURE and SESSION_SECRET == _DEFAULT_SESSION_SECRET:
    raise ValueError("SESSION_SECRET must be set to a random value in production (COOKIE_SECURE=true)")

# ── Scan Workspace ───────────────────────────────────────────────────────────
SCAN_TEMP_DIR: str = os.getenv("SCAN_TEMP_DIR", str(Path(__file__).resolve().parent.parent / "scans"))

# ── Web App URL ──────────────────────────────────────────────────────────────
FRONTEND_URL: str = os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/")

# ── Hosted-deployment guardrails ─────────────────────────────────────────────
# A public deployment executes code from the repos it scans and spends LLM
# credits per scan, so it needs limits. Defaults are permissive for local dev;
# render.yaml sets the production values.
#
# Whose repositories may be scanned: comma-separated GitHub owners. "*" = any
# repo; "@self" = repos owned by the signed-in user. e.g. "acme,@self".
SCAN_ALLOWED_OWNERS: list[str] = [
    o.strip() for o in os.getenv("SCAN_ALLOWED_OWNERS", "*").split(",") if o.strip()
]
# Scans running at once across all users (CPU/RAM bound on small instances).
MAX_CONCURRENT_SCANS: int = int(os.getenv("MAX_CONCURRENT_SCANS", "4"))
# Scans one user may have in flight at once.
MAX_ACTIVE_SCANS_PER_USER: int = int(os.getenv("MAX_ACTIVE_SCANS_PER_USER", "1"))
# Rolling 24h caps (0 = unlimited). Bound LLM spend on a public demo.
MAX_SCANS_PER_USER_PER_DAY: int = int(os.getenv("MAX_SCANS_PER_USER_PER_DAY", "0"))
MAX_SCANS_PER_DAY: int = int(os.getenv("MAX_SCANS_PER_DAY", "0"))

# When the signed-in user cannot push to the scanned repo, ANVIL forks it. By
# default the fix PR is opened INSIDE the user's fork, so a public deployment can
# never be used to send automated PRs to third-party projects. Set true to open
# the PR against the upstream repo instead (classic contribution flow).
ALLOW_UPSTREAM_PRS: bool = _env_bool("ALLOW_UPSTREAM_PRS", "false")

# Optional deliberately-vulnerable repo the UI offers as a one-click demo.
DEMO_REPO_URL: str = os.getenv("DEMO_REPO_URL", "").strip()

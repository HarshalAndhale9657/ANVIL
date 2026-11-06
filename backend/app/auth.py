"""
GitHub OAuth authentication router.

Handles the full OAuth flow:
  1. GET /api/auth/github   → redirect to GitHub authorization page
  2. GET /api/auth/callback → exchange code for token, set cookie
  3. GET /api/auth/me       → return current user info
  4. POST /api/auth/logout  → clear cookie
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from urllib.parse import urlencode

from cryptography.fernet import Fernet, InvalidToken

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from itsdangerous import BadSignature, URLSafeSerializer

from app.config import (
    COOKIE_SAMESITE,
    COOKIE_SECURE,
    FRONTEND_URL,
    GITHUB_CLIENT_ID,
    GITHUB_REDIRECT_URI,
    SESSION_SECRET,
)

from app.github_service import (
    exchange_code_for_token,
    get_github_user,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["auth"])

# ────────────────────────────────────────────────────────────────
# Cookie / Session Config
# ────────────────────────────────────────────────────────────────

# The session cookie carries the user's GitHub OAuth token (repo scope). It is
# ENCRYPTED (Fernet: AES-128-CBC + HMAC-SHA256), not merely signed — a signed
# cookie is just base64, so the token would be readable by anything that ever
# sees the cookie value (logs, proxies, browser extensions).
_fernet = Fernet(base64.urlsafe_b64encode(
    hashlib.sha256(f"anvil-session-v2:{SESSION_SECRET}".encode()).digest()
))
_state_signer = URLSafeSerializer(SESSION_SECRET, salt="oauth-state")

_COOKIE_NAME = "anvil_session"
_STATE_COOKIE_NAME = "anvil_oauth_state"

_COOKIE_MAX_AGE = 86400 * 7
_STATE_COOKIE_MAX_AGE = 600

_COOKIE_SECURE = COOKIE_SECURE

# Shared cookie attributes. The SAME attributes must be used when SETTING and
# when DELETING a cookie, otherwise the browser treats them as different cookies
# and delete_cookie silently fails (session never clears in cross-origin/HTTPS
# deployments where samesite=None/secure=True are in effect).
_COOKIE_KWARGS = {
    "path": "/",
    "httponly": True,
    "samesite": COOKIE_SAMESITE,
    "secure": COOKIE_SECURE,
}


# ────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────

def encode_session(token: str) -> str:
    """Encrypt a GitHub token into an opaque session-cookie value."""
    return _fernet.encrypt(token.encode()).decode()


def decode_session(value: str) -> str | None:
    """Decrypt a session-cookie value; None if missing, tampered, or expired."""
    if not value:
        return None
    try:
        return _fernet.decrypt(value.encode(), ttl=_COOKIE_MAX_AGE).decode()
    except (InvalidToken, ValueError, TypeError):
        return None


def _get_token_from_cookie(request: Request) -> str | None:
    return decode_session(request.cookies.get(_COOKIE_NAME))


def require_auth(request: Request) -> str:
    token = _get_token_from_cookie(request)

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated"
        )

    return token


# ────────────────────────────────────────────────────────────────
# Routes
# ────────────────────────────────────────────────────────────────

@router.get("/github")
async def github_login():

    if not GITHUB_CLIENT_ID:
        raise HTTPException(
            status_code=500,
            detail="GITHUB_CLIENT_ID not configured"
        )

    state = secrets.token_urlsafe(32)

    params = urlencode({
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": GITHUB_REDIRECT_URI,
        "scope": "repo",
        "state": state,
    })

    response = RedirectResponse(
        url=f"https://github.com/login/oauth/authorize?{params}"
    )

    response.set_cookie(
        key=_STATE_COOKIE_NAME,
        value=_state_signer.dumps(state),
        max_age=_STATE_COOKIE_MAX_AGE,
        **_COOKIE_KWARGS,
    )

    return response


@router.get("/callback")
async def github_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
):

    # ─────────────────────────────────────────────
    # Handle a denied / failed authorization: GitHub redirects here with
    # ?error=... and no code. Bounce back to the frontend with an error hint
    # instead of returning a raw 422 for the missing `code` query param.
    # ─────────────────────────────────────────────

    # Every failure bounces the browser back to the app with a readable
    # ?auth_error= (rendered by the frontend) — never a raw JSON error page on
    # the API, which is a dead end for the user.
    def _fail(code_: str, description: str) -> RedirectResponse:
        params = urlencode({"auth_error": code_, "auth_error_description": description})
        response = RedirectResponse(url=f"{FRONTEND_URL}/?{params}", status_code=302)
        response.delete_cookie(_STATE_COOKIE_NAME, **_COOKIE_KWARGS)
        return response

    if error or not code:
        logger.warning("OAuth callback without code (error=%s): %s", error, error_description)
        return _fail(error or "missing_code", error_description or "Authorization was not completed")

    # ─────────────────────────────────────────────
    # Validate OAuth state (CSRF protection)
    # ─────────────────────────────────────────────

    stored_state_raw = request.cookies.get(_STATE_COOKIE_NAME)
    try:
        stored_state = _state_signer.loads(stored_state_raw) if stored_state_raw else None
    except BadSignature:
        stored_state = None

    if not state or not stored_state or not secrets.compare_digest(state.encode(), str(stored_state).encode()):
        logger.warning("OAuth state missing/invalid/mismatched — possible CSRF or expired login")
        return _fail("invalid_state", "Your sign-in session expired. Please try connecting GitHub again.")

    # ─────────────────────────────────────────────
    # Exchange GitHub code for access token
    # ─────────────────────────────────────────────

    try:
        token = await exchange_code_for_token(code)
    except Exception as exc:
        logger.error("OAuth token exchange failed: %s", exc)
        return _fail("token_exchange_failed", "GitHub did not accept the sign-in code. Please try again.")

    # ─────────────────────────────────────────────
    # Store signed session cookie
    # ─────────────────────────────────────────────

    signed = encode_session(token)

    response = RedirectResponse(
        url=f"{FRONTEND_URL}/",
        status_code=302
    )

    response.set_cookie(
        key=_COOKIE_NAME,
        value=signed,
        max_age=_COOKIE_MAX_AGE,
        **_COOKIE_KWARGS,
    )

    response.delete_cookie(_STATE_COOKIE_NAME, **_COOKIE_KWARGS)

    logger.info(
        "GitHub OAuth complete — session cookie set (secure=%s)",
        _COOKIE_SECURE
    )

    return response


@router.get("/me")
async def get_current_user(request: Request):

    token = require_auth(request)

    try:
        # IMPORTANT FIX:
        # must await async function
        user = await get_github_user(token)

        return JSONResponse(content=user)

    except Exception as exc:
        logger.error(
            "Failed to fetch GitHub user: %s",
            exc
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )


@router.post("/logout")
async def logout():

    response = JSONResponse({
        "status": "logged_out"
    })

    response.delete_cookie(_COOKIE_NAME, **_COOKIE_KWARGS)

    return response
"""
GitHub OAuth authentication router.

Handles the full OAuth flow:
  1. GET /api/auth/github   → redirect to GitHub authorization page
  2. GET /api/auth/callback → exchange code for token, set cookie
  3. GET /api/auth/me       → return current user info
  4. POST /api/auth/logout  → clear cookie
"""

from __future__ import annotations

import logging
import os
import secrets
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from itsdangerous import BadSignature, URLSafeSerializer

from app.config import (
    GITHUB_CLIENT_ID,
    GITHUB_REDIRECT_URI,
    SESSION_SECRET,
    FRONTEND_URL,
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

_signer = URLSafeSerializer(SESSION_SECRET, salt="github-token")
_state_signer = URLSafeSerializer(SESSION_SECRET, salt="oauth-state")

_COOKIE_NAME = "anvil_session"
_STATE_COOKIE_NAME = "anvil_oauth_state"

_COOKIE_MAX_AGE = 86400 * 7
_STATE_COOKIE_MAX_AGE = 600

_COOKIE_SECURE = os.getenv(
    "COOKIE_SECURE",
    "false"
).lower() in ("true", "1", "yes")

# Shared cookie attributes. The SAME attributes must be used when SETTING and
# when DELETING a cookie, otherwise the browser treats them as different cookies
# and delete_cookie silently fails (session never clears in cross-origin/HTTPS
# deployments where samesite=None/secure=True are in effect).
_COOKIE_KWARGS = {
    "path": "/",
    "httponly": True,
    "samesite": "none" if _COOKIE_SECURE else "lax",
    "secure": _COOKIE_SECURE,
}


# ────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────

def _get_token_from_cookie(request: Request) -> str | None:
    raw = request.cookies.get(_COOKIE_NAME)

    if not raw:
        return None

    try:
        return _signer.loads(raw)

    except BadSignature:
        return None


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

    if error or not code:
        logger.warning("OAuth callback without code (error=%s): %s", error, error_description)
        params = urlencode({
            "auth_error": error or "missing_code",
            "auth_error_description": error_description or "Authorization was not completed",
        })
        return RedirectResponse(url=f"{FRONTEND_URL}?{params}", status_code=302)

    # ─────────────────────────────────────────────
    # Validate OAuth state (CSRF protection)
    # ─────────────────────────────────────────────

    stored_state_raw = request.cookies.get(_STATE_COOKIE_NAME)

    if not state or not stored_state_raw:
        raise HTTPException(
            status_code=400,
            detail="Missing OAuth state"
        )

    try:
        stored_state = _state_signer.loads(stored_state_raw)

    except BadSignature:
        raise HTTPException(
            status_code=400,
            detail="Invalid OAuth state"
        )

    if not secrets.compare_digest(state, stored_state):
        raise HTTPException(
            status_code=400,
            detail="OAuth state mismatch"
        )

    # ─────────────────────────────────────────────
    # Exchange GitHub code for access token
    # ─────────────────────────────────────────────

    try:
        token = await exchange_code_for_token(code)

    except Exception as exc:
        logger.error("OAuth token exchange failed: %s", exc)

        raise HTTPException(
            status_code=400,
            detail=f"OAuth failed: {exc}"
        )

    # ─────────────────────────────────────────────
    # Store signed session cookie
    # ─────────────────────────────────────────────

    signed = _signer.dumps(token)

    response = RedirectResponse(
        url=FRONTEND_URL,
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
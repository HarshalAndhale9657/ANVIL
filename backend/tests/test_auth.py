"""GitHub OAuth flow: login redirect, CSRF state, callback, session, logout."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from app import auth
from app.main import app


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(auth, "GITHUB_CLIENT_ID", "test-client-id")
    return TestClient(app, follow_redirects=False)


def _login(client):
    r = client.get("/api/auth/github")
    assert r.status_code == 307
    loc = urlparse(r.headers["location"])
    assert loc.netloc == "github.com"
    q = parse_qs(loc.query)
    assert q["client_id"] == ["test-client-id"] and q["scope"] == ["repo"]
    assert auth._STATE_COOKIE_NAME in r.cookies
    return q["state"][0]


def test_full_login_roundtrip(client, monkeypatch):
    async def fake_exchange(code):
        assert code == "the-code"
        return "gho_realtoken"

    async def fake_user(token):
        assert token == "gho_realtoken"
        return {"login": "octo", "id": 1}

    monkeypatch.setattr(auth, "exchange_code_for_token", fake_exchange)
    monkeypatch.setattr(auth, "get_github_user", fake_user)

    state = _login(client)
    r = client.get(f"/api/auth/callback?code=the-code&state={state}")
    assert r.status_code == 302
    assert "auth_error" not in r.headers["location"]
    session = r.cookies.get(auth._COOKIE_NAME)
    assert session and "gho_realtoken" not in session
    assert auth.decode_session(session) == "gho_realtoken"

    me = client.get("/api/auth/me")
    assert me.status_code == 200 and me.json()["login"] == "octo"

    out = client.post("/api/auth/logout")
    assert out.status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_callback_with_forged_state_redirects_with_error(client):
    _login(client)
    r = client.get("/api/auth/callback?code=x&state=attacker-chosen")
    assert r.status_code == 302
    assert "auth_error=invalid_state" in r.headers["location"]
    assert auth._COOKIE_NAME not in r.cookies


def test_callback_without_state_cookie_redirects_with_error(client):
    r = client.get("/api/auth/callback?code=x&state=y")
    assert r.status_code == 302
    assert "auth_error=invalid_state" in r.headers["location"]


def test_denied_authorization_redirects_with_error(client):
    r = client.get("/api/auth/callback?error=access_denied&error_description=nope")
    assert r.status_code == 302
    assert "auth_error=access_denied" in r.headers["location"]


def test_failed_token_exchange_redirects_with_error(client, monkeypatch):
    async def boom(code):
        raise ValueError("bad_verification_code")

    monkeypatch.setattr(auth, "exchange_code_for_token", boom)
    state = _login(client)
    r = client.get(f"/api/auth/callback?code=used&state={state}")
    assert r.status_code == 302
    assert "auth_error=token_exchange_failed" in r.headers["location"]


def test_me_rejects_tampered_cookie(client):
    client.cookies.set(auth._COOKIE_NAME, "not-a-real-session")
    assert client.get("/api/auth/me").status_code == 401


def test_callback_with_non_ascii_state_is_rejected_not_500(client):
    _login(client)
    r = client.get("/api/auth/callback", params={"code": "x", "state": "é漢"})
    assert r.status_code == 302
    assert "auth_error=invalid_state" in r.headers["location"]

"""
Hosted-deployment guardrails: request validation, repo-owner allowlist,
per-user / global scan limits, and the encrypted session cookie.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.schemas import ScanRequest
from app.guardrails import ScanLimiter, ScanRejected, repo_owner_allowed


# ── ScanRequest validation ──────────────────────────────────────────────────

@pytest.mark.parametrize("url,expected", [
    ("https://github.com/octo/demo", "https://github.com/octo/demo"),
    ("https://github.com/octo/demo.git", "https://github.com/octo/demo"),
    ("https://github.com/octo/demo/", "https://github.com/octo/demo"),
    ("  https://www.github.com/Octo-Org/my.repo_1  ", "https://github.com/Octo-Org/my.repo_1"),
    ("http://github.com/octo/demo", "https://github.com/octo/demo"),
])
def test_repo_url_is_normalised(url, expected):
    assert ScanRequest(repo_url=url).repo_url == expected


@pytest.mark.parametrize("url", [
    "https://gitlab.com/octo/demo",
    "https://github.com/octo",
    "https://github.com/octo/demo/tree/main",
    "https://github.com/../etc/passwd",
    "https://github.com/octo/demo?x=1",
    "file:///etc/passwd",
    "git@github.com:octo/demo.git; rm -rf /",
    "",
])
def test_bad_repo_urls_rejected(url):
    with pytest.raises(ValidationError):
        ScanRequest(repo_url=url)


@pytest.mark.parametrize("branch", ["main", "release/1.2", "feature_x-y.z"])
def test_valid_branches(branch):
    assert ScanRequest(repo_url="https://github.com/o/r", base_branch=branch).base_branch == branch


@pytest.mark.parametrize("branch", ["-rf", "a..b", "a b", "", "x" * 300, "/lead", "trail/", "a~1", "x.lock"])
def test_bad_branches_rejected(branch):
    with pytest.raises(ValidationError):
        ScanRequest(repo_url="https://github.com/o/r", base_branch=branch)


# ── Owner allowlist ──────────────────────────────────────────────────────────

def test_owner_allowlist():
    assert repo_owner_allowed("anyone", "me", ["*"])
    assert repo_owner_allowed("Acme", "me", ["acme"])           # case-insensitive
    assert repo_owner_allowed("acme", "me", ["ACME"])
    assert repo_owner_allowed("Me", "me", ["acme", "@self"])     # own repos
    assert not repo_owner_allowed("stranger", "me", ["acme", "@self"])
    assert not repo_owner_allowed("acme", "me", [])               # empty = nothing


# ── Limiter ──────────────────────────────────────────────────────────────────

class _Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


def test_per_user_concurrency():
    lim = ScanLimiter(max_concurrent=10, max_active_per_user=1, per_user_per_day=0, per_day=0)
    lim.acquire("u1")
    with pytest.raises(ScanRejected) as e:
        lim.acquire("u1")
    assert e.value.status_code == 429
    lim.acquire("u2")  # other users unaffected
    lim.release("u1")
    lim.acquire("u1")  # slot freed


def test_global_concurrency():
    lim = ScanLimiter(max_concurrent=2, max_active_per_user=5, per_user_per_day=0, per_day=0)
    lim.acquire("a")
    lim.acquire("b")
    with pytest.raises(ScanRejected) as e:
        lim.acquire("c")
    assert e.value.status_code == 503
    lim.release("a")
    lim.acquire("c")


def test_daily_quotas_roll_off_after_24h():
    clock = _Clock()
    lim = ScanLimiter(max_concurrent=10, max_active_per_user=10,
                      per_user_per_day=2, per_day=3, clock=clock)
    lim.acquire("u"); lim.release("u")
    lim.acquire("u"); lim.release("u")
    with pytest.raises(ScanRejected):
        lim.acquire("u")                    # user cap hit
    lim.acquire("v"); lim.release("v")
    with pytest.raises(ScanRejected):
        lim.acquire("w")                    # global cap hit
    clock.t += 24 * 3600 + 1
    lim.acquire("u")                        # window rolled


def test_rejected_acquire_does_not_consume_quota():
    lim = ScanLimiter(max_concurrent=1, max_active_per_user=1, per_user_per_day=1, per_day=0)
    lim.acquire("a")
    with pytest.raises(ScanRejected):
        lim.acquire("b")                    # rejected by concurrency...
    lim.release("a")
    lim.acquire("b")                        # ...so b's daily quota is intact


def test_release_is_idempotent():
    lim = ScanLimiter(max_concurrent=1, max_active_per_user=1, per_user_per_day=0, per_day=0)
    lim.release("never-acquired")
    lim.acquire("u")
    lim.release("u")
    lim.release("u")
    lim.acquire("x")


# ── Session cookie ──────────────────────────────────────────────────────────

def test_session_cookie_is_encrypted_not_just_signed():
    from app import auth
    token = "gho_plaintextTokenMustNotBeVisible"
    value = auth.encode_session(token)
    assert token not in value
    import base64
    padded = value + "=" * (-len(value) % 4)
    try:
        assert token.encode() not in base64.urlsafe_b64decode(padded)
    except Exception:
        pass
    assert auth.decode_session(value) == token
    assert auth.decode_session(value[:-2] + "xx") is None
    assert auth.decode_session("garbage") is None


# ── API wiring ──────────────────────────────────────────────────────────────

@pytest.fixture
def client(monkeypatch):
    import app.api as api
    from app import auth, guardrails
    from app.main import app

    started = []

    async def fake_user(token):
        return {"login": "me", "id": 42}

    def fake_start_scan(token, repo_url, base_branch="main", user_key=None):
        started.append((repo_url, user_key))
        return "scan" + str(len(started))

    monkeypatch.setattr(api, "get_github_user", fake_user)
    monkeypatch.setattr(api, "start_scan", fake_start_scan)
    monkeypatch.setattr(api, "SCAN_ALLOWED_OWNERS", ["acme", "@self"])
    monkeypatch.setattr(guardrails, "scan_limiter",
                        ScanLimiter(max_concurrent=5, max_active_per_user=1,
                                    per_user_per_day=0, per_day=0))
    c = TestClient(app)
    c.cookies.set(auth._COOKIE_NAME, auth.encode_session("gho_test"))
    c.started = started
    return c


def test_scan_requires_auth(client):
    client.cookies.clear()
    r = client.post("/api/scan", json={"repo_url": "https://github.com/acme/app"})
    assert r.status_code == 401


def test_scan_rejects_bad_url_with_422(client):
    r = client.post("/api/scan", json={"repo_url": "https://evil.com/x/y"})
    assert r.status_code == 422


def test_scan_rejects_disallowed_owner(client):
    r = client.post("/api/scan", json={"repo_url": "https://github.com/pallets/flask"})
    assert r.status_code == 403
    assert "pallets" in r.json()["detail"]
    assert client.started == []


def test_scan_allowed_owner_and_self(client):
    r = client.post("/api/scan", json={"repo_url": "https://github.com/acme/app.git"})
    assert r.status_code == 202, r.text
    assert client.started == [("https://github.com/acme/app", "42")]


def test_second_concurrent_scan_is_429(client):
    assert client.post("/api/scan", json={"repo_url": "https://github.com/me/x"}).status_code == 202
    r = client.post("/api/scan", json={"repo_url": "https://github.com/me/y"})
    assert r.status_code == 429


def test_public_config_endpoint(client):
    r = client.get("/api/config")
    assert r.status_code == 200
    body = r.json()
    assert set(body) >= {"demo_repo_url", "allowed_owners", "upstream_prs", "limits"}


def test_api_health(client):
    assert client.get("/api/health").json()["status"] == "ok"

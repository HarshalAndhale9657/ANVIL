"""
End-to-end API endpoint tests for Anvil backend.
Tests all routes without authentication dependency.
"""
import requests
import json

BASE = "http://localhost:8000"
PASS = 0
FAIL = 0

def test(name, fn):
    global PASS, FAIL
    print(f"\n{'='*60}")
    print(f"TEST: {name}")
    try:
        fn()
        PASS += 1
        print(f"  ✓ PASSED")
    except Exception as e:
        FAIL += 1
        print(f"  ✗ FAILED: {e}")

# ----- Tests -----

def test_health():
    r = requests.get(f"{BASE}/health", timeout=10)
    print(f"  Status: {r.status_code}")
    print(f"  Body: {r.json()}")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    assert r.json()["status"] == "ok", "Status should be 'ok'"

def test_openapi():
    r = requests.get(f"{BASE}/openapi.json", timeout=10)
    print(f"  Status: {r.status_code}")
    data = r.json()
    paths = list(data["paths"].keys())
    print(f"  Registered paths: {paths}")
    assert r.status_code == 200
    assert "/api/scan" in paths, f"/api/scan not found in paths: {paths}"
    assert "/api/auth/github" in paths, f"/api/auth/github not found"
    assert "/health" in paths, f"/health not found"

def test_oauth_redirect():
    r = requests.get(f"{BASE}/api/auth/github", timeout=10, allow_redirects=False)
    print(f"  Status: {r.status_code}")
    loc = r.headers.get("Location", "N/A")
    print(f"  Location: {loc[:100]}...")
    assert r.status_code in (302, 307), f"Expected redirect, got {r.status_code}"
    assert "github.com/login/oauth/authorize" in loc, "Should redirect to GitHub"
    assert "client_id=" in loc, "Should include client_id"

def test_auth_me_unauthed():
    r = requests.get(f"{BASE}/api/auth/me", timeout=10)
    print(f"  Status: {r.status_code}")
    assert r.status_code == 401, f"Expected 401, got {r.status_code}"

def test_scan_unauthed():
    r = requests.post(f"{BASE}/api/scan",
                      json={"repo_url": "https://github.com/test/test"},
                      timeout=10)
    print(f"  Status: {r.status_code}")
    assert r.status_code == 401, f"Expected 401, got {r.status_code}"

def test_scan_get_requires_auth():
    # Scan result is owner-scoped: unauthenticated access is rejected (401)
    # before any 404 lookup, so a scan_id cannot be probed anonymously.
    r = requests.get(f"{BASE}/api/scan/nonexistent123", timeout=10)
    print(f"  Status: {r.status_code}")
    assert r.status_code == 401, f"Expected 401 (auth required), got {r.status_code}"

def test_scan_stream_requires_auth():
    r = requests.get(f"{BASE}/api/scan/nonexistent123/stream", timeout=10)
    print(f"  Status: {r.status_code}")
    assert r.status_code == 401, f"Expected 401 (auth required), got {r.status_code}"

def test_legacy_webhook():
    r = requests.post(f"{BASE}/webhook", json={"test": True}, timeout=10)
    print(f"  Status: {r.status_code}")
    print(f"  Body: {r.json()}")
    assert r.status_code == 202, f"Expected 202, got {r.status_code}"
    assert "trace_id" in r.json(), "Should include trace_id"

def test_cors_headers():
    r = requests.options(
        f"{BASE}/api/scan",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
        },
        timeout=10
    )
    print(f"  Status: {r.status_code}")
    print(f"  CORS headers: {dict((k,v) for k,v in r.headers.items() if 'access-control' in k.lower())}")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    assert "access-control-allow-origin" in {k.lower() for k in r.headers}, "Missing CORS header"

def test_auth_logout():
    r = requests.post(f"{BASE}/api/auth/logout", timeout=10)
    print(f"  Status: {r.status_code}")
    print(f"  Body: {r.json()}")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    assert r.json()["status"] == "logged_out"


# ----- Run -----

test("Health Endpoint", test_health)
test("OpenAPI Docs", test_openapi)
test("GitHub OAuth Redirect", test_oauth_redirect)
test("Auth /me (unauthenticated)", test_auth_me_unauthed)
test("POST /api/scan (unauthenticated)", test_scan_unauthed)
test("GET /api/scan/{id} (auth required)", test_scan_get_requires_auth)
test("GET /api/scan/{id}/stream (auth required)", test_scan_stream_requires_auth)
test("Legacy Webhook", test_legacy_webhook)
test("CORS Headers", test_cors_headers)
test("Auth Logout", test_auth_logout)

print(f"\n{'='*60}")
print(f"RESULTS: {PASS} passed, {FAIL} failed out of {PASS+FAIL} tests")
if FAIL > 0:
    print("⚠️  SOME TESTS FAILED")
else:
    print("✅ ALL TESTS PASSED")

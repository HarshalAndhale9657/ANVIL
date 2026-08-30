"""
Integration tests for the live re-exploit-fails patch gate.

These launch a real (tiny) Flask app as a subprocess and re-run a real exploit
against it — no OpenAI, no network egress beyond loopback. They prove the gate:
  * accepts a genuinely-correct fix,
  * rejects a fix that breaks startup (the exact `flask.safe_join` failure class
    that static validation waved through),
  * rejects a fix that leaves the vulnerability open.
"""
import textwrap

import pytest

from app.patch_validator import validate_patch_by_reexploit

# ── Fixtures: a minimal vulnerable Flask app + patch variants + an exploit ────

VULN_APP = textwrap.dedent('''
    import base64, pickle
    from flask import Flask, request, jsonify
    app = Flask(__name__)

    @app.route("/")
    def index():
        return "ok"

    @app.route("/api/v1/user/preferences", methods=["GET", "POST"])
    def prefs():
        raw = request.cookies.get("session_prefs")
        if raw:
            p = pickle.loads(base64.b64decode(raw))
            theme = p.get("theme", "default") if isinstance(p, dict) else "default"
            return jsonify({"active_theme": theme})
        return jsonify({"active_theme": "default"})

    if __name__ == "__main__":
        app.run(host="127.0.0.1", port=9999)
''')

# Correct fix: JSON instead of pickle. App still works; exploit fails.
GOOD_PATCH = textwrap.dedent('''
    import base64, json
    from flask import Flask, request, jsonify
    app = Flask(__name__)

    @app.route("/")
    def index():
        return "ok"

    @app.route("/api/v1/user/preferences", methods=["GET", "POST"])
    def prefs():
        raw = request.cookies.get("session_prefs")
        if raw:
            try:
                p = json.loads(base64.b64decode(raw))
            except Exception:
                p = {}
            theme = p.get("theme", "default") if isinstance(p, dict) else "default"
            return jsonify({"active_theme": theme})
        return jsonify({"active_theme": "default"})

    if __name__ == "__main__":
        app.run(host="127.0.0.1", port=9999)
''')

# Broken fix: `from flask import safe_join` was removed in Flask 2.1 -> ImportError
# at startup. Looks plausible, passes static checks, but the app won't run.
BROKEN_PATCH = textwrap.dedent('''
    import base64, json
    from flask import Flask, request, jsonify, safe_join
    app = Flask(__name__)

    @app.route("/")
    def index():
        return "ok"

    @app.route("/api/v1/user/preferences", methods=["GET", "POST"])
    def prefs():
        return jsonify({"active_theme": "default"})

    if __name__ == "__main__":
        app.run(host="127.0.0.1", port=9999)
''')

EXPLOIT = textwrap.dedent('''
    import base64, pickle, requests
    class P:
        def __reduce__(self):
            return (eval, ("{'theme': 'PWNED_BY_ANVIL'}",))
    cookie = base64.b64encode(pickle.dumps(P())).decode()
    try:
        r = requests.post("http://127.0.0.1:9999/api/v1/user/preferences",
                          cookies={"session_prefs": cookie}, timeout=5)
        if "PWNED_BY_ANVIL" in r.text:
            print("[+] server returned attacker-controlled value")
            print("EXPLOIT_SUCCESS")
            print("EXTRACTED_DATA:", r.text.strip())
        else:
            print("EXPLOIT_FAILED")
    except Exception as e:
        print("EXPLOIT_FAILED", e)
''')

_TIMEOUT = 10


def _write_target(tmp_path):
    (tmp_path / "app.py").write_text(VULN_APP, encoding="utf-8")
    return str(tmp_path)


def test_good_patch_is_accepted(tmp_path):
    repo = _write_target(tmp_path)
    res = validate_patch_by_reexploit(
        repo_dir=repo, target_file="app.py", fixed_code=GOOD_PATCH,
        exploit_code=EXPLOIT, startup_timeout=_TIMEOUT,
    )
    assert res.applicable, res.reason
    assert res.valid is True, res.reason


def test_broken_patch_is_rejected(tmp_path):
    """The safe_join import-error class: static checks miss it; the live gate must not."""
    repo = _write_target(tmp_path)
    res = validate_patch_by_reexploit(
        repo_dir=repo, target_file="app.py", fixed_code=BROKEN_PATCH,
        exploit_code=EXPLOIT, startup_timeout=_TIMEOUT,
    )
    assert res.applicable, res.reason
    assert res.valid is False
    assert "start" in res.reason.lower()
    # The real startup error must be captured so a retry can be fed the cause.
    assert "safe_join" in res.reason or "ImportError" in res.reason, res.reason


def test_ineffective_patch_is_rejected(tmp_path):
    """A 'fix' that doesn't change the vulnerable code must be rejected."""
    repo = _write_target(tmp_path)
    res = validate_patch_by_reexploit(
        repo_dir=repo, target_file="app.py", fixed_code=VULN_APP,  # unchanged
        exploit_code=EXPLOIT, startup_timeout=_TIMEOUT,
    )
    assert res.applicable, res.reason
    assert res.valid is False
    assert "still" in res.reason.lower()


def test_non_http_exploit_is_not_applicable(tmp_path):
    repo = _write_target(tmp_path)
    res = validate_patch_by_reexploit(
        repo_dir=repo, target_file="app.py", fixed_code=GOOD_PATCH,
        exploit_code="print('EXPLOIT_SUCCESS')  # code-only PoC, no HTTP",
        startup_timeout=_TIMEOUT,
    )
    assert res.applicable is False
    assert res.valid is None

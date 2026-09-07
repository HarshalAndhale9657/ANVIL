"""Benchmark target — intentionally vulnerable. DO NOT DEPLOY.
Insecure deserialization: pickle.loads() on an attacker-controlled cookie."""
import base64
import pickle

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/")
def index():
    return "preferences service"


@app.route("/api/v1/user/preferences", methods=["GET", "POST"])
def preferences():
    raw = request.cookies.get("session_prefs")
    if raw:
        prefs = pickle.loads(base64.b64decode(raw))  # noqa: S301 (intentional)
        theme = prefs.get("theme", "default") if isinstance(prefs, dict) else "default"
        return jsonify({"active_theme": theme})
    return jsonify({"active_theme": "default"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=9999, debug=False)

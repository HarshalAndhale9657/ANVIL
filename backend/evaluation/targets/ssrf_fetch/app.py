"""Benchmark target — intentionally vulnerable. DO NOT DEPLOY.
Server-side request forgery (SSRF): requests.get() on an attacker-controlled URL with no allowlist."""
import requests
from flask import Flask, jsonify, request
app = Flask(__name__)
@app.route("/")
def index():
    return "url proxy service"
@app.route("/api/proxy", methods=["POST"])
def proxy():
    data = request.get_json(silent=True) or {}
    url = data.get("url") or data.get("endpoint") or data.get("target")
    if not url:
        return jsonify({"error": "missing url"}), 400
    resp = requests.get(url, timeout=5)
    return jsonify({"status": resp.status_code, "body": resp.text})
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=9999, debug=False)

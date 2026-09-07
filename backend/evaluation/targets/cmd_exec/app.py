"""Benchmark target — intentionally vulnerable. DO NOT DEPLOY.
OS command injection: user input concatenated into a shell command run via
subprocess.check_output(..., shell=True)."""
import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/")
def index():
    return "network diagnostics service"


@app.route("/api/execute", methods=["POST"])
def execute():
    data = request.get_json(silent=True) or {}
    host = data.get("command") or data.get("cmd") or data.get("input")
    if not host:
        return jsonify({"error": "missing 'command' field"}), 400
    # Reachability check: ping the requested host a couple of times.
    cmd = "ping -n 2 " + host  # noqa: S602 (intentional shell injection)
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc:
        out = exc.output
    return jsonify({"command": cmd, "output": out.decode("utf-8", "replace")})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=9999, debug=False)

"""Benchmark target — intentionally vulnerable. DO NOT DEPLOY.
Server-side template injection / reflected XSS: user comment content is
interpolated into a Jinja2 template string via an f-string and rendered
with flask.render_template_string()."""
from flask import Flask, jsonify, request, render_template_string

app = Flask(__name__)


@app.route("/")
def index():
    return "comment service"


@app.route("/api/comment", methods=["POST"])
def comment():
    data = request.get_json(silent=True) or {}
    content = data.get("content") or data.get("message") or data.get("text") or ""
    rendered = render_template_string(f"<div class='c'>{content}</div>")
    return jsonify({"rendered": rendered})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=9999, debug=False)

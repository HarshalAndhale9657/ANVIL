"""Benchmark target — intentionally vulnerable. DO NOT DEPLOY.
Path traversal: user-controlled filename joined onto a served dir without
sanitization, so `..` escapes it and leaks arbitrary files."""
import os

from flask import Flask, Response, request

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FILES_DIR = os.path.join(BASE_DIR, "public")


@app.route("/")
def index():
    return "file service"


@app.route("/files/<path:filename>")
def get_file(filename):
    full = os.path.join(FILES_DIR, filename)  # no sanitization -> traversal
    with open(full, "r", encoding="utf-8", errors="replace") as fh:
        return Response(fh.read(), mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=9999, debug=False)

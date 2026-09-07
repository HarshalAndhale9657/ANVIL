"""Benchmark target — intentionally vulnerable. DO NOT DEPLOY.
SQL injection: user query built by f-string concatenation on the "id"/"username"
query params and executed against an in-process sqlite3 "users" table."""
import sqlite3
from flask import Flask, jsonify, request

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            email TEXT,
            role TEXT
        );
        INSERT INTO users (id, username, email, role) VALUES
            (1, 'alice', 'alice@example.com', 'admin'),
            (2, 'bob', 'bob@example.com', 'user'),
            (3, 'carol', 'carol@example.com', 'user'),
            (4, 'dave', 'dave@example.com', 'auditor');
        """
    )
    return conn


@app.route("/")
def index():
    return "user directory service"


@app.route("/api/users", methods=["GET"])
def users():
    uid = request.args.get("id")
    username = request.args.get("username")

    if uid is not None:
        query = f"SELECT id, username, email, role FROM users WHERE id = {uid}"
    elif username is not None:
        query = f"SELECT id, username, email, role FROM users WHERE username = '{username}'"
    else:
        query = "SELECT id, username, email, role FROM users"

    conn = get_db()
    try:
        rows = conn.execute(query).fetchall()
        return jsonify({"users": [dict(r) for r in rows]})
    except sqlite3.Error as exc:
        return jsonify({"error": str(exc), "query": query}), 500
    finally:
        conn.close()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=9999, debug=False)

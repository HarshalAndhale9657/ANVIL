"""
Secret isolation for UNTRUSTED code launched by the pipeline.

A scanned repository is attacker-controlled. Its entry point is executed (to
exploit it live, and again to validate the patch), so it must never be able to
read the server's secrets (OpenAI key, OAuth client secret, session secret) or
the scanning user's GitHub token.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from app.sandbox import safe_subprocess_env

SECRETS = {
    "OPENAI_API_KEY": "sk-test-should-never-leak",
    "GITHUB_CLIENT_SECRET": "gh-client-secret-should-never-leak",
    "SESSION_SECRET": "session-secret-should-never-leak",
}

# An "app" that dumps its whole environment to disk and exits.
_DUMP_ENV_APP = (
    "import json, os\n"
    "with open('env_dump.json', 'w') as f:\n"
    "    json.dump(dict(os.environ), f)\n"
)


@pytest.fixture
def secret_env(monkeypatch):
    for k, v in SECRETS.items():
        monkeypatch.setenv(k, v)
    return SECRETS


def _wait_for(path: Path, timeout: float = 20.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists() and path.stat().st_size > 0:
            try:
                return json.loads(path.read_text())
            except json.JSONDecodeError:
                pass  # still being written
        time.sleep(0.2)
    raise AssertionError(f"target app never wrote {path}")


def _assert_no_secrets(env: dict) -> None:
    leaked = {k for k, v in env.items() if v in SECRETS.values() or k in SECRETS}
    assert not leaked, f"secrets leaked into untrusted process env: {leaked}"


def test_safe_env_drops_secrets_keeps_essentials(secret_env):
    env = safe_subprocess_env()
    _assert_no_secrets(env)
    # Python must still be able to start (PATH / SYSTEMROOT on Windows).
    assert any(k.upper() == "PATH" for k in env)


def test_exploiter_target_app_cannot_read_server_secrets(secret_env, tmp_path):
    from app.agents.exploiter import _start_target_app, _stop_target_app

    (tmp_path / "app.py").write_text(_DUMP_ENV_APP)
    proc = _start_target_app(str(tmp_path), "app.py", port=5999)
    assert proc is not None
    try:
        env = _wait_for(tmp_path / "env_dump.json")
    finally:
        _stop_target_app(proc)
    _assert_no_secrets(env)


def test_patch_validator_launch_cannot_read_server_secrets(secret_env, tmp_path):
    from app.patch_validator import _launch

    (tmp_path / "app.py").write_text(_DUMP_ENV_APP)
    app = _launch(str(tmp_path), "app.py", port=5998)
    assert app is not None
    try:
        env = _wait_for(tmp_path / "env_dump.json")
    finally:
        app.stop()
    _assert_no_secrets(env)


def test_clone_does_not_persist_token_on_disk(tmp_path, monkeypatch):
    """The user's GitHub token must not be written into the clone's .git/config
    (the untrusted app later runs with cwd=repo and could read it)."""
    import app.github_service as gs

    token = "ghp_tokenShouldNeverHitDisk123"
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["env"] = kwargs.get("env") or {}
        # Simulate a successful clone creating a repo dir.
        dest = Path(cmd[-1])
        (dest / ".git").mkdir(parents=True, exist_ok=True)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(gs, "SCAN_TEMP_DIR", str(tmp_path))
    monkeypatch.setattr(gs.subprocess, "run", fake_run)
    gs.clone_repo(token, "https://github.com/octo/demo", "scan123")

    assert token not in " ".join(captured["cmd"]), "token must not appear on the git command line / remote URL"
    # It is passed out-of-band as an HTTP auth header via GIT_CONFIG_* env.
    assert any("extraheader" in str(v).lower() for v in captured["env"].values())


def test_clone_error_message_redacts_token(tmp_path, monkeypatch):
    import app.github_service as gs

    token = "ghp_secretTokenValue999"

    def failing_run(cmd, **kwargs):
        return subprocess.CompletedProcess(
            cmd, 128, "", f"fatal: could not read from https://x-access-token:{token}@github.com/o/r"
        )

    monkeypatch.setattr(gs, "SCAN_TEMP_DIR", str(tmp_path))
    monkeypatch.setattr(gs.subprocess, "run", failing_run)
    with pytest.raises(RuntimeError) as exc:
        gs.clone_repo(token, "https://github.com/o/r", "scan456")
    assert token not in str(exc.value)


def test_checkpoints_never_serialise_github_token():
    """State is checkpointed to SQLite after every CPN transition; the user's
    GitHub token must never be part of that serialisation."""
    from app.schemas import MasterState, WebhookPayload

    token = "gho_tokenMustNotBeCheckpointed"
    state = MasterState(
        trace_id="t", task_id="s", current_node="ingress", repo_url="https://github.com/o/r",
        repo_dir="/tmp/x", github_token=token, base_branch="main",
        webhook=WebhookPayload(target_url="u", deployment_id="d", github_token=token),
    )
    assert token not in json.dumps(state.model_dump(mode="json"))
    assert token not in state.model_dump_json()
    # ...but it is still available in memory for clone / PR creation.
    assert state.github_token == token
    assert state.webhook.github_token == token


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="POSIX process groups")
def test_stopping_target_app_kills_its_descendants(tmp_path):
    """A malicious app that spawns a background child must not leave it running
    on the host after the scan stops the app."""
    import os
    from app.agents.exploiter import _start_target_app, _stop_target_app

    (tmp_path / "app.py").write_text(
        "import subprocess, sys, time\n"
        "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(300)'])\n"
        "open('child.pid', 'w').write(str(p.pid))\n"
        "time.sleep(300)\n"
    )
    proc = _start_target_app(str(tmp_path), "app.py", port=5997)
    pid_file = tmp_path / "child.pid"
    deadline = time.time() + 20
    while time.time() < deadline and not (pid_file.exists() and pid_file.read_text()):
        time.sleep(0.2)
    child = int(pid_file.read_text())
    _stop_target_app(proc)
    time.sleep(0.5)
    try:
        os.kill(child, 0)
        alive = True
    except ProcessLookupError:
        alive = False
    if alive:  # might be a zombie awaiting reaping by init — check state
        with open(f"/proc/{child}/stat") as f:
            alive = f.read().split()[2] != "Z"
    assert not alive, "grandchild process survived the scan"

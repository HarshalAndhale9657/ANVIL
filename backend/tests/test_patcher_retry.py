"""
Unit tests for the patcher's self-correcting retry loop.

The LLM and the live gate are mocked so these stay fast and hermetic; the gate
itself is covered end-to-end in test_patch_validator.py. Here we verify the loop:
  * a rejected patch is retried with the rejection fed back into the prompt,
  * the accepted (good) patch is the one pushed to the PR,
  * if every attempt is rejected, no PR is opened (fail-closed RuntimeError).
"""
import json

import pytest

import app.agents.patcher as patcher
import app.github_service as gh
import app.patch_validator as pv
from app.patch_validator import PatchValidation
from app.schemas import (
    ExploitOutput,
    HttpMethod,
    ReconOutput,
    VerificationResult,
    VulnerableEndpoint,
)


class _Usage:
    prompt_tokens = 10
    completion_tokens = 20


class _Msg:
    def __init__(self, content):
        self.content = content


class _Choice:
    def __init__(self, content):
        self.message = _Msg(content)


class _Resp:
    def __init__(self, content):
        self.choices = [_Choice(content)]
        self.usage = _Usage()


def _fake_client(fixed_codes, recorded_prompts):
    """OpenAI-shaped client that returns the given fixed_codes in order."""
    seq = [json.dumps({"fixed_code": fc, "explanation": f"fix {i}", "confidence": 0.9})
           for i, fc in enumerate(fixed_codes)]

    class _Completions:
        def create(self, **kw):
            recorded_prompts.append(kw["messages"][1]["content"])
            return _Resp(seq[len(recorded_prompts) - 1])

    class _Chat:
        completions = _Completions()

    class _Client:
        chat = _Chat()

    return _Client()


def _setup(tmp_path):
    (tmp_path / "app.py").write_text("import pickle\n# vulnerable\n", encoding="utf-8")
    recon = ReconOutput(
        target_url="https://github.com/demo/x", detected_framework="Flask",
        vulnerable_endpoints=[VulnerableEndpoint(
            path="app.py:1", method=HttpMethod.GET, injection_vector="pickle deserialization")],
    )
    exploit = ExploitOutput(
        vulnerability_confirmed=True,
        exploit_payload_used="import requests\nrequests.post('http://127.0.0.1:9999/x')\nprint('EXPLOIT_SUCCESS')",
        sandbox_stdout="EXPLOIT_SUCCESS",
    )
    verification = VerificationResult(verified=True, reason="ok")
    return recon, exploit, verification


def test_retry_then_accept(tmp_path, monkeypatch):
    recon, exploit, verification = _setup(tmp_path)

    BROKEN = "import json  # sanitize validate v1 (broken)\n"
    GOOD = "import json  # sanitize validate v2 (good)\n"
    prompts = []
    monkeypatch.setattr(patcher, "_get_client", lambda: _fake_client([BROKEN, GOOD], prompts))

    gate_seq = [
        PatchValidation(True, False, "Patched app failed to start. Startup error: ImportError: cannot import name 'safe_join'"),
        PatchValidation(True, True, "validated live"),
    ]
    seen_codes = []

    def fake_gate(**kw):
        seen_codes.append(kw["fixed_code"])
        return gate_seq[len(seen_codes) - 1]

    monkeypatch.setattr(pv, "validate_patch_by_reexploit", fake_gate)

    pushed = {}

    def fake_pr(**kw):
        pushed["files"] = kw["fixed_files"]
        return "https://github.com/demo/x/pull/1"

    monkeypatch.setattr(gh, "create_branch_and_pr", fake_pr)

    result = patcher.run_patch_github(
        recon=recon, exploit=exploit, verification=verification, trace_id="trace123456",
        github_token="tok", repo_url="https://github.com/demo/x", repo_dir=str(tmp_path), base_branch="main",
    )

    # Two attempts, second accepted; the GOOD patch is what got pushed.
    assert len(prompts) == 2
    assert seen_codes == [BROKEN, GOOD]
    assert pushed["files"][0]["content"] == GOOD
    assert result.pr_url == "https://github.com/demo/x/pull/1"
    # The rejection (with the real cause) was fed back into attempt 2.
    assert "REJECTED" in prompts[1]
    assert "safe_join" in prompts[1]


def test_all_attempts_rejected_fails_closed(tmp_path, monkeypatch):
    recon, exploit, verification = _setup(tmp_path)

    monkeypatch.setattr(
        patcher, "_get_client",
        lambda: _fake_client(["import json  # sanitize validate attempt\n"] * 5, []),
    )
    monkeypatch.setattr(
        pv, "validate_patch_by_reexploit",
        lambda **kw: PatchValidation(True, False, "Exploit STILL succeeds against the patched app."),
    )

    called = {"pr": False}

    def fake_pr(**kw):
        called["pr"] = True
        return "should-not-happen"

    monkeypatch.setattr(gh, "create_branch_and_pr", fake_pr)

    with pytest.raises(RuntimeError, match="No valid patch after"):
        patcher.run_patch_github(
            recon=recon, exploit=exploit, verification=verification, trace_id="trace123456",
            github_token="tok", repo_url="https://github.com/demo/x", repo_dir=str(tmp_path), base_branch="main",
        )
    assert called["pr"] is False  # fail-closed: no PR opened

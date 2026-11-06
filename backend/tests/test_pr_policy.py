"""
PR-target policy: when the user cannot push to the scanned repo, the fix PR
goes into the user's own fork by default, so a public deployment can't be used
to send automated PRs to third-party projects. ALLOW_UPSTREAM_PRS opts into the
classic cross-repo (fork -> upstream) contribution flow.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import app.github_service as gs


class FakeRepo:
    def __init__(self, full_name, *, push, fork=False):
        self.full_name = full_name
        self.name = full_name.split("/")[1]
        self.owner = SimpleNamespace(login=full_name.split("/")[0])
        self.default_branch = "main"
        self.permissions = SimpleNamespace(push=push, admin=False)
        self.fork = fork
        self.pulls = []
        self.refs = {"heads/main": "basesha"}
        self.synced = []

    def get_git_ref(self, ref):
        if ref not in self.refs:
            raise Exception("Not Found")
        return SimpleNamespace(object=SimpleNamespace(sha=self.refs[ref]), edit=lambda **k: None)

    def create_git_ref(self, ref, sha):
        self.refs[ref.removeprefix("refs/")] = sha

    def get_contents(self, path, ref=None):
        raise Exception("404")

    def create_file(self, **kw):
        pass

    def create_fork(self):
        raise AssertionError("fork should already exist in this test")

    def merge_upstream(self, branch):
        self.synced.append(branch)

    def create_pull(self, title, body, head, base):
        self.pulls.append({"head": head, "base": base})
        return SimpleNamespace(html_url=f"https://github.com/{self.full_name}/pull/1")


@pytest.fixture
def world(monkeypatch):
    upstream = FakeRepo("pallets/flask", push=False)
    fork = FakeRepo("visitor/flask", push=True, fork=True)
    repos = {r.full_name: r for r in (upstream, fork)}

    class FakeGithub:
        def __init__(self, token):
            pass

        def get_repo(self, name):
            return repos[name]

        def get_user(self):
            return SimpleNamespace(login="visitor")

    monkeypatch.setattr(gs, "Github", FakeGithub)
    return upstream, fork


def _open_pr():
    return gs.create_branch_and_pr(
        token="t", repo_url="https://github.com/pallets/flask",
        branch_name="fix/anvil-1", base_branch="main",
        fixed_files=[{"path": "app.py", "content": "safe"}],
    )


def test_default_pr_goes_to_users_fork_not_upstream(world, monkeypatch):
    upstream, fork = world
    monkeypatch.setattr(gs, "ALLOW_UPSTREAM_PRS", False)
    url = _open_pr()
    assert upstream.pulls == [], "must never open a PR on a repo the user doesn't control"
    assert fork.pulls == [{"head": "fix/anvil-1", "base": "main"}]
    assert url.startswith("https://github.com/visitor/flask/")
    assert fork.synced == ["main"], "fork base branch is synced so the PR diff is just the fix"


def test_upstream_pr_when_explicitly_allowed(world, monkeypatch):
    upstream, fork = world
    monkeypatch.setattr(gs, "ALLOW_UPSTREAM_PRS", True)
    _open_pr()
    assert upstream.pulls == [{"head": "visitor:fix/anvil-1", "base": "main"}]
    assert fork.pulls == []


def test_same_repo_pr_when_user_has_push_access(world, monkeypatch):
    upstream, _ = world
    upstream.permissions = SimpleNamespace(push=True, admin=False)
    monkeypatch.setattr(gs, "ALLOW_UPSTREAM_PRS", False)
    _open_pr()
    assert upstream.pulls == [{"head": "fix/anvil-1", "base": "main"}]

"""Unit tests for the evaluation harness — mocked agents, no LLM / Docker."""
from types import SimpleNamespace

from evaluation.harness import TargetResult, TargetSpec, _vuln_matches, aggregate, run_target
from evaluation.report import to_dict, to_markdown


def _recon(vectors):
    eps = [SimpleNamespace(injection_vector=v, vulnerability_type=None, path="app.py:1", taint_path=None)
           for v in vectors]
    return SimpleNamespace(vulnerable_endpoints=eps)


def test_vuln_matches_by_type_and_file():
    known = {"type": "insecure_deserialization", "file": "app.py"}
    assert _vuln_matches(known, _recon(["pickle.loads on cookie in app.py"]))
    assert not _vuln_matches(known, _recon(["SQL injection in db.py"]))


def test_aggregate_rates():
    rs = [
        TargetResult("a", detected=True, exploited=True, verified=True, patched=True),
        TargetResult("b", detected=True, exploited=True, verified=True, patched=False),
        TargetResult("c", detected=True, exploited=False, verified=False, patched=False),
        TargetResult("d", detected=False),
    ]
    m = aggregate(rs)
    assert (m.total, m.detected, m.exploited, m.verified, m.patched) == (4, 3, 2, 2, 1)
    assert m.detection_rate == 0.75
    assert m.patch_rate == 0.25


def test_run_target_full_success_with_mocks(tmp_path):
    spec = TargetSpec(name="t", path=str(tmp_path), framework="Flask", entry_point="app.py",
                      known_vulns=[{"type": "insecure_deserialization", "file": "app.py"}])
    res = run_target(
        spec,
        recon_fn=lambda d, u: _recon(["pickle deserialization in app.py"]),
        exploit_fn=lambda r, d, e: SimpleNamespace(vulnerability_confirmed=True),
        verify_fn=lambda x: SimpleNamespace(verified=True, reason="ok"),
        patch_fn=lambda r, x, v, d, n: True,
    )
    assert res.detected and res.exploited and res.verified and res.patched
    assert res.vulns_found == 1


def test_run_target_unverified_stops_before_patch(tmp_path):
    spec = TargetSpec(name="t", path=str(tmp_path), framework="Flask", entry_point="app.py",
                      known_vulns=[{"type": "sql_injection", "file": "app.py"}])
    calls = {"patch": 0}

    def patch_fn(*a, **k):
        calls["patch"] += 1
        return True

    res = run_target(
        spec,
        recon_fn=lambda d, u: _recon(["SQL injection union in app.py"]),
        exploit_fn=lambda r, d, e: SimpleNamespace(vulnerability_confirmed=True),
        verify_fn=lambda x: SimpleNamespace(verified=False, reason="no marker"),
        patch_fn=patch_fn,
    )
    assert res.detected and res.exploited and not res.verified and not res.patched
    assert calls["patch"] == 0  # patch stage not reached when unverified


def test_report_contains_metrics():
    rs = [
        TargetResult("a", detected=True, exploited=True, verified=True, patched=True),
        TargetResult("b", detected=True, exploited=False),
    ]
    m = aggregate(rs)
    d = to_dict(rs, m)
    md = to_markdown(rs, m)
    assert d["summary"]["targets"] == 2 and d["summary"]["patched"] == 1
    assert "ANVIL Benchmark Report" in md
    assert "100%" in md   # detection 2/2
    assert "50%" in md    # patched 1/2

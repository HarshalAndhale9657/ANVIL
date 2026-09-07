"""
Evaluation harness core.

Runs the ANVIL pipeline (recon -> exploit -> verify -> patch) against a benchmark
of known-vulnerable apps carried as local directories, each with a `benchmark.json`
ground-truth manifest, and measures:

  * detection    — recon found a vulnerability matching a known one
  * exploitation  — the exploit was confirmed by the sandbox
  * verification  — the deterministic verifier accepted it
  * patch         — a patch was produced that PASSES the live re-exploit gate
                    (i.e. the patched app still starts and the exploit no longer
                    succeeds), validated inside a sealed container when available

No GitHub is used: targets are local dirs and the patcher's PR push is stubbed,
so the patch metric reflects a *live-validated* fix, not a merged PR.

The per-stage agent calls are injected (default = the real agents) so the
orchestration + metrics can be unit-tested with mocks and no LLM/Docker.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

logger = logging.getLogger(__name__)


# ── Ground truth + results ────────────────────────────────────────────────────

@dataclass
class TargetSpec:
    name: str
    path: str
    framework: str
    entry_point: str
    known_vulns: List[dict] = field(default_factory=list)

    @classmethod
    def load(cls, target_dir) -> "TargetSpec":
        p = Path(target_dir)
        m = json.loads((p / "benchmark.json").read_text(encoding="utf-8"))
        return cls(
            name=m.get("name", p.name),
            path=str(p),
            framework=m.get("framework", "unknown"),
            entry_point=m["entry_point"],
            known_vulns=m.get("known_vulnerabilities", []),
        )


@dataclass
class TargetResult:
    name: str
    detected: bool = False
    exploited: bool = False
    verified: bool = False
    patched: bool = False
    vulns_found: int = 0
    detail: str = ""
    error: str = ""
    seconds: float = 0.0


@dataclass
class SuiteMetrics:
    total: int = 0
    detected: int = 0
    exploited: int = 0
    verified: int = 0
    patched: int = 0

    def _rate(self, n: int) -> float:
        return round(n / self.total, 3) if self.total else 0.0

    @property
    def detection_rate(self) -> float:
        return self._rate(self.detected)

    @property
    def exploitation_rate(self) -> float:
        return self._rate(self.exploited)

    @property
    def verification_rate(self) -> float:
        return self._rate(self.verified)

    @property
    def patch_rate(self) -> float:
        return self._rate(self.patched)


def aggregate(results: List[TargetResult]) -> SuiteMetrics:
    m = SuiteMetrics(total=len(results))
    for r in results:
        m.detected += int(r.detected)
        m.exploited += int(r.exploited)
        m.verified += int(r.verified)
        m.patched += int(r.patched)
    return m


# ── Detection matching (recon vs ground truth) ───────────────────────────────

# Ground-truth vuln type -> keywords we accept in recon's vector/type/taint.
_TYPE_KEYWORDS = {
    "insecure_deserialization": ("pickle", "deserial", "unpickle", "yaml.load", "marshal"),
    "path_traversal": ("traversal", "path travers", "directory travers", "lfi", "os.path.join"),
    "sql_injection": ("sql", "injection", "union", "query"),
    "command_injection": ("command inject", "os.system", "subprocess", "shell"),
    "ssrf": ("ssrf", "request forgery", "urllib", "fetch"),
    "xss": ("xss", "cross-site", "render_template_string", "innerhtml"),
}


def _vuln_matches(known: dict, recon) -> bool:
    """True if recon reported a vulnerability matching this known one."""
    kfile = (known.get("file") or "").lower()
    ktype = (known.get("type") or "").lower()
    keywords = _TYPE_KEYWORDS.get(ktype, (ktype,))
    for ep in getattr(recon, "vulnerable_endpoints", []) or []:
        hay = " ".join(str(x).lower() for x in (
            getattr(ep, "injection_vector", ""),
            getattr(ep, "vulnerability_type", "") or "",
            getattr(ep, "path", ""),
            getattr(ep, "taint_path", "") or "",
        ))
        type_hit = any(k in hay for k in keywords)
        file_hit = (not kfile) or (kfile in hay)
        if type_hit and file_hit:
            return True
    return False


# ── Real agent adapters (default injection) ───────────────────────────────────

def _real_recon(target_dir, repo_url):
    from app.agents.recon import run_recon_source
    return run_recon_source(target_dir, repo_url)


def _real_exploit(recon, target_dir, entry_point):
    from app.agents.exploiter import run_exploit
    return run_exploit(recon, repo_dir=target_dir, entry_point=entry_point)


def _real_verify(exploit):
    from app.agents.verifier import verify_exploit
    return verify_exploit(exploit)


def _real_patch(recon, exploit, verification, target_dir, name) -> bool:
    """Run the real patcher with the GitHub push stubbed; True iff it produced a
    patch that passed validation (incl. the live re-exploit gate)."""
    import app.github_service as gh
    from app.agents.patcher import run_patch_github

    orig = gh.create_branch_and_pr
    gh.create_branch_and_pr = lambda **kw: "eval://no-push"
    try:
        run_patch_github(
            recon=recon, exploit=exploit, verification=verification,
            trace_id=f"eval-{name}",
            github_token="eval", repo_url=f"https://github.com/eval/{name}",
            repo_dir=target_dir, base_branch="main",
        )
        return True
    except Exception as exc:
        logger.info("[%s] patch not validated: %s", name, exc)
        return False
    finally:
        gh.create_branch_and_pr = orig


# ── Run one target / the suite ────────────────────────────────────────────────

def run_target(
    spec: TargetSpec,
    *,
    recon_fn: Callable = _real_recon,
    exploit_fn: Callable = _real_exploit,
    verify_fn: Callable = _real_verify,
    patch_fn: Callable = _real_patch,
    do_patch: bool = True,
) -> TargetResult:
    """Execute the pipeline against one benchmark target and score it."""
    res = TargetResult(name=spec.name)
    t0 = time.time()
    try:
        repo_url = f"https://github.com/eval/{spec.name}"
        recon = recon_fn(spec.path, repo_url)
        res.vulns_found = len(getattr(recon, "vulnerable_endpoints", []) or [])
        res.detected = any(_vuln_matches(kv, recon) for kv in spec.known_vulns) if spec.known_vulns else res.vulns_found > 0
        if res.vulns_found == 0:
            res.detail = "recon found no vulnerabilities"
            return res

        exploit = exploit_fn(recon, spec.path, spec.entry_point)
        res.exploited = bool(getattr(exploit, "vulnerability_confirmed", False))

        verification = verify_fn(exploit)
        res.verified = bool(getattr(verification, "verified", False))
        if not res.verified:
            res.detail = f"not verified: {getattr(verification, 'reason', '')[:160]}"
            return res

        if do_patch:
            res.patched = bool(patch_fn(recon, exploit, verification, spec.path, spec.name))
            res.detail = "patch validated" if res.patched else "no valid patch produced"
        else:
            res.detail = "verified (patch step skipped)"
        return res
    except Exception as exc:
        logger.exception("[%s] target run failed", spec.name)
        res.error = str(exc)
        return res
    finally:
        res.seconds = round(time.time() - t0, 1)


def discover_targets(targets_root) -> List[TargetSpec]:
    root = Path(targets_root)
    specs = []
    for manifest in sorted(root.glob("*/benchmark.json")):
        try:
            specs.append(TargetSpec.load(manifest.parent))
        except Exception as exc:
            logger.warning("skipping %s: %s", manifest.parent, exc)
    return specs


def run_suite(targets_root, *, do_patch: bool = True, results_dir=None, **fns) -> tuple[List[TargetResult], SuiteMetrics]:
    """Run every discovered target. If results_dir is given, each target's
    result is written to <results_dir>/partial/<name>.json as it completes, so
    an interrupted run keeps its partial results (see load_partials)."""
    import json as _json

    specs = discover_targets(targets_root)
    partial_dir = None
    if results_dir:
        partial_dir = Path(results_dir) / "partial"
        partial_dir.mkdir(parents=True, exist_ok=True)

    results: List[TargetResult] = []
    for i, s in enumerate(specs, 1):
        logger.info("[%d/%d] target: %s", i, len(specs), s.name)
        r = run_target(s, do_patch=do_patch, **fns)
        results.append(r)
        if partial_dir:
            (partial_dir / f"{r.name}.json").write_text(
                _json.dumps(_result_to_dict(r), indent=2), encoding="utf-8")
    return results, aggregate(results)


def _result_to_dict(r: TargetResult) -> dict:
    from dataclasses import asdict
    return asdict(r)


def load_partials(results_dir) -> List[TargetResult]:
    """Rebuild TargetResults from per-target JSONs written during a run — lets a
    report be assembled after an interruption."""
    import json as _json

    partial_dir = Path(results_dir) / "partial"
    out: List[TargetResult] = []
    if partial_dir.is_dir():
        for f in sorted(partial_dir.glob("*.json")):
            try:
                out.append(TargetResult(**_json.loads(f.read_text(encoding="utf-8"))))
            except Exception as exc:
                logger.warning("skip partial %s: %s", f, exc)
    return out

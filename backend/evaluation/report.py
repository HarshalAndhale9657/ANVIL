"""Render evaluation results as JSON + a human-readable Markdown report."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple

from evaluation.harness import SuiteMetrics, TargetResult


def _pct(x: float) -> str:
    return f"{round(x * 100)}%"


def to_dict(results: List[TargetResult], metrics: SuiteMetrics) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "targets": metrics.total,
            "detection_rate": metrics.detection_rate,
            "exploitation_rate": metrics.exploitation_rate,
            "verification_rate": metrics.verification_rate,
            "patch_rate": metrics.patch_rate,
            "detected": metrics.detected,
            "exploited": metrics.exploited,
            "verified": metrics.verified,
            "patched": metrics.patched,
        },
        "targets": [asdict(r) for r in results],
    }


def to_markdown(results: List[TargetResult], metrics: SuiteMetrics) -> str:
    mark = lambda b: "✅" if b else "—"
    lines = [
        "# ANVIL Benchmark Report",
        "",
        f"_{metrics.total} known-vulnerable targets_",
        "",
        "| Metric | Rate | Count |",
        "|---|---|---|",
        f"| Detected | {_pct(metrics.detection_rate)} | {metrics.detected}/{metrics.total} |",
        f"| Exploited (sandbox-confirmed) | {_pct(metrics.exploitation_rate)} | {metrics.exploited}/{metrics.total} |",
        f"| Verified (deterministic gate) | {_pct(metrics.verification_rate)} | {metrics.verified}/{metrics.total} |",
        f"| Patched (live re-exploit-validated) | {_pct(metrics.patch_rate)} | {metrics.patched}/{metrics.total} |",
        "",
        "| Target | Detected | Exploited | Verified | Patched | Time(s) | Detail |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in results:
        detail = (r.error or r.detail or "").replace("|", "\\|")[:90]
        lines.append(
            f"| {r.name} | {mark(r.detected)} | {mark(r.exploited)} | "
            f"{mark(r.verified)} | {mark(r.patched)} | {r.seconds} | {detail} |"
        )
    lines.append("")
    return "\n".join(lines)


def write_report(results: List[TargetResult], metrics: SuiteMetrics, out_dir) -> Tuple[Path, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "benchmark_report.json"
    md_path = out / "benchmark_report.md"
    json_path.write_text(json.dumps(to_dict(results, metrics), indent=2), encoding="utf-8")
    md_path.write_text(to_markdown(results, metrics), encoding="utf-8")
    return json_path, md_path

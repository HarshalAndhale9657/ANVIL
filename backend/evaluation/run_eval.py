"""
CLI: run the ANVIL benchmark suite and write a report.

From backend/:
    python -m evaluation.run_eval                 # full pipeline incl. patching
    python -m evaluation.run_eval --no-patch      # detection/exploit/verify only (cheaper)
    python -m evaluation.run_eval --targets DIR --out DIR

Makes real GPT-4o calls (recon/exploit/patch) and uses Docker for the sealed
patch gate when available; costs a little OpenAI credit per target.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from evaluation.harness import run_suite
from evaluation.report import to_markdown, write_report


def main() -> None:
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description="Run the ANVIL vulnerability benchmark.")
    ap.add_argument("--targets", default=str(here / "targets"), help="dir of benchmark targets")
    ap.add_argument("--out", default=str(here / "results"), help="report output dir")
    ap.add_argument("--no-patch", action="store_true", help="skip the patch stage")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    for noisy in ("httpx", "httpcore", "openai", "urllib3", "werkzeug"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    patch_evaluated = not args.no_patch
    results, metrics = run_suite(args.targets, do_patch=patch_evaluated, results_dir=args.out)
    print("\n" + to_markdown(results, metrics, patch_evaluated=patch_evaluated))
    json_path, md_path = write_report(results, metrics, args.out, patch_evaluated=patch_evaluated)
    print(f"\nWrote: {json_path}\n       {md_path}")


if __name__ == "__main__":
    main()

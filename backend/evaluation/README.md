# ANVIL Evaluation Harness

Measures the ANVIL pipeline against a benchmark of **known-vulnerable apps** and
reports detection / exploitation / verification / live-validated-patch rates —
the honest "does it actually work?" number.

## Run

From `backend/`:

```bash
python -m evaluation.run_eval             # full pipeline (recon -> exploit -> verify -> patch)
python -m evaluation.run_eval --no-patch  # detection/exploit/verify only (cheaper)
```

Writes `evaluation/results/benchmark_report.{json,md}`.

Real runs make GPT-4o calls (needs `OPENAI_API_KEY` in `backend/.env`) and use
Docker for the sealed patch gate when available. **No GitHub is used** — targets
are local dirs and the patcher's PR push is stubbed — so the *Patched* metric
reflects a **live-validated fix** (the patched app still starts **and** the
original exploit no longer succeeds), not a merged PR.

## Metrics

| Metric | Meaning |
|--------|---------|
| **Detected** | recon found a vulnerability matching the target's ground truth |
| **Exploited** | the exploit was confirmed in the sandbox |
| **Verified** | the deterministic verifier accepted it |
| **Patched** | a generated patch passed the live re-exploit gate |

## Corpus

Each `targets/<name>/` is a small, intentionally-insecure app plus a
`benchmark.json` ground-truth manifest. ⚠️ **These are deliberately vulnerable
test fixtures — never deploy them.**

| Target | Vulnerability class |
|--------|---------------------|
| `pickle_prefs` | insecure deserialization (RCE) |
| `path_traversal` | path traversal (arbitrary file read) |

Add a target by dropping a new `targets/<name>/` directory containing the app,
its `requirements.txt`, and a `benchmark.json`.

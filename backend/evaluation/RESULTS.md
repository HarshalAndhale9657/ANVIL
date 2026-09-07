# ANVIL Benchmark Results

_Run 2026-09-08 · 6 known-vulnerable targets · real GPT‑4o pipeline · patch stage
validated by re-running the exploit inside a `--network none` container (no GitHub)._

| Metric | Rate | Count |
|---|---|---|
| Detected | **100%** | 6/6 |
| Exploited (sandbox-confirmed) | **83%** | 5/6 |
| Verified (deterministic gate) | **83%** | 5/6 |
| Patched (live re-exploit-validated) | **50%** | 3/6 |

| Target | Class | Detected | Exploited | Verified | Patched |
|---|---|---|---|---|---|
| `pickle_prefs` | insecure deserialization (RCE) | ✅ | ✅ | ✅ | ✅ |
| `path_traversal` | path traversal | ✅ | ✅ | ✅ | — |
| `sqli_users` | SQL injection | ✅ | ✅ | ✅ | ✅ |
| `ssti_comment` | SSTI / reflected XSS | ✅ | ✅ | ✅ | — |
| `cmd_exec` | command injection | ✅ | ✅ | ✅ | ✅ |
| `ssrf_fetch` | SSRF | ✅ | — | — | — |

## Reading the numbers (honestly)

- **Detection 100%** — recon found every planted vulnerability across all six classes.
- **Exploit/verify 83%** — 5/6 exploited and *deterministically* verified. The miss is
  **SSRF**: it is *detected*, but proving impact needs a reachable internal target that a
  local, offline harness doesn't provide — not a detection failure.
- **Live-validated patch 50% (3/6)** — a deliberately *strict* metric. A patch counts only
  if the patched app **still starts** AND the **original exploit no longer succeeds**, checked
  by re-running the exploit inside a sealed container. The gate visibly earned this number:
  - `ssti_comment`, attempt 1 → the model's fix imported `flask.escape` (removed in Flask 2.1)
    → the app **wouldn't start** → gate **rejected** it — even though static validation had
    *passed* it. Attempts 2–3 → the fix didn't actually close the SSTI → rejected. The pipeline
    shipped **no patch rather than a broken one** (fail-closed).
  - `path_traversal` likewise produced no fix that survived re-exploitation within 3 attempts.

**50% is the rate *after* discarding broken and ineffective fixes** — which is the whole point
of the live re-exploit gate. A pipeline that reported "100% patched" on this corpus would be
lying; ANVIL reports the number that's actually true.

_Reproduce: `cd backend && python -m evaluation.run_eval` (or `--no-patch` for the cheaper
detection/exploit/verify pass). Raw JSON + Markdown land under `evaluation/results/` (gitignored)._

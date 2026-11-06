"""Test the actual run_exploit function with the deterministic fallback."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dotenv import load_dotenv
load_dotenv()

import logging
logging.basicConfig(level=logging.INFO, format="%(name)s | %(message)s")

from app.github_service import read_repo_files, detect_entry_point
from app.agents.recon import run_recon_source
from app.agents.exploiter import run_exploit
from app.agents.verifier import verify_exploit

# Find latest clone
repo_dir = None
for d in sorted(os.listdir("scans"), reverse=True):
    candidate = os.path.join("scans", d, "repo")
    if os.path.isdir(candidate):
        repo_dir = candidate
        break

print(f"[1] Repo dir: {repo_dir}")
print(f"[2] Running recon...")
recon = run_recon_source(repo_dir, "https://github.com/HarshalAndhale9657/anvil-demo-target")
print(f"    Found {len(recon.vulnerable_endpoints)} vulns")

entry = detect_entry_point(repo_dir)
print(f"[3] Entry point: {entry}")

print(f"[4] Running FULL run_exploit (with deterministic fallback)...")
result = run_exploit(recon, repo_dir=repo_dir, entry_point=entry)
print(f"\n{'='*50}")
print(f"vulnerability_confirmed: {result.vulnerability_confirmed}")
print(f"evidence: {result.exploit_evidence}")
print(f"stdout preview: {result.sandbox_stdout[:500]}")

print(f"\n[5] Running verifier...")
v = verify_exploit(result)
print(f"Verified: {v.verified}")
print(f"Reason: {v.reason}")

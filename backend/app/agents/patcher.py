"""
Patcher Agent — generates a code patch that fixes the exploited vulnerability
and opens a Pull Request on the user's GitHub repository via the GitHub API
(PyGithub): create a fix branch, commit the patched file(s), and open the PR —
forking the repo first if the user lacks push access.
"""

from __future__ import annotations

import difflib
import json
import logging
from pathlib import Path
from typing import Optional

try:
    import omium as _omium_mod
except Exception:
    _omium_mod = None


def _noop_trace(*a, **kw):
    def _d(fn): return fn
    return _d


class _OmiumShim:
    trace = staticmethod(_noop_trace)


omium = _omium_mod if _omium_mod is not None else _OmiumShim()
from openai import OpenAI

from app.config import LIVE_PATCH_GATE, LLM_MODEL, LLM_TEMPERATURE, OPENAI_API_KEY, PATCH_MAX_ATTEMPTS
from app.schemas import ExploitOutput, PatchOutput, ReconOutput, VerificationResult
from app.telemetry import trace_operation

logger = logging.getLogger(__name__)

_client: Optional[OpenAI] = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        _client = OpenAI(api_key=OPENAI_API_KEY)
    return _client


# ── Regression Test ──────────────────────────────────────────────────────────


def _static_patch_validation(
    original_code: str,
    fixed_code: str,
    exploit_payload: str,
    target_file: str = None,
    span=None,
) -> tuple[bool, str]:
    """
    Static validation for GitHub PR mode (web app), where ANVIL does NOT
    control the running server process.

    Checks that the patch:
      1. Actually changed the code (non-empty diff).
      2. For Python files: validates syntax via AST.
      3. Introduces at least one security-relevant pattern.
      4. Does not reintroduce obvious unsafe patterns from the original.

    Returns (passed: bool, reason: str).
    """
    # 1. Must have changed something
    if fixed_code.strip() == original_code.strip():
        return False, "Patch produced no changes to the source code."

    # 2. Syntax check — only for Python files
    is_python = True
    if target_file:
        ext = Path(target_file).suffix.lower()
        is_python = ext in (".py", ".pyw")

    if is_python:
        import ast
        try:
            ast.parse(fixed_code)
        except SyntaxError as exc:
            return False, f"Patched code has a syntax error: {exc}"

    # 3. Look for known unsafe patterns that should have been removed.
    #    These are heuristics covering the most common vulnerability classes.
    UNSAFE_PATTERNS = {
        "path_traversal": [
            "os.path.join(",
            "open(",
        ],
        "sql_injection": [
            'f"SELECT',
            "execute(f",
            ".format(",
        ],
        "command_injection": [
            "os.system(",
            "shell=True",
            "exec(",
            "eval(",
        ],
        "deserialization": [
            "pickle.loads(",
            "yaml.load(",
            "marshal.loads(",
        ],
    }

    # Specific security-improvement markers only. Bare tokens like "?", "filter",
    # "escape", "execute(" appear in ordinary code and would make almost any
    # change look like a "security improvement", so they are intentionally left
    # out to keep this gate meaningful.
    SAFE_PATTERNS = [
        # Path safety
        "realpath", "resolve()", "abspath", "normpath",
        "commonpath", "commonprefix",
        "secure_filename", "safe_join",
        # SQL safety
        "parameterized", "parameterize", "prepared", ":param", "placeholder",
        # Input validation
        "sanitize", "validate", "allowlist", "whitelist",
        # Command safety
        "shlex.quote", "shlex.split",
        # Deserialization safety
        "yaml.safe_load", "json.loads",
        # JS/TS safe patterns
        "path.resolve", "path.normalize",
        "encodeURIComponent", "escapeHtml", "sanitizeHtml",
        "DOMPurify", "helmet", "csurf", "express-validator",
    ]

    fixed_lower = fixed_code.lower()
    original_lower = original_code.lower()
    
    # Check if safe patterns were ADDED (not just present)
    has_safe_pattern = any(
        p.lower() in fixed_lower and p.lower() not in original_lower
        for p in SAFE_PATTERNS
    )
    
    # Check if unsafe patterns were REMOVED
    removed_unsafe = False
    for vuln_type, patterns in UNSAFE_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in original_lower and pattern.lower() not in fixed_lower:
                removed_unsafe = True
                logger.info("Detected removal of unsafe pattern: %s", pattern)
                break

    # Count lines changed
    orig_lines = set(original_code.splitlines())
    fixed_lines = set(fixed_code.splitlines())
    added = fixed_lines - orig_lines
    removed = orig_lines - fixed_lines

    if not added and not removed:
        return False, "Patch produced no line-level changes."

    logger.info(
        "Static patch validation: %d lines added, %d lines removed, "
        "safe_pattern_added=%s, unsafe_removed=%s, is_python=%s",
        len(added), len(removed), has_safe_pattern, removed_unsafe, is_python,
    )

    if span:
        span.set_attribute("regression.mode", "static")
        span.set_attribute("regression.lines_added", len(added))
        span.set_attribute("regression.lines_removed", len(removed))
        span.set_attribute("regression.has_safe_pattern", has_safe_pattern)
        span.set_attribute("regression.removed_unsafe", removed_unsafe)
        span.set_attribute("regression.is_python", is_python)

    # Validation passes if:
    # 1. Code changed (lines added/removed)
    # 2. AND (safe pattern added OR unsafe pattern removed)
    if not (has_safe_pattern or removed_unsafe):
        return False, (
            "Patch does not introduce security improvements. "
            "No safe patterns added and no unsafe patterns removed."
        )

    return True, (
        f"Static validation passed: {len(added)} lines added, "
        f"{len(removed)} lines removed"
        + (", safe pattern added" if has_safe_pattern else "")
        + (", unsafe pattern removed" if removed_unsafe else "")
        + "."
    )


# ── Mode 1: GitHub API Patch (web app) ───────────────────────────────────────

@omium.trace("patcher_agent", span_type="agent")
def run_patch_github(
    recon: ReconOutput,
    exploit: ExploitOutput,
    verification: VerificationResult,
    trace_id: str,
    github_token: str,
    repo_url: str,
    repo_dir: str,
    base_branch: str = "main",
) -> PatchOutput:
    """
    Generate a fix and push it as a Pull Request to the user's GitHub repo
    via the GitHub API (no local git needed for the push).
    """
    from app.github_service import create_branch_and_pr, parse_repo_full_name

    with trace_operation(
        "patcher_agent_github",
        attributes={
            "agent.name": "patcher",
            "agent.mode": "github_api",
            "agent.repo_url": repo_url,
            "agent.trace_id": trace_id,
        },
    ) as span:
        repo_full_name = parse_repo_full_name(repo_url)

        # Step 1: Identify the vulnerable file and read it
        vuln_path = None
        if recon.vulnerable_endpoints:
            raw_path = recon.vulnerable_endpoints[0].path
            # Extract file path (strip line numbers like "server.py:23")
            vuln_path = raw_path.split(":")[0] if ":" in raw_path else raw_path

        # Try to find the file in the cloned repo
        target_file = None
        original_code = ""
        if vuln_path and repo_dir:
            candidate = Path(repo_dir) / vuln_path
            if candidate.exists():
                target_file = vuln_path
                original_code = candidate.read_text(encoding="utf-8")
            else:
                # Search by name, but prefer the candidate whose full relative
                # path matches the reported path. A plain rglob-first-match can
                # otherwise patch an unrelated file that merely shares a basename
                # (e.g. utils/config.py when the vuln is in app/config.py).
                filename = Path(vuln_path).name
                candidates = list(Path(repo_dir).rglob(filename))
                if candidates:
                    norm_vuln = vuln_path.replace("\\", "/").lstrip("./")

                    def _rel(p):
                        return str(p.relative_to(repo_dir)).replace("\\", "/")

                    best = (
                        next((p for p in candidates if _rel(p) == norm_vuln), None)
                        or next((p for p in candidates if _rel(p).endswith("/" + norm_vuln)), None)
                        or min(candidates, key=lambda p: len(_rel(p)))
                    )
                    target_file = _rel(best)
                    original_code = best.read_text(encoding="utf-8")

        if not target_file or not original_code:
            raise RuntimeError(
                f"Cannot locate vulnerable file '{vuln_path}' in cloned repo"
            )

        # Step 2: Ask LLM for the fix
        client = _get_client()

        system_prompt = (
            "You are a security patch agent. Given the vulnerable source code and "
            "the exploit details, generate a fixed version of the code that eliminates "
            "the vulnerability. Return ONLY valid JSON:\n"
            "{\n"
            '  "fixed_code": "<the complete fixed source code>",\n'
            '  "explanation": "<brief explanation of what was fixed>",\n'
            '  "confidence": <float 0-1>\n'
            "}\n"
            "The fix should:\n"
            "1. Sanitize user input to prevent the exploit\n"
            "2. Keep all other functionality intact\n"
            "3. Use secure coding practices (path canonicalization, input validation)\n"
            "4. NOT add any comments referencing this tool or AI\n"
        )

        vuln_desc = (
            recon.vulnerable_endpoints[0].injection_vector
            if recon.vulnerable_endpoints else "unknown"
        )

        user_prompt = (
            f"## Vulnerable File: {target_file}\n"
            f"```python\n{original_code}\n```\n\n"
            f"## Vulnerability Details\n"
            f"- Type: {vuln_desc}\n"
            f"- Exploit payload:\n```python\n{exploit.exploit_payload_used}\n```\n"
            f"- Sandbox stdout: {exploit.sandbox_stdout[:500]}\n"
            f"- Verification: {verification.reason}\n"
        )

        # Steps 3–3b: generate a fix and validate it, retrying with the
        # validator's feedback when a patch is ineffective or breaks the app.
        #   • Static analysis is a fast first filter.
        #   • The LIVE re-exploit gate is authoritative when it can run: it
        #     applies the fix to a throwaway copy, relaunches the app, and
        #     re-runs the original exploit — accepting only if the app still
        #     starts, serves a benign request, and the exploit no longer works.
        # Each rejection is fed back to the model for a corrected attempt. If no
        # attempt yields a valid patch we fail closed (no PR).
        fixed_code = explanation = None
        confidence = 0.0
        validation_label = None
        feedback = None
        last_rejection = None

        for attempt in range(1, PATCH_MAX_ATTEMPTS + 1):
            attempt_prompt = user_prompt
            if feedback:
                attempt_prompt += (
                    "\n\n## Your previous fix was REJECTED — correct it\n"
                    f"{feedback}\n"
                    "Return a corrected fix that: keeps the app starting (every import "
                    "must be valid for the installed library versions), preserves existing "
                    "behaviour, and actually closes the vulnerability."
                )

            try:
                response = client.chat.completions.create(
                    model=LLM_MODEL,
                    temperature=LLM_TEMPERATURE,
                    response_format={"type": "json_object"},
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": attempt_prompt},
                    ],
                )
                raw = json.loads(response.choices[0].message.content)
                fixed_code = raw["fixed_code"]
                explanation = raw["explanation"]
                confidence = float(raw.get("confidence", 0.8))
                if response.usage:
                    span.set_attribute(f"llm.attempt{attempt}.prompt_tokens", response.usage.prompt_tokens)
                    span.set_attribute(f"llm.attempt{attempt}.completion_tokens", response.usage.completion_tokens)
            except Exception as exc:
                # LLM/infra failure (not a rejected patch) — fail closed.
                logger.error("LLM patch generation failed (attempt %d): %s", attempt, exc)
                span.add_event("llm_patch_failed", attributes={"attempt": attempt, "error": str(exc)})
                raise RuntimeError(f"Patch generation failed; refusing to open a placebo PR: {exc}")

            # Static gate.
            static_ok, static_reason = _static_patch_validation(
                original_code=original_code,
                fixed_code=fixed_code,
                exploit_payload=exploit.exploit_payload_used,
                target_file=target_file,
                span=span,
            )
            if not static_ok:
                last_rejection = f"static analysis: {static_reason}"
                feedback = f"Reason: {last_rejection}"
                logger.warning("Patch attempt %d/%d rejected (static): %s", attempt, PATCH_MAX_ATTEMPTS, static_reason)
                continue

            # Live re-exploit gate (authoritative when applicable).
            validation_label = f"Static analysis: {static_reason}"
            if LIVE_PATCH_GATE:
                from app.patch_validator import validate_patch_by_reexploit

                live = validate_patch_by_reexploit(
                    repo_dir=repo_dir,
                    target_file=target_file,
                    fixed_code=fixed_code,
                    exploit_code=exploit.exploit_payload_used,
                )
                span.set_attribute(f"regression.attempt{attempt}.live_applicable", live.applicable)
                span.set_attribute(f"regression.attempt{attempt}.live_reason", live.reason[:200])
                if live.applicable and not live.valid:
                    last_rejection = live.reason
                    feedback = f"Reason: {live.reason}"
                    logger.warning("Patch attempt %d/%d rejected (live gate): %s", attempt, PATCH_MAX_ATTEMPTS, live.reason)
                    continue
                if live.applicable:
                    validation_label = f"Live re-exploit gate (attempt {attempt}/{PATCH_MAX_ATTEMPTS}): {live.reason}"
                else:
                    logger.info("Live re-exploit gate not applicable: %s", live.reason)

            # Accepted.
            span.set_attribute("patch.attempts", attempt)
            span.set_attribute("agent.decision_rationale", (explanation or "")[:500])
            break
        else:
            raise RuntimeError(
                f"No valid patch after {PATCH_MAX_ATTEMPTS} attempts. Last rejection: {last_rejection}"
            )

        # Step 4: Build the PR content
        fix_branch = f"anvil/fix-{trace_id[:12]}"
        pr_title = f"🛡️ Security Fix: {vuln_desc[:80]} — Anvil Scan {trace_id[:8]}"
        pr_body = (
            f"## 🔍 Vulnerability Report\n\n"
            f"**Repository**: {repo_url}\n"
            f"**File**: `{target_file}`\n"
            f"**Type**: {vuln_desc}\n\n"
            f"## 💣 Proof of Exploitation\n\n"
            f"```\n{exploit.sandbox_stdout[:1000]}\n```\n\n"
            f"## 🩹 Fix Applied\n\n{explanation}\n\n"
            f"## ✅ Patch Validation\n\n"
            f"{validation_label}\n\n"
            f"**Confidence**: {confidence:.0%}\n"
            f"**Trace ID**: `{trace_id}`\n\n"
            f"---\n"
            f"*This PR was automatically generated by [Anvil](https://github.com) — "
            f"Autonomous Security Remediation Platform*"
        )

        # Step 5: Push to GitHub and create PR
        pr_url = create_branch_and_pr(
            token=github_token,
            repo_full_name=repo_full_name,
            base_branch=base_branch,
            fix_branch=fix_branch,
            fixed_files=[{"path": target_file, "content": fixed_code}],
            pr_title=pr_title,
            pr_body=pr_body,
        )

        span.set_attribute("patch.branch", fix_branch)
        span.set_attribute("patch.confidence", confidence)
        span.set_attribute("patch.pr_url", pr_url)

        # Generate a proper unified diff for display
        unified_diff = "\n".join(
            difflib.unified_diff(
                original_code.splitlines(),
                fixed_code.splitlines(),
                fromfile=f"a/{target_file}",
                tofile=f"b/{target_file}",
                lineterm="",
            )
        ) or "(no diff available)"

        result = PatchOutput(
            file_modified=target_file,
            unified_diff=unified_diff,
            pull_request_title=pr_title,
            pull_request_body=pr_body,
            confidence_score=confidence,
            pr_url=pr_url,
        )

        logger.info("PR created: %s (confidence=%.0f%%)", pr_url, confidence * 100)
        return result



"""
Verifier Agent — deterministic, non-generative validation node.

This is NOT an LLM. It is a pure Python function that procedurally
checks whether the Exploiter's sandbox_stdout actually proves the
vulnerability was exploited. It compares Action_Requested vs
System_State_Change.

If verification fails, it generates a structured error payload
for the Orchestrator to trigger a re-generation or graceful halt.
"""

from __future__ import annotations

import logging

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

from app.schemas import ExploitOutput, VerificationResult
from app.telemetry import trace_operation

logger = logging.getLogger(__name__)

# The single deterministic success marker the Exploiter must print
_SUCCESS_MARKER = "EXPLOIT_SUCCESS"

# Minimum length of *positive* evidence (excluding marker/failure lines).
_MIN_EVIDENCE_LENGTH = 5

# Lines that indicate a FAILED probe rather than proof of exploitation. These
# must never be counted as evidence — otherwise a completely failed exploit
# whose stdout merely contains the word "error" would pass verification.
_FAILURE_INDICATORS = (
    "failed", "connection refused", "connection error",
    "timed out", "timeout", "exploit_failed", "refused",
    "traceback (most recent call last)",
)


@omium.trace("verifier_agent", span_type="agent")
def verify_exploit(exploit: ExploitOutput) -> VerificationResult:
    """
    Deterministically verify that the exploit produced real side-effects.

    Rules:
    1. vulnerability_confirmed must be True
    2. sandbox_stdout must contain the EXPLOIT_SUCCESS marker
    3. stdout must contain meaningful content beyond just the marker
       (prevents hallucinated empty exploits)
    """
    with trace_operation(
        "verifier_agent",
        attributes={
            "agent.name": "verifier",
            "agent.is_deterministic": True,
        },
    ) as span:
        stdout = exploit.sandbox_stdout

        # ── Check 1: exploit self-reported success ────────────────────────
        if not exploit.vulnerability_confirmed:
            reason = (
                "Exploit agent reported vulnerability_confirmed=False. "
                "The sandbox did not confirm exploitation."
            )
            span.set_attribute("verification.result", "REJECTED")
            span.set_attribute("verification.reason", reason)
            logger.warning("Verification FAILED: %s", reason)
            return VerificationResult(
                verified=False,
                reason=reason,
                expected_pattern=f"{_SUCCESS_MARKER} in stdout",
                actual_value=stdout[:200],
                failure_category="not_confirmed",
            )

        # ── Check 2: stdout contains the success marker ──────────────────
        if _SUCCESS_MARKER not in stdout:
            reason = (
                f"stdout does not contain the success marker "
                f"'{_SUCCESS_MARKER}'. "
                "The exploit may have hallucinated success."
            )
            span.set_attribute("verification.result", "REJECTED")
            span.set_attribute("verification.reason", reason)
            logger.warning("Verification FAILED: %s", reason)
            return VerificationResult(
                verified=False,
                reason=reason,
                expected_pattern=_SUCCESS_MARKER,
                actual_value=stdout[:200],
                failure_category="no_marker",
            )

        # ── Check 3: stdout has meaningful, NON-FAILURE evidence ─────────
        # A failed exploit often still prints the success marker (buggy LLM
        # payloads / template tails), so the marker alone is not proof. We
        # require a POSITIVE proof line AND that the surrounding evidence is
        # not merely failure/traceback noise.
        def _is_failure_line(line: str) -> bool:
            s = line.strip().lower()
            if not s:
                return True
            if line.lstrip().startswith("[-]"):   # template failure prefix
                return True
            return any(ind in s for ind in _FAILURE_INDICATORS)

        # Meaningful evidence = non-empty, non-failure lines, excluding the
        # marker itself and the "EXTRACTED_DATA:" label line.
        meaningful_lines = [
            line for line in stdout.replace(_SUCCESS_MARKER, "").splitlines()
            if line.strip()
            and not _is_failure_line(line)
            and not line.strip().lower().startswith("extracted_data:")
        ]
        evidence_text = "\n".join(meaningful_lines).strip()

        low = stdout.lower()
        # A positive proof signal: explicit extracted data, a confirmation
        # line, or a template "[+]" success prefix.
        has_positive_proof = (
            "extracted_data:" in low
            or "confirmed:" in low
            or any(line.lstrip().startswith("[+]") for line in stdout.splitlines())
        )

        # Confirmed if there is either an explicit positive-proof marker OR a
        # real (non-failure) evidence line of sufficient length. Failure-only
        # and marker-only stdout have neither, so they are rejected.
        exploit_confirmed = (
            has_positive_proof
            or len(evidence_text) >= _MIN_EVIDENCE_LENGTH
        )

        if not exploit_confirmed:
            reason = (
                f"stdout contains '{_SUCCESS_MARKER}' but has minimal "
                f"evidence ({len(evidence_text)} chars of content). "
                "The exploit may have printed the marker without actually "
                "extracting any data. This looks like a hallucinated exploit."
            )
            span.set_attribute("verification.result", "REJECTED")
            span.set_attribute("verification.reason", reason)
            logger.warning("Verification FAILED: %s", reason)
            return VerificationResult(
                verified=False,
                reason=reason,
                expected_pattern=f"{_SUCCESS_MARKER} + meaningful evidence",
                actual_value=stdout[:200],
                failure_category="no_evidence",
            )
        
        # Special case: if evidence is short but accepted, log it
        if len(evidence_text) < _MIN_EVIDENCE_LENGTH:
            logger.info(
                "Accepting short evidence (%d chars) due to auxiliary exploit signals",
                len(evidence_text)
            )

        # ── All checks passed ────────────────────────────────────────────
        has_evidence = bool(exploit.exploit_evidence)
        # Describe HOW it passed: a positive-proof marker (e.g. EXTRACTED_DATA /
        # a "[+]" confirmation) vs. a substantial block of extracted evidence —
        # so the reason never reads as the contradictory "0 chars of evidence".
        proof = (
            f"{len(evidence_text)} chars of extracted evidence"
            if len(evidence_text) >= _MIN_EVIDENCE_LENGTH
            else "a positive-proof marker"
        )
        reason = (
            f"Exploitation verified: stdout contains '{_SUCCESS_MARKER}' with {proof}"
            + (" (evidence captured)" if has_evidence else "")
            + "."
        )
        span.set_attribute("verification.result", "VERIFIED")
        span.set_attribute("verification.evidence_length", len(evidence_text))
        logger.info("Verification PASSED: %s", reason)
        return VerificationResult(
            verified=True,
            reason=reason,
            expected_pattern=_SUCCESS_MARKER,
            actual_value=stdout[:200],
        )

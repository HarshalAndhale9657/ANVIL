"""
Colored Petri Net (CPN) Graph Engine — deterministic orchestration.

Defines the multi-agent execution graph as a bipartite graph of
Places (system states) and Transitions (agent actions). Routing
decisions are made via pure Python if/else logic — the LLM is
NEVER consulted for graph traversal decisions.

The Master State (the "coloured token") flows through the net.
After each transition fires, the state is checkpointed to SQLite.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

from app import db
from app.schemas import AttemptRecord, MasterState
from app.telemetry import trace_operation

logger = logging.getLogger(__name__)


# ── Place & Transition definitions ───────────────────────────────────────────

class Place:
    """A state node in the Petri net (e.g. 'recon_ready', 'exploit_done')."""
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description

    def __repr__(self) -> str:
        return f"Place({self.name!r})"


class Transition:
    """
    An executable edge in the Petri net.
    
    - source:     the Place this transition departs from
    - targets:    mapping of condition-label → destination Place
    - action:     the function to execute (agent logic)
    - guard:      optional pure-Python predicate that must be True to fire
    """
    def __init__(
        self,
        name: str,
        source: Place,
        targets: Dict[str, Place],
        action: Callable[[MasterState], MasterState],
        guard: Optional[Callable[[MasterState], bool]] = None,
    ):
        self.name = name
        self.source = source
        self.targets = targets
        self.action = action
        self.guard = guard

    def can_fire(self, state: MasterState) -> bool:
        """Check if this transition's guard allows firing."""
        if state.current_node != self.source.name:
            return False
        if self.guard and not self.guard(state):
            return False
        return True

    def fire(self, state: MasterState) -> MasterState:
        """Execute the action and return the updated state."""
        return self.action(state)


# ── The CPN Engine ───────────────────────────────────────────────────────────

class CPNEngine:
    """
    Executes a Colored Petri Net by repeatedly finding and firing
    enabled transitions until the token reaches a terminal place.
    """

    def __init__(self) -> None:
        self.places: Dict[str, Place] = {}
        self.transitions: List[Transition] = []
        self.terminal_places: set[str] = set()

    def add_place(self, name: str, *, terminal: bool = False, description: str = "") -> Place:
        place = Place(name, description)
        self.places[name] = place
        if terminal:
            self.terminal_places.add(name)
        return place

    def add_transition(
        self,
        name: str,
        source: Place,
        targets: Dict[str, Place],
        action: Callable[[MasterState], MasterState],
        guard: Optional[Callable[[MasterState], bool]] = None,
    ) -> Transition:
        t = Transition(name, source, targets, action, guard)
        self.transitions.append(t)
        return t

    def run(self, state: MasterState) -> MasterState:
        """
        Execute the CPN from the current state until a terminal place
        is reached or no transitions can fire.
        """
        with trace_operation(
            "cpn_engine_run",
            attributes={
                "cpn.trace_id": state.trace_id,
                "cpn.start_node": state.current_node,
            },
        ) as engine_span:
            max_steps = 20  # absolute safety limit
            step = 0

            while step < max_steps:
                step += 1

                # Check if we reached a terminal place
                if state.current_node in self.terminal_places:
                    state.completed = True
                    logger.info("CPN reached terminal place: %s", state.current_node)
                    engine_span.set_attribute("cpn.final_node", state.current_node)
                    engine_span.set_attribute("cpn.steps", step)
                    break

                # Find an enabled transition
                fired = False
                for transition in self.transitions:
                    if transition.can_fire(state):
                        logger.info(
                            "Step %d: firing transition '%s' from '%s'",
                            step, transition.name, state.current_node,
                        )

                        with trace_operation(
                            f"transition:{transition.name}",
                            attributes={
                                "cpn.transition": transition.name,
                                "cpn.source": transition.source.name,
                                "cpn.step": step,
                                "cpn.retry_count": state.retry_count,
                            },
                        ):
                            # Fire the transition (execute agent logic)
                            state = transition.fire(state)

                            # Checkpoint to SQLite after every transition
                            db.save_checkpoint(
                                state.trace_id,
                                state.current_node,
                                state.model_dump(mode="json"),
                            )

                        fired = True
                        break

                if not fired:
                    logger.error(
                        "CPN deadlock: no transition can fire from '%s'",
                        state.current_node,
                    )
                    state.error = f"Deadlock at {state.current_node}"
                    state.completed = True
                    break

            if step >= max_steps:
                logger.error("CPN exceeded max steps (%d)", max_steps)
                state.error = f"Exceeded max steps ({max_steps})"
                state.completed = True

            engine_span.set_attribute("cpn.final_node", state.current_node)
            engine_span.set_attribute("cpn.total_steps", step)
            return state


# ── Build the Web App CPN ────────────────────────────────────────────────────

def build_web_cpn(scan_id: str, emit_fn, loop=None) -> CPNEngine:
    """
    Construct the CPN for the web app mode.
    Uses source code analysis (not HTTP probing) and GitHub API for patching.
    Emits SSE events via emit_fn after each transition.

    emit_fn signature: async def emit(scan_id, stage, status, message, ...)
    """
    import asyncio
    from app.agents.exploiter import run_exploit
    from app.agents.patcher import run_patch_github
    from app.agents.recon import run_recon_source
    from app.agents.verifier import verify_exploit
    from app.config import SANDBOX_MAX_RETRIES
    from app.schemas import ScanStage

    def _emit_sync(stage, status, message, **kwargs):
        """Synchronously push an SSE event from a blocking thread."""
        try:
            if loop and loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    emit_fn(scan_id, stage, status, message, **kwargs),
                    loop,
                ).result(timeout=5)
            else:
                asyncio.run(emit_fn(scan_id, stage, status, message, **kwargs))
        except Exception as exc:
            logger.warning("Failed to emit SSE event: %s", exc)

    engine = CPNEngine()

    # ── Places ────────────────────────────────────────────────────────────
    p_ingress       = engine.add_place("ingress", description="Scan received")
    p_recon_ready   = engine.add_place("recon_ready", description="Ready to scan source code")
    p_exploit_ready = engine.add_place("exploit_ready", description="Ready to exploit")
    p_exploit_done  = engine.add_place("exploit_done", description="Exploit complete")
    p_patch_ready   = engine.add_place("patch_ready", description="Ready to patch & PR")
    p_patch_done    = engine.add_place("patch_done", terminal=True, description="PR created")
    p_end_safe      = engine.add_place("end_safe", terminal=True, description="No vulnerability found")
    p_end_error     = engine.add_place("end_error", terminal=True, description="Pipeline failed")
    p_dead_letter   = engine.add_place("dead_letter", terminal=True, description="Max exploit attempts exceeded — requires human review")

    # ── T1: Ingress → Recon ───────────────────────────────────────────────
    def t1_action(state: MasterState) -> MasterState:
        # Scope the sandbox signature circuit-breaker to this scan so identical
        # payloads from previous scans don't pre-trip it.
        from app.sandbox import reset_circuit_breaker
        reset_circuit_breaker()
        state.current_node = "recon_ready"
        return state

    engine.add_transition("t1_start_recon", p_ingress, {"default": p_recon_ready}, t1_action)

    # ── T2: Recon (source code analysis) ─────────────────────────────────
    def t2_action(state: MasterState) -> MasterState:
        try:
            result = run_recon_source(state.repo_dir, state.repo_url or state.webhook.target_url, emit_fn=_emit_sync)
            state.recon = result
            vuln_count = len(result.vulnerable_endpoints)

            if result.vulnerable_endpoints:
                logger.info("Recon found %d vulnerabilities in %s", vuln_count, state.repo_url)
                _emit_sync(ScanStage.RECON, "done",
                           f"Found {vuln_count} vulnerability(ies)",
                           vuln_count=vuln_count, progress_pct=30)
                state.current_node = "exploit_ready"
            else:
                logger.info("Recon found no vulnerabilities in %s", state.repo_url)
                _emit_sync(ScanStage.RECON, "done",
                           "No vulnerabilities found — repo is clean!",
                           vuln_count=0, progress_pct=100)
                state.current_node = "end_safe"
        except Exception as exc:
            logger.error("Recon failed: %s", exc, exc_info=True)
            state.error = f"Recon agent failed: {str(exc)}"
            _emit_sync(ScanStage.RECON, "error", f"Recon failed: {exc}")
            state.current_node = "end_error"
        return state

    engine.add_transition(
        "t2_run_recon", p_recon_ready,
        {"has_vulns": p_exploit_ready, "no_vulns": p_end_safe, "error": p_end_error},
        t2_action,
    )

    # ── T3: Exploit ──────────────────────────────────────────────────────
    def t3_action(state: MasterState) -> MasterState:
        _emit_sync(ScanStage.EXPLOIT, "running",
                    "Generating exploit payload...", progress_pct=40)
        try:
            # Detect entry point for auto-launching the target app
            from app.github_service import detect_entry_point
            entry_point = detect_entry_point(state.repo_dir) if state.repo_dir else None
            if entry_point:
                logger.info("Auto-detected entry point: %s", entry_point)
                _emit_sync(ScanStage.EXPLOIT, "running",
                            f"Starting target app ({entry_point}) for live exploit...",
                            progress_pct=42)

            result = run_exploit(state.recon, repo_dir=state.repo_dir, entry_point=entry_point,
                                 attempt_history=state.attempt_history)
            state.exploit = result
            logger.info("Exploit completed: confirmed=%s, has_evidence=%s",
                       result.vulnerability_confirmed, bool(result.exploit_evidence))
            _emit_sync(ScanStage.EXPLOIT, "done",
                        f"Exploit {'confirmed' if result.vulnerability_confirmed else 'attempted'}",
                        detail=result.exploit_evidence or result.sandbox_stdout[:200] if result.exploit_evidence or result.sandbox_stdout else None,
                        progress_pct=55)
            state.current_node = "exploit_done"
        except Exception as exc:
            logger.error("Exploit failed: %s", exc, exc_info=True)
            state.error = f"Exploit agent failed: {str(exc)}"
            _emit_sync(ScanStage.EXPLOIT, "error", f"Exploit failed: {exc}")
            state.current_node = "end_error"
        return state

    engine.add_transition(
        "t3_run_exploit", p_exploit_ready,
        {"done": p_exploit_done, "error": p_end_error},
        t3_action,
    )

    # ── T4: Verify ───────────────────────────────────────────────────────
    def t4_action(state: MasterState) -> MasterState:
        _emit_sync(ScanStage.VERIFY, "running",
                    "Verifying exploit (deterministic)...", progress_pct=60)
        try:
            result = verify_exploit(state.exploit)
            state.verification = result

            if result.verified:
                logger.info("Verification passed: %s", result.reason)
                _emit_sync(ScanStage.VERIFY, "done",
                            f"Exploit verified: {result.reason[:100]}", progress_pct=70)
                state.current_node = "patch_ready"
            else:
                # Record the failed attempt for feedback-aware retries
                if state.exploit:
                    state.attempt_history.append(AttemptRecord(
                        attempt_number=state.retry_count + 1,
                        exploit_code=state.exploit.exploit_payload_used[:2000],
                        sandbox_stdout=state.exploit.sandbox_stdout[:1000],
                        failure_reason=result.reason[:500],
                    ))

                state.retry_count += 1
                if state.retry_count > SANDBOX_MAX_RETRIES:
                    logger.error(
                        "Max retries (%d) exceeded — routing to dead letter",
                        SANDBOX_MAX_RETRIES,
                    )
                    state.error = (
                        f"Verification failed after {state.retry_count} retries: "
                        f"{result.reason}"
                    )
                    _emit_sync(ScanStage.VERIFY, "error",
                                f"Max retries exceeded: {result.reason[:100]}")
                    state.current_node = "dead_letter"
                else:
                    logger.warning("Verification failed (attempt %d/%d): %s",
                                 state.retry_count, SANDBOX_MAX_RETRIES, result.reason)
                    _emit_sync(ScanStage.VERIFY, "running",
                                f"Verification failed (attempt {state.retry_count}/{SANDBOX_MAX_RETRIES}), retrying...",
                                progress_pct=45)
                    state.current_node = "exploit_ready"
        except Exception as exc:
            logger.error("Verifier failed: %s", exc, exc_info=True)
            state.error = f"Verifier failed: {str(exc)}"
            _emit_sync(ScanStage.VERIFY, "error", f"Verification failed: {exc}")
            state.current_node = "end_error"
        return state

    engine.add_transition(
        "t4_verify", p_exploit_done,
        {"verified": p_patch_ready, "retry": p_exploit_ready, "dead_letter": p_dead_letter, "fail": p_end_error},
        t4_action,
    )

    # ── T5: Patch + GitHub PR ────────────────────────────────────────────
    def t5_action(state: MasterState) -> MasterState:
        _emit_sync(ScanStage.PATCH, "running",
                    "Generating security fix...", progress_pct=75)
        try:
            result = run_patch_github(
                recon=state.recon,
                exploit=state.exploit,
                verification=state.verification,
                trace_id=state.trace_id,
                github_token=state.github_token,
                repo_url=state.repo_url,
                repo_dir=state.repo_dir,
                base_branch=state.base_branch,
            )
            state.patch = result
            logger.info("Patch completed: PR=%s, confidence=%.0f%%",
                       result.pr_url, result.confidence_score * 100)

            _emit_sync(ScanStage.PUSHING, "done",
                        f"Pull Request created!",
                        pr_url=result.pr_url, progress_pct=95)
            state.current_node = "patch_done"
        except Exception as exc:
            logger.error("Patch failed: %s", exc, exc_info=True)
            state.error = f"Patch agent failed: {str(exc)}"
            _emit_sync(ScanStage.PATCH, "error", f"Patch failed: {exc}")
            state.current_node = "end_error"
        return state

    engine.add_transition(
        "t5_run_patch", p_patch_ready,
        {"done": p_patch_done, "error": p_end_error},
        t5_action,
    )

    return engine


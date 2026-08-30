"""
Pipeline runner — executes the CPN engine in a background asyncio task
(offloading the blocking CPN run via asyncio.to_thread) and emits SSE
events for real-time frontend updates.

Each scan gets its own asyncio.Queue for SSE event streaming.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
from datetime import datetime
from typing import Dict, Optional

from app import db
from app.github_service import (
    cleanup_scan_dir,
    clone_repo,
    create_branch_and_pr,
    parse_repo_full_name,
    read_repo_files,
)
from app.schemas import (
    MasterState,
    ScanEvent,
    ScanResult,
    ScanStage,
    WebhookPayload,
)
from app.telemetry import init_telemetry, trace_operation

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

logger = logging.getLogger(__name__)

# ── In-memory scan registry ──────────────────────────────────────────────────
# Maps scan_id → {queue, result, task, owner, repo_url, created_at}

_scans: Dict[str, dict] = {}

# How long a finished scan's result stays queryable before it is evicted to
# free memory. The transient queue/task are released immediately on completion.
_SCAN_TTL_SECONDS = 3600


def owner_id(token: str) -> str:
    """Stable, non-reversible identifier for the owning session token."""
    return hashlib.sha256((token or "").encode()).hexdigest()


def get_scan_queue(scan_id: str) -> Optional[asyncio.Queue]:
    """Get the SSE event queue for a scan."""
    entry = _scans.get(scan_id)
    return entry.get("queue") if entry else None


def get_scan_result(scan_id: str) -> Optional[ScanResult]:
    """Get the final result for a completed scan."""
    entry = _scans.get(scan_id)
    return entry.get("result") if entry else None


def get_scan_owner(scan_id: str) -> Optional[str]:
    """Return the owner_id bound to a scan, or None if unknown."""
    entry = _scans.get(scan_id)
    return entry.get("owner") if entry else None


def list_scans(owner: Optional[str] = None) -> list[dict]:
    """
    Return a summary of scans. If *owner* is given, only that session's scans
    are returned (prevents one session from seeing every session's scans).
    """
    results = []
    for scan_id, entry in _scans.items():
        if owner is not None and entry.get("owner") != owner:
            continue
        r = entry.get("result")
        results.append({
            "scan_id": scan_id,
            "repo_url": entry.get("repo_url", ""),
            "status": r.status if r else "running",
            "stage": r.stage.value if r else "queued",
            "pr_url": r.pr_url if r else None,
            "created_at": entry.get("created_at", ""),
        })
    return results


def _schedule_scan_eviction(scan_id: str) -> None:
    """
    Release the transient queue/task immediately (the SSE stream has already
    terminated on completed/failed) and evict the whole entry after a TTL so
    GET /api/scan/{id} stays answerable for a while, then frees memory.
    """
    entry = _scans.get(scan_id)
    if entry is None:
        return
    entry["queue"] = None
    entry.pop("task", None)
    try:
        loop = asyncio.get_running_loop()
        loop.call_later(_SCAN_TTL_SECONDS, lambda: _scans.pop(scan_id, None))
    except RuntimeError:
        _scans.pop(scan_id, None)  # no running loop (sync/CLI): evict now


# ── Event emitter ────────────────────────────────────────────────────────────

async def _emit(scan_id: str, stage: ScanStage, status: str,
                message: str = "", detail: str = None,
                pr_url: str = None, vuln_count: int = None,
                progress_pct: int = 0):
    """Push a ScanEvent to the scan's SSE queue."""
    # Keep the progress bar monotonic: an exploit/verify retry emits lower
    # numbers (e.g. 40/45 after 70), which would otherwise make the frontend
    # bar jump backward. Never let progress decrease mid-scan; errors still
    # snap to 100 via their own emit.
    entry = _scans.get(scan_id)
    if entry is not None and status != "error":
        prev = entry.get("max_progress", 0)
        if progress_pct < prev:
            progress_pct = prev
        entry["max_progress"] = progress_pct

    event = ScanEvent(
        scan_id=scan_id,
        stage=stage,
        status=status,
        message=message,
        detail=detail,
        pr_url=pr_url,
        vuln_count=vuln_count,
        progress_pct=progress_pct,
    )
    queue = get_scan_queue(scan_id)
    if queue:
        await queue.put(event)
    logger.info("[%s] %s — %s: %s", scan_id[:8], stage.value, status, message)


# ── Pipeline execution ───────────────────────────────────────────────────────

@omium.trace("scan_pipeline", span_type="function")
async def run_scan(
    scan_id: str,
    token: str,
    repo_url: str,
    base_branch: str = "main",
) -> None:
    """
    Full scan pipeline:
      1. Clone repo
      2. Read source files
      3. Run CPN (Recon → Exploit → Verify → Patch)
      4. Push fix branch + create PR on GitHub

    Runs in the event loop via asyncio.to_thread for blocking operations.
    """
    init_telemetry()

    with trace_operation(
        "scan_pipeline",
        attributes={
            "scan.id": scan_id,
            "scan.repo_url": repo_url,
            "scan.base_branch": base_branch,
        },
    ):
        try:
            # Ensure scan entry exists for direct CLI calls
            if scan_id not in _scans:
                _scans[scan_id] = {
                    "queue": asyncio.Queue(),
                    "result": None,
                    "repo_url": repo_url,
                    "owner": owner_id(token),
                    "created_at": datetime.utcnow().isoformat(),
                }

            # ── Stage 1: Clone ────────────────────────────────────────────
            await _emit(scan_id, ScanStage.CLONING, "running",
                        f"Cloning {repo_url}...", progress_pct=5)

            repo_dir = await asyncio.to_thread(clone_repo, token, repo_url, scan_id)

            await _emit(scan_id, ScanStage.CLONING, "done",
                        "Repository cloned successfully", progress_pct=10)

            # ── Stage 2: Build MasterState and run CPN ────────────────────
            trace_id = uuid.uuid4().hex
            task_id = scan_id

            # Create a synthetic webhook payload for CPN compatibility
            repo_full_name = parse_repo_full_name(repo_url)
            webhook = WebhookPayload(
                target_url=repo_url,
                deployment_id=scan_id,
                repo_url=repo_url,
                repo_name=repo_full_name,
                github_token=token,
                base_branch=base_branch,
            )

            state = MasterState(
                trace_id=trace_id,
                task_id=task_id,
                current_node="ingress",
                repo_url=repo_url,
                repo_dir=str(repo_dir),
                webhook=webhook,
                github_token=token,
                base_branch=base_branch,
            )

            # Checkpoint initial state
            db.save_checkpoint(trace_id, "ingress", state.model_dump(mode="json"))

            # ── Run CPN with event hooks ──────────────────────────────────
            await _emit(scan_id, ScanStage.RECON, "running",
                        "Scanning source code for vulnerabilities...", progress_pct=15)

            from app.graph import build_web_cpn
            loop = asyncio.get_running_loop()
            cpn = build_web_cpn(scan_id, _emit, loop=loop)
            final_state = await asyncio.to_thread(cpn.run, state)

            # ── Store result ──────────────────────────────────────────────
            pr_url = final_state.patch.pr_url if final_state.patch else None
            vuln_count = len(final_state.recon.vulnerable_endpoints) if final_state.recon else 0

            if final_state.error:
                result = ScanResult(
                    scan_id=scan_id,
                    repo_url=repo_url,
                    status="failed",
                    stage=ScanStage.FAILED,
                    error=final_state.error,
                    recon=final_state.recon,
                    exploit=final_state.exploit,
                    verification=final_state.verification,
                )
                _scans[scan_id]["result"] = result
                await _emit(scan_id, ScanStage.FAILED, "error",
                            f"Pipeline failed: {final_state.error}",
                            progress_pct=100)
            else:
                result = ScanResult(
                    scan_id=scan_id,
                    repo_url=repo_url,
                    status="completed",
                    stage=ScanStage.COMPLETED,
                    vulnerabilities=(
                        final_state.recon.vulnerable_endpoints if final_state.recon else []
                    ),
                    pr_url=pr_url,
                    completed_at=datetime.utcnow().isoformat(),
                    recon=final_state.recon,
                    exploit=final_state.exploit,
                    verification=final_state.verification,
                    patch=final_state.patch,
                )
                _scans[scan_id]["result"] = result
                await _emit(scan_id, ScanStage.COMPLETED, "done",
                            "Scan complete!" + (f" PR: {pr_url}" if pr_url else ""),
                            pr_url=pr_url,
                            vuln_count=vuln_count,
                            progress_pct=100)

        except Exception as exc:
            logger.exception("Scan %s failed with exception", scan_id)
            result = ScanResult(
                scan_id=scan_id,
                repo_url=repo_url,
                status="failed",
                stage=ScanStage.FAILED,
                error=str(exc),
            )
            _scans[scan_id]["result"] = result
            await _emit(scan_id, ScanStage.FAILED, "error",
                        f"Unexpected error: {exc}", progress_pct=100)
        finally:
            # Always reclaim the cloned repo (disk) and schedule the in-memory
            # scan entry for TTL eviction, on every terminal path.
            try:
                cleanup_scan_dir(scan_id)
            except Exception:
                logger.warning("Scan dir cleanup failed for %s", scan_id, exc_info=True)
            _schedule_scan_eviction(scan_id)


def start_scan(token: str, repo_url: str, base_branch: str = "main") -> str:
    """
    Register a new scan and kick off the pipeline as an asyncio task.
    Returns the scan_id.
    """
    scan_id = uuid.uuid4().hex[:16]
    queue: asyncio.Queue = asyncio.Queue()

    _scans[scan_id] = {
        "queue": queue,
        "result": None,
        "repo_url": repo_url,
        "owner": owner_id(token),
        "created_at": datetime.utcnow().isoformat(),
    }

    # Fire-and-forget in the event loop. start_scan is always called from
    # within an async request handler, so a running loop is guaranteed.
    loop = asyncio.get_running_loop()
    task = loop.create_task(run_scan(scan_id, token, repo_url, base_branch))
    _scans[scan_id]["task"] = task

    logger.info("Scan %s started for %s", scan_id, repo_url)
    return scan_id

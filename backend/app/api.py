"""
Scan API router — endpoints for starting scans, streaming progress,
and retrieving results.

Uses Server-Sent Events (SSE) for real-time pipeline progress.
"""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

from app.auth import require_auth
from app.pipeline import (
    get_scan_owner,
    get_scan_queue,
    get_scan_result,
    list_scans,
    owner_id,
    start_scan,
)
from app.schemas import ScanRequest

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["scan"])


@router.post("/scan")
async def create_scan(body: ScanRequest, request: Request):
    """
    Start a new vulnerability scan on a GitHub repository.
    Returns the scan_id and SSE stream URL immediately.
    """
    token = require_auth(request)

    scan_id = start_scan(
        token=token,
        repo_url=body.repo_url,
        base_branch=body.base_branch,
    )

    return JSONResponse(
        status_code=202,
        content={
            "scan_id": scan_id,
            "status": "accepted",
            "stream_url": f"/api/scan/{scan_id}/stream",
            "message": "Scan pipeline started",
        },
    )


@router.get("/scan/{scan_id}/stream")
async def scan_stream(scan_id: str, request: Request):
    """
    Server-Sent Events endpoint for real-time scan progress.
    Streams ScanEvent JSON objects as they arrive.

    Sends an initial 'connected' event so the client knows the stream is alive,
    then keepalives every 30s to prevent proxy timeouts. The stream always
    terminates once the scan reaches a terminal state — even for a client that
    connects (or reconnects) after the terminal event was already consumed, or
    after the queue was evicted — so it can never hang forever.
    """
    # Auth + ownership: EventSource sends the session cookie (withCredentials),
    # so we can bind the stream to its owner and avoid leaking another user's
    # scan output. Use 404 (not 403) so we don't confirm a scan_id exists.
    token = require_auth(request)
    owner = get_scan_owner(scan_id)
    if owner is None or owner != owner_id(token):
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    def _terminal_event():
        res = get_scan_result(scan_id)
        if res is not None and res.stage.value in ("completed", "failed"):
            return {"event": res.stage.value, "data": res.model_dump_json()}
        return None

    async def event_generator():
        try:
            # Send an immediate connection-confirmation event so the client
            # knows the stream is alive before any pipeline events arrive.
            yield {
                "event": "connected",
                "data": json.dumps({"scan_id": scan_id, "status": "stream_connected"}),
            }

            # Already finished (connected/reconnected late): replay the terminal
            # event once and stop instead of blocking on an idle queue forever.
            term = _terminal_event()
            if term is not None:
                yield term
                return

            while True:
                queue = get_scan_queue(scan_id)
                if queue is None:
                    # Queue was evicted after completion — emit terminal if any.
                    term = _terminal_event()
                    if term is not None:
                        yield term
                    logger.info("Scan %s queue removed, closing SSE", scan_id)
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30)
                    yield {
                        "event": event.stage.value,
                        "data": event.model_dump_json(),
                    }
                    # Stop streaming after terminal events
                    if event.stage.value in ("completed", "failed"):
                        break
                except asyncio.TimeoutError:
                    # A terminal result may have been stored while we waited.
                    term = _terminal_event()
                    if term is not None:
                        yield term
                        break
                    # Send keepalive to prevent proxy/browser timeout
                    yield {"event": "keepalive", "data": "{}"}
        except asyncio.CancelledError:
            logger.info("SSE stream cancelled for scan %s", scan_id)

    return EventSourceResponse(
        event_generator(),
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
        # Server-side keepalive comment every 15s so proxies don't drop the
        # idle SSE connection. (ping=0 would busy-loop with no delay.)
        ping=15,
    )


@router.get("/scan/{scan_id}")
async def get_scan(scan_id: str, request: Request):
    """Get the full result of a completed scan (owner only)."""
    token = require_auth(request)
    owner = get_scan_owner(scan_id)
    if owner is None or owner != owner_id(token):
        # 404 (not 403) so we don't confirm the scan_id exists to non-owners.
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    result = get_scan_result(scan_id)
    if result is None:
        # Owner entry exists but no result yet → still running.
        return JSONResponse({"scan_id": scan_id, "status": "running"})

    return JSONResponse(result.model_dump(mode="json"))


@router.get("/scans")
async def list_all_scans(request: Request):
    """List all scans for the current session (owner-scoped)."""
    token = require_auth(request)
    return JSONResponse(list_scans(owner=owner_id(token)))

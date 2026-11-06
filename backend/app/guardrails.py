"""
Guardrails for hosted deployments.

A public ANVIL instance clones and executes code from the repos it scans and
spends LLM credits on every scan, so admission is controlled at the API edge:

  * repo_owner_allowed — which repositories may be scanned at all
  * ScanLimiter        — per-user and global concurrency + rolling 24h quotas

State is in-process (the scan registry is too — see pipeline.py), which matches
the single-worker deployment model. All mutation happens on the event loop
thread, so no locking is needed.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Callable, Deque, Dict

from app.config import (
    MAX_ACTIVE_SCANS_PER_USER,
    MAX_CONCURRENT_SCANS,
    MAX_SCANS_PER_DAY,
    MAX_SCANS_PER_USER_PER_DAY,
)

_DAY_SECONDS = 24 * 3600


class ScanRejected(Exception):
    """A scan request refused by policy; maps directly onto an HTTP error."""

    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def repo_owner_allowed(repo_owner: str, user_login: str, allowed: list[str]) -> bool:
    """
    True if *repo_owner*'s repositories may be scanned by *user_login*.

    *allowed* entries are GitHub owners (matched case-insensitively, as GitHub
    does), plus two specials: "*" (any repository) and "@self" (repositories
    the user owns).
    """
    owner = (repo_owner or "").lower()
    allowed_l = {a.lower() for a in allowed}
    if "*" in allowed_l:
        return True
    if "@self" in allowed_l and owner == (user_login or "").lower():
        return True
    return owner in allowed_l


class ScanLimiter:
    """Concurrency + rolling-window quota admission control for scans."""

    def __init__(
        self,
        *,
        max_concurrent: int,
        max_active_per_user: int,
        per_user_per_day: int,
        per_day: int,
        clock: Callable[[], float] = time.time,
    ):
        self.max_concurrent = max_concurrent
        self.max_active_per_user = max_active_per_user
        self.per_user_per_day = per_user_per_day
        self.per_day = per_day
        self._clock = clock
        self._active: Dict[str, int] = defaultdict(int)
        self._user_history: Dict[str, Deque[float]] = defaultdict(deque)
        self._global_history: Deque[float] = deque()

    # ── helpers ──────────────────────────────────────────────────────────────
    def _prune(self, history: Deque[float], now: float) -> None:
        while history and history[0] <= now - _DAY_SECONDS:
            history.popleft()

    @property
    def active_total(self) -> int:
        return sum(self._active.values())

    # ── API ──────────────────────────────────────────────────────────────────
    def acquire(self, user_key: str) -> None:
        """Admit one scan for *user_key* or raise ScanRejected. Checks run
        before anything is recorded, so a rejection never consumes quota."""
        now = self._clock()
        user_hist = self._user_history[user_key]
        self._prune(user_hist, now)
        self._prune(self._global_history, now)

        if self._active[user_key] >= self.max_active_per_user:
            raise ScanRejected(
                429, "You already have a scan running — wait for it to finish before starting another."
            )
        if self.max_concurrent and self.active_total >= self.max_concurrent:
            raise ScanRejected(
                503, "The scanner is at capacity right now. Please try again in a few minutes."
            )
        if self.per_user_per_day and len(user_hist) >= self.per_user_per_day:
            raise ScanRejected(
                429, f"Daily limit reached ({self.per_user_per_day} scans per 24h). Please try again tomorrow."
            )
        if self.per_day and len(self._global_history) >= self.per_day:
            raise ScanRejected(
                503, "This demo has reached its daily scan budget. Please try again tomorrow."
            )

        self._active[user_key] += 1
        user_hist.append(now)
        self._global_history.append(now)

    def release(self, user_key: str) -> None:
        """Free *user_key*'s concurrency slot. Safe to call more than once."""
        if self._active.get(user_key, 0) > 0:
            self._active[user_key] -= 1
            if self._active[user_key] == 0:
                del self._active[user_key]


scan_limiter = ScanLimiter(
    max_concurrent=MAX_CONCURRENT_SCANS,
    max_active_per_user=MAX_ACTIVE_SCANS_PER_USER,
    per_user_per_day=MAX_SCANS_PER_USER_PER_DAY,
    per_day=MAX_SCANS_PER_DAY,
)

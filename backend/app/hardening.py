"""
Process-level hardening for the API server.

ANVIL executes code from the repositories it scans (to exploit them live and to
re-test patches). Those children get a scrubbed environment (see
app.sandbox.safe_subprocess_env), but on Linux any same-uid process can still
read the *server's* original environment from /proc/<pid>/environ — exactly
where a PaaS such as Render injects OPENAI_API_KEY, GITHUB_CLIENT_SECRET and
SESSION_SECRET.

Marking the server non-dumpable (prctl PR_SET_DUMPABLE=0) makes the kernel deny
unprivileged access to its /proc/<pid>/{environ,mem,maps,...} files and ptrace
attach. A process can always read its own /proc/self, so the server itself is
unaffected; children reset to dumpable on exec, which is fine.
"""

from __future__ import annotations

import logging
import sys

logger = logging.getLogger(__name__)

_PR_SET_DUMPABLE = 4


def harden_process() -> bool:
    """Apply OS hardening to the current process. Returns True if applied."""
    if not sys.platform.startswith("linux"):
        return False
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            logger.warning("prctl(PR_SET_DUMPABLE, 0) failed: errno %d", ctypes.get_errno())
            return False
        return True
    except Exception as exc:  # never block startup over hardening
        logger.warning("Process hardening unavailable: %s", exc)
        return False

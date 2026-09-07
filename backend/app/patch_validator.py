"""
Live patch validation — the "re-exploit-fails" gate.

Static analysis can only guess whether a fix is correct; it cannot tell that a
patch is *ineffective* (the exploit still works) or *broken* (the patched app no
longer starts — e.g. an import error a linter-style check would miss). This
module closes that gap by actually running the patched code:

    1. BASELINE  — launch an UNPATCHED copy of the repo and reproduce the
                   original exploit. If the app can't start here, or the exploit
                   doesn't reproduce, the gate is INCONCLUSIVE (caller falls back
                   to static validation — we never reject on a harness problem).
    2. PATCHED   — apply the fix to the copy and relaunch:
                     • app must still START (a patch that breaks startup → INVALID,
                       and we capture the startup error so the caller can feed it
                       back to the model for a corrected retry)
                     • a benign request must still work (no 5xx → functionality kept)
                     • the original exploit must now FAIL (vuln closed → VALID)

Only if the baseline reproduces AND the patched app is healthy AND the exploit no
longer succeeds is the patch accepted.

Isolation note: today the app + exploit run as host subprocesses. Everything that
touches the OS is funnelled through the small `_TargetApp` launcher and the
sandbox, so a stronger runtime (ephemeral, network-sealed container) can replace
them without changing the validation protocol.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import requests

from app.config import SANDBOX_TIMEOUT_SECONDS
from app.sandbox import execute_payload

logger = logging.getLogger(__name__)

_SUCCESS_MARKER = "EXPLOIT_SUCCESS"
_LAUNCHER_NAME = "__anvil_patchval_launcher__.py"

# Files/dirs never worth copying into the throwaway validation workspace.
_COPY_IGNORE = shutil.ignore_patterns(
    ".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build",
    "__anvil_launcher__.py", _LAUNCHER_NAME,
)


@dataclass
class PatchValidation:
    """Outcome of the live gate.

    applicable — could we actually run the gate (launchable HTTP app + exploit)?
    valid      — True: patch is good; False: patch is bad; None: not applicable.
    reason     — human-readable justification (includes the startup error when a
                 patched app fails to boot, so it can drive a corrected retry).
    """
    applicable: bool
    valid: Optional[bool]
    reason: str


# ── Target-app launcher (self-contained; captures startup stderr) ─────────────

def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _patch_entry_source(source: str, port: int) -> str:
    """Force debug off, bind loopback, and pin the listen port (same rules the
    exploiter uses to launch a target app)."""
    patched = re.sub(r"debug\s*=\s*True", "debug=False", source)
    patched = re.sub(r"host\s*=\s*['\"]0\.0\.0\.0['\"]", "host='127.0.0.1'", patched)

    def _fix_run(match: "re.Match") -> str:
        call = match.group(0)
        if re.search(r"port\s*=\s*\d+", call):
            return re.sub(r"port\s*=\s*\d+", f"port={port}", call)
        return re.sub(r"\.run\(", f".run(port={port}, ", call, count=1)

    return re.sub(r"\.run\([^)]*\)", _fix_run, patched)


class _TargetApp:
    """A launched target-app subprocess with captured startup output."""

    def __init__(self, proc, port, launcher_path, log_file, log_path):
        self.proc = proc
        self.port = port
        self._launcher_path = launcher_path
        self._log_file = log_file
        self._log_path = log_path

    def wait_up(self, timeout: int) -> bool:
        """Return True once the port accepts a connection; False if the process
        exits first (broken app) or the timeout elapses."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return False  # process already exited — it will never come up
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=1):
                    return True
            except OSError:
                time.sleep(0.3)
        return False

    def startup_error(self) -> str:
        """Tail of the app's stderr — the real reason a broken patch failed."""
        try:
            self._log_file.flush()
        except Exception:
            pass
        try:
            text = Path(self._log_path).read_text(encoding="utf-8", errors="replace")
        except Exception:
            return ""
        # Prefer the last exception line (e.g. "ImportError: cannot import ...").
        lines = [ln for ln in text.splitlines() if ln.strip()]
        tail = "\n".join(lines[-6:])
        return tail[-600:].strip()

    def stop(self) -> None:
        try:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=3)
        except Exception:
            pass
        try:
            self._log_file.close()
        except Exception:
            pass
        for path in (self._launcher_path, self._log_path):
            try:
                os.remove(path)
            except OSError:
                pass


def _launch(repo_dir: str, entry_point: str, port: int) -> Optional[_TargetApp]:
    """Start the (possibly patched) app on *port*; None if it can't be launched
    at all (missing entry / spawn error). stderr is captured to a file so a
    crashing app can never deadlock on a full pipe."""
    entry_path = os.path.join(repo_dir, entry_point)
    if not os.path.isfile(entry_path):
        return None
    source = Path(entry_path).read_text(encoding="utf-8", errors="replace")
    launcher_path = os.path.join(repo_dir, _LAUNCHER_NAME)
    Path(launcher_path).write_text(_patch_entry_source(source, port), encoding="utf-8")
    log_path = launcher_path + ".log"
    log_file = open(log_path, "wb")
    try:
        proc = subprocess.Popen(
            [sys.executable, launcher_path],
            stdout=subprocess.DEVNULL,
            stderr=log_file,
            cwd=repo_dir,
        )
    except Exception as exc:
        logger.warning("Failed to spawn target app for validation: %s", exc)
        log_file.close()
        for path in (launcher_path, log_path):
            try:
                os.remove(path)
            except OSError:
                pass
        return None
    return _TargetApp(proc, port, launcher_path, log_file, log_path)


# ── Exploit helpers ───────────────────────────────────────────────────────────

def _looks_like_http_exploit(code: str) -> bool:
    """True if *code* is an HTTP exploit we can re-target at a fresh port."""
    if not code:
        return False
    uses_http_client = ("requests" in code) or ("urllib" in code)
    has_local_target = re.search(r"(127\.0\.0\.1|localhost):\d+|http://", code) is not None
    return uses_http_client and has_local_target


def _retarget(code: str, port: int) -> str:
    """Point every 127.0.0.1:<port>/localhost:<port> in *code* at *port*."""
    return re.sub(r"(127\.0\.0\.1|localhost):\d+", f"127.0.0.1:{port}", code)


def _exploit_succeeds(port: int, exploit_code: str) -> bool:
    """Run *exploit_code* (re-targeted to *port*) in the sandbox; True if the
    success marker is present."""
    _ok, stdout, _stderr = execute_payload(_retarget(exploit_code, port), timeout=SANDBOX_TIMEOUT_SECONDS)
    return _SUCCESS_MARKER in stdout


# ── Container-based gate (preferred when Docker is available) ─────────────────

def _validate_via_container(*, repo_dir, target_file, fixed_code, exploit_code, entry_point) -> PatchValidation:
    """Run the baseline→patched re-exploit protocol inside sealed containers.

    Returns applicable=False (inconclusive) when the container can't reproduce
    the baseline, so the caller falls back to the host path — we never reject a
    patch on a harness/environment problem.
    """
    from app.container_runtime import run_app_and_exploit_sealed

    tmp_root = Path(tempfile.mkdtemp(prefix="anvil_patchval_c_"))
    repo_copy = tmp_root / "repo"
    try:
        shutil.copytree(repo_dir, repo_copy, ignore=_COPY_IGNORE, dirs_exist_ok=True)
        target_path = repo_copy / target_file
        if not target_path.exists():
            return PatchValidation(False, None, f"Target file '{target_file}' not present in the workspace copy.")

        # BASELINE: the exploit must reproduce against the UNPATCHED copy.
        base = run_app_and_exploit_sealed(
            repo_dir=str(repo_copy), entry_point=entry_point, exploit_code=exploit_code)
        if not base.available:
            return PatchValidation(False, None, "Container isolation unavailable — host fallback.")
        if not base.app_started:
            return PatchValidation(False, None, "Baseline app did not start in the container — inconclusive (host fallback).")
        if not base.exploit_succeeded:
            return PatchValidation(False, None, "Baseline exploit did not reproduce in the container — inconclusive (host fallback).")

        # PATCHED: apply the fix and re-test in a fresh sealed container.
        target_path.write_text(fixed_code, encoding="utf-8")
        patched = run_app_and_exploit_sealed(
            repo_dir=str(repo_copy), entry_point=entry_point, exploit_code=exploit_code)
        if not patched.available:
            return PatchValidation(False, None, "Container isolation unavailable — host fallback.")
        if not patched.app_started:
            detail = f" Startup error: {patched.error}" if patched.error else ""
            return PatchValidation(
                True, False,
                f"[sealed container] Patched app failed to start — the patch breaks the application.{detail}")
        if patched.exploit_succeeded:
            return PatchValidation(
                True, False,
                "[sealed container] Exploit STILL succeeds against the patched app — the fix is ineffective.")
        return PatchValidation(
            True, True,
            "[sealed container] Patch validated: app starts and the original exploit no longer succeeds (network-isolated).")
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


# ── The gate ──────────────────────────────────────────────────────────────────

def validate_patch_by_reexploit(
    *,
    repo_dir: str,
    target_file: str,
    fixed_code: str,
    exploit_code: str,
    benign_path: str = "/",
    startup_timeout: int = 12,
    prefer_container: bool = True,
) -> PatchValidation:
    """Validate *fixed_code* for *target_file* by re-running *exploit_code*.

    Follows the baseline→patched protocol in the module docstring. Runs the
    app+exploit inside a sealed Docker container when one is available
    (prefer_container, the default), falling back to host subprocesses when it
    isn't. Never raises for an expected condition — returns a PatchValidation.
    """
    from app.github_service import detect_entry_point

    entry_point = detect_entry_point(repo_dir)
    if not entry_point:
        return PatchValidation(False, None, "No launchable entry point — live re-exploit gate not applicable.")
    if not _looks_like_http_exploit(exploit_code):
        return PatchValidation(False, None, "Original exploit is not an HTTP exploit — live re-exploit gate not applicable.")

    # Prefer sealed-container isolation when Docker can actually run one; a
    # definitive verdict is returned, otherwise we fall through to the host path.
    if prefer_container:
        try:
            from app.container_runtime import container_isolation_available
            if container_isolation_available():
                cres = _validate_via_container(
                    repo_dir=repo_dir, target_file=target_file,
                    fixed_code=fixed_code, exploit_code=exploit_code, entry_point=entry_point,
                )
                if cres.applicable:
                    return cres
                logger.info("Container gate inconclusive (%s); falling back to host.", cres.reason)
        except Exception as exc:
            logger.warning("Container gate errored (%s); falling back to host.", exc, exc_info=True)

    tmp_root = Path(tempfile.mkdtemp(prefix="anvil_patchval_"))
    repo_copy = tmp_root / "repo"
    try:
        shutil.copytree(repo_dir, repo_copy, ignore=_COPY_IGNORE, dirs_exist_ok=True)
        target_path = repo_copy / target_file
        if not target_path.exists():
            return PatchValidation(False, None, f"Target file '{target_file}' not present in the workspace copy.")

        # ── 1. BASELINE: reproduce the exploit against the UNPATCHED copy ──────
        app = _launch(str(repo_copy), entry_point, _find_free_port())
        if app is None:
            return PatchValidation(False, None, "Baseline app could not be launched — live gate not applicable (static fallback).")
        try:
            if not app.wait_up(startup_timeout):
                return PatchValidation(
                    False, None,
                    "Baseline app did not start in this environment — live gate inconclusive (static fallback).",
                )
            if not _exploit_succeeds(app.port, exploit_code):
                return PatchValidation(
                    False, None,
                    "Baseline exploit did not reproduce here — live gate inconclusive (static fallback).",
                )
        finally:
            app.stop()

        # ── 2. PATCHED: apply the fix and re-test ─────────────────────────────
        target_path.write_text(fixed_code, encoding="utf-8")

        app = _launch(str(repo_copy), entry_point, _find_free_port())
        if app is None:
            return PatchValidation(True, False, "Patched app could not be launched — the patch breaks the application.")
        try:
            if not app.wait_up(startup_timeout):
                # The unpatched app started moments ago, so this is the patch's
                # fault. Surface the real startup error for a corrected retry.
                err = app.startup_error()
                detail = f" Startup error: {err}" if err else ""
                return PatchValidation(
                    True, False,
                    f"Patched app failed to start — the patch breaks the application.{detail}",
                )

            # Functionality preserved: a benign request must not 5xx.
            try:
                resp = requests.get(f"http://127.0.0.1:{app.port}{benign_path}", timeout=5)
                if resp.status_code >= 500:
                    return PatchValidation(
                        True, False,
                        f"Patched app returns {resp.status_code} on a benign request — functionality broken.",
                    )
            except requests.RequestException as exc:
                return PatchValidation(
                    True, False,
                    f"Patched app is unreachable on a benign request: {exc}",
                )

            # Vulnerability closed?
            if _exploit_succeeds(app.port, exploit_code):
                return PatchValidation(
                    True, False,
                    "Exploit STILL succeeds against the patched app — the fix is ineffective.",
                )

            return PatchValidation(
                True, True,
                "Patch validated live: app starts, serves benign requests, and the original exploit no longer succeeds.",
            )
        finally:
            app.stop()
    except Exception as exc:  # infrastructure failure — never reject on our own bug
        logger.warning("Live patch gate errored (%s); falling back to static validation.", exc, exc_info=True)
        return PatchValidation(False, None, f"Live gate error (static fallback): {exc}")
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

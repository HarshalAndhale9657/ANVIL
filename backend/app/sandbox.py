"""
AST-Validated Subprocess Sandbox — Fail-Closed execution layer.

Replaces Docker with a native Python subprocess that is protected by:
1. AST filtering — blocks dangerous imports/calls before execution.
2. Stripped environment — payload cannot read host env vars.
3. Hard timeout — prevents infinite loops from locking the system.
4. Signature hashing — prevents the exact same failed call from retrying.

If ANY validation step fails, the sandbox refuses to execute (fail-closed).
"""

from __future__ import annotations

import ast
import hashlib
import logging
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, Optional, Set, Tuple

from app.config import SANDBOX_TIMEOUT_SECONDS

logger = logging.getLogger(__name__)

# ── Blocked constructs ───────────────────────────────────────────────────────

_BLOCKED_MODULES: Set[str] = {
    "shutil", "ctypes", "multiprocessing", "signal",
    "importlib", "code", "codeop", "compileall",
    "pty", "resource", "readline",
    "socket", "threading",
}

_BLOCKED_FUNCTIONS: Set[str] = {
    "os.remove", "os.unlink", "os.rmdir", "os.removedirs",
    "os.rename", "os.renames", "os.replace",
    "os.system", "os.popen", "os.exec", "os.execl",
    "os.execle", "os.execlp", "os.execlpe", "os.execv",
    "os.execve", "os.execvp", "os.execvpe", "os.fork",
    "subprocess.Popen", "subprocess.call", "subprocess.run",
    "eval", "exec", "__import__", "compile",
    "shutil.rmtree", "shutil.move",
    "pickle.loads", "pickle.load",
    "importlib.import_module",
    "ctypes.cdll",
}

# ── Signature-hash dedup (circuit breaker) ───────────────────────────────────

_seen_hashes: Dict[str, int] = {}


def _signature_hash(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def reset_circuit_breaker() -> None:
    """
    Clear the per-scan signature dedup counter.

    Called at the start of every scan (CPN ingress) so the breaker is scoped
    to a single scan: identical payloads from *previous* scans never trip it,
    and the dict cannot grow without bound across the process lifetime.
    """
    _seen_hashes.clear()


# ── AST validation ───────────────────────────────────────────────────────────

class _DangerousNodeVisitor(ast.NodeVisitor):
    """Walk the AST and raise ValueError on any blocked construct."""

    def __init__(self) -> None:
        self.violations: list[str] = []

    def visit_Import(self, node: ast.Import) -> None:
        """Block dangerous module imports."""
        for alias in node.names:
            top_module = alias.name.split(".")[0]
            if top_module in _BLOCKED_MODULES:
                self.violations.append(f"Blocked import: {alias.name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Block dangerous from-imports including submodules."""
        if node.module:
            top_module = node.module.split(".")[0]
            if top_module in _BLOCKED_MODULES:
                self.violations.append(f"Blocked import-from: {node.module}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Block dangerous function calls and open() in write mode."""
        func_name = _resolve_call_name(node)
        if func_name and func_name in _BLOCKED_FUNCTIONS:
            self.violations.append(f"Blocked call: {func_name}")
        # Block open() in write/append/create modes
        if func_name == "open" and len(node.args) > 1:
            mode_arg = node.args[1]
            if isinstance(mode_arg, ast.Constant) and isinstance(mode_arg.value, str):
                if any(m in mode_arg.value for m in ("w", "a", "x", "+")):
                    self.violations.append(
                        f"Blocked write-mode open() at line {node.lineno}"
                    )
        # Also block open() with mode keyword arg in write mode
        if func_name == "open":
            for keyword in node.keywords:
                if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
                    if isinstance(keyword.value.value, str) and any(
                        m in keyword.value.value for m in ("w", "a", "x", "+")
                    ):
                        self.violations.append(
                            f"Blocked write-mode open() at line {node.lineno}"
                        )
        self.generic_visit(node)


def _resolve_call_name(node: ast.Call) -> Optional[str]:
    """Best-effort resolution of a Call node to a dotted name."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        parts = []
        current = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def validate_code(code: str) -> Tuple[bool, str]:
    """
    Parse and AST-validate *code*. Returns (ok, message).
    If ok is False, the code MUST NOT be executed.
    """
    # Step 1: syntax check
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return False, f"SyntaxError: {exc}"

    # Step 2: dangerous-node check
    visitor = _DangerousNodeVisitor()
    visitor.visit(tree)
    if visitor.violations:
        return False, "Blocked constructs: " + "; ".join(visitor.violations)

    return True, "OK"


# ── Execution ────────────────────────────────────────────────────────────────

def execute_payload(
    code: str,
    *,
    timeout: int = SANDBOX_TIMEOUT_SECONDS,
    max_retries: int = 3,
) -> Tuple[bool, str, str]:
    """
    Execute *code* in a restricted subprocess.

    Returns (success, stdout, stderr).
    Fail-closed: any validation failure → (False, "", error_msg).
    """
    # ── Circuit breaker: signature dedup (counts FAILED runs only) ────────
    # The counter is bumped only when a run actually fails (see below), so a
    # payload is blocked once it has failed `max_retries` times — never merely
    # because it was *attempted* that many times. This lets a scan's final
    # (and possibly first-successful) retry actually run.
    sig = _signature_hash(code)
    if _seen_hashes.get(sig, 0) >= max_retries:
        msg = f"Circuit breaker: payload hash {sig[:12]}… failed {_seen_hashes[sig]} times. Blocked."
        logger.warning(msg)
        return False, "", msg

    def _record_failure() -> None:
        _seen_hashes[sig] = _seen_hashes.get(sig, 0) + 1

    # ── AST validation ───────────────────────────────────────────────────
    ok, reason = validate_code(code)
    if not ok:
        logger.warning("Sandbox rejected payload: %s", reason)
        _record_failure()
        return False, "", reason

    # ── Write to an isolated temp dir & execute ──────────────────────────
    # A dedicated per-execution directory (not the server CWD) prevents temp
    # files from polluting the working directory and keeps concurrent scans
    # from colliding on relative paths.
    tmp_dir = Path(tempfile.mkdtemp(prefix="anvil_sbx_"))
    tmp_path = tmp_dir / "payload.py"
    tmp_path.write_text(code, encoding="utf-8")

    try:
        # Build a safe environment with a fail-closed ALLOWLIST: only the
        # variables Python startup, TLS/DNS, and HTTP egress legitimately need
        # are forwarded. Every other variable — including any current-or-future
        # secret — is dropped by default rather than relying on a denylist that
        # silently leaks anything not explicitly named.
        import os as _os

        _ALLOWED_VARS = {
            # Windows OS essentials
            "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC",
            "TEMP", "TMP", "HOMEDRIVE", "HOMEPATH", "USERPROFILE",
            "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "NUMBER_OF_PROCESSORS",
            "PROCESSOR_ARCHITECTURE",
            # POSIX OS essentials (if run on Linux/Docker)
            "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
            # Python resolution
            "PYTHONHOME", "PYTHONPATH", "PYTHONIOENCODING", "PYTHONUTF8",
            # TLS / CA bundles (so requests HTTPS works)
            "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
            # Proxy (if the operator routes egress through a proxy)
            "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
            "HTTP_PROXY".lower(), "HTTPS_PROXY".lower(), "NO_PROXY".lower(),
        }
        _allowed_upper = {v.upper() for v in _ALLOWED_VARS}
        # Match case-insensitively (Windows env keys vary in case) while
        # preserving the original key name and value.
        safe_env = {
            k: v for k, v in _os.environ.items() if k.upper() in _allowed_upper
        }

        result = subprocess.run(
            [sys.executable, str(tmp_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=safe_env,
            cwd=str(tmp_dir),
        )
        success = result.returncode == 0
        if success:
            _seen_hashes.pop(sig, None)
        else:
            _record_failure()
        return (success, result.stdout, result.stderr)
    except subprocess.TimeoutExpired:
        msg = f"Sandbox timeout after {timeout}s"
        logger.warning(msg)
        _record_failure()
        return False, "", msg
    except Exception as exc:
        _record_failure()
        return False, "", f"Sandbox error: {exc}"
    finally:
        # Best-effort cleanup. On Windows a just-killed child may still hold a
        # lock on the temp file for a moment; swallow the resulting error so it
        # never masks the real return value.
        try:
            import shutil as _shutil
            _shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass

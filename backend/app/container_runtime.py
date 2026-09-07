"""
Docker-based sealed isolation runtime.

Runs an untrusted target app together with its exploit inside ONE ephemeral,
network-sealed container:

    docker run --rm --network none --memory 512m --pids-limit 256 --cpus 2 ...

`--network none` still provides loopback, so the exploit can hit the app over
127.0.0.1, but there is no internet egress and no host-network access; the
container is ephemeral, resource-capped, and (via the base image) runs as a
non-root user. This is the hardened alternative to launching the app + exploit
as host subprocesses.

Flow:
  * the host copies the repo + the (port-retargeted) exploit + an in-container
    runner into a throwaway workspace and bind-mounts it read-only-ish at /work;
  * the runner (inside the container) copies the repo to a container-local dir
    (so it can write regardless of bind-mount perms), patches the app entry to a
    fixed loopback port, starts it, waits for it, runs the exploit against it,
    and prints machine-readable markers the host parses.

Availability is gated by a real self-check (`docker run` a trivial sealed
container must succeed); when Docker isn't usable, callers fall back to the host
runtime. Nothing here executes unless that self-check passes.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Base image built by ANVIL (python:3.12-slim + flask + requests + non-root user).
BASE_IMAGE = os.getenv("ANVIL_SANDBOX_IMAGE", "anvil-sandbox:latest")
_APP_PORT = 9100

_COPY_IGNORE = shutil.ignore_patterns(
    ".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build",
    "__anvil_launcher__.py", "__anvil_patchval_launcher__.py", "__anvil_c_launcher__.py",
)

# In-container runner. Stdlib only; runs under the sandbox user in the sealed container.
_RUNNER_SCRIPT = r'''
import os, re, shutil, socket, subprocess, sys, time

ENTRY = sys.argv[1]
PORT = int(sys.argv[2])
SRC_REPO = "/work/repo"
WORK_REPO = "/tmp/repo"

# Copy the bind-mounted repo into a container-local, writable dir (bind mounts
# may not be writable by the non-root sandbox user).
shutil.copytree(SRC_REPO, WORK_REPO, dirs_exist_ok=True)

entry_path = os.path.join(WORK_REPO, ENTRY)
src = open(entry_path, "r", encoding="utf-8", errors="replace").read()
src = re.sub(r"debug\s*=\s*True", "debug=False", src)
src = re.sub(r"host\s*=\s*['\"]0\.0\.0\.0['\"]", "host='127.0.0.1'", src)
def _fixrun(m):
    c = m.group(0)
    if re.search(r"port\s*=\s*\d+", c):
        return re.sub(r"port\s*=\s*\d+", "port=%d" % PORT, c)
    return re.sub(r"\.run\(", ".run(port=%d, " % PORT, c, count=1)
src = re.sub(r"\.run\([^)]*\)", _fixrun, src)
launcher = os.path.join(WORK_REPO, "__anvil_c_launcher__.py")
open(launcher, "w", encoding="utf-8").write(src)

errlog = "/tmp/app_stderr.log"
proc = subprocess.Popen([sys.executable, launcher], cwd=WORK_REPO,
                        stdout=subprocess.DEVNULL, stderr=open(errlog, "wb"))

up = False
deadline = time.time() + 15
while time.time() < deadline:
    if proc.poll() is not None:
        break
    try:
        with socket.create_connection(("127.0.0.1", PORT), timeout=1):
            up = True
            break
    except OSError:
        time.sleep(0.3)

if not up:
    try:
        err = open(errlog, "r", encoding="utf-8", errors="replace").read()[-800:]
    except Exception:
        err = ""
    print("__ANVIL_APP_FAILED__")
    print(err)
    sys.exit(0)

print("__ANVIL_APP_STARTED__")
sys.stdout.flush()

try:
    r = subprocess.run([sys.executable, "/work/exploit.py"], cwd="/tmp",
                       capture_output=True, text=True, timeout=30)
    print("__ANVIL_EXPLOIT_STDOUT__")
    print(r.stdout)
    if r.stderr:
        print("__ANVIL_EXPLOIT_STDERR__")
        print(r.stderr[-500:])
finally:
    try:
        proc.terminate()
    except Exception:
        pass
'''


@dataclass
class SealedResult:
    available: bool               # could we run the sealed container at all?
    app_started: bool = False     # did the target app come up inside the container?
    exploit_succeeded: bool = False  # did the exploit print EXPLOIT_SUCCESS?
    stdout: str = ""              # full container stdout (markers + exploit output)
    error: str = ""               # failure/inapplicable reason (incl. app startup error)


# ── Docker discovery + availability ───────────────────────────────────────────

def find_docker() -> Optional[str]:
    """Locate the docker CLI: PATH first, then Docker Desktop's per-user/system paths.

    On Windows we must return an explicit `.exe` — subprocess cannot execute an
    extension-less absolute path, and shutil.which can return one (Docker Desktop
    ships an extension-less `docker` shim alongside `docker.exe`)."""
    names = ("docker.exe", "docker") if os.name == "nt" else ("docker",)
    for name in names:
        p = shutil.which(name)
        if p:
            if os.name == "nt" and not p.lower().endswith(".exe") and os.path.isfile(p + ".exe"):
                return p + ".exe"
            return p
    candidates = [
        os.path.join(os.path.expanduser("~"), "AppData", "Local", "Programs",
                     "DockerDesktop", "resources", "bin", "docker.exe"),
        r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
        "/usr/bin/docker", "/usr/local/bin/docker",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def _image_present(docker: str, image: str) -> bool:
    try:
        r = subprocess.run([docker, "images", "-q", image],
                           capture_output=True, text=True, timeout=15)
        return r.returncode == 0 and bool(r.stdout.strip())
    except Exception:
        return False


_avail_cache: Optional[bool] = None


def container_isolation_available(image: str = BASE_IMAGE, *, force: bool = False) -> bool:
    """True iff we can actually run a sealed container: docker present, base image
    present, and a trivial `docker run --network none <image> true` succeeds.
    Cached (the daemon state is stable within a run); pass force=True to re-probe."""
    global _avail_cache
    if _avail_cache is not None and not force:
        return _avail_cache
    ok = False
    docker = find_docker()
    if docker and _image_present(docker, image):
        try:
            r = subprocess.run([docker, "run", "--rm", "--network", "none", image, "true"],
                               capture_output=True, timeout=45)
            ok = (r.returncode == 0)
        except Exception as exc:
            logger.info("container self-check failed: %s", exc)
            ok = False
    _avail_cache = ok
    return ok


# ── Sealed run ─────────────────────────────────────────────────────────────────

def _retarget(code: str, port: int) -> str:
    return re.sub(r"(127\.0\.0\.1|localhost):\d+", f"127.0.0.1:{port}", code)


def run_app_and_exploit_sealed(
    *,
    repo_dir: str,
    entry_point: str,
    exploit_code: str,
    image: str = BASE_IMAGE,
    app_port: int = _APP_PORT,
    run_timeout: int = 90,
) -> SealedResult:
    """Run *entry_point* (the target app) and *exploit_code* together in a sealed
    container. Returns a SealedResult; available=False means the caller should
    fall back to the host runtime (Docker not usable / base image missing)."""
    docker = find_docker()
    if not docker:
        return SealedResult(available=False, error="docker CLI not found")
    if not _image_present(docker, image):
        return SealedResult(available=False, error=f"base image '{image}' not present")

    ws = Path(tempfile.mkdtemp(prefix="anvil_cwork_"))
    try:
        shutil.copytree(repo_dir, ws / "repo", ignore=_COPY_IGNORE, dirs_exist_ok=True)
        (ws / "exploit.py").write_text(_retarget(exploit_code, app_port), encoding="utf-8")
        (ws / "runner.py").write_text(_RUNNER_SCRIPT, encoding="utf-8")

        mount = str(ws).replace("\\", "/")
        argv = [
            docker, "run", "--rm",
            "--network", "none",
            "--memory", "512m", "--pids-limit", "256", "--cpus", "2",
            "-v", f"{mount}:/work",
            image, "python", "/work/runner.py", entry_point, str(app_port),
        ]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=run_timeout)
        except subprocess.TimeoutExpired:
            return SealedResult(available=True, error=f"sealed container timed out after {run_timeout}s")

        out = proc.stdout or ""
        app_started = "__ANVIL_APP_STARTED__" in out
        exploit_out = out.split("__ANVIL_EXPLOIT_STDOUT__", 1)[1] if "__ANVIL_EXPLOIT_STDOUT__" in out else ""
        exploit_succeeded = "EXPLOIT_SUCCESS" in exploit_out
        error = ""
        if not app_started and "__ANVIL_APP_FAILED__" in out:
            error = out.split("__ANVIL_APP_FAILED__", 1)[1][:800].strip()
        elif not app_started:
            error = (proc.stderr or out or "unknown container failure")[-800:]
        return SealedResult(
            available=True, app_started=app_started,
            exploit_succeeded=exploit_succeeded, stdout=out, error=error,
        )
    finally:
        shutil.rmtree(ws, ignore_errors=True)

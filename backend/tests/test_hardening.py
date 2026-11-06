"""
Process hardening: the server's own environment (where a PaaS injects the
OpenAI key / OAuth secret / session secret) must not be readable by the
untrusted processes it spawns via /proc/<server-pid>/environ.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parent.parent


def test_harden_process_is_safe_to_call_everywhere():
    from app.hardening import harden_process

    # Returns True on Linux (applied), False elsewhere — never raises.
    assert harden_process() in (True, False)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux /proc semantics")
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0,
                    reason="root has CAP_SYS_PTRACE and can read any environ")
def test_child_cannot_read_server_environ():
    server = textwrap.dedent("""
        import subprocess, sys
        from app.hardening import harden_process
        assert harden_process() is True
        child = (
            "import os\\n"
            "try:\\n"
            "    open(f'/proc/{os.getppid()}/environ','rb').read(); print('READABLE')\\n"
            "except PermissionError:\\n"
            "    print('BLOCKED')\\n"
        )
        print(subprocess.run([sys.executable, '-c', child], capture_output=True, text=True).stdout.strip())
    """)
    r = subprocess.run(
        [sys.executable, "-c", server],
        capture_output=True, text=True, cwd=BACKEND,
        env={**os.environ, "OPENAI_API_KEY": "sk-should-stay-private"},
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "BLOCKED"

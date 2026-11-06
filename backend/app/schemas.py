"""
Strict Pydantic v2 data contracts for deterministic inter-agent handoffs.

Every agent input/output is typed here. LLMs are forced to return
structured JSON matching these schemas — no free-form text passes
between agents.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ── Webhook Ingress ──────────────────────────────────────────────────────────

class WebhookPayload(BaseModel):
    """Incoming deployment webhook validated at the FastAPI edge."""
    target_url: str = Field(..., description="URL of the deployed staging service")
    deployment_id: str = Field(..., description="Unique deployment identifier")
    repo_url: Optional[str] = Field(None, description="Git clone URL of the target repo")
    auth_signature: Optional[str] = Field(None, description="HMAC signature for payload integrity")
    # Web-app pipeline additions (populated by pipeline.py, not from external webhooks)
    repo_name: Optional[str] = Field(None, description="'owner/repo' short name, e.g. 'DevOpsDreamer/ANVIL'")
    # exclude=True: never serialised (state is checkpointed to SQLite after every
    # CPN transition; a token on disk is readable by the scanned repo's code).
    github_token: Optional[str] = Field(
        None, exclude=True, repr=False, description="OAuth token used for cloning and PR creation"
    )
    base_branch: str = Field("main", description="Branch to scan and base the fix PR against")


# ── Agent 1: Reconnaissance ──────────────────────────────────────────────────

class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class VulnerableEndpoint(BaseModel):
    """A single discovered vulnerability in the target."""
    model_config = ConfigDict(extra="ignore")

    path: str = Field(..., description="URL path or file:line of the vulnerable endpoint")
    method: HttpMethod = Field(..., description="HTTP method to trigger the vulnerability")
    injection_vector: str = Field(..., description="Description of the injection vector")
    vulnerability_type: Optional[str] = Field(
        None,
        description="Category: path_traversal, sqli, cmdi, ssti, idor, xxe, deserialize, xss, ssrf",
    )
    severity: Optional[str] = Field(
        None,
        description="Severity level: critical, high, medium, low",
    )
    confidence: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="Confidence score 0.0-1.0",
    )
    taint_path: Optional[str] = Field(
        None,
        description="Source param -> ... -> sink call taint path",
    )
    code_snippet: Optional[str] = Field(
        None, description="Exact vulnerable lines of code",
    )


class ReconOutput(BaseModel):
    """Strict output contract for the Reconnaissance agent."""
    model_config = ConfigDict(extra="ignore")

    target_url: str = Field(..., description="Base URL of the scanned target")
    detected_framework: str = Field(..., description="Detected web framework or server")
    vulnerable_endpoints: List[VulnerableEndpoint] = Field(
        ..., description="Catalogued attack surface without raw HTTP responses"
    )


# ── Agent 2: Exploitation ────────────────────────────────────────────────────

class ExploitOutput(BaseModel):
    """Strict output contract for the Exploiter agent."""
    model_config = ConfigDict(extra="ignore")

    vulnerability_confirmed: bool = Field(
        ..., description="Whether the vulnerability was actively confirmed"
    )
    exploit_payload_used: str = Field(
        ..., description="Exact Python exploit code that was executed"
    )
    sandbox_stdout: str = Field(
        ..., description="Raw stdout captured from the sandbox execution"
    )
    exploit_evidence: Optional[str] = Field(
        None, description="Evidence of successful exploitation extracted from stdout"
    )
    expected_proof_pattern: Optional[str] = Field(
        None, description="The pattern the Verifier should check for in stdout"
    )
    exploit_type: Optional[str] = Field(
        None, description="Category of exploit used (path_traversal, sqli, etc.)"
    )
    attempt_number: int = Field(
        1, description="Which attempt this is (1-indexed)"
    )


# ── Agent 3: Patching ────────────────────────────────────────────────────────

class PatchOutput(BaseModel):
    """Strict output contract for the Patcher agent."""
    model_config = ConfigDict(extra="ignore")

    file_modified: str = Field(..., description="Relative path to the patched file")
    unified_diff: str = Field(..., description="Unified diff of the applied fix")
    pull_request_title: str = Field(..., description="Title for the generated PR/commit")
    pull_request_body: str = Field(
        ..., description="Body describing the vulnerability and the fix"
    )
    confidence_score: float = Field(
        ..., ge=0.0, le=1.0, description="Model confidence in the patch correctness"
    )
    pr_url: Optional[str] = Field(
        None, description="URL of the created GitHub Pull Request"
    )
    commit_hash: Optional[str] = Field(
        None, description="Git commit hash of the fix"
    )
    tests_passed: Optional[bool] = Field(
        None, description="Whether the target app's tests passed after patching"
    )


# ── Verifier ─────────────────────────────────────────────────────────────────

class VerificationResult(BaseModel):
    """Output of the deterministic Verifier node."""
    model_config = ConfigDict(extra="ignore")

    verified: bool = Field(
        ..., description="True only if the sandbox stdout cryptographically proves exploitation"
    )
    reason: str = Field(..., description="Human-readable justification")
    expected_pattern: Optional[str] = Field(
        None, description="The pattern or hash the Verifier was checking for"
    )
    actual_value: Optional[str] = Field(
        None, description="The actual value found in stdout"
    )
    failure_category: Optional[str] = Field(
        None,
        description="Category of failure: timeout | wrong_output | exception | no_marker | no_evidence",
    )


# ── Master State (CPN Token) ────────────────────────────────────────────────

class AttemptRecord(BaseModel):
    """Record of a single exploit attempt for feedback-aware retries."""
    attempt_number: int
    exploit_code: str
    sandbox_stdout: str
    failure_reason: str


class MasterState(BaseModel):
    """The coloured token that flows through the Petri net."""
    trace_id: str
    task_id: str
    current_node: str = "ingress"
    retry_count: int = 0
    webhook: Optional[WebhookPayload] = None
    recon: Optional[ReconOutput] = None
    exploit: Optional[ExploitOutput] = None
    verification: Optional[VerificationResult] = None
    patch: Optional[PatchOutput] = None
    error: Optional[str] = None
    completed: bool = False
    # Exploit retry feedback
    attempt_history: List[AttemptRecord] = Field(
        default_factory=list,
        description="History of failed exploit attempts for feedback-aware retries",
    )
    # Web-app additions
    repo_url: Optional[str] = None
    repo_dir: Optional[str] = None
    # In-memory only — excluded from model_dump()/JSON so checkpoints and logs
    # never contain the user's GitHub token.
    github_token: Optional[str] = Field(None, exclude=True, repr=False)
    base_branch: str = "main"


# ── Web App Schemas ──────────────────────────────────────────────────────────

# GitHub owner: 1-39 alnum/hyphen. Repo: 1-100 of alnum . _ -  (no "..").
_REPO_URL_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/"
    r"(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/"
    r"(?P<repo>[A-Za-z0-9._-]{1,100}?)(?:\.git)?/?$"
)
# Conservative git ref name: path-like segments of safe characters.
_BRANCH_RE = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$")


class ScanRequest(BaseModel):
    """Request body for POST /api/scan. Validated at the edge so malformed
    input is a 422 here, not a failure halfway through a scan."""
    repo_url: str = Field(..., description="GitHub repo URL, e.g. https://github.com/user/repo")
    base_branch: str = Field("main", description="Branch to scan and base the fix PR against")

    @field_validator("repo_url")
    @classmethod
    def _normalise_repo_url(cls, v: str) -> str:
        m = _REPO_URL_RE.match((v or "").strip())
        if not m or m.group("repo") in (".", "..") or ".." in m.group("repo"):
            raise ValueError("must be a GitHub repository URL like https://github.com/owner/repo")
        return f"https://github.com/{m.group('owner')}/{m.group('repo')}"

    @field_validator("base_branch")
    @classmethod
    def _validate_branch(cls, v: str) -> str:
        v = (v or "").strip()
        if (
            not v or len(v) > 100 or not _BRANCH_RE.match(v) or v.startswith("-")
            or ".." in v or v.endswith(".lock") or v.endswith(".")
        ):
            raise ValueError("invalid branch name")
        return v

    @property
    def repo_owner(self) -> str:
        return self.repo_url.rsplit("/", 2)[-2]


class ScanStage(str, Enum):
    """Pipeline stages for SSE progress updates."""
    QUEUED = "queued"
    CLONING = "cloning"
    RECON = "recon"
    EXPLOIT = "exploit"
    VERIFY = "verify"
    PATCH = "patch"
    PUSHING = "pushing"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanEvent(BaseModel):
    """A single SSE event pushed to the frontend."""
    scan_id: str
    stage: ScanStage
    status: str = Field(..., description="'running' | 'done' | 'error'")
    message: str = ""
    detail: Optional[str] = None
    pr_url: Optional[str] = None
    vuln_count: Optional[int] = None
    progress_pct: int = Field(0, ge=0, le=100)


class ScanResult(BaseModel):
    """Full scan result returned by GET /api/scan/{scan_id}."""
    scan_id: str
    repo_url: str
    status: str
    stage: ScanStage
    vulnerabilities: List[VulnerableEndpoint] = []
    pr_url: Optional[str] = None
    error: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at: Optional[str] = None
    recon: Optional[ReconOutput] = None
    exploit: Optional[ExploitOutput] = None
    verification: Optional[VerificationResult] = None
    patch: Optional[PatchOutput] = None


"""
GitHub service — handles all GitHub API and git CLI interactions.

Provides:
  - clone_repo: shallow-clones a repo using token-based HTTPS auth
  - read_repo_files: reads source files from disk for analysis
  - create_branch_and_pr: commits a fix and opens a Pull Request
  - parse_repo_full_name: extracts 'owner/repo' from any GitHub URL
  - cleanup_scan_dir: removes temporary scan directories
  - exchange_code_for_token: exchanges OAuth code for access token
  - get_github_user: fetches the authenticated user's info
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

import httpx
from github import Github

from app.config import GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, SCAN_TEMP_DIR

logger = logging.getLogger(__name__)

# All scan clones go under SCAN_TEMP_DIR (single source of truth in app.config,
# so clone_repo and cleanup_scan_dir can never diverge).


# ── URL Parsing ──────────────────────────────────────────────────────────────

def parse_repo_full_name(repo_url: str) -> str:
    """Extract 'owner/repo' from an HTTPS or SSH GitHub URL."""
    # HTTPS: https://github.com/owner/repo or https://github.com/owner/repo.git
    match = re.match(r"https?://github\.com/([^/]+/[^/]+?)(?:\.git)?/?$", repo_url)
    if match:
        return match.group(1)

    # SSH: git@github.com:owner/repo.git
    match = re.match(r"git@github\.com:([^/]+/[^/]+?)(?:\.git)?$", repo_url)
    if match:
        return match.group(1)

    raise ValueError(f"Cannot parse GitHub repo from URL: {repo_url}")


# ── Clone ────────────────────────────────────────────────────────────────────

def clone_repo(token: str, repo_url: str, scan_id: str) -> str:
    """
    Clone a GitHub repo into a temporary directory inside SCAN_TEMP_DIR.
    Uses the token for HTTPS authentication.
    Returns the absolute path to the cloned directory.

    If the destination already exists (from a previous failed run),
    it is removed before cloning.
    """
    full_name = parse_repo_full_name(repo_url)
    clone_url = f"https://x-access-token:{token}@github.com/{full_name}.git"

    dest = Path(SCAN_TEMP_DIR) / scan_id
    repo_path = dest / "repo"

    # Clean up stale clone from any previous run
    if repo_path.exists():
        logger.warning("Removing stale clone directory: %s", repo_path)
        shutil.rmtree(repo_path, ignore_errors=True)

    dest.mkdir(parents=True, exist_ok=True)

    logger.info("Cloning %s into %s", full_name, repo_path)
    result = subprocess.run(
        ["git", "clone", "--depth", "1", clone_url, str(repo_path)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed: {result.stderr}")

    repo_dir = str(repo_path)
    logger.info("Clone complete: %s", repo_dir)
    return repo_dir


# ── Read repo files for analysis ─────────────────────────────────────────────

# HIGH-PRIORITY: actual source code files likely to contain vulnerabilities
_CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".rb", ".php",
    ".go", ".rs", ".c", ".cpp", ".h", ".cs", ".swift", ".kt",
}

# LOW-PRIORITY: config / data files — only included if budget allows
_CONFIG_EXTENSIONS = {
    ".html", ".yml", ".yaml", ".toml", ".ini", ".cfg",
    ".env", ".sql", ".sh", ".bash", ".dockerfile",
}

# ALL scannable extensions (union of both)
_SCANNABLE_EXTENSIONS = _CODE_EXTENSIONS | _CONFIG_EXTENSIONS

# Files that should NEVER be scanned (eat token budget, no security value)
_SKIP_FILENAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock",
    "Pipfile.lock", "poetry.lock", "Cargo.lock", "Gemfile.lock",
    "go.sum", ".DS_Store", "thumbs.db",
    "__anvil_launcher__.py",
}

# Filename patterns that indicate data files, not code
_DATA_FILE_PATTERNS = {
    "dataset", "training", "embedding", "vector", "checkpoint",
    "weights", "model_config", "manifest", "fixture", "seed",
    "migration", "schema.json", "swagger", "openapi",
}

_SKIP_DIRS = {
    # Package / dependency directories
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".next", ".nuxt", "vendor", ".tox",
    ".eggs", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "site-packages", ".cargo", "target",
    # Data / ML / assets directories (RAG, CV, ML projects)
    "data", "datasets", "models", "weights", "checkpoints",
    "embeddings", "vectors", "corpus", "raw_data", "processed_data",
    "training_data", "test_data", "fixtures", "samples",
    "assets", "static", "public", "media", "uploads", "images",
    "logs", "coverage", "htmlcov",
    # Documentation / non-code
    "docs", "doc", ".github", ".vscode", ".idea",
    "migrations", "alembic",
}

_MAX_CODE_FILE_SIZE = 100_000   # 100 KB for source code files
_MAX_CONFIG_FILE_SIZE = 15_000  # 15 KB for config/data files (skip large JSONs)

# Keywords that boost a file's security relevance score
_SECURITY_KEYWORDS = {
    "route", "router", "handler", "endpoint", "view", "controller",
    "auth", "login", "session", "token", "password", "secret",
    "upload", "file", "download", "exec", "eval", "query", "sql",
    "deserializ", "pickle", "yaml.load", "marshal", "shelve",
    "subprocess", "os.system", "popen", "shell",
    "request", "response", "api", "server", "app", "main",
    "middleware", "security", "sanitize", "validate",
    "cors", "csrf", "xss", "injection",
}

# Filenames that are almost always security-relevant
_HIGH_PRIORITY_NAMES = {
    "app.py", "main.py", "server.py", "wsgi.py", "asgi.py",
    "routes.py", "views.py", "handlers.py", "api.py", "urls.py",
    "auth.py", "login.py", "middleware.py", "settings.py", "config.py",
    "index.js", "app.js", "server.js", "index.ts", "app.ts",
    "routes.js", "routes.ts", "controller.js", "controller.ts",
    ".env", ".env.example", "docker-compose.yml", "Dockerfile",
}


def _file_priority_score(rel_path: str, content: str) -> int:
    """
    Assign a priority score to a file. Higher = more likely to contain
    security-relevant code. Used to sort files so the most important
    ones are analyzed first within the token budget.
    """
    score = 0
    filename = Path(rel_path).name.lower()
    ext = Path(rel_path).suffix.lower()

    # High-priority filenames
    if filename in _HIGH_PRIORITY_NAMES:
        score += 100

    # Source code files > config files
    if ext in _CODE_EXTENSIONS:
        score += 50
    elif ext in _CONFIG_EXTENSIONS:
        score += 10

    # Boost files with security-relevant keywords in content
    content_lower = content[:5000].lower()  # Check first 5KB only
    keyword_hits = sum(1 for kw in _SECURITY_KEYWORDS if kw in content_lower)
    score += keyword_hits * 8

    # Boost files that define routes/endpoints
    if any(pattern in content_lower for pattern in (
        "@app.route", "@router.", "app.get(", "app.post(", "app.put(",
        "app.delete(", "express()", "fastapi", "flask", "django",
        "def get(", "def post(", "def put(", "def delete(",
    )):
        score += 80

    # Penalize test files
    if "test" in filename or "spec" in filename or rel_path.startswith("test"):
        score -= 30

    # Penalize deeply nested files (likely less important)
    depth = len(Path(rel_path).parts)
    if depth > 4:
        score -= (depth - 4) * 5

    return score


def _is_data_file(filename: str, content: str) -> bool:
    """
    Heuristic check: is this file actually data rather than code?
    Catches large JSON arrays/objects that are dataset dumps,
    not configuration files.
    """
    lower_name = filename.lower()

    # Known data file patterns
    if any(pattern in lower_name for pattern in _DATA_FILE_PATTERNS):
        return True

    # Large JSON files that start with '[' are almost certainly data arrays
    if lower_name.endswith(".json") and len(content) > 5000:
        stripped = content.lstrip()
        if stripped.startswith("["):
            return True

    return False


def read_repo_files(repo_dir: str) -> list[dict]:
    """
    Walk *repo_dir* and read scannable source files.
    Returns list of {"path": relative_path, "content": text_content,
                     "priority": int} sorted by security relevance
    (highest priority first).
    """
    files = []
    root = Path(repo_dir)

    if not root.exists():
        logger.warning("Repo dir does not exist: %s", repo_dir)
        return files

    for path in root.rglob("*"):
        # Skip directories and non-scannable files
        if not path.is_file():
            continue

        # Skip known junk files
        if path.name in _SKIP_FILENAMES:
            continue

        # Check if any parent directory should be skipped
        rel = path.relative_to(root)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue

        ext = path.suffix.lower()
        if ext not in _SCANNABLE_EXTENSIONS:
            continue

        # Apply size limits based on file type
        file_size = path.stat().st_size
        max_size = _MAX_CODE_FILE_SIZE if ext in _CODE_EXTENSIONS else _MAX_CONFIG_FILE_SIZE
        if file_size > max_size:
            continue

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue  # Skip unreadable files silently

        # Skip data files masquerading as config (large JSON arrays, datasets)
        if _is_data_file(path.name, content):
            logger.debug("Skipping data file: %s", rel)
            continue

        priority = _file_priority_score(str(rel), content)
        files.append({"path": str(rel), "content": content, "priority": priority})

    # Sort by priority (highest first) so the most important files
    # are analyzed first within the token budget
    files.sort(key=lambda f: f["priority"], reverse=True)

    logger.info(
        "Read %d scannable files from %s (top priority: %s)",
        len(files),
        repo_dir,
        files[0]["path"] if files else "none",
    )
    return files


def detect_entry_point(repo_dir: str) -> Optional[str]:
    """
    Detect the main runnable Python entry point of a web application.
    Returns the relative path to the entry script, or None.

    Heuristics (in priority order):
      1. A file containing `if __name__ == '__main__':` with `app.run(`
      2. A file named app.py, main.py, server.py, run.py, wsgi.py
      3. The first .py file importing flask/fastapi/django
    """
    root = Path(repo_dir)
    candidates = []

    for path in root.rglob("*.py"):
        rel = path.relative_to(root)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue
        if path.name in _SKIP_FILENAMES:
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        has_main_guard = "__name__" in content and "__main__" in content
        has_app_run = "app.run(" in content or "uvicorn.run(" in content
        has_framework = any(fw in content for fw in ("flask", "Flask", "FastAPI", "fastapi", "Django", "django"))

        score = 0
        if has_main_guard and has_app_run:
            score = 100
        elif path.name in ("app.py", "main.py", "server.py", "run.py", "wsgi.py"):
            score = 50
        elif has_framework:
            score = 25
        
        if score > 0:
            candidates.append((score, str(rel), content))

    if not candidates:
        return None

    # Return the highest-scored candidate
    candidates.sort(key=lambda x: x[0], reverse=True)
    best_path = candidates[0][1]
    logger.info("Detected entry point: %s (score=%d)", best_path, candidates[0][0])
    return best_path


# ── Cleanup ──────────────────────────────────────────────────────────────────

def cleanup_scan_dir(scan_id: str) -> None:
    """Remove the scan directory if it exists."""
    dest = Path(SCAN_TEMP_DIR) / scan_id
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
        logger.info("Cleaned up scan dir: %s", dest)


# ── GitHub API: branches + PRs ───────────────────────────────────────────────

def _has_push_access(repo) -> bool:
    """Check if the authenticated user has push access to the repo."""
    try:
        perms = repo.permissions
        return perms and (perms.push or perms.admin)
    except Exception:
        return False


def _get_or_create_fork(g: Github, upstream_repo, max_wait: int = 30):
    """
    Fork the upstream repo into the authenticated user's account.
    If a fork already exists, return it. Waits briefly for GitHub to
    finish creating the fork (async on GitHub's side).
    """
    import time

    user = g.get_user()
    fork_full_name = f"{user.login}/{upstream_repo.name}"

    # Check if we already have a fork
    try:
        existing = g.get_repo(fork_full_name)
        if existing.fork:
            logger.info("Reusing existing fork: %s", fork_full_name)
            return existing
    except Exception:
        pass  # No existing fork, create one

    logger.info("Forking %s into %s...", upstream_repo.full_name, user.login)
    fork = upstream_repo.create_fork()

    # GitHub forks are async — poll until the fork is ready
    for _ in range(max_wait):
        try:
            fresh = g.get_repo(fork.full_name)
            # Fork is ready when we can read the default branch ref
            fresh.get_git_ref(f"heads/{upstream_repo.default_branch}")
            logger.info("Fork ready: %s", fresh.full_name)
            return fresh
        except Exception:
            time.sleep(1)

    # Return the fork object anyway; it may work by the time we push
    return fork


def create_branch_and_pr(
    *,
    # Accept both naming conventions for backward compatibility
    github_token: Optional[str] = None,
    token: Optional[str] = None,
    repo_url: Optional[str] = None,
    repo_full_name: Optional[str] = None,
    branch_name: Optional[str] = None,
    fix_branch: Optional[str] = None,
    base_branch: str = "main",
    # Single file mode
    file_path: Optional[str] = None,
    new_content: Optional[str] = None,
    # Multi-file mode (from patcher)
    fixed_files: Optional[list] = None,
    commit_message: str = "fix: automated security patch by Anvil",
    pr_title: str = "Security Fix",
    pr_body: str = "",
) -> str:
    """
    Create a fix branch, commit the patched file(s), and open a Pull Request.
    Returns the URL of the created PR.

    If the authenticated user does NOT have push access to the target repo,
    the function automatically forks the repo and opens a cross-repo PR
    (fork → upstream), which is the standard GitHub contribution model.
    
    Includes retry logic and better error handling.
    """
    # Resolve parameter aliases
    _token = github_token or token
    _branch = branch_name or fix_branch
    if not _token:
        raise ValueError("github_token or token is required")
    if not _branch:
        raise ValueError("branch_name or fix_branch is required")

    # Resolve repo name
    if repo_full_name:
        full_name = repo_full_name
    elif repo_url:
        full_name = parse_repo_full_name(repo_url)
    else:
        raise ValueError("repo_url or repo_full_name is required")

    try:
        g = Github(_token)
        upstream_repo = g.get_repo(full_name)
    except Exception as exc:
        raise RuntimeError(f"Failed to access repository {full_name}: {exc}")

    # Determine if we need to fork
    use_fork = not _has_push_access(upstream_repo)

    if use_fork:
        logger.info(
            "No push access to %s — will fork and open cross-repo PR",
            full_name,
        )
        try:
            push_repo = _get_or_create_fork(g, upstream_repo)
            fork_owner = push_repo.owner.login
        except Exception as exc:
            raise RuntimeError(f"Failed to create/access fork: {exc}")
    else:
        push_repo = upstream_repo
        fork_owner = None

    # Get the SHA of the base branch head (from upstream)
    try:
        base_ref = upstream_repo.get_git_ref(f"heads/{base_branch}")
        base_sha = base_ref.object.sha
    except Exception as exc:
        # Try common alternative branch names
        for alt_branch in ["master", "develop", "dev"]:
            try:
                base_ref = upstream_repo.get_git_ref(f"heads/{alt_branch}")
                base_sha = base_ref.object.sha
                base_branch = alt_branch
                logger.info("Using alternative base branch: %s", alt_branch)
                break
            except Exception:
                continue
        else:
            try:
                branches = [b.name for b in list(upstream_repo.get_branches())[:5]]
                branch_list = ", ".join(branches)
            except Exception:
                branch_list = "unknown"
            raise RuntimeError(
                f"Could not find base branch '{base_branch}' or alternatives. "
                f"Available branches: {branch_list}"
            )

    # Create the new branch on the push target (fork or upstream)
    try:
        push_repo.create_git_ref(ref=f"refs/heads/{_branch}", sha=base_sha)
        logger.info("Created branch: %s on %s", _branch, push_repo.full_name)
    except Exception as exc:
        if "Reference already exists" in str(exc):
            logger.warning("Branch %s already exists, will update it", _branch)
            # Update the existing branch to point to base_sha
            try:
                ref = push_repo.get_git_ref(f"heads/{_branch}")
                ref.edit(sha=base_sha, force=True)
                logger.info("Updated existing branch %s", _branch)
            except Exception as update_exc:
                logger.error("Failed to update existing branch: %s", update_exc)
                raise RuntimeError(f"Branch {_branch} exists and cannot be updated: {update_exc}")
        else:
            raise RuntimeError(f"Failed to create branch {_branch}: {exc}")

    # Build list of files to commit
    files_to_commit = []
    if fixed_files:
        files_to_commit = fixed_files  # [{path, content}, ...]
    elif file_path and new_content:
        files_to_commit = [{"path": file_path, "content": new_content}]
    else:
        raise ValueError("Either fixed_files or (file_path + new_content) is required")

    # Commit each file to the push target
    commit_errors = []
    for f in files_to_commit:
        fpath = f["path"]
        fcontent = f["content"]
        try:
            # Try to update existing file
            contents = push_repo.get_contents(fpath, ref=_branch)
            # Handle both single file and list of files
            if isinstance(contents, list):
                if len(contents) > 0:
                    file_sha = contents[0].sha
                else:
                    raise Exception("File not found")
            else:
                file_sha = contents.sha
            
            push_repo.update_file(
                path=fpath,
                message=commit_message,
                content=fcontent,
                sha=file_sha,
                branch=_branch,
            )
            logger.info("Updated %s on branch %s", fpath, _branch)
        except Exception as get_exc:
            # File doesn't exist, create it
            try:
                push_repo.create_file(
                    path=fpath,
                    message=commit_message,
                    content=fcontent,
                    branch=_branch,
                )
                logger.info("Created %s on branch %s", fpath, _branch)
            except Exception as create_exc:
                error_msg = f"Failed to commit {fpath}: {create_exc}"
                logger.error(error_msg)
                commit_errors.append(error_msg)

    if commit_errors:
        raise RuntimeError(f"Failed to commit files: {'; '.join(commit_errors)}")

    # Open the PR on the UPSTREAM repo
    # For cross-repo PRs, head must be "fork_owner:branch"
    head_ref = f"{fork_owner}:{_branch}" if use_fork else _branch

    try:
        pr = upstream_repo.create_pull(
            title=pr_title,
            body=pr_body,
            head=head_ref,
            base=base_branch,
        )
        logger.info("PR created: %s", pr.html_url)
        return pr.html_url
    except Exception as exc:
        # Check if PR already exists
        if "pull request already exists" in str(exc).lower():
            # Try to find the existing PR. get_pulls(head=...) REQUIRES the
            # fully-qualified "owner:branch" form; a bare branch name silently
            # matches nothing. head_ref is already qualified for fork PRs; for
            # same-repo PRs we must add the upstream owner.
            try:
                qualified_head = head_ref if use_fork else f"{upstream_repo.owner.login}:{_branch}"
                prs = upstream_repo.get_pulls(state="open", head=qualified_head, base=base_branch)
                for pr in prs:
                    logger.info("Found existing PR: %s", pr.html_url)
                    return pr.html_url
            except Exception:
                pass
        raise RuntimeError(f"Failed to create pull request: {exc}")


# ── OAuth helpers ────────────────────────────────────────────────────────────

async def exchange_code_for_token(code: str) -> str:
    """Exchange a GitHub OAuth authorization code for an access token."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://github.com/login/oauth/access_token",
            json={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
            },
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()

    token = data.get("access_token")
    if not token:
        raise ValueError(f"GitHub token exchange failed: {data}")
    return token


async def get_github_user(token: str) -> dict:
    """Fetch the authenticated user's profile from GitHub."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {token}"},
        )
        resp.raise_for_status()
        return resp.json()

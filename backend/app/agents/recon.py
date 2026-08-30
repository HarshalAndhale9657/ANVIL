"""
Reconnaissance Agent — scans cloned repository source code and catalogs
the attack surface into a strict ReconOutput schema.

Uses GPT-4o to identify vulnerabilities in the source, batched by security
relevance, and complements it with a deterministic regex pattern scan so
findings survive an LLM failure.
"""

from __future__ import annotations

import json
import logging
from typing import List, Optional

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
from openai import OpenAI

from app.config import LLM_MODEL, LLM_TEMPERATURE, OPENAI_API_KEY
from app.schemas import ReconOutput
from app.telemetry import trace_operation

logger = logging.getLogger(__name__)

_client: Optional[OpenAI] = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        _client = OpenAI(api_key=OPENAI_API_KEY)
    return _client


# ── Mode 1: Source Code Analysis ─────────────────────────────────────────────

# Budget per batch in characters (~30K tokens)
_BATCH_CHAR_BUDGET = 120_000
# Maximum number of batches to analyze (prevents runaway API calls)
_MAX_BATCHES = 4


def _build_system_prompt(repo_url: str) -> str:
    """Build the system prompt for source code vulnerability analysis."""
    example_json = json.dumps({
        "target_url": repo_url,
        "detected_framework": "Flask/Express/Django/etc",
        "vulnerable_endpoints": [
            {
                "path": "src/routes/files.py:45",
                "method": "GET",
                "injection_vector": "Path traversal via unsanitized user input in os.path.join"
            }
        ]
    }, indent=2)

    return (
        "You are an expert security code reviewer. Analyze the source code below "
        "and identify ALL security vulnerabilities.\n\n"
        "You MUST return valid JSON with EXACTLY this structure:\n"
        f"```json\n{example_json}\n```\n\n"
        "Rules:\n"
        "- target_url: the repository URL (string)\n"
        "- detected_framework: the main framework used in the project (string)\n"
        "- vulnerable_endpoints: array of objects, each with:\n"
        "  - path: file path and line number where the vulnerability exists (e.g. 'server.py:23')\n"
        "  - method: HTTP method associated (GET/POST/etc), or GET if not applicable\n"
        "  - injection_vector: detailed description of the vulnerability and how it can be exploited\n"
        "- Focus on: path traversal, SQL injection, XSS, command injection, SSRF, "
        "insecure deserialization, hardcoded secrets, auth bypass, IDOR, "
        "unsafe file handling, insecure crypto, race conditions\n"
        "- Include ALL vulnerabilities found, ranked by severity\n"
        "- Be specific about the exact line/function and the attack vector\n"
        "- If no vulnerabilities found, return empty vulnerable_endpoints array\n"
        "- Do NOT report vulnerabilities in test files or documentation\n"
    )


def _parse_llm_recon_response(raw_json: str, repo_url: str) -> Optional[ReconOutput]:
    """
    Parse and validate the LLM's JSON response into a ReconOutput.
    Tries multiple strategies:
      1. Direct Pydantic validation
      2. Manual JSON extraction (handles markdown-wrapped responses)
      3. Partial extraction of vulnerable_endpoints array
    Returns None if all strategies fail.
    """
    import re

    # Strategy 1: direct validation
    try:
        return ReconOutput.model_validate_json(raw_json)
    except Exception as exc:
        logger.debug("Direct validation failed: %s", exc)

    # Strategy 2: try to extract JSON from markdown code blocks
    try:
        json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw_json, re.DOTALL)
        if json_match:
            return ReconOutput.model_validate_json(json_match.group(1))
    except Exception as exc:
        logger.debug("Markdown extraction failed: %s", exc)

    # Strategy 3: parse raw JSON and manually construct ReconOutput
    try:
        data = json.loads(raw_json)
        from app.schemas import VulnerableEndpoint, HttpMethod

        endpoints = []
        raw_endpoints = data.get("vulnerable_endpoints", [])
        for ep in raw_endpoints:
            try:
                # Normalize method field
                method_str = str(ep.get("method", "GET")).upper()
                try:
                    method = HttpMethod(method_str)
                except ValueError:
                    method = HttpMethod.GET

                endpoints.append(VulnerableEndpoint(
                    path=str(ep.get("path", "unknown")),
                    method=method,
                    injection_vector=str(ep.get("injection_vector", ep.get("description", "Unknown vulnerability"))),
                ))
            except Exception:
                continue

        return ReconOutput(
            target_url=data.get("target_url", repo_url),
            detected_framework=data.get("detected_framework", "Unknown"),
            vulnerable_endpoints=endpoints,
        )
    except Exception as exc:
        logger.debug("Manual construction failed: %s", exc)

    return None


def _split_files_into_batches(files: list[dict], budget: int = _BATCH_CHAR_BUDGET) -> list[list[dict]]:
    """
    Split files into batches that fit within the character budget.
    Files are already sorted by priority (highest first from read_repo_files).
    """
    batches = []
    current_batch = []
    current_size = 0

    for f in files:
        content_len = len(f["content"])

        # If a single file exceeds the budget, truncate it
        if content_len > budget:
            truncated = dict(f)
            truncated["content"] = f["content"][:budget - 1000] + "\n... (truncated)"
            content_len = len(truncated["content"])
            f = truncated

        if current_size + content_len > budget and current_batch:
            batches.append(current_batch)
            current_batch = []
            current_size = 0

        current_batch.append(f)
        current_size += content_len

    if current_batch:
        batches.append(current_batch)

    return batches


def _analyze_batch(
    client,
    batch: list[dict],
    repo_url: str,
    system_prompt: str,
    batch_num: int,
    total_batches: int,
) -> list:
    """
    Analyze a single batch of files and return the vulnerable endpoints found.
    Includes retry logic for LLM failures.
    """
    # Build code digest for this batch
    code_digest_parts = []
    for f in batch:
        code_digest_parts.append(f"### {f['path']}\n```\n{f['content']}\n```")
    code_digest = "\n\n".join(code_digest_parts)

    batch_context = ""
    if total_batches > 1:
        batch_context = (
            f"\n\n[NOTE: This is batch {batch_num}/{total_batches} of the repository. "
            f"Analyze ONLY the code shown here. This batch contains {len(batch)} files.]\n"
        )

    user_content = f"Repository: {repo_url}{batch_context}\n\nSource code:\n{code_digest}"

    # Try up to 2 times for each batch
    max_retries = 2
    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model=LLM_MODEL,
                temperature=LLM_TEMPERATURE,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content},
                ],
            )

            raw_json = response.choices[0].message.content
            logger.info(
                "Batch %d/%d LLM response (attempt %d): %s",
                batch_num, total_batches, attempt + 1, raw_json[:300],
            )

            result = _parse_llm_recon_response(raw_json, repo_url)
            if result is not None:
                return result.vulnerable_endpoints

            logger.warning(
                "Batch %d/%d: could not parse LLM response (attempt %d/%d)",
                batch_num, total_batches, attempt + 1, max_retries,
            )

        except Exception as exc:
            logger.error(
                "Batch %d/%d: LLM call failed (attempt %d/%d): %s",
                batch_num, total_batches, attempt + 1, max_retries, exc,
            )

    return []


def _detect_framework_from_files(files: list[dict]) -> str:
    """
    Detect the web framework from file contents and structure.
    Returns the detected framework name or "Unknown".
    """
    framework_indicators = {
        "Flask": ["from flask import", "import flask", "@app.route", "Flask(__name__)"],
        "FastAPI": ["from fastapi import", "import fastapi", "FastAPI()", "@app.get", "@app.post"],
        "Django": ["from django", "import django", "django.conf", "INSTALLED_APPS"],
        "Express": ["express()", "require('express')", "app.listen(", "app.get(", "app.post("],
        "Next.js": ["next/", "import { NextPage", "getServerSideProps", "getStaticProps"],
        "React": ["import React", "from 'react'", "useState", "useEffect"],
        "Vue": ["import Vue", "from 'vue'", "new Vue(", "createApp("],
        "Spring": ["@SpringBootApplication", "@RestController", "@RequestMapping", "import org.springframework"],
        "Rails": ["class ApplicationController", "Rails.application", "ActiveRecord::Base"],
    }
    
    framework_scores = {name: 0 for name in framework_indicators}
    
    for file_info in files[:20]:  # Check first 20 files only
        content = file_info['content'].lower()
        for framework, indicators in framework_indicators.items():
            for indicator in indicators:
                if indicator.lower() in content:
                    framework_scores[framework] += 1
    
    # Return framework with highest score
    max_score = max(framework_scores.values())
    if max_score > 0:
        for framework, score in framework_scores.items():
            if score == max_score:
                return framework
    
    return "Unknown"


def _deterministic_vuln_scan(files: list[dict], repo_url: str) -> list:
    """
    Deterministic vulnerability scanner - fallback when LLM fails.
    Uses regex patterns to detect common vulnerability patterns.
    Enhanced with more patterns and better detection.
    """
    from app.schemas import VulnerableEndpoint, HttpMethod
    import re
    
    vulnerabilities = []
    
    # Vulnerability patterns (pattern, vuln_type, description, severity)
    VULN_PATTERNS = [
        # Path Traversal - HIGH PRIORITY
        (r'os\.path\.join\([^)]*(?:request\.|params\.|query\.|body\.)[^)]*\)', 'path_traversal',
         'Unsafe path construction with user input - potential path traversal', 'HIGH'),
        (r'open\([^)]*(?:request\.|params\.|query\.)[^)]*["\']r', 'path_traversal',
         'Direct file open with user input - potential path traversal', 'HIGH'),
        (r'Path\([^)]*(?:request\.|params\.|query\.)[^)]*\)', 'path_traversal',
         'Path object with user input - potential path traversal', 'HIGH'),
        (r'readFile\([^)]*(?:req\.|params\.|query\.)[^)]*\)', 'path_traversal',
         'File read with user input - potential path traversal', 'HIGH'),
        
        # SQL Injection - CRITICAL
        (r'execute\(f["\']SELECT.*?{.*?}', 'sql_injection',
         'SQL query with f-string interpolation - SQL injection risk', 'CRITICAL'),
        (r'execute\(["\'].*?\+.*?(?:request\.|params\.|query\.)', 'sql_injection',
         'SQL query with string concatenation - SQL injection risk', 'CRITICAL'),
        (r'\.format\(.*?(?:request\.|params\.|query\.)', 'sql_injection',
         'SQL query with .format() - SQL injection risk', 'CRITICAL'),
        (r'query\(["\']SELECT.*?\+', 'sql_injection',
         'SQL query with concatenation - SQL injection risk', 'CRITICAL'),
        (r'raw\(["\']SELECT.*?%s', 'sql_injection',
         'Raw SQL with string formatting - SQL injection risk', 'CRITICAL'),
        
        # Command Injection - CRITICAL
        (r'os\.system\([^)]*(?:request\.|params\.|query\.)[^)]*\)', 'command_injection',
         'os.system() with user input - command injection risk', 'CRITICAL'),
        (r'subprocess\.(run|call|Popen)\([^)]*shell\s*=\s*True', 'command_injection',
         'subprocess with shell=True - command injection risk', 'CRITICAL'),
        (r'exec\([^)]*(?:request\.|params\.|query\.)[^)]*\)', 'command_injection',
         'exec() with user input - arbitrary code execution', 'CRITICAL'),
        (r'eval\([^)]*(?:request\.|params\.|query\.)[^)]*\)', 'command_injection',
         'eval() with user input - arbitrary code execution', 'CRITICAL'),
        
        # Insecure Deserialization - CRITICAL
        (r'pickle\.loads?\([^)]*(?:request\.|params\.|cookies\.)[^)]*\)', 'deserialization',
         'pickle.loads() on user input - arbitrary code execution risk', 'CRITICAL'),
        (r'yaml\.load\([^)]*(?:request\.|params\.)[^)]*\)', 'deserialization',
         'yaml.load() on user input - arbitrary code execution risk', 'CRITICAL'),
        (r'jsonpickle\.decode\([^)]*(?:request\.|params\.)[^)]*\)', 'deserialization',
         'jsonpickle.decode() on user input - code execution risk', 'CRITICAL'),
        (r'marshal\.loads?\([^)]*(?:request\.|params\.)[^)]*\)', 'deserialization',
         'marshal.loads() on user input - code execution risk', 'CRITICAL'),
        
        # XSS - HIGH
        (r'render_template_string\([^)]*(?:request\.|params\.|query\.)[^)]*\)', 'xss',
         'render_template_string with user input - XSS risk', 'HIGH'),
        (r'\.innerHTML\s*=\s*.*?(?:req\.|params\.|query\.)', 'xss',
         'innerHTML assignment with user input - XSS risk', 'HIGH'),
        (r'document\.write\([^)]*(?:req\.|params\.|query\.)[^)]*\)', 'xss',
         'document.write with user input - XSS risk', 'HIGH'),
        
        # SSRF - HIGH
        (r'requests\.(?:get|post|put|delete)\([^)]*(?:request\.|params\.|query\.)[^)]*\)', 'ssrf',
         'HTTP request with user-controlled URL - SSRF risk', 'HIGH'),
        (r'urllib\.request\.urlopen\([^)]*(?:request\.|params\.)[^)]*\)', 'ssrf',
         'URL open with user input - SSRF risk', 'HIGH'),
        (r'fetch\([^)]*(?:req\.|params\.|query\.)[^)]*\)', 'ssrf',
         'fetch() with user-controlled URL - SSRF risk', 'HIGH'),
        
        # Hardcoded Secrets - MEDIUM. Require a secret-LOOKING value (>=16 chars,
        # secret alphabet) and exclude obvious placeholders / env-var references
        # so benign defaults like password="your-password-here" or
        # token=os.getenv(...) don't flood recon with false positives.
        (r'(?:password|passwd|secret|api_key|apikey|access_token|auth_token)\s*=\s*'
         r'["\'](?!your|example|changeme|placeholder|xxx|test|sample|dummy|none|null|redacted|<|\{|\$)'
         r'[A-Za-z0-9+/_\-]{16,}["\']', 'hardcoded_secret',
         'Hardcoded credential detected', 'MEDIUM'),
        (r'(?:AWS_ACCESS_KEY|AWS_SECRET|GITHUB_TOKEN)\s*=\s*["\'][A-Za-z0-9+/_\-]{16,}["\']', 'hardcoded_secret',
         'Hardcoded API credential detected', 'MEDIUM'),
    ]
    
    for file_info in files:
        content = file_info['content']
        path = file_info['path']
        
        # Skip test files
        if 'test' in path.lower() or 'spec' in path.lower():
            continue
        
        for pattern, vuln_type, description, severity in VULN_PATTERNS:
            matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
            for match in matches:
                # Find line number
                line_num = content[:match.start()].count('\n') + 1
                
                # Extract the actual vulnerable code snippet
                lines = content.splitlines()
                if 0 <= line_num - 1 < len(lines):
                    code_snippet = lines[line_num - 1].strip()[:100]
                else:
                    code_snippet = match.group(0)[:100]
                
                vulnerabilities.append(VulnerableEndpoint(
                    path=f"{path}:{line_num}",
                    method=HttpMethod.GET,
                    injection_vector=f"[{severity}] {description}\nCode: {code_snippet}"
                ))
    
    return vulnerabilities


@omium.trace("recon_agent", span_type="agent")
def run_recon_source(repo_dir: str, repo_url: str, emit_fn=None) -> ReconOutput:
    """
    Scan cloned source code for vulnerabilities.
    Reads files from disk and sends them to GPT-4o for analysis.

    For large repos, splits files into multiple batches and analyzes
    each batch separately, then merges all discovered vulnerabilities.
    
    If LLM fails, falls back to deterministic pattern matching.
    """
    from app.github_service import read_repo_files
    from app.schemas import ScanStage

    with trace_operation(
        "recon_agent_source",
        attributes={"agent.name": "recon", "agent.mode": "source_code", "agent.repo_url": repo_url},
    ) as span:
        # Step 1: read source files (pre-sorted by security relevance)
        files = read_repo_files(repo_dir)
        total_file_count = len(files)
        span.set_attribute("recon.file_count", total_file_count)

        if not files:
            logger.warning("No scannable files found in %s", repo_dir)
            return ReconOutput(
                target_url=repo_url,
                detected_framework="Unknown",
                vulnerable_endpoints=[],
            )

        logger.info(
            "Recon: analyzing %d files from %s (top files: %s)",
            total_file_count,
            repo_dir,
            ", ".join(f["path"] for f in files[:5]),
        )

        # Step 2: split into batches for chunked analysis
        batches = _split_files_into_batches(files)
        num_batches = min(len(batches), _MAX_BATCHES)
        batches = batches[:num_batches]

        span.set_attribute("recon.batch_count", num_batches)
        span.set_attribute("recon.files_per_batch", [len(b) for b in batches])
        logger.info(
            "Recon: split into %d batches (%s files each)",
            num_batches,
            [len(b) for b in batches],
        )

        if emit_fn:
            emit_fn(ScanStage.RECON, "running", f"Found {total_file_count} scannable files. Splitting into {num_batches} batches for AI analysis...", progress_pct=18)

        # Step 3: Try LLM analysis first
        all_endpoints = []
        detected_framework = "Unknown"
        llm_failed = False

        try:
            client = _get_client()
            system_prompt = _build_system_prompt(repo_url)

            for i, batch in enumerate(batches, 1):
                logger.info(
                    "Recon batch %d/%d: analyzing %d files (%s ...)",
                    i, num_batches, len(batch),
                    ", ".join(f["path"] for f in batch[:3]),
                )
                
                if emit_fn:
                    emit_fn(ScanStage.RECON, "running", f"Analyzing batch {i}/{num_batches} with AI model ({len(batch)} files)...", progress_pct=18 + int((i / num_batches) * 10))

                batch_endpoints = _analyze_batch(
                    client, batch, repo_url, system_prompt, i, num_batches,
                )
                all_endpoints.extend(batch_endpoints)

                logger.info(
                    "Recon batch %d/%d: found %d vulnerabilities",
                    i, num_batches, len(batch_endpoints),
                )
                
                if emit_fn:
                    emit_fn(ScanStage.RECON, "running", f"Batch {i}/{num_batches} complete: found {len(batch_endpoints)} potential issues", progress_pct=18 + int((i / num_batches) * 10) + 2)
                
                # Extract framework from first successful batch
                if detected_framework == "Unknown" and batch_endpoints:
                    # Try to detect framework from file extensions and imports
                    detected_framework = _detect_framework_from_files(batch)
        except Exception as exc:
            logger.warning("LLM analysis failed: %s - falling back to deterministic scan", exc)
            llm_failed = True
            span.add_event("llm_failed_fallback_to_deterministic")

        # Step 4: ALWAYS run deterministic scan as a complement
        # This ensures we catch vulnerabilities even if LLM misses them
        logger.info("Running deterministic vulnerability scan...")
        if emit_fn:
            emit_fn(ScanStage.RECON, "running", "Running deterministic fallback scan...", progress_pct=29)
            
        deterministic_vulns = _deterministic_vuln_scan(files, repo_url)
        
        # Merge LLM and deterministic results
        if deterministic_vulns:
            logger.info("Deterministic scan found %d vulnerabilities", len(deterministic_vulns))
            all_endpoints.extend(deterministic_vulns)
            span.set_attribute("recon.deterministic_vuln_count", len(deterministic_vulns))
        
        if llm_failed:
            span.set_attribute("recon.used_deterministic_fallback", True)
        
        # Detect framework if not already detected
        if detected_framework == "Unknown":
            detected_framework = _detect_framework_from_files(files)

        # Step 5: deduplicate endpoints (same file+method+vector = same vuln)
        seen = set()
        unique_endpoints = []
        for ep in all_endpoints:
            # Keep the FULL path (incl. line number) so two distinct vulns in
            # the same file are not merged, and use a longer vector slice so
            # different findings aren't collapsed by a shared 50-char prefix.
            key = (ep.path, ep.method, ep.injection_vector[:120])
            if key not in seen:
                seen.add(key)
                unique_endpoints.append(ep)

        result = ReconOutput(
            target_url=repo_url,
            detected_framework=detected_framework,
            vulnerable_endpoints=unique_endpoints,
        )

        span.set_attribute("recon.total_vulns", len(unique_endpoints))
        span.set_attribute("recon.batches_analyzed", num_batches)
        logger.info(
            "Source recon complete: %d unique vulnerabilities from %d batches (%d total files)",
            len(unique_endpoints), num_batches, total_file_count,
        )
        return result



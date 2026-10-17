"""
Gitleaks output ingester — parses Gitleaks JSON/SARIF into CommitShield's
CandidateFinding objects for re-scoring by the classifier.

CommitShield is a POST-PROCESSOR, not a standalone scanner.
This design decision:
  1. Avoids reimplementing 150+ battle-tested detection rules
  2. Lets CommitShield focus on its actual contribution: calibrated classification
  3. Complements Gitleaks instead of competing with it
  4. Gitleaks is MIT licensed — safe to depend on

Gitleaks invocation:
  gitleaks detect --staged --report-format json --report-path /tmp/gl.json
  gitleaks detect --staged --report-format sarif --report-path /tmp/gl.sarif
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CandidateFinding:
    """
    A raw finding from Gitleaks, before CommitShield classifies it.
    CommitShield will add: confidence score, evidence chain, change_status.
    """
    rule_id: str
    rule_description: str
    file_path: str
    line_number: int
    line_content: str          # The matched line (used for feature extraction)
    matched_value: str         # Redacted by Gitleaks (or we redact here)
    commit: str = ""
    author: str = ""
    date: str = ""
    secret: str = ""           # Raw unredacted — NEVER stored/reported, only used for feature extraction then discarded
    tags: list[str] = field(default_factory=list)
    context_lines: list[str] = field(default_factory=list)  # ±3 context lines


def run_gitleaks_on_staged(
    gitleaks_path: str = "gitleaks",
    extra_args: list[str] | None = None,
) -> list[CandidateFinding]:
    """
    Run Gitleaks against staged files and return candidate findings.

    Uses --staged flag (Gitleaks reads from git index, not working directory).
    Falls back to empty list if Gitleaks is not installed.
    """
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        report_path = f.name

    cmd = [
        gitleaks_path,
        "detect",
        "--staged",
        "--report-format", "json",
        "--report-path", report_path,
        "--no-color",
        "--exit-code", "0",  # Don't fail — we handle exit code ourselves
    ]

    if extra_args:
        cmd.extend(extra_args)

    try:
        subprocess.run(cmd, capture_output=True, check=False, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # Gitleaks not installed or timed out
        return []

    findings = parse_gitleaks_json(Path(report_path))
    Path(report_path).unlink(missing_ok=True)
    return findings


def parse_gitleaks_json(report_path: Path) -> list[CandidateFinding]:
    """Parse Gitleaks JSON output into CandidateFinding objects."""
    if not report_path.exists():
        return []

    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []

    if not isinstance(data, list):
        return []

    findings: list[CandidateFinding] = []
    for item in data:
        if not isinstance(item, dict):
            continue

        raw_secret = item.get("Secret", "") or item.get("Match", "")
        redacted = _redact(raw_secret)

        finding = CandidateFinding(
            rule_id=item.get("RuleID", "unknown"),
            rule_description=item.get("Description", ""),
            file_path=item.get("File", ""),
            line_number=item.get("StartLine", 0),
            line_content=item.get("Line", "") or item.get("Match", ""),  # Gitleaks uses 'Match' in older versions
            matched_value=redacted,
            commit=item.get("Commit", ""),
            author=item.get("Author", ""),
            date=item.get("Date", ""),
            secret=raw_secret,  # Held temporarily for feature extraction only
            tags=item.get("Tags", []),
        )
        findings.append(finding)


    return findings


def parse_gitleaks_sarif(report_path: Path) -> list[CandidateFinding]:
    """Parse Gitleaks SARIF output (alternative format)."""
    if not report_path.exists():
        return []

    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []

    findings: list[CandidateFinding] = []
    for run in data.get("runs", []):
        for result in run.get("results", []):
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                art = phys.get("artifactLocation", {})
                region = phys.get("region", {})

                finding = CandidateFinding(
                    rule_id=result.get("ruleId", "unknown"),
                    rule_description=result.get("message", {}).get("text", ""),
                    file_path=art.get("uri", ""),
                    line_number=region.get("startLine", 0),
                    line_content=region.get("snippet", {}).get("text", ""),
                    matched_value="[redacted]",
                )
                findings.append(finding)

    return findings


def get_staged_diff_context(file_path: str, context_lines: int = 3) -> dict[int, list[str]]:
    """
    Get added lines from staged diff with surrounding context.
    Returns dict mapping line_number → [context_lines].

    Using -U3 to get 3 surrounding context lines — needed for variable name extraction.
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", f"-U{context_lines}", "--", file_path],
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {}

    context_map: dict[int, list[str]] = {}
    current_line = 0
    window: list[str] = []

    import re
    for line in result.stdout.splitlines():
        if line.startswith("@@"):
            m = re.search(r"\+(\d+)", line)
            if m:
                current_line = int(m.group(1)) - 1
        elif line.startswith("+") and not line.startswith("+++"):
            current_line += 1
            window.append(line[1:])
            if len(window) > context_lines * 2 + 1:
                window.pop(0)
            context_map[current_line] = list(window)
        elif not line.startswith("-"):
            current_line += 1
            window.append(line)
            if len(window) > context_lines * 2 + 1:
                window.pop(0)

    return context_map


def _redact(value: str) -> str:
    """
    Redact a secret value.
    Reveals at most 25% of characters (max 4), preserving last 3 for identification.
    """
    n = len(value)
    if n <= 8:
        return "*" * n
    reveal_prefix = min(4, max(2, n // 4))  # At most 25%, max 4 chars
    stars = n - reveal_prefix - 3
    return value[:reveal_prefix] + "*" * stars + value[-3:]


# Public alias for external callers and tests
redact_secret = _redact


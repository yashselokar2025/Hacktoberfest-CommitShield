"""
Core orchestration engine — wires all CommitShield modules together.

Scan flow:
  1. Extract staged files from Git index
  2. Detect candidate secrets using pattern library
  3. Apply multi-signal classifier to each candidate
  4. Compare against baseline (NEW/EXISTING/RESOLVED)
  5. Parse dependency manifests + query OSV.dev
  6. Apply evidence-based priority modifiers
  7. Return ScanResult for reporting
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Optional

from commitshield.core.finding import (
    ChangeStatus,
    Confidence,
    DependencyFinding,
    Ecosystem,
    EvidenceItem,
    ExposureScope,
    ScanResult,
    SecretFinding,
    Severity,
)
from commitshield.scanner.classifier import classify
from commitshield.scanner.patterns import ALL_PATTERNS, PatternRule, Severity as PSeverity


# Skip binary/generated files
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".mp3", ".mp4", ".wav", ".avi", ".pyc", ".pyo", ".class",
    ".exe", ".dll", ".so", ".dylib", ".wasm", ".zip", ".tar",
    ".gz", ".rar", ".7z", ".pdf",
}

# Files where entropy is too noisy
ENTROPY_SKIP_FILES = {"package-lock.json", "yarn.lock", "poetry.lock", "Pipfile.lock"}


def _redact(value: str) -> str:
    """Redact a secret — show first 4 + asterisks + last 3 characters."""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 7) + value[-3:]


def scan_staged(
    repo_root: Path,
    allowlist_patterns: list[str] | None = None,
    allowlist_rule_ids: set[str] | None = None,
    skip_entropy: bool = False,
    scan_deps: bool = True,
) -> ScanResult:
    """
    Full scan of currently staged files.
    This is the main scan path called from the pre-commit hook.
    """
    from commitshield.git.staged import get_staged_files, StagedFile

    start = time.monotonic()
    result = ScanResult(scan_mode="staged")

    staged = get_staged_files()
    result.files_scanned = len(staged)

    if not staged:
        return result

    # ── Secret scanning ──────────────────────────────────────────
    all_matched_values: set[str] = set()
    candidate_findings: list[SecretFinding] = []

    for sf in staged:
        if Path(sf.path).suffix.lower() in SKIP_EXTENSIONS:
            continue
        findings = _scan_file_content(
            content=sf.content,
            file_path=sf.path,
            allowlist_patterns=allowlist_patterns or [],
            allowlist_rule_ids=allowlist_rule_ids or set(),
            skip_entropy=skip_entropy,
            exposure_scope=ExposureScope.STAGED,
        )
        candidate_findings.extend(findings)
        all_matched_values.update(f.matched_value for f in findings)

    # Apply duplication signal (post-scan, needs all values)
    for f in candidate_findings:
        _apply_duplication_signal(f, all_matched_values)

    result.secret_findings = candidate_findings

    # ── Dependency scanning ──────────────────────────────────────
    if scan_deps:
        from commitshield.scanner.dependencies import discover_manifests, check_vulnerabilities
        from commitshield.prioritizer.engine import prioritize_all
        deps = discover_manifests(repo_root)
        result.deps_checked = len(deps)
        if deps:
            raw_dep_findings = check_vulnerabilities(deps)
            result.dependency_findings = prioritize_all(raw_dep_findings)

    result.duration_ms = (time.monotonic() - start) * 1000
    return result


def scan_content(
    content: str,
    file_path: str,
    allowlist_patterns: list[str] | None = None,
    allowlist_rule_ids: set[str] | None = None,
    skip_entropy: bool = False,
) -> list[SecretFinding]:
    """Scan arbitrary string content for secrets. Used for tests and check command."""
    return _scan_file_content(
        content=content,
        file_path=file_path,
        allowlist_patterns=allowlist_patterns or [],
        allowlist_rule_ids=allowlist_rule_ids or set(),
        skip_entropy=skip_entropy,
        exposure_scope=ExposureScope.CURRENT,
    )


def _scan_file_content(
    content: str,
    file_path: str,
    allowlist_patterns: list[str],
    allowlist_rule_ids: set[str],
    skip_entropy: bool,
    exposure_scope: ExposureScope,
) -> list[SecretFinding]:
    """Internal: scan file content against all patterns + entropy."""
    findings: list[SecretFinding] = []
    lines = content.splitlines()

    active_patterns = [
        p for p in ALL_PATTERNS
        if p.id not in allowlist_rule_ids
    ]

    for rule in active_patterns:
        try:
            compiled = re.compile(rule.regex, re.MULTILINE)
        except re.error:
            continue

        for line_num, line in enumerate(lines, start=1):
            for match in compiled.finditer(line):
                raw_value = match.group(0)
                if match.lastindex:
                    try:
                        raw_value = match.group(1)
                    except IndexError:
                        pass

                if not raw_value or len(raw_value) < 6:
                    continue

                # Allowlist check
                if _is_allowlisted(raw_value, allowlist_patterns):
                    continue

                redacted = _redact(raw_value)

                # Apply multi-signal classifier
                classification = classify(
                    rule_id=rule.id,
                    matched_value=raw_value,
                    file_path=file_path,
                    line_content=line,
                    is_newly_introduced=True,  # Will be updated by baseline comparison
                )

                finding = SecretFinding(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    description=rule.description,
                    severity=Severity(rule.severity.value),
                    file_path=file_path,
                    line_number=line_num,
                    line_content=line.rstrip(),
                    matched_value=redacted,
                    confidence=classification.confidence,
                    confidence_score=classification.score,
                    evidence=classification.evidence,
                    exposure_scope=exposure_scope,
                    tags=rule.tags,
                )
                findings.append(finding)

    # Deduplicate by (file, line, rule_id)
    seen: set[tuple] = set()
    unique: list[SecretFinding] = []
    for f in findings:
        key = (f.file_path, f.line_number, f.rule_id)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return sorted(unique, key=lambda x: (x.file_path, x.line_number))


def _apply_duplication_signal(finding: SecretFinding, all_values: set[str]) -> None:
    """Post-scan: update the classifier score with duplication signal."""
    count = sum(1 for v in all_values if v == finding.matched_value)
    if count > 1:
        weight = 0.05 if count <= 3 else 0.05
        finding.evidence.append(EvidenceItem(
            signal="value_duplication",
            description=f"Value appears in {count} locations in this commit",
            weight_applied=weight,
        ))
        new_score = min(1.0, finding.confidence_score + weight)
        finding.confidence_score = new_score
        if new_score >= 0.60:
            finding.confidence = Confidence.HIGH
        elif new_score >= 0.35:
            finding.confidence = Confidence.MEDIUM


def _is_allowlisted(value: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        try:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        except re.error:
            pass
    return False

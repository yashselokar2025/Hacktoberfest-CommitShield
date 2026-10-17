"""
Core Finding dataclass — unified model for all security findings in CommitShield.

A Finding carries not just the detection result, but also:
- Evidence: which signals drove the classification
- Confidence: how certain the classifier is
- Change status: NEW / EXISTING / RESOLVED / UNCERTAIN
- Exposure scope: STAGED / CURRENT / HISTORICAL
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    """How certain the multi-signal classifier is about this finding."""
    HIGH = "HIGH"       # Score >= 0.60 — strong evidence, block commit
    MEDIUM = "MEDIUM"   # Score >= 0.35 — plausible, require review
    LOW = "LOW"         # Score < 0.35  — weak match, informational


class ChangeStatus(str, Enum):
    """Whether this finding was introduced by the current change."""
    NEW = "NEW"               # Not in baseline — introduced by this commit
    EXISTING = "EXISTING"     # Already in baseline — not introduced by this commit
    RESOLVED = "RESOLVED"     # Was in baseline but no longer present
    CHANGED = "CHANGED"       # Same location, different value or context
    UNCERTAIN = "UNCERTAIN"   # Cannot reliably classify against baseline


class ExposureScope(str, Enum):
    """Where in the Git timeline this finding exists."""
    STAGED = "STAGED"         # In current staged changes (highest urgency)
    CURRENT = "CURRENT"       # In latest committed files
    HISTORICAL = "HISTORICAL"  # In old commits, removed from current


@dataclass
class EvidenceItem:
    """A single signal that influenced the confidence classification."""
    signal: str           # Signal name (pattern_match, variable_name, etc.)
    description: str      # Human-readable explanation
    weight_applied: float  # Positive = increases confidence, negative = decreases
    value: str = ""       # Optional supporting value (e.g., entropy score)


@dataclass
class SecretFinding:
    """
    A candidate secret exposure with multi-signal evidence.

    This is the core innovation: each finding carries an evidence chain
    explaining WHY the classifier assigned its confidence level.
    """
    # Detection metadata
    rule_id: str
    rule_name: str
    description: str
    severity: Severity

    # Location
    file_path: str
    line_number: int
    line_content: str           # The full line (redacted in reports)
    matched_value: str          # ALWAYS REDACTED before storage/output

    # Multi-signal classifier output (THE INNOVATION)
    confidence: Confidence
    confidence_score: float     # Raw score 0.0–1.0
    evidence: list[EvidenceItem] = field(default_factory=list)

    # Change awareness
    change_status: ChangeStatus = ChangeStatus.UNCERTAIN
    is_newly_introduced: bool = False

    # Exposure scope
    exposure_scope: ExposureScope = ExposureScope.STAGED

    # Git context
    commit_sha: str = ""
    introduced_in_commit: str = ""

    # Finding identity (stable hash for baseline comparison)
    finding_id: str = ""

    # Tags for filtering
    tags: list[str] = field(default_factory=list)
    is_entropy_based: bool = False

    def __post_init__(self):
        if not self.finding_id:
            self.finding_id = self._compute_finding_id()

    def _compute_finding_id(self) -> str:
        """
        Compute a stable finding ID for baseline comparison.
        Based on: file_path + rule_id + redacted_value_hash
        NOT line number (which changes as code evolves).
        """
        # Hash the redacted value to get a stable identifier
        value_hash = hashlib.sha256(self.matched_value.encode()).hexdigest()[:16]
        identity_str = f"{self.file_path}::{self.rule_id}::{value_hash}"
        return hashlib.sha256(identity_str.encode()).hexdigest()[:32]

    @property
    def severity_icon(self) -> str:
        icons = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "⚪",
        }
        return icons.get(self.severity, "?")

    @property
    def confidence_icon(self) -> str:
        return {"HIGH": "●", "MEDIUM": "◐", "LOW": "○"}.get(self.confidence.value, "?")

    @property
    def change_status_icon(self) -> str:
        return {
            ChangeStatus.NEW: "🆕",
            ChangeStatus.EXISTING: "🔄",
            ChangeStatus.RESOLVED: "✅",
            ChangeStatus.CHANGED: "🔀",
            ChangeStatus.UNCERTAIN: "❓",
        }.get(self.change_status, "?")

    def to_dict(self) -> dict:
        """Serialize to dict — safe for JSON export (no raw secrets)."""
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "confidence_score": round(self.confidence_score, 3),
            "change_status": self.change_status.value,
            "exposure_scope": self.exposure_scope.value,
            "file": self.file_path,
            "line": self.line_number,
            "matched_value": self.matched_value,  # already redacted
            "is_newly_introduced": self.is_newly_introduced,
            "evidence": [
                {
                    "signal": e.signal,
                    "description": e.description,
                    "weight": round(e.weight_applied, 3),
                }
                for e in self.evidence
            ],
            "tags": self.tags,
        }


@dataclass
class DependencyFinding:
    """A vulnerable dependency with evidence-based risk prioritization."""
    package_name: str
    version: str
    ecosystem: str  # "PyPI" or "npm"
    cve_ids: list[str]
    osv_ids: list[str]
    advisory_severity: str      # Raw severity from CVE database
    priority: str               # CommitShield's computed priority (with modifiers)
    priority_score: float       # Raw computed score

    summary: str
    references: list[str] = field(default_factory=list)

    # Change awareness — the key innovation for deps
    is_newly_introduced: bool = False  # Not in previous lockfile?
    is_direct_dependency: bool = True  # Direct vs transitive
    fixed_version_available: str = ""  # If empty = no fix known
    exploit_available: bool = False    # EPSS or known exploit in the wild

    # Prioritizer evidence chain
    priority_reasons: list[str] = field(default_factory=list)

    # Source manifest
    source_file: str = ""
    finding_id: str = ""

    def __post_init__(self):
        if not self.finding_id:
            id_str = f"{self.package_name}::{self.version}::{self.ecosystem}"
            self.finding_id = hashlib.sha256(id_str.encode()).hexdigest()[:32]

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "package": self.package_name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "advisory_severity": self.advisory_severity,
            "priority": self.priority,
            "priority_score": round(self.priority_score, 3),
            "cve_ids": self.cve_ids,
            "osv_ids": self.osv_ids,
            "summary": self.summary,
            "is_newly_introduced": self.is_newly_introduced,
            "is_direct_dependency": self.is_direct_dependency,
            "fixed_version_available": self.fixed_version_available,
            "exploit_available": self.exploit_available,
            "priority_reasons": self.priority_reasons,
        }


@dataclass
class ScanResult:
    """Complete result of a CommitShield scan."""
    secret_findings: list[SecretFinding] = field(default_factory=list)
    dependency_findings: list[DependencyFinding] = field(default_factory=list)
    files_scanned: int = 0
    deps_checked: int = 0
    duration_ms: float = 0.0
    scan_mode: str = "staged"  # staged / full / history
    base_revision: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def new_secret_findings(self) -> list[SecretFinding]:
        return [f for f in self.secret_findings if f.change_status == ChangeStatus.NEW]

    @property
    def existing_secret_findings(self) -> list[SecretFinding]:
        return [f for f in self.secret_findings if f.change_status == ChangeStatus.EXISTING]

    @property
    def resolved_secret_findings(self) -> list[SecretFinding]:
        return [f for f in self.secret_findings if f.change_status == ChangeStatus.RESOLVED]

    @property
    def new_dep_findings(self) -> list[DependencyFinding]:
        return [f for f in self.dependency_findings if f.is_newly_introduced]

    @property
    def should_block(self) -> bool:
        """True if this scan result warrants blocking the commit."""
        # Block on HIGH/MEDIUM confidence NEW secrets
        blocking_secrets = [
            f for f in self.new_secret_findings
            if f.confidence in (Confidence.HIGH, Confidence.MEDIUM)
        ]
        # Block on CRITICAL/HIGH priority newly-introduced deps
        blocking_deps = [
            f for f in self.new_dep_findings
            if f.priority in ("CRITICAL", "HIGH")
        ]
        return bool(blocking_secrets or blocking_deps)

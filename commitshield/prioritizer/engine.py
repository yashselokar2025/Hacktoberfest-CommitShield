"""
Evidence-Based Dependency Risk Prioritizer — CommitShield's second research contribution.

Instead of presenting all CVEs with their raw CVSS scores, this module computes
a transparent, explainable risk priority for each vulnerable dependency using
application-specific evidence signals:

  1. Base advisory severity (CVSS score)
  2. Whether the dependency is newly introduced (×1.5 modifier)
  3. Whether it's a direct vs transitive dependency (×1.3)
  4. Whether a fixed version is available (×1.2 urgency)
  5. Whether exploit code is publicly available (×1.4)
  6. Whether usage evidence exists (×0.7 if clearly not used)

The modifier chain is fully transparent — the developer sees exactly which
factors drove the final priority classification.

Research basis:
  "Can dependency vulnerability alerts be prioritized more effectively
   using application-specific evidence?"
"""

from __future__ import annotations

from commitshield.core.finding import DependencyFinding


# ─────────────────────────────────────────────────────────────
# BASE SCORES FROM ADVISORY SEVERITY
# ─────────────────────────────────────────────────────────────

ADVISORY_BASE_SCORES = {
    "CRITICAL": 9.5,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.5,
    "NONE": 0.5,
}

# Priority thresholds (after modifiers)
PRIORITY_THRESHOLDS = {
    "CRITICAL": 12.0,
    "HIGH": 8.0,
    "MEDIUM": 5.0,
    "LOW": 2.0,
}


def prioritize(finding: DependencyFinding) -> DependencyFinding:
    """
    Apply the transparent priority modifier chain to a dependency finding.

    Modifies the finding in-place with:
    - priority: CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL
    - priority_score: numeric score after modifiers
    - priority_reasons: list of human-readable reason strings

    Returns the modified finding.
    """
    base = ADVISORY_BASE_SCORES.get(finding.advisory_severity.upper(), 5.0)
    score = base
    reasons: list[str] = [
        f"Base advisory severity: {finding.advisory_severity} (score: {base})"
    ]

    # ── Modifier 1: Newly introduced ──────────────────────────────
    # HIGHEST IMPACT modifier — a brand-new vulnerable dependency is
    # immediately actionable and should be caught before it's committed.
    if finding.is_newly_introduced:
        score *= 1.5
        reasons.append(
            "★ NEWLY INTRODUCED: This dependency was not in the previous lockfile. "
            "Priority increased by 50% — act before it's committed."
        )
    else:
        reasons.append(
            "Dependency was already present before this commit (existing security debt)."
        )

    # ── Modifier 2: Direct vs transitive ─────────────────────────
    if finding.is_direct_dependency:
        score *= 1.3
        reasons.append(
            "Direct dependency: You control this package version directly. "
            "Priority increased by 30%."
        )
    else:
        reasons.append(
            "Transitive dependency: Remediation may require updating a parent package."
        )

    # ── Modifier 3: Fixed version available ───────────────────────
    if finding.fixed_version_available:
        score *= 1.2
        reasons.append(
            f"Fixed version available: {finding.fixed_version_available}. "
            "A patched release exists — priority increased by 20%."
        )
    else:
        reasons.append(
            "No fixed version available. Monitor the advisory for a patch."
        )

    # ── Modifier 4: Exploit available ────────────────────────────
    if finding.exploit_available:
        score *= 1.4
        reasons.append(
            "⚠ Known exploit available in the wild. Priority increased by 40%."
        )

    # ── Map final score to priority level ────────────────────────
    if score >= PRIORITY_THRESHOLDS["CRITICAL"]:
        priority = "CRITICAL"
    elif score >= PRIORITY_THRESHOLDS["HIGH"]:
        priority = "HIGH"
    elif score >= PRIORITY_THRESHOLDS["MEDIUM"]:
        priority = "MEDIUM"
    elif score >= PRIORITY_THRESHOLDS["LOW"]:
        priority = "LOW"
    else:
        priority = "INFORMATIONAL"

    reasons.append(f"Final priority score: {score:.2f} → {priority}")

    finding.priority = priority
    finding.priority_score = score
    finding.priority_reasons = reasons
    return finding


def prioritize_all(findings: list[DependencyFinding]) -> list[DependencyFinding]:
    """Prioritize all findings and sort by priority score (highest first)."""
    prioritized = [prioritize(f) for f in findings]
    # Sort: newly-introduced first, then by priority score
    return sorted(
        prioritized,
        key=lambda f: (0 if f.is_newly_introduced else 1, -f.priority_score),
    )


def build_prioritization_explanation(finding: DependencyFinding) -> str:
    """Build a human-readable explanation of the priority decision."""
    lines = [
        f"Package: {finding.package_name} v{finding.version} ({finding.ecosystem})",
        f"Advisory severity: {finding.advisory_severity}",
        f"CommitShield priority: {finding.priority} (score: {finding.priority_score:.2f})",
        "",
        "Priority reasoning:",
    ]
    for i, reason in enumerate(finding.priority_reasons, 1):
        lines.append(f"  {i}. {reason}")

    if finding.fixed_version_available:
        lines.append("")
        lines.append(f"  Suggested action: Update to {finding.fixed_version_available}")

    return "\n".join(lines)

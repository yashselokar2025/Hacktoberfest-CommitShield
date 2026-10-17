"""
Terminal reporter — rich, evidence-first output for CommitShield.

Key design principle: Show WHAT CHANGED, not all 20 existing findings.
New findings shown prominently; existing findings collapsed to a summary.

v2 functions: work with CandidateFinding + ClassificationResult (post-processor arch).
v1 functions: kept for backward-compat with ScanResult-based code.
"""

from __future__ import annotations

import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

# Force UTF-8 on Windows so emoji/box-drawing don't crash
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console(stderr=True, highlight=False)

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange1",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold cyan",
    "INFO":     "dim white",
}

CONFIDENCE_COLORS = {
    "HIGH":   "bold red",
    "MEDIUM": "bold yellow",
    "LOW":    "dim white",
}


# ─────────────────────────────────────────────────────────────
# v2 API  (post-processor architecture, CandidateFinding-based)
# ─────────────────────────────────────────────────────────────

def print_banner(version: str = "1.0.0") -> None:
    console.print(Panel.fit(
        f"[bold white]CommitShield[/bold white] [dim]v{version}[/dim]  *  "
        "[dim]Evidence-Based Change-Aware Security Gate[/dim]",
        border_style="bright_blue",
        padding=(0, 2),
    ))


def print_scan_overview_v2(new_findings: list, existing_findings: list) -> None:
    """Summary line: what changed vs what was already known."""
    n_new = len(new_findings)
    n_existing = len(existing_findings)

    console.print()
    if n_new == 0:
        console.print("  [bold green]OK  No new security risks introduced by this commit.[/bold green]")
        if n_existing:
            console.print(
                f"  [dim]INFO {n_existing} pre-existing finding(s) in baseline -- "
                "not introduced by this change.[/dim]"
            )
    else:
        console.print(f"  [bold red]NEW  {n_new} new finding(s) introduced by this commit[/bold red]")
        if n_existing:
            console.print(
                f"  [dim]SKIP {n_existing} pre-existing finding(s) suppressed "
                "(already in baseline)[/dim]"
            )


def print_new_findings_v2(findings: list) -> None:
    """Full evidence chain for each NEW finding."""
    if not findings:
        return

    console.print()
    console.print(Panel(
        f"[bold red]>> {len(findings)} NEW Secret Finding(s) -- Introduced by This Commit[/bold red]",
        border_style="red",
        padding=(0, 1),
    ))

    for i, f in enumerate(findings, 1):
        result = f._classification
        conf_color = CONFIDENCE_COLORS.get(result.confidence_label, "white")
        urg_color  = SEVERITY_COLORS.get(result.urgency, "white")

        console.print(
            f"\n  [{i}] [{urg_color}]{result.urgency}[/{urg_color}]  "
            f"[bold white]{f.rule_id}[/bold white]  "
            f"[dim]{f.rule_description}[/dim]"
        )
        console.print(f"      File : [cyan]{f.file_path}[/cyan]:[dim]{f.line_number}[/dim]")

        # Show redacted value
        snippet = (f.line_content or "").strip()[:120]
        if snippet:
            console.print(f"      Line : [italic dim]{snippet}[/italic dim]")
        console.print(f"      Value: [bold yellow]{f.matched_value}[/bold yellow]")

        # Confidence + probability
        hard_tag = " [dim](hard-block rule)[/dim]" if result.is_hard_block else ""
        console.print(
            f"\n      Confidence : [{conf_color}]{result.confidence_label}[/{conf_color}]"
            f"  P(secret)=[bold]{result.prob_secret:.3f}[/bold]{hard_tag}"
        )

        # Evidence chain — the core contribution
        if result.evidence:
            console.print("      Evidence   :")
            for ev in result.evidence[:5]:
                sign   = "+" if ev.contribution >= 0 else ""
                color  = "green" if ev.contribution > 0.1 else "red" if ev.contribution < -0.1 else "dim"
                contrib_str = f"[{color}]{sign}{ev.contribution:.2f}[/{color}]"
                console.print(
                    f"        {contrib_str}  [dim]{ev.feature:<28}[/dim]  {ev.description}"
                )

        # Change status badge
        status = getattr(f, "_change_status", "NEW")
        if status == "NEW":
            console.print("      Status     : [bold red]NEW[/bold red] -- not in baseline")

        # Gemma Semantic Auditor second opinion
        gemma_audit = getattr(f, "_gemma_audit", None)
        if gemma_audit:
            g_verdict = "[bold red]REAL LEAK[/bold red]" if gemma_audit.is_real_secret else "[bold green]FALSE POSITIVE[/bold green]"
            console.print(
                f"\n      [bold magenta]🤖 Gemma LLM Audit[/bold magenta] ({gemma_audit.model_used}): {g_verdict} "
                f"[dim](conf: {gemma_audit.confidence:.2f})[/dim]"
            )
            console.print(f"      [dim]Reasoning  : {gemma_audit.reasoning}[/dim]")
            if gemma_audit.remediation_suggestion:
                console.print(f"      [bold cyan]Fix        : {gemma_audit.remediation_suggestion}[/bold cyan]")

    console.print()



def print_existing_summary(findings: list) -> None:
    """Collapsed one-liner for pre-existing findings."""
    if not findings:
        return
    console.print(
        f"\n  [dim]--- {len(findings)} pre-existing finding(s) in baseline "
        "(suppressed -- not introduced by this commit)[/dim]"
    )
    console.print(
        "  [dim]    Run 'commitshield history' to review all known findings.[/dim]"
    )


def print_final_verdict_v2(
    new_count: int,
    existing_count: int,
    should_block: bool,
    duration_ms: float,
) -> None:
    """Final PASS / BLOCK verdict panel."""
    console.print()
    if should_block:
        status = "[bold red]BLOCKED -- This commit contains new high-confidence security risks[/bold red]"
        border = "red"
    else:
        status = "[bold green]PASSED -- No new high-confidence security risks introduced[/bold green]"
        border = "green"

    new_str      = f"[bold red]{new_count}[/bold red]" if new_count else "[green]0[/green]"
    existing_str = f"[dim]{existing_count}[/dim]"

    console.print(Panel(
        f"{status}\n\n"
        f"  New findings (this commit):  {new_str}\n"
        f"  Existing (suppressed):       {existing_str}\n"
        f"  Scan duration:               [dim]{duration_ms:.0f}ms[/dim]",
        border_style=border,
        padding=(0, 2),
    ))

    if should_block:
        console.print(
            "  [dim]To bypass (use responsibly):   git commit --no-verify[/dim]\n"
            "  [dim]To suppress a finding: add to .commitshield.yaml allowlist.[/dim]"
        )


# ─────────────────────────────────────────────────────────────
# v1 API  (kept for backward compat with ScanResult-based code)
# ─────────────────────────────────────────────────────────────

def print_scan_overview(result) -> None:
    """v1: ScanResult-based overview."""
    try:
        from commitshield.core.finding import ScanResult
        new_s = len(result.new_secret_findings)
        existing_s = len(result.existing_secret_findings)
        resolved_s = len(result.resolved_secret_findings)
        new_d = len(result.new_dep_findings)
    except Exception:
        console.print("[dim]Scan complete.[/dim]")
        return

    if new_s == 0 and new_d == 0 and resolved_s == 0:
        console.print("\n  [bold green]OK  No new security risks introduced.[/bold green]")
        if existing_s:
            console.print(f"  [dim]INFO {existing_s} pre-existing finding(s) in baseline.[/dim]")
        return

    console.print()
    if new_s:
        console.print(f"  [bold red]NEW  {new_s} new secret finding(s)[/bold red]")
    if new_d:
        console.print(f"  [bold orange1]NEW  {new_d} new vulnerable dependency(ies)[/bold orange1]")
    if existing_s:
        console.print(f"  [dim]SKIP {existing_s} existing finding(s) already in baseline[/dim]")
    if resolved_s:
        console.print(f"  [bold green]RESOLVED  {resolved_s} previously found secret(s)[/bold green]")


def print_new_secret_findings(findings: list) -> None:
    """v1: SecretFinding-based full output."""
    if not findings:
        return
    console.print()
    console.print(Panel(
        f"[bold red]>> {len(findings)} NEW Secret Finding(s)[/bold red]",
        border_style="red", padding=(0, 1),
    ))
    for i, f in enumerate(findings, 1):
        try:
            sev_color  = SEVERITY_COLORS.get(f.severity.value, "white")
            conf_color = CONFIDENCE_COLORS.get(f.confidence.value, "white")
            console.print(
                f"\n  [{i}] [{sev_color}]{f.severity.value}[/{sev_color}]  "
                f"[bold white]{f.rule_name}[/bold white]"
            )
            console.print(f"      [cyan]{f.file_path}[/cyan]:{f.line_number}")
            console.print(f"      Confidence: [{conf_color}]{f.confidence.value}[/{conf_color}] "
                          f"(score: {f.confidence_score:.2f})")
            for ev in (f.evidence or [])[:4]:
                sign  = "+" if ev.weight_applied >= 0 else ""
                color = "green" if ev.weight_applied > 0 else "red"
                console.print(f"        [{color}]{sign}{ev.weight_applied:.2f}[/{color}]  {ev.description}")
        except AttributeError:
            console.print(f"  [{i}] {f}")


def print_existing_findings_summary(findings: list) -> None:
    """v1: Collapsed summary for pre-existing findings."""
    if not findings:
        return
    console.print(
        f"\n  [dim]--- {len(findings)} pre-existing finding(s) in baseline (suppressed)[/dim]"
    )


def print_final_verdict(result, duration_ms: float) -> None:
    """v1: ScanResult-based final verdict."""
    try:
        blocked = result.should_block
        new_s   = len(result.new_secret_findings)
        exist_s = len(result.existing_secret_findings)
        resolved_s = len(result.resolved_secret_findings)
    except AttributeError:
        console.print("[dim]Scan complete.[/dim]")
        return

    status = (
        "[bold red]BLOCKED[/bold red]" if blocked
        else "[bold green]PASSED[/bold green]"
    )
    border = "red" if blocked else "green"
    console.print(Panel(
        f"{status}\n\n"
        f"  New secret findings: {'[bold red]' + str(new_s) + '[/bold red]' if new_s else '[green]0[/green]'}\n"
        f"  Existing (suppressed): [dim]{exist_s}[/dim]\n"
        f"  Resolved: [green]{resolved_s}[/green]\n"
        f"  Duration: [dim]{duration_ms:.0f}ms[/dim]",
        border_style=border, padding=(0, 2),
    ))

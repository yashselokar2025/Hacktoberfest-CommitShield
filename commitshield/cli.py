"""
CommitShield CLI — Evidence-based, change-aware security gate for Git.

Architecture: Post-processor on Gitleaks JSON output.
Gitleaks detects; CommitShield classifies and explains.

Commands:
  scan      — Scan staged files (calls Gitleaks, then re-scores with LR classifier)
  check     — Scan arbitrary file or text
  train     — Train the LR classifier on SecretBench
  history   — Show finding history for this repo
  baseline  — Manage the finding baseline (clear, export)
  install   — Install pre-commit hook
  uninstall — Remove pre-commit hook
  model     — Show current classifier model information
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

err_console = Console(stderr=True)


@click.group()
@click.version_option(version="1.0.0", prog_name="CommitShield")
def main() -> None:
    """
    CommitShield — Evidence-based, change-aware security gate.

    Post-processor on Gitleaks: classifies each finding using 7 evidence
    signals (logistic regression), compares against baseline (NEW/EXISTING/RESOLVED),
    and outputs explainable confidence per finding.

    Quick start:
      commitshield install              # Install pre-commit hook
      commitshield scan                 # Scan staged files
      commitshield train --csv ...      # Train on SecretBench

    Research:
      commitshield model                # Show classifier coefficients
    """
    pass


# ─────────────────────────────────────────────────────────────────────
# scan
# ─────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--gitleaks-path", default="gitleaks", envvar="COMMITSHIELD_GITLEAKS_PATH",
              show_default=True, help="Path to Gitleaks binary.")
@click.option("--threshold", type=float, default=0.35,
              help="Minimum P(secret) to surface a finding [0.0–1.0].")
@click.option("--block-threshold", type=float, default=0.70,
              help="P(secret) threshold to block the commit.")
@click.option("--verify", is_flag=True, default=False,
              help="Opt-in: verify credentials via provider APIs (sends data to third parties).")
@click.option("--gemma/--no-gemma", default=True,
              help="Enable Gemma LLM semantic auditor for contextual second-opinion.")
@click.option("--gemma-model", default="gemma2:2b",
              help="Gemma model variant (e.g. gemma2:2b, gemma2:9b).")
@click.option("--no-baseline", is_flag=True, default=False,
              help="Skip baseline comparison (treat all findings as NEW).")
@click.option("--output", type=click.Choice(["terminal", "json", "sarif"]),
              default="terminal", help="Output format.")
@click.option("--save-baseline/--no-save-baseline", default=True,
              help="Save new findings to local baseline store.")
@click.pass_context
def scan(
    ctx: click.Context,
    gitleaks_path: str,
    threshold: float,
    block_threshold: float,
    verify: bool,
    gemma: bool,
    gemma_model: str,
    no_baseline: bool,
    output: str,
    save_baseline: bool,
) -> None:
    """Scan staged files for secrets (pre-commit mode)."""
    from commitshield.ingest.gitleaks import run_gitleaks_on_staged, get_staged_diff_context
    from commitshield.model.classifier import CommitShieldClassifier
    from commitshield.model.gemma_auditor import GemmaAuditor
    from commitshield.baseline.store import BaselineStore

    from commitshield.git.staged import get_repo_root, get_base_revision
    from commitshield.report.terminal import (
        print_banner, print_scan_overview_v2, print_new_findings_v2,
        print_existing_summary, print_final_verdict_v2,
    )
    import time

    start = time.monotonic()

    if output == "terminal":
        print_banner()

    # Step 1: Run Gitleaks
    err_console.print("[dim]  Running Gitleaks on staged files...[/dim]")
    raw_findings = run_gitleaks_on_staged(gitleaks_path)

    if not raw_findings:
        err_console.print(
            "\n  [bold green]✓ Gitleaks found no candidates in staged files.[/bold green]"
        )
        sys.exit(0)

    err_console.print(
        f"  [dim]Gitleaks found {len(raw_findings)} candidate(s). "
        "Running CommitShield classifier...[/dim]"
    )

    # Step 2: Classify with logistic regression
    classifier = CommitShieldClassifier()
    all_values = [f.secret for f in raw_findings]

    classified = []
    for finding in raw_findings:
        context = get_staged_diff_context(finding.file_path)
        context_lines = context.get(finding.line_number, [])

        result = classifier.classify(
            rule_id=finding.rule_id,
            value=finding.secret,
            file_path=finding.file_path,
            line_content=finding.line_content,
            context_lines=context_lines,
            is_newly_introduced=True,  # Will be updated by baseline
            all_values=all_values,
        )
        finding._classification = result
        classified.append(finding)

    # Step 3: Filter by threshold
    surfaced = [
        f for f in classified
        if (f._classification.prob_secret >= threshold
            or f._classification.is_hard_block)
    ]

    # Step 4: Baseline comparison (NEW/EXISTING/RESOLVED)
    repo_root = get_repo_root()
    repo_path = str(repo_root) if repo_root else "."

    new_findings = []
    existing_findings = []

    if not no_baseline:
        store = BaselineStore()
        known_ids = store.load_known_ids(repo_path)
        for f in surfaced:
            if f.finding_id in known_ids:
                f._change_status = "EXISTING"
                existing_findings.append(f)
            else:
                f._change_status = "NEW"
                new_findings.append(f)
        if save_baseline:
            store.save_new(new_findings, repo_path)
    else:
        new_findings = surfaced
        for f in new_findings:
            f._change_status = "NEW"

    # Step 5: Optional Gemma Semantic Second-Opinion Audit
    if gemma and new_findings:
        err_console.print(f"  [dim]Invoking Gemma ({gemma_model}) contextual audit...[/dim]")
        auditor = GemmaAuditor(model_name=gemma_model)
        for f in new_findings:
            context = get_staged_diff_context(f.file_path)
            context_lines = context.get(f.line_number, [])
            g_res = auditor.audit(
                rule_id=f.rule_id,
                masked_token=f.matched_value,
                file_path=f.file_path,
                line_content=f.line_content,
                context_lines=context_lines,
            )
            f._gemma_audit = g_res

    # Step 6: Determine if we should block
    blocking = [
        f for f in new_findings
        if (f._classification.prob_secret >= block_threshold
            or f._classification.is_hard_block)
    ]
    should_block = bool(blocking)


    duration_ms = (time.monotonic() - start) * 1000

    # Step 6: Output
    if output == "terminal":
        print_scan_overview_v2(new_findings, existing_findings)
        print_new_findings_v2(new_findings)
        print_existing_summary(existing_findings)
        print_final_verdict_v2(
            new_count=len(new_findings),
            existing_count=len(existing_findings),
            should_block=should_block,
            duration_ms=duration_ms,
        )
    elif output == "json":
        import json
        data = {
            "new_findings": [_finding_to_dict(f) for f in new_findings],
            "existing_findings": [_finding_to_dict(f) for f in existing_findings],
            "should_block": should_block,
            "scan_duration_ms": duration_ms,
        }
        click.echo(json.dumps(data, indent=2))
    elif output == "sarif":
        from commitshield.report.sarif import generate_sarif
        click.echo(generate_sarif(new_findings))

    sys.exit(1 if should_block else 0)


def _finding_to_dict(f) -> dict:
    c = f._classification
    ret = {
        "rule_id": f.rule_id,

        "file": f.file_path,
        "line": f.line_number,
        "matched_value": f.matched_value,
        "prob_secret": round(c.prob_secret, 4),
        "confidence": c.confidence_label,
        "urgency": c.urgency,
        "is_hard_block": c.is_hard_block,
        "change_status": getattr(f, "_change_status", "UNKNOWN"),
        "evidence": [
            {"feature": e.feature, "description": e.description,
             "coefficient": round(e.coefficient, 3), "contribution": round(e.contribution, 3)}
            for e in c.evidence
        ],
    }
    gemma_audit = getattr(f, "_gemma_audit", None)
    if gemma_audit:
        ret["gemma_audit"] = {
            "is_real_secret": gemma_audit.is_real_secret,
            "confidence": gemma_audit.confidence,
            "reasoning": gemma_audit.reasoning,
            "remediation": gemma_audit.remediation_suggestion,
            "model": gemma_audit.model_used,
        }
    return ret



# ─────────────────────────────────────────────────────────────────────
# train
# ─────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("train_json", type=click.Path(exists=True))
@click.option("--model-path", type=click.Path(), default=None,
              help="Where to save the trained model.")
def train(train_json: str, model_path: str | None) -> None:
    """
    Train the logistic regression classifier on SecretBench.

    TRAIN_JSON: Path to train.json output from prepare_dataset.py.

    Example:
      commitshield train experiments/secretbench/train.json
    """
    import json
    from pathlib import Path as P
    from commitshield.model.features import build_feature_vector
    from commitshield.model.classifier import train_model, DEFAULT_MODEL_PATH

    data = json.loads(P(train_json).read_text())
    err_console.print(f"  Loaded {len(data)} training examples.")

    X, y = [], []
    for ex in data:
        fv = build_feature_vector(
            rule_id=ex.get("rule_id", ""),
            value=ex.get("value", ""),
            file_path=ex.get("file_path", ""),
            line_content=ex.get("line_content", ""),
            context_lines=[],
            is_newly_introduced=False,
            all_values=[],
        )
        X.append(fv)
        y.append(ex["label"])

    out = P(model_path) if model_path else DEFAULT_MODEL_PATH
    err_console.print(f"  Training logistic regression on {len(X)} examples...")
    results = train_model(X, y, out)

    err_console.print("\n  ── Training results (5-fold CV) ──")
    err_console.print(f"  Precision: {results['precision']:.4f}")
    err_console.print(f"  Recall:    {results['recall']:.4f}")
    err_console.print(f"  F1:        {results['f1']:.4f}")
    err_console.print(f"\n  Learned coefficients (feature importance):")
    for name, coef in results["coefficients"].items():
        sign = "+" if coef >= 0 else ""
        err_console.print(f"    {name:<30} {sign}{coef:.4f}")
    err_console.print(f"\n  Model saved: {out}")


# ─────────────────────────────────────────────────────────────────────
# model
# ─────────────────────────────────────────────────────────────────────

@main.command()
def model() -> None:
    """Show current classifier model information and coefficients."""
    from commitshield.model.classifier import CommitShieldClassifier
    import json
    clf = CommitShieldClassifier()
    info = clf.get_model_info()
    err_console.print(f"\n  Mode: {info['mode']}")
    err_console.print(f"  Note: {info['note']}")
    err_console.print(f"\n  Thresholds:")
    err_console.print(f"    BLOCK:  P(secret) ≥ {info['threshold_high']}")
    err_console.print(f"    WARN:   P(secret) ≥ {info['threshold_medium']}")
    err_console.print(f"\n  Coefficients (learned feature weights):")
    for name, coef in info["coefficients"].items():
        bar = "▓" * int(abs(coef) * 10)
        sign = "+" if coef >= 0 else ""
        err_console.print(f"    {name:<30} {sign}{coef:.4f}  {bar}")


# ─────────────────────────────────────────────────────────────────────
# install / uninstall
# ─────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--repo", type=click.Path(), default=".", help="Repository root.")
def install(repo: str) -> None:
    """Install CommitShield as a pre-commit hook."""
    from commitshield.git.hooks import install_hook
    result = install_hook(Path(repo))
    if result:
        err_console.print(f"  [green]✓ Hook installed: {result}[/green]")
    else:
        err_console.print("  [red]✗ Failed to install hook.[/red]")
        sys.exit(1)


@main.command()
@click.option("--repo", type=click.Path(), default=".", help="Repository root.")
def uninstall(repo: str) -> None:
    """Remove the CommitShield pre-commit hook."""
    from commitshield.git.hooks import uninstall_hook
    uninstall_hook(Path(repo))
    err_console.print("  [green]✓ Hook removed.[/green]")


# ─────────────────────────────────────────────────────────────────────
# history
# ─────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--repo", type=click.Path(), default=".", help="Repository root.")
@click.option("--limit", type=int, default=20, help="Number of recent scans to show.")
def history(repo: str, limit: int) -> None:
    """Show finding history and scan timeline for this repository."""
    from commitshield.baseline.store import BaselineStore
    import json
    store = BaselineStore()
    scans = store.get_scan_history(str(Path(repo).resolve()), limit=limit)
    if not scans:
        err_console.print("  No scan history found.")
        return
    for scan in scans:
        err_console.print(
            f"  {scan.get('scanned_at', '?')[:19]}  "
            f"mode={scan.get('scan_mode', '?'):<8}  "
            f"new={scan.get('new_findings', 0)}  "
            f"resolved={scan.get('resolved_findings', 0)}"
        )


if __name__ == "__main__":
    main()

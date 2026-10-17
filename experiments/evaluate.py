"""
CommitShield Evaluation Harness — Research Validation System

Runs the three-approach experiment:
  Approach A: Pattern-only detection (baseline, no context)
  Approach B: Pattern + entropy (like detect-secrets)
  Approach C: CommitShield full multi-signal classifier

Measures: Precision, Recall, F1, False-Positive Rate, False-Negative Count

Usage:
  python experiments/evaluate.py --dataset experiments/dataset/
  python experiments/evaluate.py --approach A  # single approach
  python experiments/evaluate.py --compare     # full A vs B vs C comparison

This is the experimental validation required to substantiate the research claim:
  "CommitShield's multi-signal classifier improves precision over pattern-only
   scanning while maintaining comparable recall."
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


@dataclass
class LabeledExample:
    """A single labeled test case from the dataset."""
    file_path: str
    content: str
    line_number: int
    line_content: str
    label: Literal["TRUE_POSITIVE", "FALSE_POSITIVE"]  # Ground truth
    secret_type: str     # e.g., "aws_key", "placeholder", "test_fixture"
    notes: str = ""


@dataclass
class DetectionResult:
    file_path: str
    line_number: int
    rule_id: str
    confidence: str  # HIGH / MEDIUM / LOW
    score: float


@dataclass
class EvalMetrics:
    approach: str
    tp: int  # True positives (correctly flagged genuine secrets)
    fp: int  # False positives (incorrectly flagged non-secrets)
    tn: int  # True negatives (correctly ignored non-secrets)
    fn: int  # False negatives (missed genuine secrets)
    precision: float
    recall: float
    f1: float
    fpr: float  # False positive rate = FP / (FP + TN)

    def display(self) -> str:
        return (
            f"\n  Approach: {self.approach}\n"
            f"  TP={self.tp}  FP={self.fp}  TN={self.tn}  FN={self.fn}\n"
            f"  Precision: {self.precision:.3f}  Recall: {self.recall:.3f}  "
            f"F1: {self.f1:.3f}  FPR: {self.fpr:.3f}"
        )


def load_dataset(dataset_dir: Path) -> list[LabeledExample]:
    """Load labeled examples from the dataset directory."""
    examples: list[LabeledExample] = []

    manifest_path = dataset_dir / "manifest.json"
    if not manifest_path.exists():
        print(f"[ERROR] Dataset manifest not found: {manifest_path}")
        print("Run: python experiments/build_dataset.py to generate the dataset")
        return []

    manifest = json.loads(manifest_path.read_text())
    for entry in manifest["examples"]:
        file_path = dataset_dir / entry["file"]
        if not file_path.exists():
            continue
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        examples.append(LabeledExample(
            file_path=str(file_path),
            content=content,
            line_number=entry["line"],
            line_content=entry.get("line_content", ""),
            label=entry["label"],
            secret_type=entry["secret_type"],
            notes=entry.get("notes", ""),
        ))

    return examples


# ─────────────────────────────────────────────────────────────
# APPROACH A: Pattern-only (baseline)
# ─────────────────────────────────────────────────────────────

def detect_approach_a(examples: list[LabeledExample]) -> list[DetectionResult]:
    """
    Approach A: Pure pattern matching, no context analysis.
    Equivalent to Gitleaks default config behavior.
    """
    from commitshield.scanner.patterns import ALL_PATTERNS
    results = []
    for ex in examples:
        for rule in ALL_PATTERNS:
            try:
                m = re.search(rule.regex, ex.line_content, re.IGNORECASE)
            except re.error:
                continue
            if m:
                results.append(DetectionResult(
                    file_path=ex.file_path,
                    line_number=ex.line_number,
                    rule_id=rule.id,
                    confidence="HIGH",   # Approach A has no confidence calibration
                    score=1.0,
                ))
                break   # One match per line for approach A
    return results


# ─────────────────────────────────────────────────────────────
# APPROACH B: Pattern + entropy (detect-secrets style)
# ─────────────────────────────────────────────────────────────

def detect_approach_b(examples: list[LabeledExample]) -> list[DetectionResult]:
    """
    Approach B: Pattern matching + Shannon entropy (like detect-secrets).
    No semantic context analysis.
    """
    import math
    from commitshield.scanner.patterns import ALL_PATTERNS

    def entropy(value: str) -> float:
        if not value:
            return 0.0
        freq = {}
        for c in value:
            freq[c] = freq.get(c, 0) + 1
        total = len(value)
        return -sum((n/total) * math.log2(n/total) for n in freq.values() if n > 0)

    results = []
    for ex in examples:
        matched = False
        for rule in ALL_PATTERNS:
            try:
                m = re.search(rule.regex, ex.line_content, re.IGNORECASE)
            except re.error:
                continue
            if m:
                raw = m.group(0)
                ent = entropy(raw)
                # Basic entropy filter: suppress if entropy < 3.0 (likely placeholder)
                if ent < 3.0 and len(raw) < 30:
                    continue
                results.append(DetectionResult(
                    file_path=ex.file_path,
                    line_number=ex.line_number,
                    rule_id=rule.id,
                    confidence="HIGH" if ent > 4.5 else "MEDIUM",
                    score=min(1.0, ent / 5.0),
                ))
                matched = True
                break
    return results


# ─────────────────────────────────────────────────────────────
# APPROACH C: CommitShield full multi-signal classifier
# ─────────────────────────────────────────────────────────────

def detect_approach_c(examples: list[LabeledExample]) -> list[DetectionResult]:
    """
    Approach C: CommitShield multi-signal context classifier.
    Uses all 7 evidence signals with explainable confidence scoring.
    """
    from commitshield.scanner.patterns import ALL_PATTERNS
    from commitshield.scanner.classifier import classify

    results = []
    for ex in examples:
        for rule in ALL_PATTERNS:
            try:
                m = re.search(rule.regex, ex.line_content, re.IGNORECASE)
            except re.error:
                continue
            if m:
                raw = m.group(0)
                classification = classify(
                    rule_id=rule.id,
                    matched_value=raw,
                    file_path=ex.file_path,
                    line_content=ex.line_content,
                    is_newly_introduced=True,
                )
                # CommitShield only surfaces HIGH and MEDIUM confidence
                if classification.confidence.value in ("HIGH", "MEDIUM"):
                    results.append(DetectionResult(
                        file_path=ex.file_path,
                        line_number=ex.line_number,
                        rule_id=rule.id,
                        confidence=classification.confidence.value,
                        score=classification.score,
                    ))
                break
    return results


# ─────────────────────────────────────────────────────────────
# METRICS COMPUTATION
# ─────────────────────────────────────────────────────────────

def compute_metrics(
    approach: str,
    detections: list[DetectionResult],
    examples: list[LabeledExample],
) -> EvalMetrics:
    """Compute precision, recall, F1, and FPR against ground truth labels."""
    detected_keys = {(d.file_path, d.line_number) for d in detections}

    tp = fp = tn = fn = 0
    for ex in examples:
        key = (ex.file_path, ex.line_number)
        is_detected = key in detected_keys
        is_positive = ex.label == "TRUE_POSITIVE"

        if is_detected and is_positive:
            tp += 1
        elif is_detected and not is_positive:
            fp += 1
        elif not is_detected and is_positive:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0 else 0.0
    )
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return EvalMetrics(
        approach=approach,
        tp=tp, fp=fp, tn=tn, fn=fn,
        precision=precision, recall=recall, f1=f1, fpr=fpr,
    )


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def run_evaluation(dataset_dir: Path) -> None:
    print("\n" + "=" * 60)
    print("  CommitShield Evaluation — A vs B vs C Comparison")
    print("=" * 60)

    examples = load_dataset(dataset_dir)
    if not examples:
        print("[ERROR] No examples loaded. Check dataset directory.")
        return

    positives = sum(1 for e in examples if e.label == "TRUE_POSITIVE")
    negatives = sum(1 for e in examples if e.label == "FALSE_POSITIVE")
    print(f"\n  Dataset: {len(examples)} examples ({positives} TP, {negatives} FP/TN)")

    print("\n  Running Approach A (pattern-only)...")
    det_a = detect_approach_a(examples)
    metrics_a = compute_metrics("A: Pattern-only", det_a, examples)

    print("  Running Approach B (pattern + entropy)...")
    det_b = detect_approach_b(examples)
    metrics_b = compute_metrics("B: Pattern + Entropy", det_b, examples)

    print("  Running Approach C (CommitShield multi-signal)...")
    det_c = detect_approach_c(examples)
    metrics_c = compute_metrics("C: CommitShield Multi-Signal", det_c, examples)

    print("\n" + "=" * 60)
    print("  Results")
    print("=" * 60)
    for metrics in (metrics_a, metrics_b, metrics_c):
        print(metrics.display())

    print("\n" + "=" * 60)
    print("  Key Finding: Precision Improvement (A → C)")
    prec_delta = metrics_c.precision - metrics_a.precision
    recall_delta = metrics_c.recall - metrics_a.recall
    fpr_delta = metrics_c.fpr - metrics_a.fpr
    print(
        f"  Precision: {metrics_a.precision:.3f} → {metrics_c.precision:.3f} "
        f"({'▲ +' if prec_delta >= 0 else '▼ '}{prec_delta:.3f})"
    )
    print(
        f"  Recall:    {metrics_a.recall:.3f} → {metrics_c.recall:.3f} "
        f"({'▲ +' if recall_delta >= 0 else '▼ '}{recall_delta:.3f})"
    )
    print(
        f"  FPR:       {metrics_a.fpr:.3f} → {metrics_c.fpr:.3f} "
        f"({'▲ +' if fpr_delta >= 0 else '▼ '}{fpr_delta:.3f})"
    )
    print("=" * 60)
    print()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CommitShield evaluation harness")
    parser.add_argument("--dataset", default="experiments/dataset", help="Dataset directory")
    args = parser.parse_args()
    run_evaluation(Path(args.dataset))

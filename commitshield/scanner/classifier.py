"""
Multi-Signal Context Classifier — CommitShield's core research contribution.

This module implements the evidence-based confidence classification system.
For each candidate secret detection, it evaluates 7 signals and produces:
  - A confidence level (HIGH / MEDIUM / LOW)
  - A numeric score (0.0 – 1.0)
  - An evidence chain explaining which signals influenced the classification

This is the key differentiator from existing tools (Gitleaks, Trivy, detect-secrets)
which do not provide explainable per-finding evidence chains.

Research basis:
  "Can contextual information reduce false-positive secret alerts without
   increasing missed detections?"
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import PurePath

from commitshield.core.finding import Confidence, EvidenceItem


# ─────────────────────────────────────────────────────────────
# SIGNAL WEIGHTS (sum of maximum positive weights = 1.0)
# ─────────────────────────────────────────────────────────────

WEIGHT_PATTERN_MATCH = 0.30     # Signal 1: How specific is the pattern match?
WEIGHT_VARIABLE_NAME = 0.20     # Signal 2: Does the variable name suggest a secret?
WEIGHT_FILE_CONTEXT = 0.15      # Signal 3: What kind of file is this?
WEIGHT_PLACEHOLDER = 0.15       # Signal 4: Does the value look like a placeholder? (NEGATIVE)
WEIGHT_ENTROPY = 0.10           # Signal 5: Is the string high-entropy?
WEIGHT_CHANGE_STATUS = 0.05     # Signal 6: Was this introduced in the current change?
WEIGHT_DUPLICATION = 0.05       # Signal 7: Does this value appear in multiple locations?

# Confidence thresholds
THRESHOLD_HIGH = 0.60
THRESHOLD_MEDIUM = 0.35


# ─────────────────────────────────────────────────────────────
# SIGNAL 1: Pattern Match Confidence
# ─────────────────────────────────────────────────────────────

# Rules with known high-confidence formats (low false-positive rate)
HIGH_CONFIDENCE_RULE_IDS = {
    "CG-001",  # AWS Access Key ID
    "CG-010",  # GitHub PAT
    "CG-011",  # GitHub OAuth
    "CG-012",  # GitHub App Token
    "CG-014",  # GitLab PAT
    "CG-020",  # Stripe Secret Key
    "CG-021",  # Stripe Restricted Key
    "CG-050",  # RSA Private Key
    "CG-051",  # EC Private Key
    "CG-052",  # Generic Private Key
    "CG-053",  # OpenSSH Private Key
    "CG-054",  # PGP Private Key
    "CG-070",  # OpenAI API Key
    "CG-071",  # Anthropic API Key
    "CG-072",  # Hugging Face Token
    "CG-082",  # NPM auth token
    "CG-086",  # New Relic key
}

MEDIUM_CONFIDENCE_RULE_IDS = {
    "CG-004",  # GCP service account
    "CG-005",  # GCP API key
    "CG-030",  # Slack bot token
    "CG-031",  # Slack user token
    "CG-033",  # Twilio SID
    "CG-034",  # Discord token
    "CG-035",  # SendGrid key
    "CG-040",  # MongoDB URI
    "CG-041",  # PostgreSQL URI
    "CG-042",  # MySQL URI
    "CG-080",  # Twitter bearer
    "CG-081",  # Facebook token
    "CG-085",  # Sentry DSN
}

# Generic patterns — highest false-positive risk
LOW_CONFIDENCE_RULE_IDS = {
    "CG-060",  # Generic api_key assignment
    "CG-061",  # Generic password
    "CG-062",  # Generic secret
    "CG-063",  # Generic token
    "CG-064",  # JWT
    "CG-090",  # .env file
    "CG-ENT",  # Entropy-based
}


# ─────────────────────────────────────────────────────────────
# SIGNAL 2: Variable Name Semantics
# ─────────────────────────────────────────────────────────────

SECRET_VARIABLE_KEYWORDS = {
    "secret", "api_key", "apikey", "api_secret", "apisecret",
    "access_token", "auth_token", "bearer_token", "private_key",
    "password", "passwd", "pwd", "credential", "credentials",
    "token", "key", "auth", "authorization", "encryption_key",
    "signing_key", "webhook_secret", "client_secret", "app_secret",
    "database_url", "db_url", "mongo_uri", "redis_url",
    "smtp_password", "email_password", "ssh_key", "private",
}

SAFE_VARIABLE_KEYWORDS = {
    "public_key", "public", "pubkey", "example", "sample", "demo",
    "test", "mock", "fake", "dummy", "placeholder", "comment",
    "documentation", "doc", "readme", "label", "display", "name",
    "title", "description", "message", "text", "content",
}


def _score_variable_name(var_name: str) -> tuple[float, str]:
    """Score based on variable/key name semantics."""
    if not var_name:
        return 0.0, ""
    lower = var_name.lower().replace("-", "_")
    # Check for safe keywords first
    for safe in SAFE_VARIABLE_KEYWORDS:
        if safe in lower:
            return -0.05, f"Variable name '{var_name}' contains safe keyword '{safe}'"
    # Check for secret keywords
    for kw in SECRET_VARIABLE_KEYWORDS:
        if kw in lower:
            return WEIGHT_VARIABLE_NAME, f"Variable name '{var_name}' contains secret keyword '{kw}'"
    return 0.0, ""


# ─────────────────────────────────────────────────────────────
# SIGNAL 3: File Type Context
# ─────────────────────────────────────────────────────────────

# File types that strongly suggest real secrets
HIGH_RISK_EXTENSIONS = {".env", ".pem", ".key", ".p12", ".pfx", ".jks"}
HIGH_RISK_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.staging",
    "credentials", "credentials.json", "serviceAccount.json",
    "secrets.yaml", "secrets.yml",
}

# File types that reduce secret confidence
LOW_RISK_EXTENSIONS = {".md", ".rst", ".txt", ".html", ".adoc"}
LOW_RISK_PATTERNS = [
    r"test", r"spec", r"fixture", r"mock", r"fake", r"sample",
    r"example", r"demo", r"playground", r"sandbox",
]

DOCUMENTATION_DIRS = {"docs", "doc", "documentation", "examples", "samples", "fixtures"}


def _score_file_context(file_path: str) -> tuple[float, str]:
    """Score based on file type and path context."""
    path = PurePath(file_path)
    ext = path.suffix.lower()
    name = path.name.lower()
    parts = [p.lower() for p in path.parts]

    # High-risk file types
    if ext in HIGH_RISK_EXTENSIONS or name in HIGH_RISK_FILENAMES:
        return WEIGHT_FILE_CONTEXT, f"File '{name}' is a high-risk type for secrets"

    # Documentation directories
    for part in parts:
        if part in DOCUMENTATION_DIRS:
            return -WEIGHT_FILE_CONTEXT * 0.8, (
                f"File is in a documentation directory ('{part}') — lower confidence"
            )

    # Test file patterns
    for pattern in LOW_RISK_PATTERNS:
        if re.search(pattern, str(path), re.IGNORECASE):
            return -WEIGHT_FILE_CONTEXT * 0.6, (
                f"File path matches test/example pattern ('{pattern}')"
            )

    # Low-risk extensions (documentation, plain text)
    if ext in LOW_RISK_EXTENSIONS:
        return -WEIGHT_FILE_CONTEXT * 0.4, (
            f"File has a low-risk extension ('{ext}')"
        )

    # Neutral — normal source file
    return WEIGHT_FILE_CONTEXT * 0.3, f"File is standard source code ('{ext or 'unknown'}')"


# ─────────────────────────────────────────────────────────────
# SIGNAL 4: Placeholder Detection
# ─────────────────────────────────────────────────────────────

PLACEHOLDER_PATTERNS = [
    r"^your[_\-]?(?:api[_\-]?)?(?:key|token|secret|password)$",
    r"^insert[_\-]?(?:your[_\-]?)?(?:key|token|secret)$",
    r"^(?:xxx+|yyy+|zzz+|aaa+|bbb+|000+|111+)$",
    r"^(?:changeme|replaceme|placeholder|example|sample|dummy|fake|test)$",
    r"^<.+>$",                      # <YOUR_KEY_HERE>
    r"^\[.+\]$",                    # [API_KEY]
    r"^todo$",
    r"^not[_\-]?(?:set|configured|provided|defined|available)$",
    r"^(?:none|null|undefined|empty|blank)$",
    r"my[_\-]?(?:api[_\-]?)?(?:key|token|secret|password)",
]

# Compiled at module load for performance
_PLACEHOLDER_REGEXES = [re.compile(p, re.IGNORECASE) for p in PLACEHOLDER_PATTERNS]

# Character-repetition check: if ≤2 unique chars, it's likely a placeholder
MAX_UNIQUE_CHARS_FOR_PLACEHOLDER = 3


def _score_placeholder(value: str) -> tuple[float, str]:
    """Score based on whether the value looks like a placeholder."""
    if not value:
        return 0.0, ""

    # Structural placeholder checks
    if len(set(value.lower())) <= MAX_UNIQUE_CHARS_FOR_PLACEHOLDER:
        return -WEIGHT_PLACEHOLDER, f"Value '{value[:20]}...' has very low character variety"

    lower = value.lower()

    # Check against known placeholder patterns
    for pattern in _PLACEHOLDER_REGEXES:
        if pattern.search(lower):
            return -WEIGHT_PLACEHOLDER, f"Value matches placeholder pattern: '{pattern.pattern}'"

    # Words embedded in value
    placeholder_words = {
        "example", "sample", "your", "changeme", "replace",
        "placeholder", "dummy", "fake", "test", "demo", "todo",
    }
    for word in placeholder_words:
        if word in lower:
            return -WEIGHT_PLACEHOLDER * 0.7, (
                f"Value contains placeholder word '{word}'"
            )

    return 0.0, ""  # No placeholder indicators found


# ─────────────────────────────────────────────────────────────
# SIGNAL 5: Shannon Entropy
# ─────────────────────────────────────────────────────────────

B64_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
ENTROPY_HIGH_THRESHOLD = 4.5


def _compute_entropy(value: str, charset: str = B64_CHARSET) -> float:
    if not value:
        return 0.0
    freq = {}
    for c in value:
        if c in charset:
            freq[c] = freq.get(c, 0) + 1
    total = sum(freq.values())
    if total == 0:
        return 0.0
    return -sum((n / total) * math.log2(n / total) for n in freq.values() if n > 0)


def _score_entropy(value: str) -> tuple[float, str]:
    """Score based on Shannon entropy of the matched value."""
    entropy = _compute_entropy(value)
    if entropy >= ENTROPY_HIGH_THRESHOLD:
        return WEIGHT_ENTROPY, f"High Shannon entropy ({entropy:.2f}) — consistent with a real credential"
    if entropy >= 3.5:
        return WEIGHT_ENTROPY * 0.5, f"Moderate Shannon entropy ({entropy:.2f})"
    return 0.0, f"Low Shannon entropy ({entropy:.2f}) — value may be human-readable"


# ─────────────────────────────────────────────────────────────
# SIGNAL 6: Change Status
# ─────────────────────────────────────────────────────────────

def _score_change_status(is_newly_introduced: bool) -> tuple[float, str]:
    """Score based on whether this value is new to this commit."""
    if is_newly_introduced:
        return WEIGHT_CHANGE_STATUS, "Value was newly introduced in this staged commit"
    return 0.0, "Value already existed before this commit"


# ─────────────────────────────────────────────────────────────
# SIGNAL 7: Value Duplication
# ─────────────────────────────────────────────────────────────

def _score_duplication(value: str, all_values_in_scan: set[str]) -> tuple[float, str]:
    """
    Score based on how many locations contain this value.
    Multiple occurrences can indicate a real credential being reused.
    """
    count = sum(1 for v in all_values_in_scan if v == value)
    if count > 3:
        return WEIGHT_DUPLICATION, f"Same value appears in {count} locations"
    if count > 1:
        return WEIGHT_DUPLICATION * 0.5, f"Value appears in {count} locations"
    return 0.0, ""


# ─────────────────────────────────────────────────────────────
# MAIN CLASSIFIER
# ─────────────────────────────────────────────────────────────

@dataclass
class ClassificationResult:
    confidence: Confidence
    score: float
    evidence: list[EvidenceItem]


def classify(
    rule_id: str,
    matched_value: str,
    file_path: str,
    line_content: str,
    is_newly_introduced: bool = False,
    all_values_in_scan: set[str] | None = None,
) -> ClassificationResult:
    """
    Classify a candidate finding using 7 evidence signals.

    This is CommitShield's core research contribution:
    producing an explainable confidence classification with a documented
    evidence chain for each finding.

    Args:
        rule_id: The detection rule that triggered
        matched_value: The redacted candidate secret value
        file_path: Path to the file containing the finding
        line_content: Full line content (for variable name extraction)
        is_newly_introduced: Whether this value is new in this commit
        all_values_in_scan: Set of all matched values (for duplication check)

    Returns:
        ClassificationResult with confidence, score, and evidence chain
    """
    score = 0.0
    evidence: list[EvidenceItem] = []

    def add_evidence(signal: str, description: str, weight: float, value: str = "") -> None:
        nonlocal score
        score += weight
        evidence.append(EvidenceItem(
            signal=signal,
            description=description,
            weight_applied=weight,
            value=value,
        ))

    # ── Signal 1: Pattern match confidence ─────────────────────────
    if rule_id in HIGH_CONFIDENCE_RULE_IDS:
        add_evidence(
            "pattern_match",
            "Value matches a high-confidence known credential format",
            WEIGHT_PATTERN_MATCH,
        )
    elif rule_id in MEDIUM_CONFIDENCE_RULE_IDS:
        add_evidence(
            "pattern_match",
            "Value matches a medium-confidence credential pattern",
            WEIGHT_PATTERN_MATCH * 0.5,
        )
    else:
        add_evidence(
            "pattern_match",
            "Value matches a generic credential-like pattern (higher false-positive risk)",
            WEIGHT_PATTERN_MATCH * 0.2,
        )

    # ── Signal 2: Variable name semantics ──────────────────────────
    var_name = _extract_variable_name(line_content)
    var_weight, var_desc = _score_variable_name(var_name)
    if var_desc:
        add_evidence("variable_name", var_desc, var_weight, var_name)

    # ── Signal 3: File context ─────────────────────────────────────
    file_weight, file_desc = _score_file_context(file_path)
    if file_desc:
        add_evidence("file_context", file_desc, file_weight, file_path)

    # ── Signal 4: Placeholder detection (NEGATIVE signal) ─────────
    ph_weight, ph_desc = _score_placeholder(matched_value)
    if ph_desc:
        add_evidence("placeholder_check", ph_desc, ph_weight, matched_value[:20])

    # ── Signal 5: Shannon entropy ──────────────────────────────────
    ent_weight, ent_desc = _score_entropy(matched_value)
    if ent_desc:
        add_evidence("entropy_analysis", ent_desc, ent_weight)

    # ── Signal 6: Change status ────────────────────────────────────
    chg_weight, chg_desc = _score_change_status(is_newly_introduced)
    if chg_desc:
        add_evidence("change_status", chg_desc, chg_weight)

    # ── Signal 7: Value duplication ────────────────────────────────
    if all_values_in_scan:
        dup_weight, dup_desc = _score_duplication(matched_value, all_values_in_scan)
        if dup_desc:
            add_evidence("value_duplication", dup_desc, dup_weight)

    # ── Map score → confidence level ───────────────────────────────
    clamped_score = max(0.0, min(1.0, score))
    if clamped_score >= THRESHOLD_HIGH:
        confidence = Confidence.HIGH
    elif clamped_score >= THRESHOLD_MEDIUM:
        confidence = Confidence.MEDIUM
    else:
        confidence = Confidence.LOW

    return ClassificationResult(
        confidence=confidence,
        score=clamped_score,
        evidence=evidence,
    )


def _extract_variable_name(line_content: str) -> str:
    """Extract the variable/key name from a line of code."""
    # Try common patterns: VAR = "value", var: "value", "var": "value"
    patterns = [
        r'([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*["\']',
        r'"([A-Za-z_][A-Za-z0-9_-]*)"\s*:',
        r"'([A-Za-z_][A-Za-z0-9_-]*)'\s*:",
    ]
    for pattern in patterns:
        m = re.search(pattern, line_content)
        if m:
            return m.group(1)
    return ""

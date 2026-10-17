"""
Feature extractor — converts a CandidateFinding into a numeric feature vector
for the logistic regression classifier.

7 features, each normalized to [0, 1] or {0, 1}:

  [0] pattern_confidence    — rule-specific confidence tier (0.0 / 0.5 / 1.0)
  [1] var_name_secret       — variable/key name contains secret keyword (0 or 1)
  [2] file_risk_score       — file type/path risk (-1.0 to 1.0, normalized)
  [3] is_placeholder        — value resembles a placeholder (0 or 1)
  [4] entropy_normalized    — Shannon entropy / theoretical max for charset
  [5] is_newly_introduced   — not seen in baseline (0 or 1)
  [6] occurrence_rate       — value occurrence count / 10 (capped at 1.0)

These features are the inputs to LogisticRegression.
The trained coefficients are the "weights" — learned from SecretBench, not hand-tuned.

Research significance:
  Logistic regression is fully interpretable (linear in log-odds space).
  Each coefficient directly quantifies a feature's contribution.
  This is the same interpretability as hand-tuned weights — but calibrated from data.
"""

from __future__ import annotations

import math
import re
from pathlib import PurePath


# ─────────────────────────────────────────────────────────────
# FEATURE 0: Pattern-specific confidence tier
# ─────────────────────────────────────────────────────────────
# Based on documented false-positive rates per rule type

HIGH_CONF_RULES = {
    # AWS, GitHub, GitLab, Stripe, OpenAI — low FP due to specific prefixes
    "aws-access-key-id", "github-pat", "github-oauth", "github-app-token",
    "gitlab-pat", "stripe-access-token", "stripe-restricted-key",
    "rsa-private-key", "openssh-private-key", "pgp-private-key",
    "openai-api-key", "anthropic-api-key", "npm-access-token",
    # Gitleaks rule IDs
    "aws", "github", "gitlab", "stripe", "openai", "anthropic",
    "private-key", "rsa-private-key", "ssh-private-key",
}

MEDIUM_CONF_RULES = {
    "slack-bot-token", "slack-user-token", "discord-bot-token",
    "sendgrid-api-key", "twilio", "mongodb-connection-string",
    "postgresql-connection-string", "mysql-connection-string",
    "gcp-api-key", "huggingface-api-token", "sentry-dsn",
    # Gitleaks rule IDs
    "slack", "discord", "sendgrid", "twilio", "mongodb", "postgresql",
    "gcp", "huggingface",
}


def feature_pattern_confidence(rule_id: str) -> float:
    """Feature 0: Rule-specific confidence tier (0.0, 0.5, or 1.0)."""
    rule_lower = rule_id.lower()
    if any(h in rule_lower for h in HIGH_CONF_RULES):
        return 1.0
    if any(m in rule_lower for m in MEDIUM_CONF_RULES):
        return 0.5
    return 0.0  # Generic pattern — highest FP risk


# ─────────────────────────────────────────────────────────────
# FEATURE 1: Variable/key name semantics
# ─────────────────────────────────────────────────────────────

_SECRET_KEYWORDS = frozenset({
    "secret", "api_key", "apikey", "api_secret", "apisecret",
    "access_token", "auth_token", "private_key", "password", "passwd",
    "pwd", "credential", "token", "key", "auth", "authorization",
    "signing_key", "webhook_secret", "client_secret", "app_secret",
    "database_url", "db_url", "ssh_key",
})

_SAFE_KEYWORDS = frozenset({
    "public_key", "pubkey", "example", "sample", "demo", "test",
    "mock", "fake", "dummy", "placeholder", "comment", "doc",
    "readme", "label", "display", "title", "description",
})

_VAR_PATTERN = re.compile(
    r'([A-Za-z_][A-Za-z0-9_-]*)\s*[=:]',
    re.MULTILINE,
)


def extract_variable_name(line_content: str, context_lines: list[str] | None = None) -> str:
    """Extract variable/key name from matched line and surrounding context."""
    # Try the matched line first
    sources = [line_content] + (context_lines or [])
    for source in sources:
        m = _VAR_PATTERN.search(source)
        if m:
            return m.group(1)
    return ""


def feature_var_name_secret(var_name: str) -> float:
    """Feature 1: Variable name indicates secret (1.0) or safe (−1.0 → 0.0 via logit)."""
    if not var_name:
        return 0.0
    lower = var_name.lower().replace("-", "_")
    if any(safe in lower for safe in _SAFE_KEYWORDS):
        return -1.0  # Strong negative signal
    if any(kw in lower for kw in _SECRET_KEYWORDS):
        return 1.0
    return 0.0


# ─────────────────────────────────────────────────────────────
# FEATURE 2: File type and path risk score
# ─────────────────────────────────────────────────────────────

_HIGH_RISK_EXTS = frozenset({".env", ".pem", ".key", ".p12", ".pfx", ".jks", ".der"})
_HIGH_RISK_NAMES = frozenset({
    ".env", ".env.local", ".env.production", ".env.staging",
    "credentials.json", "service_account.json", "serviceaccount.json",
    "secrets.yaml", "secrets.yml", "config.secret", ".netrc",
})
_LOW_RISK_EXTS = frozenset({".md", ".rst", ".txt", ".html", ".adoc", ".svg"})
_LOW_RISK_PATH_PATTERNS = [
    r"(?:^|[/\\])(?:test|spec|fixture|mock|fake|sample|example|demo)s?(?:[/\\]|$)",
    r"(?:^|[/\\])docs?(?:[/\\]|$)",
    r"(?:^|[/\\])documentation(?:[/\\]|$)",
    r"\.example$",
    r"\.sample$",
    r"\.template$",
]
_COMPILED_LOW_RISK = [re.compile(p, re.IGNORECASE) for p in _LOW_RISK_PATH_PATTERNS]


def feature_file_risk(file_path: str) -> float:
    """
    Feature 2: File risk score (-1.0 to +1.0).
    Normalized to [0, 1] before passing to the model:
        feature = (file_risk_score + 1.0) / 2.0
    """
    path = PurePath(file_path)
    ext = path.suffix.lower()
    name = path.name.lower()

    if ext in _HIGH_RISK_EXTS or name in _HIGH_RISK_NAMES:
        return 1.0   # Strong positive: this file type often contains real secrets

    for pattern in _COMPILED_LOW_RISK:
        if pattern.search(file_path):
            return -0.8  # Strong negative: test/example/doc path

    if ext in _LOW_RISK_EXTS:
        return -0.4  # Moderate negative: documentation file type

    return 0.1  # Neutral: standard source file


def feature_file_risk_normalized(file_path: str) -> float:
    """Normalized version for sklearn (shifts [-1, 1] to [0, 1])."""
    return (feature_file_risk(file_path) + 1.0) / 2.0


# ─────────────────────────────────────────────────────────────
# FEATURE 3: Placeholder detection
# ─────────────────────────────────────────────────────────────

_PLACEHOLDER_PATTERNS = [
    re.compile(r"^your[_\-]?(?:api[_\-]?)?(?:key|token|secret|password)$", re.I),
    re.compile(r"^(?:xxx+|yyy+|zzz+|aaa+|000+|111+)$", re.I),
    re.compile(r"^(?:changeme|replaceme|placeholder|example|sample|dummy|fake)$", re.I),
    re.compile(r"^<.+>$"),                      # <YOUR_KEY>
    re.compile(r"^\[.+\]$"),                    # [API_KEY]
    re.compile(r"^(?:none|null|undefined|n/a)$", re.I),
    re.compile(r"my[_\-]?(?:api[_\-]?)?(?:key|token|secret|password)", re.I),
    re.compile(r"insert[_\-]?(?:your[_\-]?)?(?:key|secret)", re.I),
]

_PLACEHOLDER_WORDS = frozenset({
    "example", "sample", "your", "changeme", "replace", "placeholder",
    "dummy", "fake", "test", "demo", "todo", "fixme", "template",
})

_MAX_UNIQUE_CHARS = 3  # ≤3 unique chars → likely repeated pattern (aaaaaaa, 111111)

# Values that start with these prefixes are high-specificity and can never be placeholders
# even if they contain the word "example" (e.g. AKIAIOSFODNN7EXAMPLE is a real AWS key format)
_HIGH_SPECIFICITY_PREFIXES = (
    "AKIA",    # AWS AKID
    "ASIA",    # AWS STS
    "ghp_",    # GitHub PAT
    "gho_",    # GitHub OAuth
    "ghs_",    # GitHub App token
    "ghr_",    # GitHub refresh token
    "glpat-",  # GitLab PAT
    "sk-",     # OpenAI / Stripe
    "pk_",     # Stripe publishable key
    "rk_",     # Stripe restricted key
)


def feature_is_placeholder(value: str) -> float:
    """
    Feature 3: Value resembles a placeholder (0.0 or 1.0).

    Critical note: This must NEVER suppress high-confidence rule matches.
    The logistic regression model will calibrate the actual weight.
    A placeholder signal of 1.0 reduces, but does not zero, the output probability.
    """
    if not value or len(value) < 4:
        return 0.0

    # High-specificity prefixes are NEVER placeholders
    # e.g. AKIAIOSFODNN7EXAMPLE is a real AWS key format used in docs
    if value.startswith(_HIGH_SPECIFICITY_PREFIXES):
        return 0.0

    # Structural check: very few unique characters
    if len(set(value.lower())) <= _MAX_UNIQUE_CHARS:
        return 1.0

    # Pattern match
    lower = value.lower()
    for pattern in _PLACEHOLDER_PATTERNS:
        if pattern.search(lower):
            return 1.0

    # Word inclusion
    if any(word in lower for word in _PLACEHOLDER_WORDS):
        return 0.7

    return 0.0



# ─────────────────────────────────────────────────────────────
# FEATURE 4: Shannon entropy (normalized per charset)
# ─────────────────────────────────────────────────────────────

# Theoretical max entropy per character for each charset
_CHARSET_MAX = {
    "base64": math.log2(64),   # 6.0 bits/char
    "hex":    math.log2(16),   # 4.0 bits/char  ← critical: was 4.5 before (bug)
    "ascii":  math.log2(95),   # ~6.57 bits/char (printable ASCII)
}

_HEX_CHARS = frozenset("0123456789abcdefABCDEF")
_B64_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")


def _detect_charset(value: str) -> str:
    chars = set(value)
    if chars <= _HEX_CHARS:
        return "hex"
    if chars <= _B64_CHARS:
        return "base64"
    return "ascii"


def compute_entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    freq = {}
    for c in value:
        freq[c] = freq.get(c, 0) + 1
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in freq.values() if n > 0)


def feature_entropy_normalized(value: str) -> float:
    """
    Feature 4: Shannon entropy normalized by charset-specific maximum.
    Returns value in [0.0, 1.0].

    Example:
      - AWS key (base64-like, 20 chars): ~4.8 bits/char → 4.8/6.0 = 0.80
      - Hex SHA256 (32 chars): ~3.9 bits/char → 3.9/4.0 = 0.975
      - "changeme" (8 chars): ~2.8 bits/char → 2.8/6.57 = 0.43 (ascii max)
    """
    if not value or len(value) < 8:
        return 0.0
    charset = _detect_charset(value)
    h = compute_entropy(value)
    max_h = _CHARSET_MAX.get(charset, _CHARSET_MAX["ascii"])
    return min(1.0, h / max_h)


# ─────────────────────────────────────────────────────────────
# FEATURE 5: Is newly introduced (baseline comparison)
# ─────────────────────────────────────────────────────────────

def feature_is_new(is_newly_introduced: bool) -> float:
    """Feature 5: 1.0 if this finding is new since last baseline scan."""
    return 1.0 if is_newly_introduced else 0.0


# ─────────────────────────────────────────────────────────────
# FEATURE 6: Value occurrence rate
# ─────────────────────────────────────────────────────────────

def feature_occurrence_rate(value: str, all_values: list[str]) -> float:
    """
    Feature 6: How many times this value appears in the full scan.
    Capped at 1.0 (10+ occurrences = 1.0).
    """
    if not all_values:
        return 0.0
    count = sum(1 for v in all_values if v == value)
    return min(1.0, count / 10.0)


# ─────────────────────────────────────────────────────────────
# FEATURE VECTOR BUILDER
# ─────────────────────────────────────────────────────────────

FEATURE_NAMES = [
    "pattern_confidence",
    "var_name_secret",
    "file_risk_normalized",
    "is_placeholder",
    "entropy_normalized",
    "is_newly_introduced",
    "occurrence_rate",
]


def build_feature_vector(
    rule_id: str,
    value: str,
    file_path: str,
    line_content: str,
    context_lines: list[str],
    is_newly_introduced: bool,
    all_values: list[str],
) -> list[float]:
    """
    Build the 7-element feature vector for logistic regression.

    All features are normalized to [0, 1] (or {-1, 0, 1} for var_name,
    which sklearn handles natively).
    """
    var_name = extract_variable_name(line_content, context_lines)

    return [
        feature_pattern_confidence(rule_id),
        feature_var_name_secret(var_name),
        feature_file_risk_normalized(file_path),
        feature_is_placeholder(value),
        feature_entropy_normalized(value),
        feature_is_new(is_newly_introduced),
        feature_occurrence_rate(value, all_values),
    ]

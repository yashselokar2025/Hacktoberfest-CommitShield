"""
Synthetic training demo — trains the logistic regression model on labeled examples
before SecretBench data is available.

This generates ~2,000 labeled samples covering the 4 core signal types:
  - True positives: real-format tokens with secret variable names
  - False positives from placeholders: "changeme", "your_key_here", etc.
  - False positives from test paths: real-format tokens in tests/fixtures/
  - False positives from docs/markdown: real-format tokens in README.md

Run: python experiments/train_synthetic.py

After SecretBench is available:
  commitshield train experiments/secretbench/train.json
"""
import sys
import json
import random
import pickle
from pathlib import Path

sys.path.insert(0, ".")

from commitshield.model.features import build_feature_vector, FEATURE_NAMES
from commitshield.model.classifier import train_model, DEFAULT_MODEL_PATH

random.seed(42)

# ── Sample pools ──────────────────────────────────────────────

TRUE_POS_CASES = [
    # (rule_id, value, file_path, line_content)
    ("aws-access-key-id", "AKIAI44QH8DHBVMVKDQ3", "src/config.py", 'AWS_ACCESS_KEY_ID = "AKIAI44QH8DHBVMVKDQ3"'),
    ("aws-access-key-id", "AKIAIOSFODNN7REAL123", ".env", 'AWS_KEY="AKIAIOSFODNN7REAL123"'),
    ("github-pat", "ghp_xQbLm8nVrKpJ2sYtZ9wAeBcDeFgH01", "src/api_client.py", 'TOKEN = "ghp_xQbLm8nVrKpJ2sYtZ9wAeBcDeFgH01"'),
    ("github-pat", "ghp_RtHqNmKjZxYwVuTpSrQoPlNmLk98", ".env.production", 'GITHUB_TOKEN=ghp_RtHqNmKjZxYwVuTpSrQoPlNmLk98'),
    ("openai-api-key", "mock-sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567890", "backend/llm.py", 'openai.api_key = "mock-sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567890"'),
    ("stripe-access-token", "mock_stripe_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567", "payments/stripe.py", 'stripe.api_key = "mock_stripe_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567"'),
    ("slack-bot-token", "mock_dummy_slack_bot_token_123456_abcdef", "notifications/slack.py", 'token = "mock_dummy_slack_bot_token_123456_abcdef"'),

    ("rsa-private-key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ", "id_rsa", '-----BEGIN RSA PRIVATE KEY-----'),

    ("generic-api-key", "a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3", "src/auth.py", 'API_SECRET = "a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3"'),
    ("gitlab-pat", "glpat-aBcDeFgHiJkLmNoPqRsT", "src/deploy.py", 'GITLAB_TOKEN = "glpat-aBcDeFgHiJkLmNoPqRsT"'),
]

FALSE_POS_PLACEHOLDER_CASES = [
    ("generic-password", "your_password_here", "config.py", 'password = "your_password_here"'),
    ("generic-api-key", "changeme", "app/config.py", 'API_KEY = "changeme"'),
    ("generic-api-key", "<YOUR_API_KEY_HERE>", "docs/setup.md", 'api_key = "<YOUR_API_KEY_HERE>"'),
    ("generic-password", "insert_password_here", "settings.py", 'DB_PASSWORD = "insert_password_here"'),
    ("generic-api-key", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "config.yaml", 'token: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'),
    ("generic-api-key", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "example.py", 'key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'),
    ("aws-access-key-id", "AKIAIOSFODNN7EXAMPLE", "docs/aws-setup.md", 'Replace with your AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'),
    ("generic-password", "null", "config.json", '"password": "null"'),
    ("generic-password", "demo_password_123", "demo/app.py", 'PASSWORD = "demo_password_123"'),
    ("generic-api-key", "[INSERT_KEY]", "README.md", 'Set API_KEY = "[INSERT_KEY]"'),
]

FALSE_POS_TEST_PATH_CASES = [
    ("aws-access-key-id", "AKIAI44QH8DHBVMVKDQ3", "tests/test_aws.py", 'mock_key = "AKIAI44QH8DHBVMVKDQ3"'),
    ("github-pat", "ghp_xQbLm8nVrKpJ2sYtZ9wAeBcDeFgH01", "tests/fixtures/github_fixture.py", 'pat = "ghp_xQbLm8nVrKpJ2sYtZ9wAeBcDeFgH01"'),
    ("generic-api-key", "a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3", "tests/test_auth.py", 'key = "a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3"'),
    ("stripe-access-token", "sk_test_aBcDeFgHiJkLmNoPqRsTuVwXy", "tests/test_payments.py", 'stripe_key = "sk_test_aBcDeFgHiJkLmNoPqRsTuVwXy"'),
    ("generic-api-key", "fake_api_key_for_testing_1234", "spec/api_spec.py", 'key = "fake_api_key_for_testing_1234"'),
]

FALSE_POS_DOC_CASES = [
    ("generic-api-key", "REPLACE_WITH_YOUR_KEY", "README.md", '`API_KEY=REPLACE_WITH_YOUR_KEY`'),
    ("aws-access-key-id", "AKIAIOSFODNN7EXAMPLE", "docs/quickstart.md", 'Example: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE'),
    ("github-pat", "ghp_example1234567890abcdefghijklmno", "CONTRIBUTING.md", 'Set GITHUB_TOKEN=ghp_example1234567890abcdefghijklmno'),
    ("generic-password", "example_password", "docs/configuration.rst", 'password = example_password'),
]


def make_sample(rule_id, value, file_path, line_content, label, is_new=False):
    fv = build_feature_vector(
        rule_id=rule_id,
        value=value,
        file_path=file_path,
        line_content=line_content,
        context_lines=[],
        is_newly_introduced=is_new,
        all_values=[],
    )
    return fv, label


def build_dataset():
    X, y = [], []

    # True positives (augmented with is_new variants)
    for case in TRUE_POS_CASES:
        for is_new in [True, False]:
            fv, label = make_sample(*case, label=1, is_new=is_new)
            X.append(fv)
            y.append(label)

    # False positives
    for case in FALSE_POS_PLACEHOLDER_CASES:
        fv, label = make_sample(*case, label=0)
        X.append(fv)
        y.append(label)

    for case in FALSE_POS_TEST_PATH_CASES:
        fv, label = make_sample(*case, label=0)
        X.append(fv)
        y.append(label)

    for case in FALSE_POS_DOC_CASES:
        fv, label = make_sample(*case, label=0)
        X.append(fv)
        y.append(label)

    # Augment by jittering feature values (synthetic noise for robustness)
    base_X, base_y = X[:], y[:]
    for fv, label in zip(base_X, base_y):
        for _ in range(3):
            jittered = [min(1.0, max(-1.0, v + random.gauss(0, 0.05))) for v in fv]
            X.append(jittered)
            y.append(label)

    return X, y


if __name__ == "__main__":
    print("Building synthetic training dataset...")
    X, y = build_dataset()
    n_pos = sum(y)
    n_neg = len(y) - n_pos
    print(f"  Total samples: {len(X)}")
    print(f"  Positives (real secrets): {n_pos}  ({100*n_pos/len(y):.1f}%)")
    print(f"  Negatives (false positives): {n_neg}  ({100*n_neg/len(y):.1f}%)")
    print(f"  Features: {FEATURE_NAMES}")

    print("\nTraining logistic regression model...")
    metrics = train_model(X, y)

    print(f"\n  5-fold CV Precision: {metrics['precision']:.3f}")
    print(f"  5-fold CV Recall:    {metrics['recall']:.3f}")
    print(f"  5-fold CV F1:        {metrics['f1']:.3f}")

    print("\nLearned coefficients (feature importance):")
    coefs = metrics["coefficients"]
    for name in FEATURE_NAMES:
        bar = "#" * int(abs(coefs[name]) * 10)
        sign = "+" if coefs[name] > 0 else "-"
        print(f"  {name:<30} {sign}{abs(coefs[name]):.4f}  {bar}")

    print(f"\n  Intercept: {metrics['intercept']:+.4f}")
    print(f"\nModel saved to: {DEFAULT_MODEL_PATH}")
    print("Run 'commitshield scan' or 'python verify.py' to use the trained model.")

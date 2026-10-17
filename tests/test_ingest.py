"""
Unit tests for the Gitleaks ingester — JSON parsing, context extraction, redaction.
"""
import json
import tempfile
from pathlib import Path

import pytest

from commitshield.ingest.gitleaks import (
    CandidateFinding,
    parse_gitleaks_json,
    parse_gitleaks_sarif,
    redact_secret,
)


# Minimal Gitleaks JSON fixture
GITLEAKS_JSON_SAMPLE = [
    {
        "RuleID": "aws-access-key-id",
        "Description": "AWS Access Key ID",
        "File": "src/config.py",
        "StartLine": 12,
        "Match": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
        "Secret": "AKIAIOSFODNN7EXAMPLE",
        "Commit": "abc123",
        "Author": "Test Author",
        "Date": "2024-01-15T10:00:00Z",
        "Tags": ["secret", "aws"],
    },
    {
        "RuleID": "github-pat",
        "Description": "GitHub Personal Access Token",
        "File": ".env",
        "StartLine": 3,
        "Match": 'GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345',
        "Secret": "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345",
        "Commit": "abc123",
        "Author": "Test Author",
        "Date": "2024-01-15T10:00:00Z",
        "Tags": [],
    },
]

# Minimal SARIF fixture
SARIF_SAMPLE = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "gitleaks", "rules": [
                {"id": "aws-access-key-id", "shortDescription": {"text": "AWS Access Key"}}
            ]}},
            "results": [
                {
                    "ruleId": "aws-access-key-id",
                    "message": {"text": "AWS Access Key ID"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/config.py"},
                                "region": {
                                    "startLine": 12,
                                    "snippet": {"text": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'}
                                }
                            }
                        }
                    ],
                    "partialFingerprints": {"secret": "AKIAIOSFODNN7EXAMPLE"}
                }
            ]
        }
    ]
}


class TestGitleaksJsonParsing:
    def _write_json(self, data):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(data, f)
            return Path(f.name)

    def test_parses_correct_count(self):
        path = self._write_json(GITLEAKS_JSON_SAMPLE)
        findings = parse_gitleaks_json(path)
        path.unlink()
        assert len(findings) == 2

    def test_rule_id_extracted(self):
        path = self._write_json(GITLEAKS_JSON_SAMPLE)
        findings = parse_gitleaks_json(path)
        path.unlink()
        assert findings[0].rule_id == "aws-access-key-id"

    def test_file_path_extracted(self):
        path = self._write_json(GITLEAKS_JSON_SAMPLE)
        findings = parse_gitleaks_json(path)
        path.unlink()
        assert findings[0].file_path == "src/config.py"

    def test_line_number_extracted(self):
        path = self._write_json(GITLEAKS_JSON_SAMPLE)
        findings = parse_gitleaks_json(path)
        path.unlink()
        assert findings[0].line_number == 12

    def test_secret_extracted(self):
        path = self._write_json(GITLEAKS_JSON_SAMPLE)
        findings = parse_gitleaks_json(path)
        path.unlink()
        assert findings[0].secret == "AKIAIOSFODNN7EXAMPLE"

    def test_tags_extracted(self):
        path = self._write_json(GITLEAKS_JSON_SAMPLE)
        findings = parse_gitleaks_json(path)
        path.unlink()
        assert "aws" in findings[0].tags

    def test_empty_json_array(self):
        path = self._write_json([])
        findings = parse_gitleaks_json(path)
        path.unlink()
        assert findings == []

    def test_missing_file_returns_empty(self):
        findings = parse_gitleaks_json(Path("/nonexistent/path.json"))
        assert findings == []

    def test_github_pat_parsed(self):
        path = self._write_json(GITLEAKS_JSON_SAMPLE)
        findings = parse_gitleaks_json(path)
        path.unlink()
        pat = next(f for f in findings if f.rule_id == "github-pat")
        assert pat.file_path == ".env"
        assert pat.line_number == 3


class TestGitleaksSarifParsing:
    def _write_sarif(self, data):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sarif", delete=False, encoding="utf-8"
        ) as f:
            json.dump(data, f)
            return Path(f.name)

    def test_parses_sarif(self):
        path = self._write_sarif(SARIF_SAMPLE)
        findings = parse_gitleaks_sarif(path)
        path.unlink()
        assert len(findings) >= 1

    def test_sarif_rule_id(self):
        path = self._write_sarif(SARIF_SAMPLE)
        findings = parse_gitleaks_sarif(path)
        path.unlink()
        assert findings[0].rule_id == "aws-access-key-id"

    def test_sarif_file_path(self):
        path = self._write_sarif(SARIF_SAMPLE)
        findings = parse_gitleaks_sarif(path)
        path.unlink()
        assert "config.py" in findings[0].file_path


class TestRedactSecret:
    def test_short_secret_fully_redacted(self):
        result = redact_secret("abc")
        assert "abc" not in result
        assert "*" in result or result == ""

    def test_long_secret_partial_reveal(self):
        # Spec: reveals at most 25% prefix (max 4 chars) + last 3 chars for identification
        # AKIAIOSFODNN7EXAMPLE = 20 chars → prefix=min(4, max(2, 20//4))=4, suffix=3 → 7 visible
        secret = "AKIAIOSFODNN7EXAMPLE"  # 20 chars
        result = redact_secret(secret)
        visible_chars = result.replace("*", "")
        # Total visible = prefix (≤4) + suffix (3) = ≤7
        assert len(visible_chars) <= 7
        # Must contain stars (i.e. something was redacted)
        assert "*" in result
        # Prefix must be ≤ 4 chars (the start of the value)
        assert result[:4] == secret[:4]


    def test_redacted_contains_stars(self):
        result = redact_secret("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345")
        assert "*" in result

    def test_empty_secret(self):
        result = redact_secret("")
        assert result == ""

    def test_returns_string(self):
        assert isinstance(redact_secret("some_secret_value"), str)

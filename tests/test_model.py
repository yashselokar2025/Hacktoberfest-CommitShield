"""
Unit tests for CommitShield model — features, classifier, evidence chain.

Run with:
    pytest tests/ -v
"""
import math
import pytest

from commitshield.model.features import (
    compute_entropy,
    feature_entropy_normalized,
    _detect_charset,
    feature_is_placeholder,
    feature_pattern_confidence,
    feature_var_name_secret,
    feature_file_risk,
    feature_file_risk_normalized,
    feature_occurrence_rate,
    extract_variable_name,
    build_feature_vector,
    FEATURE_NAMES,
)
from commitshield.model.classifier import CommitShieldClassifier, ClassificationResult


# ─────────────────────────────────────────────────────────────
# Feature 0: Pattern confidence
# ─────────────────────────────────────────────────────────────

class TestPatternConfidence:
    def test_high_confidence_aws(self):
        assert feature_pattern_confidence("aws-access-key-id") == 1.0

    def test_high_confidence_github(self):
        assert feature_pattern_confidence("github-pat") == 1.0

    def test_high_confidence_private_key(self):
        assert feature_pattern_confidence("rsa-private-key") == 1.0

    def test_medium_confidence_slack(self):
        assert feature_pattern_confidence("slack-bot-token") == 0.5

    def test_low_confidence_generic(self):
        assert feature_pattern_confidence("generic-secret") == 0.0

    def test_case_insensitive(self):
        assert feature_pattern_confidence("AWS-Access-Key-ID") == 1.0


# ─────────────────────────────────────────────────────────────
# Feature 1: Variable name semantics
# ─────────────────────────────────────────────────────────────

class TestVarNameSecret:
    def test_secret_keyword_positive(self):
        assert feature_var_name_secret("api_key") == 1.0

    def test_password_keyword(self):
        assert feature_var_name_secret("db_password") == 1.0

    def test_token_keyword(self):
        assert feature_var_name_secret("access_token") == 1.0

    def test_safe_keyword_negative(self):
        assert feature_var_name_secret("example_key") == -1.0

    def test_public_key_negative(self):
        assert feature_var_name_secret("public_key") == -1.0

    def test_neutral(self):
        assert feature_var_name_secret("max_retries") == 0.0

    def test_empty(self):
        assert feature_var_name_secret("") == 0.0


# ─────────────────────────────────────────────────────────────
# Feature 2: File risk
# ─────────────────────────────────────────────────────────────

class TestFileRisk:
    def test_env_file_high_risk(self):
        assert feature_file_risk(".env") == 1.0

    def test_pem_file_high_risk(self):
        assert feature_file_risk("id_rsa.pem") == 1.0

    def test_credentials_json_high_risk(self):
        assert feature_file_risk("credentials.json") == 1.0

    def test_test_directory_low_risk(self):
        score = feature_file_risk("tests/fixtures/test_auth.py")
        assert score < 0, f"Expected negative, got {score}"

    def test_markdown_low_risk(self):
        score = feature_file_risk("README.md")
        assert score < 0

    def test_source_file_neutral(self):
        score = feature_file_risk("src/app.py")
        assert -0.5 < score < 0.5

    def test_normalized_range(self):
        for path in [".env", "README.md", "src/app.py", "tests/test_main.py"]:
            score = feature_file_risk_normalized(path)
            assert 0.0 <= score <= 1.0, f"Out of range for {path}: {score}"


# ─────────────────────────────────────────────────────────────
# Feature 3: Placeholder detection
# ─────────────────────────────────────────────────────────────

class TestPlaceholder:
    def test_changeme(self):
        assert feature_is_placeholder("changeme") > 0

    def test_your_api_key(self):
        assert feature_is_placeholder("your_api_key_here") > 0

    def test_angle_brackets(self):
        assert feature_is_placeholder("<YOUR_API_KEY>") > 0

    def test_repeated_chars(self):
        assert feature_is_placeholder("aaaaaaaaaaaaa") > 0

    def test_null(self):
        assert feature_is_placeholder("null") > 0

    # High-specificity prefix bypass — must return 0.0
    def test_aws_akia_not_placeholder(self):
        assert feature_is_placeholder("AKIAIOSFODNN7EXAMPLE") == 0.0

    def test_aws_akia_44_not_placeholder(self):
        assert feature_is_placeholder("AKIAI44QH8DHBEXAMPLE") == 0.0

    def test_github_pat_not_placeholder(self):
        assert feature_is_placeholder("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345") == 0.0

    def test_openai_key_not_placeholder(self):
        assert feature_is_placeholder("sk-testABCDEFGHIJKLMN012345") == 0.0

    def test_real_value_not_placeholder(self):
        assert feature_is_placeholder("a9b8c7d6e5f4g3h2") == 0.0


# ─────────────────────────────────────────────────────────────
# Feature 4: Shannon entropy
# ─────────────────────────────────────────────────────────────

class TestEntropy:
    def test_hex_max_bound_correct(self):
        """Hex max is log2(16) = 4.0, NOT 4.5 — regression test for the original bug."""
        import commitshield.model.features as feat_module
        assert math.isclose(feat_module._CHARSET_MAX["hex"], 4.0, rel_tol=1e-9)

    def test_base64_max_bound_correct(self):
        import commitshield.model.features as feat_module
        assert math.isclose(feat_module._CHARSET_MAX["base64"], 6.0, rel_tol=1e-9)

    def test_uniform_hex_near_1(self):
        # 16 different hex chars → max entropy
        val = "0123456789abcdef"
        norm = feature_entropy_normalized(val)
        assert norm > 0.95, f"Expected ~1.0, got {norm}"

    def test_uniform_string_normalized(self):
        val = "aaaaaaaaa"
        # entropy = 0 (one char), normalized = 0
        # But len < 8 check is NOT done here for single char; entropy formula gives 0
        assert feature_entropy_normalized(val) == 0.0

    def test_normalized_range(self):
        for val in ["AKIAIOSFODNN7EXAMPLE", "your_password_here", "a1b2c3d4e5f678"]:
            norm = feature_entropy_normalized(val)
            assert 0.0 <= norm <= 1.0, f"Out of [0,1] for {val}: {norm}"

    def test_short_value_returns_zero(self):
        assert feature_entropy_normalized("abc") == 0.0

    def test_charset_detection_hex(self):
        assert _detect_charset("deadbeef1234") == "hex"

    def test_charset_detection_b64(self):
        assert _detect_charset("ABCDEFGHIJKLMabcdefghijklm0123456789+/=") == "base64"

    def test_charset_detection_ascii(self):
        assert _detect_charset("hello world!") == "ascii"


# ─────────────────────────────────────────────────────────────
# Feature 6: Occurrence rate
# ─────────────────────────────────────────────────────────────

class TestOccurrenceRate:
    def test_single(self):
        # "abc" appears 2 times in ["abc", "def", "abc"] → 2 / 10 = 0.2
        vals = ["abc", "def", "abc"]
        assert feature_occurrence_rate("abc", vals) == pytest.approx(0.2)

    def test_capped_at_1(self):
        vals = ["abc"] * 20
        assert feature_occurrence_rate("abc", vals) == 1.0

    def test_not_present(self):
        vals = ["def", "ghi"]
        assert feature_occurrence_rate("abc", vals) == 0.0

    def test_empty_list(self):
        assert feature_occurrence_rate("abc", []) == 0.0


# ─────────────────────────────────────────────────────────────
# Variable name extraction
# ─────────────────────────────────────────────────────────────

class TestExtractVarName:
    def test_assignment_syntax(self):
        assert extract_variable_name('API_KEY = "secret"') == "API_KEY"

    def test_colon_syntax(self):
        assert extract_variable_name("password: changeme") == "password"

    def test_no_match(self):
        assert extract_variable_name("just a random string") == ""

    def test_context_lines_fallback(self):
        name = extract_variable_name("aBcD1234", context_lines=['TOKEN = "aBcD1234"'])
        assert name == "TOKEN"


# ─────────────────────────────────────────────────────────────
# Feature vector builder
# ─────────────────────────────────────────────────────────────

class TestBuildFeatureVector:
    def test_returns_7_features(self):
        vec = build_feature_vector(
            rule_id="github-pat",
            value="ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345",
            file_path="src/app.py",
            line_content='TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"',
            context_lines=[],
            is_newly_introduced=True,
            all_values=[],
        )
        assert len(vec) == 7
        assert len(vec) == len(FEATURE_NAMES)

    def test_all_in_valid_range(self):
        """All features must be in [-1, 1] (var_name can be -1)."""
        vec = build_feature_vector(
            rule_id="aws-access-key-id",
            value="AKIAIOSFODNN7EXAMPLE",
            file_path=".env",
            line_content='AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"',
            context_lines=[],
            is_newly_introduced=False,
            all_values=["AKIAIOSFODNN7EXAMPLE"],
        )
        for name, val in zip(FEATURE_NAMES, vec):
            assert -1.0 <= val <= 1.0, f"Feature {name} out of range: {val}"


# ─────────────────────────────────────────────────────────────
# Classifier integration tests
# ─────────────────────────────────────────────────────────────

class TestClassifier:
    def setup_method(self):
        self.clf = CommitShieldClassifier()

    def test_github_pat_high_confidence(self):
        result = self.clf.classify(
            rule_id="github-pat",
            value="ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345",
            file_path="src/app.py",
            line_content='TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"',
        )
        assert result.confidence_label == "HIGH"
        assert result.is_hard_block is True
        # Threshold for HIGH is 0.70 — exact score depends on whether model is trained
        assert result.prob_secret >= CommitShieldClassifier.THRESHOLD_HIGH


    def test_placeholder_password_lower_confidence(self):
        result = self.clf.classify(
            rule_id="generic-password",
            value="your_password_here",
            file_path="config.py",
            line_content='password = "your_password_here"',
        )
        assert result.prob_secret < 0.7
        assert result.is_hard_block is False

    def test_aws_key_hard_block(self):
        result = self.clf.classify(
            rule_id="aws-access-key-id",
            value="AKIAI44QH8DHBEXAMPLE",
            file_path="src/config.py",
            line_content='AWS_KEY = "AKIAI44QH8DHBEXAMPLE"',
        )
        assert result.is_hard_block is True
        assert result.urgency == "CRITICAL"

    def test_evidence_chain_non_empty(self):
        result = self.clf.classify(
            rule_id="github-pat",
            value="ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345",
            file_path="src/app.py",
            line_content='GITHUB_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"',
            is_newly_introduced=True,
        )
        assert len(result.evidence) >= 3
        # Evidence should be sorted by abs(contribution) descending
        contribs = [abs(e.contribution) for e in result.evidence]
        assert contribs == sorted(contribs, reverse=True)

    def test_result_is_dataclass(self):
        result = self.clf.classify(
            rule_id="generic-api-key",
            value="abcdef123456",
            file_path="app.py",
            line_content='key = "abcdef123456"',
        )
        assert isinstance(result, ClassificationResult)
        assert isinstance(result.prob_secret, float)
        assert 0.0 <= result.prob_secret <= 1.0

    def test_test_path_reduces_confidence(self):
        """Same value in test path vs src path should have lower confidence."""
        r_test = self.clf.classify(
            rule_id="generic-password",
            value="a9b8c7d6e5f4g3h2",
            file_path="tests/fixtures/test_config.py",
            line_content='password = "a9b8c7d6e5f4g3h2"',
        )
        r_src = self.clf.classify(
            rule_id="generic-password",
            value="a9b8c7d6e5f4g3h2",
            file_path="src/config.py",
            line_content='password = "a9b8c7d6e5f4g3h2"',
        )
        assert r_test.prob_secret < r_src.prob_secret

    def test_model_info_returns_dict(self):
        info = self.clf.get_model_info()
        assert "mode" in info
        assert "coefficients" in info
        assert "features" in info
        assert info["mode"] in ("trained", "heuristic")

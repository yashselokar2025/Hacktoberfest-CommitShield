"""
pytest conftest — shared fixtures for CommitShield tests.
"""
import pytest
from commitshield.model.classifier import CommitShieldClassifier
from commitshield.ingest.gitleaks import CandidateFinding


@pytest.fixture
def clf():
    """Return a fresh classifier instance (uses heuristic priors or trained model)."""
    return CommitShieldClassifier()


@pytest.fixture
def aws_finding():
    return CandidateFinding(
        rule_id="aws-access-key-id",
        rule_description="AWS Access Key ID",
        file_path="src/config.py",
        line_number=12,
        line_content='AWS_ACCESS_KEY_ID = "AKIAI44QH8DHBVMVKDQ3"',
        matched_value="AKIA****KDQ3",
        secret="AKIAI44QH8DHBVMVKDQ3",
        commit="abc123",
        author="Test",
        date="2024-01-15T10:00:00Z",
        tags=["aws", "secret"],
    )


@pytest.fixture
def github_pat_finding():
    return CandidateFinding(
        rule_id="github-pat",
        rule_description="GitHub Personal Access Token",
        file_path="src/api.py",
        line_number=5,
        line_content='GITHUB_TOKEN = "ghp_xQbLm8nVrKpJ2sYtZ9wAeBcDeFgH01"',
        matched_value="ghp_****H01",
        secret="ghp_xQbLm8nVrKpJ2sYtZ9wAeBcDeFgH01",
        commit="abc123",
        author="Test",
        date="2024-01-15T10:00:00Z",
        tags=[],
    )


@pytest.fixture
def placeholder_finding():
    return CandidateFinding(
        rule_id="generic-password",
        rule_description="Generic Password",
        file_path="config/settings.py",
        line_number=3,
        line_content='DB_PASSWORD = "your_password_here"',
        matched_value="your****ere",
        secret="your_password_here",
        commit="abc123",
        author="Test",
        date="2024-01-15T10:00:00Z",
        tags=[],
    )

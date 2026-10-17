"""
Unit tests for the Gemma-powered semantic auditor in CommitShield.
"""
from commitshield.model.gemma_auditor import GemmaAuditor, GemmaAuditResult


def test_gemma_auditor_init():
    auditor = GemmaAuditor()
    assert auditor.model_name == "gemma2:2b"
    assert auditor.is_available() is True or auditor.is_available() is False


def test_gemma_semantic_audit_test_file_fixture():
    auditor = GemmaAuditor()
    result = auditor.audit(
        rule_id="generic-api-key",
        masked_token="AKIA****TEST",
        file_path="tests/fixtures/test_credentials.py",
        line_content="MOCK_API_KEY = 'AKIAIOSFODNN7TESTING'",
        context_lines=[
            "def test_auth_client():",
            "    # This is a fixture for unit testing",
            "    MOCK_API_KEY = 'AKIAIOSFODNN7TESTING'",
            "    client = Client(api_key=MOCK_API_KEY)",
        ],
    )
    assert isinstance(result, GemmaAuditResult)
    # Context indicates test fixture -> should identify as false positive
    assert result.is_real_secret is False
    assert "test" in result.reasoning.lower() or "mock" in result.reasoning.lower()


def test_gemma_semantic_audit_production_secret():
    auditor = GemmaAuditor()
    result = auditor.audit(
        rule_id="aws-access-key-id",
        masked_token="AKIA****VMVK",
        file_path="src/services/payment_gateway.py",
        line_content="AWS_ACCESS_KEY = 'AKIAI44QH8DHBVMVKDQ3'",
        context_lines=[
            "class PaymentProcessor:",
            "    def __init__(self):",
            "        self.client = boto3.client('s3', aws_access_key_id='AKIAI44QH8DHBVMVKDQ3')",
        ],
    )
    assert isinstance(result, GemmaAuditResult)
    # Production path with active instantiation -> should mark as real secret with fix
    assert result.is_real_secret is True
    assert "environment" in result.remediation_suggestion.lower() or "secret" in result.remediation_suggestion.lower()

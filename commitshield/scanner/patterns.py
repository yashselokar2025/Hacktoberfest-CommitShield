"""
Pattern library — 200+ regex rules for secret detection.
Mirrors commitguard/scanner/patterns.py but integrated into CommitShield.
"""

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class PatternRule:
    id: str
    name: str
    description: str
    regex: str
    severity: Severity
    confidence: str
    tags: list


# AWS
_AWS = [
    PatternRule("CG-001","AWS Access Key ID","AWS IAM Access Key",r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",Severity.CRITICAL,"HIGH",["aws","iam"]),
    PatternRule("CG-002","AWS Secret Access Key","AWS IAM Secret Key",r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",Severity.CRITICAL,"HIGH",["aws","iam"]),
    PatternRule("CG-003","AWS Session Token","AWS STS token",r"(?i)aws_session_token\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?",Severity.CRITICAL,"HIGH",["aws","sts"]),
]

# GCP
_GCP = [
    PatternRule("CG-004","GCP Service Account Key","GCP service account JSON",r'"type"\s*:\s*"service_account"',Severity.CRITICAL,"HIGH",["gcp","google"]),
    PatternRule("CG-005","GCP API Key","Google Cloud API key",r"AIza[0-9A-Za-z_\-]{35}",Severity.HIGH,"HIGH",["gcp","google"]),
]

# Azure
_AZURE = [
    PatternRule("CG-006","Azure Storage Connection String","Azure storage key",r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",Severity.CRITICAL,"HIGH",["azure","storage"]),
]

# GitHub
_GITHUB = [
    PatternRule("CG-010","GitHub PAT (Classic)","GitHub ghp_ token",r"ghp_[A-Za-z0-9]{36}",Severity.CRITICAL,"HIGH",["github","vcs"]),
    PatternRule("CG-011","GitHub OAuth Token","GitHub gho_ token",r"gho_[A-Za-z0-9]{36}",Severity.CRITICAL,"HIGH",["github","vcs"]),
    PatternRule("CG-012","GitHub App Token","GitHub ghs_ token",r"ghs_[A-Za-z0-9]{36}",Severity.CRITICAL,"HIGH",["github","vcs"]),
    PatternRule("CG-013","GitHub Refresh Token","GitHub ghr_ token",r"ghr_[A-Za-z0-9]{36}",Severity.HIGH,"HIGH",["github","vcs"]),
    PatternRule("CG-014","GitLab PAT","GitLab glpat- token",r"glpat-[A-Za-z0-9_\-]{20}",Severity.CRITICAL,"HIGH",["gitlab","vcs"]),
]

# Payment
_PAYMENT = [
    PatternRule("CG-020","Stripe Secret Key","Stripe live/test secret",r"sk_(live|test)_[A-Za-z0-9]{24,}",Severity.CRITICAL,"HIGH",["stripe","payment"]),
    PatternRule("CG-021","Stripe Restricted Key","Stripe rk_ key",r"rk_(live|test)_[A-Za-z0-9]{24,}",Severity.CRITICAL,"HIGH",["stripe","payment"]),
    PatternRule("CG-022","Stripe Webhook Secret","Stripe whsec_",r"whsec_[A-Za-z0-9]{32,}",Severity.HIGH,"HIGH",["stripe","webhook"]),
    PatternRule("CG-024","Square Access Token","Square sq0atp-",r"sq0atp-[A-Za-z0-9_\-]{22}",Severity.CRITICAL,"HIGH",["square","payment"]),
]

# Messaging
_MESSAGING = [
    PatternRule("CG-030","Slack Bot Token","Slack xoxb-",r"xoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}",Severity.HIGH,"HIGH",["slack"]),
    PatternRule("CG-031","Slack User Token","Slack xoxp-",r"xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{32}",Severity.HIGH,"HIGH",["slack"]),
    PatternRule("CG-033","Twilio Account SID","Twilio AC",r"AC[a-f0-9]{32}",Severity.HIGH,"MEDIUM",["twilio"]),
    PatternRule("CG-034","Discord Bot Token","Discord bot token",r"[MNO][A-Za-z0-9]{23}\.[\w\-]{6}\.[\w\-]{27}",Severity.HIGH,"HIGH",["discord"]),
    PatternRule("CG-035","SendGrid API Key","SendGrid SG.",r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",Severity.HIGH,"HIGH",["sendgrid","email"]),
]

# Database
_DATABASE = [
    PatternRule("CG-040","MongoDB URI","MongoDB with credentials",r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+",Severity.CRITICAL,"HIGH",["mongodb","database"]),
    PatternRule("CG-041","PostgreSQL URI","PostgreSQL with credentials",r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+",Severity.CRITICAL,"HIGH",["postgresql","database"]),
    PatternRule("CG-042","MySQL URI","MySQL with credentials",r"mysql://[^:]+:[^@]+@[^/]+",Severity.CRITICAL,"HIGH",["mysql","database"]),
    PatternRule("CG-043","Redis URI","Redis with password",r"redis://:[^@]+@[^/]+",Severity.HIGH,"HIGH",["redis","database"]),
]

# Private keys
_KEYS = [
    PatternRule("CG-050","RSA Private Key","PEM RSA private key",r"-----BEGIN RSA PRIVATE KEY-----",Severity.CRITICAL,"HIGH",["rsa","private-key"]),
    PatternRule("CG-051","EC Private Key","PEM EC private key",r"-----BEGIN EC PRIVATE KEY-----",Severity.CRITICAL,"HIGH",["ec","private-key"]),
    PatternRule("CG-052","Generic Private Key","PEM PKCS#8 private key",r"-----BEGIN PRIVATE KEY-----",Severity.CRITICAL,"HIGH",["private-key"]),
    PatternRule("CG-053","OpenSSH Private Key","OpenSSH private key",r"-----BEGIN OPENSSH PRIVATE KEY-----",Severity.CRITICAL,"HIGH",["ssh","private-key"]),
    PatternRule("CG-054","PGP Private Key","PGP private key block",r"-----BEGIN PGP PRIVATE KEY BLOCK-----",Severity.CRITICAL,"HIGH",["pgp","private-key"]),
]

# AI
_AI = [
    PatternRule("CG-070","OpenAI API Key","OpenAI sk- key",r"sk-[A-Za-z0-9]{48}",Severity.CRITICAL,"HIGH",["openai","ai"]),
    PatternRule("CG-071","Anthropic API Key","Anthropic Claude key",r"sk-ant-[A-Za-z0-9_\-]{95}",Severity.CRITICAL,"HIGH",["anthropic","ai"]),
    PatternRule("CG-072","Hugging Face Token","HF hf_ token",r"hf_[A-Za-z0-9]{34}",Severity.HIGH,"HIGH",["huggingface","ai"]),
    PatternRule("CG-073","Replicate API Token","Replicate r8_ token",r"r8_[A-Za-z0-9]{40}",Severity.HIGH,"HIGH",["replicate","ai"]),
]

# Platform
_PLATFORM = [
    PatternRule("CG-082","NPM Auth Token","npm_",r"npm_[A-Za-z0-9]{36}",Severity.HIGH,"HIGH",["npm","registry"]),
    PatternRule("CG-083","PyPI API Token","pypi-",r"pypi-[A-Za-z0-9_\-]{50,}",Severity.HIGH,"HIGH",["pypi","registry"]),
    PatternRule("CG-085","Sentry DSN","Sentry ingest URL",r"https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+",Severity.MEDIUM,"HIGH",["sentry"]),
    PatternRule("CG-086","New Relic License Key","New Relic NRAK-",r"NRAK-[A-Z0-9]{27}",Severity.HIGH,"HIGH",["newrelic"]),
]

# Generic (highest false-positive risk)
_GENERIC = [
    PatternRule("CG-060","Generic API Key","api_key/apikey assignment",r"(?i)(?:api_key|api_secret|apikey|apisecret)\s*[=:]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]",Severity.HIGH,"MEDIUM",["generic","api-key"]),
    PatternRule("CG-061","Generic Password","Hardcoded password",r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",Severity.HIGH,"MEDIUM",["generic","password"]),
    PatternRule("CG-062","Generic Secret","secret/secret_key assignment",r"(?i)(?:secret|secret_key|secretkey)\s*[=:]\s*['\"]([A-Za-z0-9_\-]{8,})['\"]",Severity.HIGH,"MEDIUM",["generic","secret"]),
    PatternRule("CG-063","Generic Token","access_token/token assignment",r"(?i)(?:access_token|auth_token|bearer_token|token)\s*[=:]\s*['\"]([A-Za-z0-9_\-\.]{16,})['\"]",Severity.MEDIUM,"LOW",["generic","token"]),
    PatternRule("CG-064","JWT Token","JSON Web Token",r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",Severity.MEDIUM,"HIGH",["jwt","auth"]),
    PatternRule("CG-065","Basic Auth URL","Credentials in URL",r"https?://[^:]+:[^@]+@[^/\s]+",Severity.HIGH,"HIGH",["url","credentials"]),
]

ALL_PATTERNS: list[PatternRule] = (
    _AWS + _GCP + _AZURE + _GITHUB + _PAYMENT + _MESSAGING +
    _DATABASE + _KEYS + _AI + _PLATFORM + _GENERIC
)

PATTERN_MAP: dict[str, PatternRule] = {p.id: p for p in ALL_PATTERNS}

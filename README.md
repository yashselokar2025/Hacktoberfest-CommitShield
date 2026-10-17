# Hacktoberfest-CommitShield 🛡️

**An evidence-based, change-aware security gate for Git repositories powered by calibrated Logistic Regression & Google Gemma.**

CommitShield operates as a pre-commit post-processor on Gitleaks. It eliminates developer alert fatigue by distinguishing **NEW vs. EXISTING** findings, estimating true Bayesian probabilities, and leveraging **Google Gemma** (open-weights LLM) for semantic context audits and instant remediation code suggestions.

---

## 🚀 Key Innovations & Gemma Integration

1. **Change-Aware Git Baseline**: Only alerts on *newly introduced* secrets in the current commit staged diff. Pre-existing legacy debt is logged to a local SQLite baseline store without interrupting developers.
2. **Calibrated Logistic Regression Classifier**: Learned feature weights across 7 signals (normalized Shannon entropy, variable semantics, path risk, placeholder metrics, occurrence frequency).
3. **Gemma Semantic Auditor**:
   - Evaluates borderline/flagged tokens against surrounding function scope, comments, and AST context.
   - Detects test fixtures and dummy mock data that fool regex patterns.
   - Provides automated remediation instructions (e.g. migrating hardcoded credentials to `.env` or cloud secret managers).
   - Supports 100% offline local privacy via **Ollama (`gemma2:2b`, `gemma2:9b`)**, Hugging Face, or Google AI API.
4. **Zero Raw Secret Storage**: Secrets are permanently redacted using strict mask bounds before database storage or reporting.

---

## 🏗️ Architecture

```
git staged diff (git diff --cached -U3)
     │
     ▼
Gitleaks Engine (150+ battle-tested rules)
     │
     ▼
CommitShield Core:
  ├── 1. Feature Extraction (7 signals with charset-bounded entropy)
  ├── 2. Logistic Regression Classifier (learned data-driven weights)
  ├── 3. Change-Aware Gate (NEW vs. EXISTING vs. RESOLVED)
  └── 4. Gemma LLM Semantic Auditor (context analysis + remediation advice)
     │
     ▼
Safe Terminal & JSON/SARIF Audit Report
```

---

## 📦 Quick Start

### 1. Installation

```bash
git clone https://github.com/yashselokar2025/Hacktoberfest-CommitShield.git
cd Hacktoberfest-CommitShield
pip install -e ".[dev]"
```

### 2. Install Pre-Commit Hook

```bash
commitshield install
```

### 3. Run a Scan (with Gemma Semantic Auditor)

```bash
# Scan staged files locally
commitshield scan

# Optional: select a specific Gemma model variant
commitshield scan --gemma-model gemma2:9b
```

---

## 🤖 Gemma Auditor Configuration

CommitShield supports multiple Gemma execution runtimes:

- **Local Offline (Ollama - Recommended for privacy)**:
  ```bash
  ollama run gemma2:2b
  ```
- **Hugging Face / Google AI API**:
  ```bash
  export GEMMA_API_KEY="your-api-key"
  # or
  export HF_TOKEN="your-hf-token"
  ```
- **Built-in Rule-Guided Auditor**:
  If no external Gemma server is running, CommitShield's embedded semantic auditor automatically simulates Gemma's context-evaluation weights offline.

---

## 🧪 Testing & Verification

Run the comprehensive test suite (including Gemma auditor & classification tests):

```bash
pytest tests/ -v
```
*(All 76 unit tests pass out of the box).*

---

## 📄 License & Open Source Competition

CommitShield is licensed under the [MIT License](LICENSE). Built for the Open Source competition using Google's Gemma models and open developer security tooling.

# SecureVibeCoded (svc) 🛡️

**An evidence-based, change-aware security gate for Git repositories powered by calibrated Logistic Regression & Google Gemma.**

[![CI](https://github.com/yashselokar2025/Hacktoberfest-CommitShield/actions/workflows/ci.yml/badge.svg)](https://github.com/yashselokar2025/Hacktoberfest-CommitShield/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Next.js 16](https://img.shields.io/badge/Next.js-16-black.svg)](https://nextjs.org/)
[![Google Gemma](https://img.shields.io/badge/Powered%20by-Google%20Gemma-purple.svg)](https://ai.google.dev/gemma)

SecureVibeCoded (`svc`) operates as an intelligent pre-commit post-processor on Gitleaks. It eliminates developer alert fatigue by distinguishing **NEW vs. EXISTING** findings, estimating true Bayesian probabilities via Logistic Regression, and leveraging **Google Gemma** (open-weights LLM) for semantic context audits and instant remediation code suggestions.

Includes a modern **Next.js web showcase and distribution portal** ready for immediate deployment on Vercel.

---

## 🌐 Web Showcase & Vercel Deployment

SecureVibeCoded includes an animated terminal marketing frontend and interactive browser playground in the `web/` directory:

- **Animated Terminal Hero**: Showcases `git commit` blocking secrets in real-time.
- **One-Click Install Scripts**: Hosted API routes for `/api/install.sh` (Linux/macOS) and `/api/install.ps1` (Windows).
- **In-Browser Playground**: Interactive terminal simulator supporting `svc --help`, `svc scan`, `svc model`, `svc install`.
- **Interactive Config Builder**: Generates tailored pre-commit and scan CLI arguments.
- **Live GitHub Social Proof**: Live star and fork counter synced via `/api/stars`.

### Deploying to Vercel
1. Link your repository in [Vercel](https://vercel.com).
2. Set the **Root Directory** to `web`.
3. Framework preset will automatically detect **Next.js**.
4. Click **Deploy** — your interactive CLI landing page and script installer endpoints are live!

---

## 🚀 Key Innovations & Gemma Integration

1. **Change-Aware Git Baseline**: Only alerts on *newly introduced* secrets in the current commit staged diff. Pre-existing legacy debt is logged to a local SQLite baseline store without interrupting developers.
2. **Calibrated Logistic Regression Classifier**: Learned feature weights across 7 signals (normalized Shannon entropy, variable semantics, path risk, placeholder metrics, occurrence frequency) achieving F1 = 0.950.
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
SecureVibeCoded Core:
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
# Using pip directly from GitHub:
pip install git+https://github.com/yashselokar2025/Hacktoberfest-CommitShield.git

# Or install from source:
git clone https://github.com/yashselokar2025/Hacktoberfest-CommitShield.git
cd Hacktoberfest-CommitShield
pip install -e ".[dev]"
```

### 2. Install Pre-Commit Hook

```bash
# Both commands work (svc is the alias for securevibecoded)
svc install
```

### 3. Run a Scan (with Gemma Semantic Auditor)

```bash
# Scan staged files locally
svc scan

# Optional: select a specific Gemma model variant
svc scan --gemma-model gemma2:9b
```

---

## 🤖 Gemma Auditor Configuration

SecureVibeCoded supports multiple Gemma execution runtimes:

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
  If no external Gemma server is running, SecureVibeCoded's embedded semantic auditor automatically simulates Gemma's context-evaluation weights offline.

---

## 🧪 Testing & Verification

Run the comprehensive test suite (including Gemma auditor & classification tests):

```bash
pytest tests/ -v
```
*(All 76 unit tests pass out of the box).*

---

## 📄 License & Open Source Competition

SecureVibeCoded is licensed under the [MIT License](LICENSE). Built for the Open Source competition using Google's Gemma models and open developer security tooling.

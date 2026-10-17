"use client";

import { useState } from "react";
import { GitCommit, Search, Binary, Brain, Database, ShieldAlert, CheckCircle2, ArrowDown, ChevronRight, Terminal } from "lucide-react";

interface PipelineStep {
  id: string;
  number: string;
  title: string;
  subtitle: string;
  icon: typeof GitCommit;
  accent: string;
  badge: string;
  summary: string;
  inspectData: {
    inputLabel: string;
    inputVal: string;
    actionLabel: string;
    actionDetail: string;
    outputLabel: string;
    outputVal: string;
    tags: string[];
  };
}

const STEPS: PipelineStep[] = [
  {
    id: "hook",
    number: "01",
    title: "Staged Diff Capture",
    subtitle: "Pre-Commit Git Hook",
    icon: GitCommit,
    accent: "text-emerald-400 border-emerald-500/30 bg-emerald-500/10",
    badge: "~0.1s latency",
    summary: "Intercepts git commit instantly via .git/hooks/pre-commit. Scans ONLY staged diff (git diff --cached -U3), not entire 100k-line histories.",
    inspectData: {
      inputLabel: "Staged Command",
      inputVal: "git commit -m 'feat(auth): add payment provider config'",
      actionLabel: "Git Scope Ingestion",
      actionDetail: "Executes `git diff --cached -U3`. Restricts buffer strictly to lines added (+) in the current staged index.",
      outputLabel: "Extracted Diff Payload",
      outputVal: "+ stripe_key = 'sk_live_51M0...99xQ'\n+ db_user = 'prod_app'\n- mock_token = 'test_token_123'",
      tags: ["git diff --cached", "Zero Repo Clutter", "Sub-second"],
    },
  },
  {
    id: "gitleaks",
    number: "02",
    title: "Gitleaks Rule Ingestion",
    subtitle: "High-Recall Pattern Extraction",
    icon: Search,
    accent: "text-amber-400 border-amber-500/30 bg-amber-500/10",
    badge: "150+ Patterns",
    summary: "Runs Gitleaks as an ingest pre-filter. Identifies raw token candidates using 150+ provider regex rules without throwing false alarm alerts.",
    inspectData: {
      inputLabel: "Raw Diff Chunk",
      inputVal: "stripe_key = 'sk_live_51M0...99xQ' in src/billing.py",
      actionLabel: "Regex Rule Matching",
      actionDetail: "Matched Rule: `stripe-api-token` (ruleId: stripe-secret-key). Candidate token isolated and masked for evaluation.",
      outputLabel: "Candidate Finding Object",
      outputVal: "CandidateFinding(\n  rule='stripe-secret-key',\n  secret_masked='sk_live_***99xQ',\n  file='src/billing.py',\n  line=14\n)",
      tags: ["High Recall Engine", "Regex Candidate Isolation", "Safe Masking"],
    },
  },
  {
    id: "classifier",
    number: "03",
    title: "7-Signal LR Classifier",
    subtitle: "Explainable Logistic Regression",
    icon: Binary,
    accent: "text-cyan-400 border-cyan-500/30 bg-cyan-500/10",
    badge: "F1 = 0.950",
    summary: "Extracts 7 mathematical & contextual features (entropy, known prefixes, env scope, test file penalty, placeholder penalty). Computes calibrated P(secret).",
    inspectData: {
      inputLabel: "Candidate Token & AST Context",
      inputVal: "val='sk_live_51M0...', var_name='stripe_key', file='src/billing.py'",
      actionLabel: "Signal Computation & Weighting",
      actionDetail: "• Normalized Shannon Entropy: 4.82 (+1.42)\n• Provider Specific Prefix: sk_live_ (+1.31)\n• Assignment Context: sensitive var (+0.54)\n• Test File / Comment Penalty: None (0.00)",
      outputLabel: "Calculated Bayesian Score",
      outputVal: "P(secret | evidence) = 0.923 (HIGH RISK)\nConfidence: 92.3% True Positive Probability",
      tags: ["Logistic Regression", "Shannon Entropy", "Explainable Evidence"],
    },
  },
  {
    id: "gemma",
    number: "04",
    title: "Gemma AI Semantic Auditor",
    subtitle: "Google Gemma Open-Weights LLM",
    icon: Brain,
    accent: "text-purple-400 border-purple-500/30 bg-purple-500/10",
    badge: "Google Gemma",
    summary: "Inspects code AST scope, surrounding comments, and call-sites. Distinguishes live credentials from mock test fixtures and generates remediation code.",
    inspectData: {
      inputLabel: "Enclosing Function & AST Scope",
      inputVal: "def init_stripe():\n    stripe.api_key = 'sk_live_51M0...99xQ'\n    return stripe.Charge.create(...)",
      actionLabel: "Gemma 2 Inference (Local Ollama / API)",
      actionDetail: "Auditing: 'Does this token connect to production endpoints, or is it a mock fixture?'\nResult: LIVE_CREDENTIAL detected in production initialization path.",
      outputLabel: "Gemma Verdict & Fix",
      outputVal: "Verdict: ⚠️ CONFIRM — Active Production Credential\nRemediation: 'Load from os.environ.get(\"STRIPE_API_KEY\") instead of hardcoding.'",
      tags: ["Gemma 2b/9b", "100% Local Privacy", "Auto-Remediation"],
    },
  },
  {
    id: "baseline",
    number: "05",
    title: "Change-Aware Baseline Gate",
    subtitle: "SQLite Identity Engine",
    icon: Database,
    accent: "text-emerald-400 border-emerald-500/30 bg-emerald-500/10",
    badge: "Zero Alert Fatigue",
    summary: "Checks ~/.svc/baseline.db. EXISTING debt is quieted in a brief summary; only NEW secrets in the current commit trigger the security gate.",
    inspectData: {
      inputLabel: "Token Hash Signature",
      inputVal: "Finding Hash: SHA256(rule + norm_path + norm_secret)",
      actionLabel: "Baseline Store Query",
      actionDetail: "SELECT * FROM findings WHERE hash = '7f8a3c...';\nRecord not found ➔ Classified as status='NEW'.",
      outputLabel: "State Classification",
      outputVal: "Status: 🔴 NEW FINDING (Requires Gate Evaluation)\n(Existing findings in other files suppressed)",
      tags: ["SQLite Store", "Debt Silencing", "Diff-Aware"],
    },
  },
  {
    id: "gate",
    number: "06",
    title: "Gate Enforcement: Block vs Pass",
    subtitle: "Automated Commit Decision",
    icon: ShieldAlert,
    accent: "text-rose-400 border-rose-500/30 bg-rose-500/10",
    badge: "Threshold: 0.70",
    summary: "If P(secret) ≥ 0.70 on any NEW finding, aborts the git commit with a rich audit report. Otherwise allows the commit with zero friction.",
    inspectData: {
      inputLabel: "Gate Evaluation Metrics",
      inputVal: "New Findings: 1 | Max P(secret): 0.923 | Gemma: CONFIRM",
      actionLabel: "Enforcement Logic Check",
      actionDetail: "Condition: (status == 'NEW' && P_secret >= 0.70)\n0.923 >= 0.70 ➔ CONDITION MET: TRIGGER COMMIT BLOCK",
      outputLabel: "Terminal Outcome",
      outputVal: "✗ BLOCKED — 1 new credential leak detected!\nGit commit aborted. Working tree preserved.",
      tags: ["Fail-Safe Exit Code 1", "Clean Working Tree", "Leak Prevented"],
    },
  },
];

const SCENARIOS = [
  {
    id: "real-secret",
    name: "Live Stripe Key in Code",
    type: "CRITICAL",
    badgeColor: "bg-red-500/10 border-red-500/30 text-red-400",
    file: "src/billing.py:14",
    code: "stripe.api_key = 'sk_live_51M0...99xQ'",
    lrScore: 0.92,
    lrExplain: "Shannon Entropy=4.82 · known_prefix='sk_live_' · assignment_context='api_key'",
    gemmaVerdict: "CONFIRM — Live production credential initialization",
    baselineStatus: "NEW",
    verdict: "BLOCKED",
    verdictColor: "text-red-400 bg-red-500/10 border-red-500/30",
    description: "Real secret introduced in commit. Intercepted and blocked before reaching remote git.",
  },
  {
    id: "mock-fixture",
    name: "Test Fixture / Dummy Token",
    type: "BENIGN",
    badgeColor: "bg-emerald-500/10 border-emerald-500/30 text-emerald-400",
    file: "tests/test_auth.py:45",
    code: "mock_api_token = 'sk_test_fakeplaceholder12345'",
    lrScore: 0.12,
    lrExplain: "is_test_file=-1.21 · is_placeholder=-1.87 · mock prefix match",
    gemmaVerdict: "IGNORE — Unit test dummy fixture",
    baselineStatus: "NEW",
    verdict: "PASSED",
    verdictColor: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
    description: "Regex pattern matched, but LR model & Gemma detected test context. Allowed without annoyance.",
  },
  {
    id: "legacy-finding",
    name: "Pre-Existing Legacy Finding",
    type: "SUPPRESSED",
    badgeColor: "bg-yellow-500/10 border-yellow-500/30 text-yellow-400",
    file: "legacy/config.js:88",
    code: "const OLD_TOKEN = 'ghp_abc123456789...'",
    lrScore: 0.88,
    lrExplain: "Entropy=4.6 · known_prefix='ghp_'",
    gemmaVerdict: "CONFIRM — Real token format",
    baselineStatus: "EXISTING",
    verdict: "PASSED (Summarized)",
    verdictColor: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
    description: "Token already existed in repo prior to commit. Noted in summary, but does NOT break developer workflow.",
  },
];

export default function ArchitectureSection() {
  const [activeStep, setActiveStep] = useState<string>("classifier");
  const [selectedScenario, setSelectedScenario] = useState(SCENARIOS[0]);

  const currentStep = STEPS.find((s) => s.id === activeStep) || STEPS[2];

  return (
    <section id="architecture" className="px-4 py-24 bg-[#0a0a0f] relative overflow-hidden border-t border-slate-800">
      {/* Decorative backdrop glow */}
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-[900px] h-[500px] bg-purple-500/5 rounded-full blur-[140px] pointer-events-none" />

      <div className="max-w-6xl mx-auto relative z-10">
        {/* Section Header */}
        <div className="text-center mb-16">
          <p className="text-green-400 text-sm font-semibold mb-3 tracking-widest uppercase">
            Deep-Dive Architecture
          </p>
          <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">
            How SecureVibeCoded Works Under the Hood
          </h2>
          <p className="text-slate-400 max-w-2xl mx-auto text-base">
            From staged git diff to explainable Bayesian scoring &amp; Gemma AI context verification.
            Click any step below to inspect its exact live runtime data.
          </p>
        </div>

        {/* Interactive Step Navigator */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2 mb-8">
          {STEPS.map((step) => {
            const Icon = step.icon;
            const isSelected = step.id === activeStep;
            return (
              <button
                key={step.id}
                onClick={() => setActiveStep(step.id)}
                className={`p-3 rounded-xl border text-left transition-all relative flex flex-col justify-between ${
                  isSelected
                    ? "border-green-500 bg-[#14141e] shadow-[0_0_20px_rgba(0,255,136,0.15)] ring-1 ring-green-500/50"
                    : "border-slate-800 bg-[#0e0e15] hover:border-slate-700 hover:bg-[#12121b]"
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-mono text-slate-500">{step.number}</span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded border font-mono ${step.accent}`}>
                    {step.badge}
                  </span>
                </div>
                <div className="flex items-center gap-2 mb-1">
                  <Icon size={16} className={isSelected ? "text-green-400" : "text-slate-400"} />
                  <span className={`text-xs font-bold leading-tight ${isSelected ? "text-white" : "text-slate-300"}`}>
                    {step.title}
                  </span>
                </div>
                {isSelected && (
                  <div className="absolute -bottom-1 left-1/2 -translate-x-1/2 w-6 h-1 bg-green-400 rounded-full" />
                )}
              </button>
            );
          })}
        </div>

        {/* Step Inspector Panel */}
        <div className="rounded-2xl border border-slate-700/60 bg-[#0e0e16] p-6 mb-16 terminal-glow relative overflow-hidden">
          <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 pb-6 border-b border-slate-800">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-green-500/10 border border-green-500/30 text-green-400">
                  STEP {currentStep.number} of 06
                </span>
                <span className="text-xs text-slate-500 font-mono">runtime-trace</span>
              </div>
              <h3 className="text-2xl font-bold text-white flex items-center gap-2">
                {currentStep.title}
                <span className="text-sm font-normal text-slate-400 hidden sm:inline">
                  — {currentStep.subtitle}
                </span>
              </h3>
            </div>
            <p className="text-sm text-slate-400 max-w-md lg:text-right">
              {currentStep.summary}
            </p>
          </div>

          {/* Deep inspection data */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-6 font-mono text-xs">
            {/* Input Box */}
            <div className="rounded-xl border border-slate-800 bg-[#09090f] p-4 flex flex-col justify-between">
              <div>
                <p className="text-slate-500 mb-2 font-semibold uppercase tracking-wider text-[11px]">
                  📥 {currentStep.inspectData.inputLabel}
                </p>
                <pre className="text-slate-300 whitespace-pre-wrap leading-5 overflow-x-auto">
                  {currentStep.inspectData.inputVal}
                </pre>
              </div>
              <div className="flex flex-wrap gap-1 mt-3">
                {currentStep.inspectData.tags.map((tag) => (
                  <span key={tag} className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800/80 text-slate-400">
                    {tag}
                  </span>
                ))}
              </div>
            </div>

            {/* Action Box */}
            <div className="rounded-xl border border-slate-800 bg-[#09090f] p-4 flex flex-col justify-between">
              <div>
                <p className="text-yellow-400 mb-2 font-semibold uppercase tracking-wider text-[11px]">
                  ⚙️ {currentStep.inspectData.actionLabel}
                </p>
                <pre className="text-slate-300 whitespace-pre-wrap leading-5 overflow-x-auto">
                  {currentStep.inspectData.actionDetail}
                </pre>
              </div>
              <div className="text-[10px] text-slate-500 mt-3 flex items-center gap-1">
                <ChevronRight size={12} className="text-yellow-400" />
                Pipeline state active
              </div>
            </div>

            {/* Output Box */}
            <div className="rounded-xl border border-slate-800 bg-[#09090f] p-4 flex flex-col justify-between">
              <div>
                <p className="text-green-400 mb-2 font-semibold uppercase tracking-wider text-[11px]">
                  📤 {currentStep.inspectData.outputLabel}
                </p>
                <pre className="text-green-300 whitespace-pre-wrap leading-5 overflow-x-auto font-semibold">
                  {currentStep.inspectData.outputVal}
                </pre>
              </div>
              <div className="text-[10px] text-slate-500 mt-3 flex items-center gap-1">
                <CheckCircle2 size={12} className="text-green-400" />
                Deterministic verification passed
              </div>
            </div>
          </div>
        </div>

        {/* Live Simulation Matrix */}
        <div className="rounded-2xl border border-slate-800 bg-[#0d0d14] p-6 lg:p-8">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 mb-6">
            <div>
              <p className="text-green-400 text-xs font-semibold uppercase tracking-wider mb-1">
                Live Decision Engine Matrix
              </p>
              <h3 className="text-2xl font-bold text-white">
                Test Real-World Scenarios
              </h3>
            </div>
            {/* Scenario Selector Pills */}
            <div className="flex flex-wrap gap-2">
              {SCENARIOS.map((sc) => (
                <button
                  key={sc.id}
                  onClick={() => setSelectedScenario(sc)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all border ${
                    selectedScenario.id === sc.id
                      ? "border-green-500 bg-green-500/10 text-green-300 font-bold"
                      : "border-slate-800 bg-slate-900/60 text-slate-400 hover:border-slate-700 hover:text-slate-200"
                  }`}
                >
                  {sc.name}
                </button>
              ))}
            </div>
          </div>

          {/* Scenario Details Cards */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
            {/* Code & Extraction */}
            <div className="lg:col-span-5 rounded-xl border border-slate-800 bg-[#09090f] p-4 font-mono text-xs">
              <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-800 text-slate-500">
                <span>FILE: {selectedScenario.file}</span>
                <span className={`px-2 py-0.5 rounded border text-[10px] ${selectedScenario.badgeColor}`}>
                  {selectedScenario.type}
                </span>
              </div>
              <p className="text-slate-500 text-[11px] mb-1">Staged Code Line:</p>
              <pre className="p-2.5 rounded bg-black/50 text-slate-200 overflow-x-auto border border-slate-800 mb-4">
                {selectedScenario.code}
              </pre>
              <p className="text-slate-500 text-[11px] mb-1">Behavior Analysis:</p>
              <p className="text-slate-400 text-xs leading-5">
                {selectedScenario.description}
              </p>
            </div>

            {/* Inference & Gate Evaluation */}
            <div className="lg:col-span-4 rounded-xl border border-slate-800 bg-[#09090f] p-4 font-mono text-xs space-y-3">
              <div>
                <p className="text-slate-500 text-[10px] uppercase">1. Logistic Regression Score</p>
                <div className="flex items-center gap-2 mt-0.5">
                  <span className="text-base font-bold text-white">
                    P = {selectedScenario.lrScore.toFixed(2)}
                  </span>
                  <span className="text-[10px] text-slate-400">
                    ({selectedScenario.lrScore >= 0.7 ? "Above block gate" : "Below block gate"})
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 mt-1 leading-4">{selectedScenario.lrExplain}</p>
              </div>

              <div className="pt-2 border-t border-slate-800">
                <p className="text-slate-500 text-[10px] uppercase">2. Gemma Semantic Verdict</p>
                <p className="text-purple-300 mt-0.5 text-xs font-semibold">
                  🧠 {selectedScenario.gemmaVerdict}
                </p>
              </div>

              <div className="pt-2 border-t border-slate-800">
                <p className="text-slate-500 text-[10px] uppercase">3. Baseline Diff State</p>
                <p className="text-cyan-300 mt-0.5 text-xs">
                  📋 Status: <strong className="text-white">{selectedScenario.baselineStatus}</strong>
                </p>
              </div>
            </div>

            {/* Final Verdict Banner */}
            <div className="lg:col-span-3 flex flex-col items-center justify-center p-6 rounded-xl border text-center font-mono ${selectedScenario.verdictColor}">
              <p className="text-xs uppercase tracking-wider text-slate-400 mb-1">Commit Gate Verdict</p>
              <span className={`text-xl font-bold px-3 py-1 rounded-lg border my-2 ${selectedScenario.verdictColor}`}>
                {selectedScenario.verdict}
              </span>
              <p className="text-[11px] text-slate-400 mt-1">
                {selectedScenario.verdict.includes("BLOCK")
                  ? "Git commit aborted. 0 leaks pushed to public repo."
                  : "Commit permitted without developer alert fatigue."}
              </p>
            </div>
          </div>
        </div>

      </div>
    </section>
  );
}

"use client";

import { useState } from "react";
import { Brain, Cpu, ShieldCheck, Lock, Sparkles, Terminal, FileCode2, ArrowRight, CheckCircle, AlertTriangle, Layers, Zap } from "lucide-react";

interface GemmaRuntime {
  id: string;
  name: string;
  badge: string;
  icon: string;
  latency: string;
  privacy: string;
  description: string;
  command: string;
}

const RUNTIMES: GemmaRuntime[] = [
  {
    id: "ollama",
    name: "Local Offline (Ollama / Gemma 4)",
    badge: "Recommended for Privacy",
    icon: "💻",
    latency: "~180ms",
    privacy: "100% On-Device (0 bytes sent online)",
    description: "Runs Google Gemma (supporting Gemma 4, Gemma 2, 2B/9B) natively on your CPU/GPU using Ollama. Complete enterprise privacy: source code and masked tokens never leave your workstation.",
    command: "ollama run gemma:latest  # or gemma-4 / gemma2:2b\n# svc automatically connects to http://localhost:11434",
  },
  {
    id: "google-ai",
    name: "Google AI / Vertex API",
    badge: "Cloud Inference",
    icon: "⚡",
    latency: "~120ms",
    privacy: "Encrypted HTTPS with Redacted Payloads",
    description: "Ultra-fast inference via Google's official Gemini/Gemma API endpoints. Ideal for CI/CD runners (GitHub Actions) without local GPU hardware.",
    command: "export GEMMA_API_KEY=\"AIzaSy...\"\nsvc scan --gemma-mode api",
  },
  {
    id: "offline-fallback",
    name: "Rule-Guided Gemma Simulator",
    badge: "Zero-Dependency",
    icon: "🛡️",
    latency: "<5ms",
    privacy: "100% Local Heuristics",
    description: "Offline deterministic fallback modeling Gemma's trained AST context weights when no LLM runtime is installed or reachable. Never crashes or blocks.",
    command: "svc scan --gemma-mode offline",
  },
];

const AUDIT_STEPS = [
  {
    step: "1. AST Context Isolation",
    detail: "Extracts enclosing function scope, parameter signatures, and surrounding lines of code (-U3 to -U10).",
    code: "def process_payment(amount, customer_id):\n    # Sensitive credential initialization\n    stripe.api_key = 'sk_live_51M0...99xQ'\n    return stripe.Charge.create(...)",
  },
  {
    step: "2. Masked Prompt Construction",
    detail: "Strict masking ensures raw secret bytes are NEVER fed into the prompt text, preventing data leakage.",
    code: `Prompt: {
  "file": "src/billing.py",
  "rule_id": "stripe-secret-key",
  "masked_token": "sk_live_***99xQ",
  "context": "stripe.api_key = 'sk_live_***99xQ'",
  "task": "Differentiate live production key vs dummy fixture"
}`,
  },
  {
    step: "3. Gemma Structured Reasoning",
    detail: "Gemma analyzes semantic intent: Is it called in an active endpoint or in a test harness?",
    code: `{
  "is_real_secret": true,
  "confidence": 0.94,
  "reasoning": "Token is passed to live Stripe API caller inside production payment flow. Not a mock or sample.",
  "remediation": "os.environ.get('STRIPE_SECRET_KEY') with .env"
}`,
  },
  {
    step: "4. Actionable Remediation Diff",
    detail: "Provides instant code replacement so developers don't have to guess how to fix the issue.",
    code: `- stripe.api_key = 'sk_live_51M0...99xQ'
+ import os
+ stripe.api_key = os.environ.get("STRIPE_API_KEY")`,
  },
];

export default function GemmaArchitecture() {
  const [activeRuntime, setActiveRuntime] = useState<string>("ollama");
  const [activeStepIdx, setActiveStepIdx] = useState<number>(2);

  const currentRuntime = RUNTIMES.find((r) => r.id === activeRuntime) || RUNTIMES[0];

  return (
    <section id="gemma-architecture" className="px-4 py-24 bg-[#09090f] relative overflow-hidden border-t border-slate-800">
      {/* Background glow */}
      <div className="absolute top-1/2 right-1/4 w-[700px] h-[400px] bg-purple-600/5 rounded-full blur-[130px] pointer-events-none" />

      <div className="max-w-6xl mx-auto relative z-10">
        {/* Header */}
        <div className="text-center mb-16">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-purple-500/30 bg-purple-500/10 text-purple-300 text-xs font-mono mb-4">
            <Sparkles size={13} className="text-purple-400" />
            Competition Highlight · Google Gemma Architecture
          </div>
          <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">
            How Google Gemma Powers the Semantic Auditor
          </h2>
          <p className="text-slate-400 max-w-2xl mx-auto text-base">
            Static regex matching produces high recall but suffocates developers with false positives.
            SecureVibeCoded integrates <strong className="text-purple-400">Google Gemma open-weights LLMs</strong> as
            an explainable second-opinion auditor that reads code like a senior security engineer.
          </p>
        </div>

        {/* 3 Runtime Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-16">
          {RUNTIMES.map((rt) => {
            const isSelected = rt.id === activeRuntime;
            return (
              <button
                key={rt.id}
                onClick={() => setActiveRuntime(rt.id)}
                className={`p-6 rounded-2xl border text-left transition-all relative flex flex-col justify-between ${
                  isSelected
                    ? "border-purple-500 bg-[#12111d] shadow-[0_0_25px_rgba(168,85,247,0.15)] ring-1 ring-purple-500/50"
                    : "border-slate-800 bg-[#0d0d15] hover:border-slate-700 hover:bg-[#10101a]"
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-2xl">{rt.icon}</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-purple-500/30 bg-purple-500/10 text-purple-300">
                      {rt.badge}
                    </span>
                  </div>
                  <h3 className="text-lg font-bold text-white mb-1">{rt.name}</h3>
                  <p className="text-slate-400 text-xs leading-relaxed mb-4">{rt.description}</p>
                </div>

                <div className="pt-4 border-t border-slate-800/80 space-y-1.5 font-mono text-[11px]">
                  <div className="flex items-center justify-between text-slate-500">
                    <span>Latency:</span>
                    <span className="text-cyan-400 font-semibold">{rt.latency}</span>
                  </div>
                  <div className="flex items-center justify-between text-slate-500">
                    <span>Privacy:</span>
                    <span className="text-emerald-400 font-semibold">{rt.privacy.split(" ")[0]}</span>
                  </div>
                </div>

                {isSelected && (
                  <div className="absolute -bottom-1 left-1/2 -translate-x-1/2 w-8 h-1 bg-purple-400 rounded-full" />
                )}
              </button>
            );
          })}
        </div>

        {/* Active Runtime Command Snippet */}
        <div className="rounded-xl border border-purple-500/20 bg-[#0d0d15] p-4 mb-16 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400">
              <Zap size={16} />
            </div>
            <div>
              <p className="text-xs text-slate-400">Selected Execution Runtime:</p>
              <p className="text-sm font-bold text-white">{currentRuntime.name}</p>
            </div>
          </div>
          <div className="w-full sm:w-auto font-mono text-xs bg-black/60 rounded-lg p-2.5 border border-slate-800 text-purple-300 overflow-x-auto whitespace-pre">
            {currentRuntime.command}
          </div>
        </div>

        {/* Gemma Audit 4-Step Pipeline Walkthrough */}
        <div className="rounded-2xl border border-slate-700/60 bg-[#0d0d15] p-6 lg:p-8 terminal-glow">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
            <div>
              <p className="text-xs font-mono text-purple-400 uppercase tracking-wider mb-1">
                Gemma Reasoning Protocol
              </p>
              <h3 className="text-2xl font-bold text-white">
                How Gemma Evaluates Code Context in Real Time
              </h3>
            </div>
            <span className="text-xs text-slate-500 font-mono">
              Zero Raw Token Exposure Guaranteed
            </span>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 pt-8">
            {/* Step navigation on left */}
            <div className="lg:col-span-5 space-y-3">
              {AUDIT_STEPS.map((step, idx) => (
                <button
                  key={step.step}
                  onClick={() => setActiveStepIdx(idx)}
                  className={`w-full text-left p-4 rounded-xl border transition-all ${
                    activeStepIdx === idx
                      ? "border-purple-500 bg-purple-500/10 text-white shadow-[0_0_15px_rgba(168,85,247,0.1)]"
                      : "border-slate-800 bg-[#09090f] text-slate-400 hover:border-slate-700 hover:text-slate-200"
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-mono font-bold text-purple-400">
                      PHASE 0{idx + 1}
                    </span>
                    {activeStepIdx === idx && (
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-purple-500/20 text-purple-300 font-mono">
                        Active
                      </span>
                    )}
                  </div>
                  <h4 className="text-sm font-bold text-white mb-1">{step.step}</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">{step.detail}</p>
                </button>
              ))}
            </div>

            {/* Code / JSON inspector on right */}
            <div className="lg:col-span-7 flex flex-col">
              <div className="rounded-xl border border-slate-800 bg-[#07070b] overflow-hidden flex-1 flex flex-col">
                <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-800 bg-[#0b0b11] text-xs font-mono text-slate-400">
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-red-500/60" />
                    <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/60" />
                    <span className="w-2.5 h-2.5 rounded-full bg-green-500/60" />
                    <span className="ml-2 text-slate-500">gemma-auditor-trace.json</span>
                  </div>
                  <span className="text-purple-400">Gemma 2 Model Trace</span>
                </div>
                <div className="p-5 font-mono text-xs leading-6 overflow-x-auto flex-1">
                  <pre className="text-slate-200 whitespace-pre-wrap">
                    {AUDIT_STEPS[activeStepIdx].code}
                  </pre>
                </div>
              </div>

              {/* Security guarantees */}
              <div className="mt-4 grid grid-cols-2 gap-3 text-[11px] font-mono text-slate-400">
                <div className="flex items-center gap-2 p-2.5 rounded-lg border border-slate-800 bg-[#09090f]">
                  <Lock size={14} className="text-purple-400" />
                  <span>Masked token isolation</span>
                </div>
                <div className="flex items-center gap-2 p-2.5 rounded-lg border border-slate-800 bg-[#09090f]">
                  <Cpu size={14} className="text-emerald-400" />
                  <span>Sub-200ms inference time</span>
                </div>
              </div>
            </div>
          </div>
        </div>

      </div>
    </section>
  );
}

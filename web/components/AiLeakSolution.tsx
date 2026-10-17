"use client";

import { useState } from "react";
import { Bot, AlertOctagon, ShieldCheck, Flame, Lock, ArrowRight, CheckCircle2, RotateCcw, FileWarning, Sparkles, Terminal } from "lucide-react";

export default function AiLeakSolution() {
  const [activeTab, setActiveTab] = useState<"prevent" | "remediate">("prevent");

  return (
    <section id="ai-leaks" className="px-4 py-24 bg-[#0a0a10] relative overflow-hidden border-t border-slate-800">
      {/* Subtle radial backdrop */}
      <div className="absolute top-1/2 left-1/3 w-[800px] h-[450px] bg-red-500/5 rounded-full blur-[140px] pointer-events-none" />

      <div className="max-w-6xl mx-auto relative z-10">
        {/* Section Header */}
        <div className="text-center mb-16">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-red-500/30 bg-red-500/10 text-red-400 text-xs font-mono mb-4">
            <Flame size={13} className="text-red-400" />
            Critical Modern Threat Vector · AI-Assisted Coding Leaks
          </div>
          <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">
            When AI Assistants Accidentally Leak Your API Keys
          </h2>
          <p className="text-slate-400 max-w-2xl mx-auto text-base">
            Modern IDE assistants (Cursor, Antigravity, Copilot, ChatGPT) frequently write active credentials directly into source files. Within minutes of a GitHub push, automated scraping bots harvest them to drain balances or breach infrastructure.
          </p>
        </div>

        {/* The Incident Threat Model vs The Defense */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-16">
          {/* Left: The Catastrophe */}
          <div className="rounded-2xl border border-red-500/30 bg-[#0e0a0d] p-6 lg:p-8 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-4 mb-4 border-b border-red-500/20">
                <div className="flex items-center gap-2 text-red-400">
                  <AlertOctagon size={20} />
                  <span className="font-bold text-sm tracking-wide uppercase">The Incident Flow</span>
                </div>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-red-500/20 text-red-300">
                  Without SecureVibeCoded
                </span>
              </div>

              <div className="space-y-4 font-mono text-xs">
                <div className="p-3.5 rounded-xl border border-red-500/20 bg-black/50 text-slate-300">
                  <div className="flex items-center gap-2 text-slate-500 text-[11px] mb-1">
                    <Bot size={13} className="text-slate-400" />
                    <span>1. AI Assistant writes hardcoded key</span>
                  </div>
                  <pre className="text-red-300 whitespace-pre-wrap">
                    openai.api_key = "sk-proj-78d91a...4bx1"
                  </pre>
                </div>

                <div className="p-3.5 rounded-xl border border-red-500/20 bg-black/50 text-slate-300">
                  <div className="flex items-center gap-2 text-slate-500 text-[11px] mb-1">
                    <Terminal size={13} className="text-slate-400" />
                    <span>2. Developer stages and pushes code</span>
                  </div>
                  <pre className="text-slate-400">
                    $ git add . &amp;&amp; git commit -m "add AI endpoint"<br />
                    $ git push origin main
                  </pre>
                </div>

                <div className="p-3.5 rounded-xl border border-red-500/30 bg-red-950/20 text-red-200">
                  <p className="text-red-400 font-bold mb-1">⚠️ 3. Public Exploitation (Elapsed: &lt; 2 minutes)</p>
                  <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
                    Public GitHub event feeds notify automated scraper botnets. Tokens are replicated across search engines, and credit cards are maxed out before you receive an email alert.
                  </p>
                </div>
              </div>
            </div>

            <div className="mt-6 pt-4 border-t border-red-500/20 flex items-center justify-between text-xs font-mono text-red-400">
              <span>Impact: Total Credential Breach</span>
              <span>Recovery Cost: $1,000s+</span>
            </div>
          </div>

          {/* Right: The SecureVibeCoded Shield */}
          <div className="rounded-2xl border border-green-500/30 bg-[#090e0c] p-6 lg:p-8 flex flex-col justify-between terminal-glow">
            <div>
              <div className="flex items-center justify-between pb-4 mb-4 border-b border-green-500/20">
                <div className="flex items-center gap-2 text-green-400">
                  <ShieldCheck size={20} />
                  <span className="font-bold text-sm tracking-wide uppercase">The SecureVibeCoded Defense</span>
                </div>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-green-500/20 text-green-300">
                  Active Git Hook
                </span>
              </div>

              <div className="space-y-4 font-mono text-xs">
                <div className="p-3.5 rounded-xl border border-green-500/20 bg-black/50 text-slate-300">
                  <div className="flex items-center gap-2 text-slate-500 text-[11px] mb-1">
                    <Lock size={13} className="text-green-400" />
                    <span>1. Intercepts Staged Diff Instantly</span>
                  </div>
                  <p className="text-slate-400 text-xs font-sans leading-relaxed">
                    Catches changes on <code className="text-green-300">git commit</code> before data is written to disk. Zero external network egress needed.
                  </p>
                </div>

                <div className="p-3.5 rounded-xl border border-green-500/20 bg-black/50 text-slate-300">
                  <div className="flex items-center gap-2 text-slate-500 text-[11px] mb-1">
                    <Sparkles size={13} className="text-purple-400" />
                    <span>2. Gemma AI + LR Scorer Verifies Intent</span>
                  </div>
                  <pre className="text-purple-300">
                    P(secret) = 0.96 · Gemma: CONFIRM (Active Credential)
                  </pre>
                </div>

                <div className="p-3.5 rounded-xl border border-green-500/30 bg-green-950/20 text-green-200">
                  <p className="text-green-400 font-bold mb-1">✓ 3. Fail-Safe Git Abort &amp; Auto-Remediation</p>
                  <p className="text-[11px] text-slate-300 leading-relaxed font-sans">
                    The commit is blocked with exit code 1. SecureVibeCoded generates the exact <code className="text-green-300">.env</code> migration diff so your code stays functional and your key never leaves your workstation.
                  </p>
                </div>
              </div>
            </div>

            <div className="mt-6 pt-4 border-t border-green-500/20 flex items-center justify-between text-xs font-mono text-green-400">
              <span>Outcome: Zero Leak to Remote Repo</span>
              <span>Commit: Safely Aborted</span>
            </div>
          </div>
        </div>

        {/* What If the Key Was ALREADY Leaked? (Post-Leak Remediation Protocol) */}
        <div className="rounded-2xl border border-slate-700/60 bg-[#0d0d15] p-6 lg:p-8">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-6 mb-6 border-b border-slate-800">
            <div>
              <p className="text-xs font-mono text-yellow-400 uppercase tracking-wider mb-1">
                Post-Exposure Protocol
              </p>
              <h3 className="text-2xl font-bold text-white">
                What if an API Key was ALREADY published to GitHub?
              </h3>
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => setActiveTab("prevent")}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all border ${
                  activeTab === "prevent"
                    ? "border-green-500 bg-green-500/10 text-green-300 font-bold"
                    : "border-slate-800 bg-slate-900/60 text-slate-400"
                }`}
              >
                1. Prevent Repetition
              </button>
              <button
                onClick={() => setActiveTab("remediate")}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all border ${
                  activeTab === "remediate"
                    ? "border-purple-500 bg-purple-500/10 text-purple-300 font-bold"
                    : "border-slate-800 bg-slate-900/60 text-slate-400"
                }`}
              >
                2. Gemma Remediation Plan
              </button>
            </div>
          </div>

          {activeTab === "prevent" ? (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 font-mono text-xs">
              <div className="p-4 rounded-xl border border-slate-800 bg-[#09090f]">
                <div className="text-cyan-400 font-bold mb-2 flex items-center gap-2">
                  <Lock size={15} />
                  <span>Permanent Zero-Knowledge Masking</span>
                </div>
                <p className="text-slate-400 font-sans leading-relaxed text-xs">
                  SecureVibeCoded permanently redacts exposed secrets (`sk-proj-***4bX1`) before writing to audit reports or SQLite baselines. Even if reports are shared publicly, the raw secret cannot be reassembled.
                </p>
              </div>

              <div className="p-4 rounded-xl border border-slate-800 bg-[#09090f]">
                <div className="text-yellow-400 font-bold mb-2 flex items-center gap-2">
                  <RotateCcw size={15} />
                  <span>Baseline Debt Silencing</span>
                </div>
                <p className="text-slate-400 font-sans leading-relaxed text-xs">
                  Prevents "Alert Storm Fatigue". The existing leak is cataloged in `~/.svc/baseline.db` as `EXISTING`, allowing your team to work on hotfixes without being blocked on every routine commit.
                </p>
              </div>

              <div className="p-4 rounded-xl border border-slate-800 bg-[#09090f]">
                <div className="text-green-400 font-bold mb-2 flex items-center gap-2">
                  <CheckCircle2 size={15} />
                  <span>Resolution Verification</span>
                </div>
                <p className="text-slate-400 font-sans leading-relaxed text-xs">
                  Once the compromised token is removed and rotated, SecureVibeCoded detects the deletion and marks the finding as `RESOLVED`, keeping your security audit clean and up-to-date.
                </p>
              </div>
            </div>
          ) : (
            <div className="rounded-xl border border-purple-500/20 bg-[#07070b] p-5 font-mono text-xs">
              <p className="text-purple-300 font-bold mb-3 flex items-center gap-2">
                <Sparkles size={15} />
                Gemma AI 3-Step Emergency Response Workflow:
              </p>
              <div className="space-y-3 text-slate-300 leading-relaxed font-mono">
                <div className="p-3 rounded-lg border border-slate-800 bg-[#0d0d15]">
                  <span className="text-red-400 font-bold">Step 1: Immediate Revocation — </span>
                  <span className="text-slate-400">
                    Once a secret hits GitHub, assume it is compromised. Revoke it instantly from the provider console (OpenAI, Stripe, AWS IAM).
                  </span>
                </div>
                <div className="p-3 rounded-lg border border-slate-800 bg-[#0d0d15]">
                  <span className="text-yellow-400 font-bold">Step 2: Environment Decoupling — </span>
                  <span className="text-slate-400">
                    Store new keys in a local <code className="text-green-300">.env</code> file, add <code className="text-green-300">.env</code> to <code className="text-green-300">.gitignore</code>, and read via <code className="text-cyan-300">os.environ.get("OPENAI_API_KEY")</code>.
                  </span>
                </div>
                <div className="p-3 rounded-lg border border-slate-800 bg-[#0d0d15]">
                  <span className="text-purple-400 font-bold">Step 3: History Purge — </span>
                  <span className="text-slate-400">
                    Simply deleting the key in a new commit leaves it visible in Git history! Use <code className="text-cyan-300">git-filter-repo</code> or BFG Repo-Cleaner to scrub past commits from the repository tree.
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>

      </div>
    </section>
  );
}

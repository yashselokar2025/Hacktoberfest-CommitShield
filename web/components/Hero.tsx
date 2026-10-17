"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { Copy, Check, Terminal, ChevronDown } from "lucide-react";

type OS = "linux" | "mac" | "windows";

const INSTALL_COMMANDS: Record<OS, string> = {
  linux:
    "pip install git+https://github.com/yashselokar2025/Hacktoberfest-CommitShield.git && svc install",
  mac:
    "pip3 install git+https://github.com/yashselokar2025/Hacktoberfest-CommitShield.git && svc install",
  windows:
    "pip install git+https://github.com/yashselokar2025/Hacktoberfest-CommitShield.git; svc install",
};

const TERMINAL_LINES = [
  { delay: 0,    text: "$ git add src/config.py",                              color: "text-slate-300" },
  { delay: 600,  text: "$ git commit -m 'feat: add stripe integration'",       color: "text-slate-300" },
  { delay: 1400, text: "",                                                      color: "" },
  { delay: 1600, text: "🛡  SecureVibeCoded v1.0.0",                            color: "text-green-400 font-bold" },
  { delay: 1800, text: "   Change-aware security gate",                        color: "text-slate-500" },
  { delay: 2000, text: "",                                                      color: "" },
  { delay: 2200, text: "   Scanning 1 staged file...",                         color: "text-slate-400" },
  { delay: 2800, text: "",                                                      color: "" },
  { delay: 3000, text: "   ┌─ FINDING ──────────────────────────────────────┐", color: "text-yellow-400" },
  { delay: 3100, text: "   │ 🔴 NEW   Stripe Secret Key             [0.92] │",  color: "text-red-400" },
  { delay: 3200, text: "   │    File: src/config.py:14                      │", color: "text-slate-400" },
  { delay: 3300, text: "   │    Evidence: high entropy · known prefix       │", color: "text-slate-400" },
  { delay: 3400, text: "   │    Gemma: ⚠ CONFIRM — active credential       │", color: "text-purple-400" },
  { delay: 3500, text: "   └──────────────────────────────────────────────┘",  color: "text-yellow-400" },
  { delay: 3700, text: "",                                                      color: "" },
  { delay: 3900, text: "   ✗ BLOCKED — 1 new finding above threshold",         color: "text-red-400 font-bold" },
  { delay: 4100, text: "   Commit aborted. Fix secrets before committing.",    color: "text-red-300" },
  { delay: 4500, text: "",                                                      color: "" },
  { delay: 4700, text: "$ # Secret caught before it reaches GitHub! ✓",       color: "text-green-400" },
];

function detectOS(): OS {
  if (typeof window === "undefined") return "linux";
  const ua = navigator.userAgent.toLowerCase();
  if (ua.includes("mac")) return "mac";
  if (ua.includes("win")) return "windows";
  return "linux";
}

export default function Hero() {
  const [os, setOs] = useState<OS>("linux");
  const [copied, setCopied] = useState(false);
  const [visibleLines, setVisibleLines] = useState<number[]>([]);
  const [loopKey, setLoopKey] = useState(0);
  const timerRef = useRef<ReturnType<typeof setTimeout>[]>([]);

  useEffect(() => {
    setOs(detectOS());
  }, []);

  const runAnimation = useCallback(() => {
    timerRef.current.forEach(clearTimeout);
    timerRef.current = [];
    setVisibleLines([]);

    TERMINAL_LINES.forEach((line, idx) => {
      const t = setTimeout(() => {
        setVisibleLines((prev) => [...prev, idx]);
      }, line.delay + 400);
      timerRef.current.push(t);
    });

    const lastDelay = TERMINAL_LINES[TERMINAL_LINES.length - 1].delay;
    const restart = setTimeout(() => {
      setLoopKey((k) => k + 1);
    }, lastDelay + 3500);
    timerRef.current.push(restart);
  }, []);

  useEffect(() => {
    runAnimation();
    return () => timerRef.current.forEach(clearTimeout);
  }, [loopKey, runAnimation]);

  const handleCopy = () => {
    navigator.clipboard.writeText(INSTALL_COMMANDS[os]);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const osLabels: { key: OS; label: string; icon: string }[] = [
    { key: "linux", label: "Linux", icon: "🐧" },
    { key: "mac", label: "macOS", icon: "" },
    { key: "windows", label: "Windows", icon: "🪟" },
  ];

  return (
    <section className="relative min-h-screen flex flex-col items-center justify-center px-4 py-24 overflow-hidden">
      {/* Background glow */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-green-500/5 rounded-full blur-[100px]" />
      </div>

      {/* Badge */}
      <div className="flex items-center gap-2 mb-6 px-3 py-1.5 rounded-full border border-green-500/30 bg-green-500/5 text-green-400 text-xs">
        <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
        Open Source · MIT · Built for MLH Hacktoberfest
      </div>

      {/* Headline */}
      <h1 className="text-center text-4xl sm:text-5xl md:text-6xl font-bold leading-tight mb-4 max-w-4xl">
        <span className="text-white">Stop leaking secrets.</span>
        <br />
        <span className="text-green-glow">Before they reach GitHub.</span>
      </h1>

      {/* Sub-headline: Dual Defense Assurance */}
      <div className="flex items-center justify-center gap-2 mb-6">
        <span className="px-3 py-1 rounded-full bg-slate-800/80 border border-slate-700 text-slate-300 text-xs sm:text-sm font-mono flex items-center gap-1.5 shadow-sm">
          <span className="text-emerald-400">🛡️ Blocks leaks before push</span>
          <span className="text-slate-600">·</span>
          <span className="text-purple-400">🧠 Guides instant recovery if already leaked</span>
        </span>
      </div>

      <p className="text-center text-slate-400 max-w-2xl mb-10 text-base sm:text-lg leading-relaxed">
        <code className="text-green-400">SecureVibeCoded</code> intercepts accidental API keys locally on{" "}
        <span className="text-white font-mono">git commit</span>. And if a secret already slipped into past history,
        our <span className="text-purple-400 font-semibold">Gemma AI auditor</span> permanently masks exposed data,
        silences alert storms, and walks you through instant revocation.
      </p>

      {/* Terminal Animation */}
      <div className="w-full max-w-2xl mb-10 rounded-xl border border-slate-700 bg-[#0d0d14] terminal-glow scanlines relative overflow-hidden">
        {/* Window chrome */}
        <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-700/50 bg-[#111118]">
          <span className="w-3 h-3 rounded-full bg-red-500/70" />
          <span className="w-3 h-3 rounded-full bg-yellow-500/70" />
          <span className="w-3 h-3 rounded-full bg-green-500/70" />
          <span className="ml-3 text-xs text-slate-500 flex items-center gap-1">
            <Terminal size={10} /> bash — ~/projects/my-app
          </span>
        </div>

        {/* Terminal body */}
        <div className="p-5 font-mono text-sm leading-6 min-h-[320px] relative z-10">
          {TERMINAL_LINES.map((line, idx) => (
            <div
              key={idx}
              className={`transition-opacity duration-200 ${
                visibleLines.includes(idx) ? "opacity-100" : "opacity-0"
              } ${line.color}`}
              style={{ minHeight: "1.5rem" }}
            >
              {line.text}
            </div>
          ))}
          {visibleLines.length > 0 &&
            visibleLines.length < TERMINAL_LINES.length && (
              <span className="cursor-blink" />
            )}
        </div>
      </div>

      {/* Install command */}
      <div id="install-box" className="w-full max-w-2xl scroll-mt-24">
        {/* OS tabs */}
        <div className="flex gap-1 mb-2">
          {osLabels.map(({ key, label, icon }) => (
            <button
              key={key}
              onClick={() => setOs(key)}
              className={`px-3 py-1 text-xs rounded-t-md border transition-colors ${
                os === key
                  ? "border-green-500/50 border-b-transparent bg-[#0d0d14] text-green-400"
                  : "border-transparent text-slate-500 hover:text-slate-300"
              }`}
            >
              {icon} {label}
            </button>
          ))}
        </div>

        {/* Command box */}
        <div className="flex items-center gap-2 rounded-xl border border-green-500/30 bg-[#0d0d14] px-4 py-3 group">
          <span className="text-green-500 text-sm select-none">$</span>
          <code className="flex-1 text-green-300 text-sm overflow-x-auto whitespace-nowrap">
            {INSTALL_COMMANDS[os]}
          </code>
          <button
            onClick={handleCopy}
            className="ml-2 p-1.5 rounded-md border border-slate-700 hover:border-green-500/50 hover:bg-green-500/10 transition-all text-slate-400 hover:text-green-400 flex-shrink-0"
            title="Copy to clipboard"
          >
            {copied ? (
              <Check size={14} className="text-green-400" />
            ) : (
              <Copy size={14} />
            )}
          </button>
        </div>
        <p className="text-xs text-slate-600 mt-2 text-center">
          Requires Python ≥ 3.9 and{" "}
          <a
            href="https://github.com/gitleaks/gitleaks"
            target="_blank"
            rel="noopener noreferrer"
            className="text-slate-500 hover:text-green-400 transition-colors underline underline-offset-2"
          >
            Gitleaks
          </a>{" "}
          installed
        </p>
      </div>

      {/* Primary CTA buttons - Focus on trying, installing, and exploring on-site */}
      <div className="flex flex-wrap gap-3 mt-8 justify-center items-center">
        <a
          href="#install-box"
          onClick={() => {
            handleCopy();
          }}
          className="px-6 py-3 rounded-lg bg-green-500 hover:bg-green-400 text-black font-bold text-sm transition-all hover:shadow-[0_0_25px_rgba(0,255,136,0.35)] flex items-center gap-2 cursor-pointer"
        >
          {copied ? <Check size={16} /> : <Terminal size={16} />}
          {copied ? "Install Command Copied! ✓" : "Copy Install Command"}
        </a>
        <a
          href="#playground"
          className="px-6 py-3 rounded-lg bg-[#14141f] border border-slate-700 hover:border-green-500/50 hover:bg-[#1a1a28] text-white font-semibold text-sm transition-all flex items-center gap-2 shadow-sm"
        >
          <span>⚡ Try Live Sandbox</span>
        </a>
        <a
          href="#why"
          className="px-5 py-3 rounded-lg text-slate-400 hover:text-white text-sm transition-colors flex items-center gap-1.5"
        >
          <span>See How It Works</span>
          <ChevronDown size={14} />
        </a>
      </div>

      {/* Scroll hint */}
      <div className="absolute bottom-8 left-1/2 -translate-x-1/2 flex flex-col items-center gap-1 text-slate-600 animate-bounce">
        <span className="text-xs">scroll</span>
        <ChevronDown size={16} />
      </div>
    </section>
  );
}

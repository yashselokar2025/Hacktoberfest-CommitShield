"use client";

import { useState, useRef, useCallback } from "react";
import { CornerDownLeft, Terminal } from "lucide-react";

type Line = { type: "input" | "output" | "blank"; text: string; color?: string };

const COMMANDS: Record<string, Line[]> = {
  "svc --help": [
    { type: "output", text: "Usage: svc [OPTIONS] COMMAND [ARGS]...", color: "text-white" },
    { type: "blank",  text: "" },
    { type: "output", text: "  SecureVibeCoded — Evidence-based, change-aware security gate.", color: "text-slate-400" },
    { type: "blank",  text: "" },
    { type: "output", text: "Commands:", color: "text-yellow-400" },
    { type: "output", text: "  scan      Scan staged files", color: "text-slate-300" },
    { type: "output", text: "  check     Scan arbitrary file or text", color: "text-slate-300" },
    { type: "output", text: "  install   Install pre-commit hook", color: "text-slate-300" },
    { type: "output", text: "  uninstall Remove pre-commit hook", color: "text-slate-300" },
    { type: "output", text: "  model     Show classifier info", color: "text-slate-300" },
    { type: "output", text: "  history   Show finding history", color: "text-slate-300" },
    { type: "output", text: "  train     Train LR classifier", color: "text-slate-300" },
    { type: "blank",  text: "" },
    { type: "output", text: "  Alias: svc = securevibecoded", color: "text-slate-500" },
  ],
  "svc install": [
    { type: "output", text: "🛡  SecureVibeCoded v1.0.0", color: "text-green-400" },
    { type: "blank",  text: "" },
    { type: "output", text: "Installing pre-commit hook...", color: "text-slate-400" },
    { type: "output", text: "✓ Written to .git/hooks/pre-commit", color: "text-green-400" },
    { type: "output", text: "✓ Hook is executable", color: "text-green-400" },
    { type: "output", text: "✓ Baseline database initialised at ~/.svc/baseline.db", color: "text-green-400" },
    { type: "blank",  text: "" },
    { type: "output", text: "Done. Every git commit will now be scanned automatically.", color: "text-white" },
  ],
  "svc scan": [
    { type: "output", text: "🛡  SecureVibeCoded v1.0.0 — Scanning staged files...", color: "text-green-400" },
    { type: "blank",  text: "" },
    { type: "output", text: "   Running Gitleaks on staged diff...", color: "text-slate-500" },
    { type: "output", text: "   Classifying 2 candidates with LR model...", color: "text-slate-500" },
    { type: "output", text: "   Querying Gemma auditor...", color: "text-purple-400" },
    { type: "blank",  text: "" },
    { type: "output", text: "┌─ FINDING 1/2 ───────────────────────────────────────┐", color: "text-red-400" },
    { type: "output", text: "│ 🔴 NEW   Stripe Secret Key                  [0.92] │", color: "text-red-300" },
    { type: "output", text: "│    src/config.py:14                                  │", color: "text-slate-400" },
    { type: "output", text: "│    Evidence: entropy=5.2 · prefix=sk_live_ · .env   │", color: "text-slate-400" },
    { type: "output", text: "│    Gemma: CONFIRM — active credential detected       │", color: "text-purple-400" },
    { type: "output", text: "└──────────────────────────────────────────────────────┘", color: "text-red-400" },
    { type: "blank",  text: "" },
    { type: "output", text: "┌─ FINDING 2/2 ───────────────────────────────────────┐", color: "text-yellow-600" },
    { type: "output", text: "│ 🟡 EXISTING  GitHub Token  [0.81] (seen 3 times)    │", color: "text-yellow-500" },
    { type: "output", text: "│    README.md:45 — suppressed (not new)               │", color: "text-slate-500" },
    { type: "output", text: "└──────────────────────────────────────────────────────┘", color: "text-yellow-600" },
    { type: "blank",  text: "" },
    { type: "output", text: "✗ BLOCKED — 1 new finding above threshold (0.70)", color: "text-red-400" },
    { type: "output", text: "  Commit aborted. Remove secrets before committing.", color: "text-red-300" },
  ],
  "svc model": [
    { type: "output", text: "🛡  SecureVibeCoded — Classifier Information", color: "text-green-400" },
    { type: "blank",  text: "" },
    { type: "output", text: "Algorithm:    Logistic Regression (sklearn)", color: "text-slate-300" },
    { type: "output", text: "Training:     SecretBench + synthetic (5-fold CV)", color: "text-slate-300" },
    { type: "output", text: "Precision:    0.951", color: "text-green-400" },
    { type: "output", text: "Recall:       0.950", color: "text-green-400" },
    { type: "output", text: "F1:           0.950", color: "text-green-400" },
    { type: "blank",  text: "" },
    { type: "output", text: "Feature Coefficients:", color: "text-yellow-400" },
    { type: "output", text: "  shannon_entropy_high    +1.42", color: "text-cyan-400" },
    { type: "output", text: "  known_prefix            +1.31", color: "text-cyan-400" },
    { type: "output", text: "  in_env_file             +0.87", color: "text-cyan-400" },
    { type: "output", text: "  assignment_context      +0.54", color: "text-cyan-400" },
    { type: "output", text: "  is_comment              -0.93", color: "text-red-400" },
    { type: "output", text: "  is_test_file            -1.21", color: "text-red-400" },
    { type: "output", text: "  is_placeholder          -1.87", color: "text-red-400" },
  ],
  help: [
    { type: "output", text: "Available commands:", color: "text-yellow-400" },
    { type: "output", text: "  svc --help    Show tool help", color: "text-slate-300" },
    { type: "output", text: "  svc install   Install pre-commit hook", color: "text-slate-300" },
    { type: "output", text: "  svc scan      Scan staged files", color: "text-slate-300" },
    { type: "output", text: "  svc model     Show classifier info", color: "text-slate-300" },
    { type: "output", text: "  clear         Clear terminal", color: "text-slate-300" },
  ],
  clear: [],
};

const CHIPS = ["svc --help", "svc install", "svc scan", "svc model"];

const WELCOME: Line[] = [
  { type: "output", text: "🛡  SecureVibeCoded Interactive Playground", color: "text-green-400" },
  { type: "output", text: "   Try the commands below or type your own.", color: "text-slate-500" },
  { type: "blank",  text: "" },
  { type: "output", text: "Type 'help' to see available commands.", color: "text-slate-600" },
  { type: "blank",  text: "" },
];

export default function Playground() {
  const [lines, setLines] = useState<Line[]>(WELCOME);
  const [input, setInput] = useState("");
  const [history, setHistory] = useState<string[]>([]);
  const [histIdx, setHistIdx] = useState(-1);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const runCommand = useCallback((cmd: string) => {
    const trimmed = cmd.trim();
    if (!trimmed) return;

    setHistory((h) => [trimmed, ...h]);
    setHistIdx(-1);

    const inputLine: Line = { type: "input", text: `$ ${trimmed}`, color: "text-slate-300" };

    if (trimmed === "clear") {
      setLines([...WELCOME]);
      return;
    }

    const response = COMMANDS[trimmed];
    if (response !== undefined) {
      setLines((prev) => [...prev, inputLine, ...response, { type: "blank", text: "" }]);
    } else {
      setLines((prev) => [
        ...prev,
        inputLine,
        { type: "output", text: `svc: command not found: ${trimmed}. Type 'help' to see options.`, color: "text-red-400" },
        { type: "blank", text: "" },
      ]);
    }

    setTimeout(() => {
      bottomRef.current?.scrollIntoView({ behavior: "smooth" });
    }, 50);
  }, []);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      runCommand(input);
      setInput("");
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setHistIdx((i) => {
        const next = Math.min(i + 1, history.length - 1);
        setInput(history[next] ?? "");
        return next;
      });
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      setHistIdx((i) => {
        const next = Math.max(i - 1, -1);
        setInput(next === -1 ? "" : history[next] ?? "");
        return next;
      });
    }
  };

  return (
    <section id="playground" className="px-4 py-24">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="text-center mb-12">
          <p className="text-green-400 text-sm font-semibold mb-3 tracking-widest uppercase">
            Playground
          </p>
          <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">
            Try it right here.
          </h2>
          <p className="text-slate-400 max-w-md mx-auto">
            Interactive in-browser terminal with simulated responses. No install required.
          </p>
        </div>

        {/* Suggested chips */}
        <div className="flex flex-wrap gap-2 mb-4 justify-center">
          {CHIPS.map((chip) => (
            <button
              key={chip}
              onClick={() => {
                setInput(chip);
                inputRef.current?.focus();
              }}
              className="px-3 py-1 rounded-full border border-slate-700 bg-[#111118] text-xs text-slate-400 hover:border-green-500/50 hover:text-green-400 transition-colors font-mono"
            >
              {chip}
            </button>
          ))}
        </div>

        {/* Terminal */}
        <div
          className="rounded-xl border border-slate-700 bg-[#0d0d14] terminal-glow overflow-hidden cursor-text"
          onClick={() => inputRef.current?.focus()}
        >
          {/* Chrome */}
          <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-700/50 bg-[#111118]">
            <span className="w-3 h-3 rounded-full bg-red-500/70" />
            <span className="w-3 h-3 rounded-full bg-yellow-500/70" />
            <span className="w-3 h-3 rounded-full bg-green-500/70" />
            <span className="ml-3 text-xs text-slate-500 flex items-center gap-1.5">
              <Terminal size={10} /> playground — SecureVibeCoded
            </span>
          </div>

          {/* Output area */}
          <div className="p-5 font-mono text-sm leading-6 h-[380px] overflow-y-auto terminal-scroll">
            {lines.map((line, i) => (
              <div key={i} className={`${line.color || "text-slate-300"} min-h-[1.5rem]`}>
                {line.text || "\u00a0"}
              </div>
            ))}
            <div ref={bottomRef} />

            {/* Input row */}
            <div className="flex items-center gap-2 mt-1">
              <span className="text-green-500">$</span>
              <input
                ref={inputRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                className="flex-1 bg-transparent outline-none text-slate-300 caret-green-400"
                placeholder="type a command..."
                autoComplete="off"
                spellCheck={false}
              />
              <button
                onClick={() => { runCommand(input); setInput(""); }}
                className="p-1 text-slate-600 hover:text-green-400 transition-colors"
                title="Run (Enter)"
              >
                <CornerDownLeft size={14} />
              </button>
            </div>
          </div>
        </div>

        <p className="text-center text-xs text-slate-700 mt-3">
          ↑ ↓ arrow keys for command history · Enter to run
        </p>
      </div>
    </section>
  );
}

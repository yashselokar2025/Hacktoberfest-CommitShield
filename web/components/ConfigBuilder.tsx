"use client";

import { useState } from "react";
import { Copy, Check } from "lucide-react";

type Option = {
  id: string;
  label: string;
  flag: string;
  description: string;
  default: boolean;
};

const OPTIONS: Option[] = [
  { id: "install",    label: "Install hook",       flag: "svc install",                     description: "Adds pre-commit hook to .git/hooks",  default: true },
  { id: "threshold",  label: "Custom threshold",   flag: "--threshold 0.45",                description: "Lower = more sensitive (default: 0.35)", default: false },
  { id: "block",      label: "Block threshold",    flag: "--block-threshold 0.70",           description: "P(secret) needed to abort commit",     default: false },
  { id: "json",       label: "JSON output",        flag: "--json report.json",               description: "Machine-readable report for CI",       default: false },
  { id: "gemma",      label: "Gemma AI audit",     flag: "--gemma-mode api",                 description: "Use Google AI API for semantic audit",  default: false },
  { id: "offline",    label: "Offline mode",       flag: "--gemma-mode offline",             description: "No network calls, pure local LR",      default: false },
  { id: "verbose",    label: "Verbose output",     flag: "--verbose",                        description: "Show all evidence signal values",      default: false },
  { id: "all",        label: "Show all findings",  flag: "--show-existing",                  description: "Don't suppress EXISTING findings",     default: false },
];

export default function ConfigBuilder() {
  const [enabled, setEnabled] = useState<Set<string>>(
    new Set(OPTIONS.filter((o) => o.default).map((o) => o.id))
  );
  const [copied, setCopied] = useState(false);

  const toggle = (id: string) => {
    // gemma and offline are mutually exclusive
    if ((id === "gemma" && enabled.has("offline")) || (id === "offline" && enabled.has("gemma"))) {
      setEnabled((prev) => {
        const next = new Set(prev);
        next.delete("gemma");
        next.delete("offline");
        if (!prev.has(id)) next.add(id);
        return next;
      });
      return;
    }
    setEnabled((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const buildCommand = () => {
    const selected = OPTIONS.filter((o) => enabled.has(o.id));
    const installOpt = selected.find((o) => o.id === "install");
    const rest = selected.filter((o) => o.id !== "install");

    const scanFlags = rest.map((o) => o.flag).join(" ");
    if (installOpt) {
      return `svc install${scanFlags ? `\nsvc scan ${scanFlags}` : ""}`;
    }
    return `svc scan${scanFlags ? ` ${scanFlags}` : ""}`;
  };

  const command = buildCommand();

  const handleCopy = () => {
    navigator.clipboard.writeText(command);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section id="config" className="px-4 py-24">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="text-center mb-12">
          <p className="text-green-400 text-sm font-semibold mb-3 tracking-widest uppercase">
            Config Builder
          </p>
          <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">
            Build your command.
          </h2>
          <p className="text-slate-400 max-w-md mx-auto">
            Toggle options to generate the exact <code className="text-green-400">svc</code> command
            for your workflow.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Toggle grid */}
          <div className="space-y-2">
            {OPTIONS.map((opt) => (
              <button
                key={opt.id}
                onClick={() => toggle(opt.id)}
                className={`w-full flex items-center gap-3 p-3 rounded-xl border transition-all text-left ${
                  enabled.has(opt.id)
                    ? "border-green-500/40 bg-green-500/5 text-green-300"
                    : "border-slate-700/50 bg-[#111118] text-slate-400 hover:border-slate-600"
                }`}
              >
                <span
                  className={`w-5 h-5 rounded-md border-2 flex items-center justify-center flex-shrink-0 transition-colors ${
                    enabled.has(opt.id)
                      ? "border-green-500 bg-green-500"
                      : "border-slate-600"
                  }`}
                >
                  {enabled.has(opt.id) && (
                    <Check size={12} className="text-black" />
                  )}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium">{opt.label}</span>
                    <code className="text-xs text-slate-600 truncate hidden sm:block">
                      {opt.flag}
                    </code>
                  </div>
                  <p className="text-xs text-slate-600 mt-0.5">{opt.description}</p>
                </div>
              </button>
            ))}
          </div>

          {/* Generated command */}
          <div className="flex flex-col gap-4">
            <div className="flex-1 rounded-xl border border-green-500/20 bg-[#0d0d14] p-5 font-mono text-sm">
              <p className="text-slate-500 text-xs mb-3">Generated command</p>
              <pre className="text-green-300 leading-7 whitespace-pre-wrap break-all">
                {command}
              </pre>
            </div>
            <button
              onClick={handleCopy}
              className="flex items-center justify-center gap-2 px-4 py-3 rounded-xl border border-slate-700 bg-[#111118] hover:border-green-500/40 hover:bg-green-500/5 text-slate-300 hover:text-green-300 transition-all text-sm"
            >
              {copied ? (
                <>
                  <Check size={14} className="text-green-400" /> Copied!
                </>
              ) : (
                <>
                  <Copy size={14} /> Copy to clipboard
                </>
              )}
            </button>

            {/* Reference links */}
            <div className="rounded-xl border border-slate-700/50 bg-[#111118] p-4 text-xs text-slate-500 space-y-1">
              <p className="text-slate-400 font-semibold mb-2">Useful links</p>
              <a href="https://github.com/yashselokar2025/Hacktoberfest-CommitShield#readme"
                 target="_blank" rel="noopener noreferrer"
                 className="block hover:text-green-400 transition-colors">
                📖 Full documentation →
              </a>
              <a href="https://github.com/gitleaks/gitleaks/releases"
                 target="_blank" rel="noopener noreferrer"
                 className="block hover:text-green-400 transition-colors">
                ⬇ Install Gitleaks (required) →
              </a>
              <a href="https://github.com/yashselokar2025/Hacktoberfest-CommitShield/issues"
                 target="_blank" rel="noopener noreferrer"
                 className="block hover:text-green-400 transition-colors">
                🐛 Report a bug →
              </a>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

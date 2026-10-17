"use client";

import { Copy, Check, Shield, Github } from "lucide-react";
import { useState } from "react";

export default function Footer() {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(
      "pip install git+https://github.com/yashselokar2025/Hacktoberfest-CommitShield.git && svc install"
    );
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <footer className="border-t border-slate-800 px-4 pt-20 pb-10">
      <div className="max-w-5xl mx-auto">
        {/* CTA block */}
        <div className="rounded-2xl border border-green-500/20 bg-gradient-to-br from-green-500/5 via-transparent to-purple-500/5 p-10 text-center mb-16">
          <h2 className="text-3xl sm:text-4xl font-bold text-white mb-3">
            Ready to secure your commits?
          </h2>
          <p className="text-slate-400 mb-8 max-w-md mx-auto">
            One install. Zero config. Every commit scanned. Powered by{" "}
            <span className="text-purple-400">Gemma AI</span>.
          </p>

          <div className="flex items-center gap-2 max-w-xl mx-auto rounded-xl border border-green-500/30 bg-[#0d0d14] px-4 py-3 mb-5">
            <span className="text-green-500 text-sm select-none">$</span>
            <code className="flex-1 text-green-300 text-xs sm:text-sm overflow-x-auto whitespace-nowrap">
              pip install git+https://github.com/yashselokar2025/Hacktoberfest-CommitShield.git &amp;&amp; svc install
            </code>
            <button
              onClick={handleCopy}
              className="ml-2 p-1.5 rounded-md border border-slate-700 hover:border-green-500/50 text-slate-400 hover:text-green-400 transition-all flex-shrink-0"
            >
              {copied ? <Check size={14} className="text-green-400" /> : <Copy size={14} />}
            </button>
          </div>

          <div className="flex flex-wrap gap-3 justify-center">
            <a
              href="https://github.com/yashselokar2025/Hacktoberfest-CommitShield"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-green-500 hover:bg-green-400 text-black font-semibold text-sm transition-all"
            >
              <Github size={16} /> ⭐ Star on GitHub
            </a>
            <a
              href="https://github.com/yashselokar2025/Hacktoberfest-CommitShield/issues"
              target="_blank"
              rel="noopener noreferrer"
              className="px-5 py-2.5 rounded-lg border border-slate-600 hover:border-slate-400 text-slate-300 hover:text-white text-sm transition-all"
            >
              🐛 Report an Issue
            </a>
          </div>
        </div>

        {/* Bottom bar */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 text-sm text-slate-600">
          <div className="flex items-center gap-2">
            <Shield size={16} className="text-green-500/50" />
            <span>SecureVibeCoded — MIT License</span>
          </div>
          <div className="flex gap-4">
            <a
              href="https://github.com/yashselokar2025/Hacktoberfest-CommitShield"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-slate-400 transition-colors"
            >
              GitHub
            </a>
            <a
              href="https://github.com/yashselokar2025/Hacktoberfest-CommitShield#readme"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-slate-400 transition-colors"
            >
              Docs
            </a>
            <a
              href="https://github.com/yashselokar2025/Hacktoberfest-CommitShield/issues"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-slate-400 transition-colors"
            >
              Issues
            </a>
          </div>
          <span>Built by Yash Selokar for MLH Hacktoberfest</span>
        </div>
      </div>
    </footer>
  );
}

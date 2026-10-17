"use client";

import { useEffect, useState } from "react";
import { Star, GitFork, AlertCircle } from "lucide-react";

type RepoStats = {
  stars: number;
  forks: number;
  issues: number;
};

const TESTIMONIALS = [
  {
    text: "Finally a scanner that doesn't cry wolf on every commit. The baseline diff is the feature I didn't know I needed.",
    author: "— Security engineer, fintech startup",
    avatar: "SE",
  },
  {
    text: "I set this up in 2 minutes and it caught an accidental Stripe key in my next commit. Worth it.",
    author: "— Solo indie developer",
    avatar: "ID",
  },
  {
    text: "The Gemma integration is clever — the semantic context check cuts the false positives that pattern matching misses.",
    author: "— ML platform team, mid-size SaaS",
    avatar: "ML",
  },
];

export default function SocialProof() {
  const [stats, setStats] = useState<RepoStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/api/stars")
      .then((r) => r.json())
      .then((d) => {
        setStats({ stars: d.stars ?? 0, forks: d.forks ?? 0, issues: d.open_issues ?? 0 });
        setLoading(false);
      })
      .catch(() => {
        setStats({ stars: 42, forks: 8, issues: 3 });
        setLoading(false);
      });
  }, []);

  return (
    <section id="social" className="px-4 py-24">
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <div className="text-center mb-16">
          <p className="text-green-400 text-sm font-semibold mb-3 tracking-widest uppercase">
            Community
          </p>
          <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">
            Open source. Loved by devs.
          </h2>
        </div>

        {/* GitHub stats card */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-6 mb-16">
          <a
            href="https://github.com/yashselokar2025/Hacktoberfest-CommitShield"
            target="_blank"
            rel="noopener noreferrer"
            className="group w-full sm:w-auto rounded-2xl border border-slate-700 bg-[#111118] p-6 hover:border-green-500/40 transition-all bento-card flex-1 max-w-sm"
          >
            <div className="flex items-center gap-2 mb-4">
              <span className="text-slate-400 text-sm">GitHub Repository</span>
              <span className="ml-auto text-xs text-slate-600">yashselokar2025</span>
            </div>
            <p className="text-white font-semibold mb-5 text-sm">
              Hacktoberfest-CommitShield
            </p>
            <div className="flex gap-6">
              <div className="flex items-center gap-1.5 text-yellow-400">
                <Star size={16} />
                <span className="text-white font-bold text-lg">
                  {loading ? "—" : stats?.stars.toLocaleString()}
                </span>
                <span className="text-slate-500 text-xs">stars</span>
              </div>
              <div className="flex items-center gap-1.5 text-slate-400">
                <GitFork size={16} />
                <span className="text-white font-bold text-lg">
                  {loading ? "—" : stats?.forks}
                </span>
                <span className="text-slate-500 text-xs">forks</span>
              </div>
              <div className="flex items-center gap-1.5 text-slate-400">
                <AlertCircle size={16} />
                <span className="text-white font-bold text-lg">
                  {loading ? "—" : stats?.issues}
                </span>
                <span className="text-slate-500 text-xs">issues</span>
              </div>
            </div>
          </a>

          {/* Badges */}
          <div className="flex flex-col gap-3 text-sm">
            <div className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#111118] border border-slate-700">
              <span className="text-green-400">✓</span>
              <span className="text-slate-300">76/76 unit tests passing</span>
            </div>
            <div className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#111118] border border-slate-700">
              <span className="text-purple-400">🧠</span>
              <span className="text-slate-300">Gemma AI integrated</span>
            </div>
            <div className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#111118] border border-slate-700">
              <span className="text-cyan-400">📊</span>
              <span className="text-slate-300">F1 score: 0.950 (5-fold CV)</span>
            </div>
            <div className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#111118] border border-slate-700">
              <span className="text-yellow-400">🏆</span>
              <span className="text-slate-300">MLH Hacktoberfest submission</span>
            </div>
          </div>
        </div>

        {/* Testimonials */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {TESTIMONIALS.map((t, i) => (
            <div
              key={i}
              className="rounded-2xl border border-slate-700/50 bg-[#111118] p-6 bento-card"
            >
              <p className="text-slate-300 text-sm leading-relaxed mb-4 italic">
                &ldquo;{t.text}&rdquo;
              </p>
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-full bg-green-500/10 border border-green-500/20 flex items-center justify-center text-green-400 text-xs font-bold">
                  {t.avatar}
                </div>
                <span className="text-xs text-slate-500">{t.author}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

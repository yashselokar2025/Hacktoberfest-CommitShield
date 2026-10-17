"use client";

const FEATURES = [
  {
    id: "diff-aware",
    size: "large",
    icon: "🔍",
    title: "Change-Aware Scanning",
    description:
      "Compares each finding against your baseline. NEW findings block the commit. EXISTING ones are summarised — not repeated every single push.",
    demo: [
      { color: "text-red-400",   text: "🔴 NEW      Stripe Key    [0.92] → BLOCK" },
      { color: "text-yellow-500",text: "🟡 EXISTING DB Password   [0.78] → noted" },
      { color: "text-green-400", text: "✓  RESOLVED AWS Token     ──── resolved" },
    ],
  },
  {
    id: "gemma",
    size: "medium",
    icon: "🧠",
    title: "Gemma AI Auditing",
    description:
      "Google's Gemma model provides semantic context analysis — distinguishing real credentials from test data and placeholder strings.",
    demo: [
      { color: "text-purple-400", text: "Gemma: CONFIRM — live credential" },
      { color: "text-slate-500",  text: "Gemma: IGNORE — test placeholder" },
    ],
    badge: "Google Gemma",
  },
  {
    id: "lr",
    size: "medium",
    icon: "📊",
    title: "Explainable LR Classifier",
    description:
      "Logistic regression with 7 evidence signals. Every decision is transparent — you see exactly why a finding was blocked or allowed.",
    demo: [
      { color: "text-cyan-400",   text: "+0.31 shannon_entropy > 4.5" },
      { color: "text-cyan-400",   text: "+0.20 known_prefix (sk_live_)" },
      { color: "text-cyan-400",   text: "+0.15 in_env_file" },
      { color: "text-slate-600",  text: "+0.15 assignment_context" },
    ],
  },
  {
    id: "pre-commit",
    size: "small",
    icon: "🪝",
    title: "Pre-commit Hook",
    description: "Installs with one command. Runs automatically on every git commit. Zero config required.",
    demo: [
      { color: "text-green-400", text: "$ svc install" },
      { color: "text-slate-400", text: "✓ Hook installed to .git/hooks/pre-commit" },
    ],
  },
  {
    id: "baseline",
    size: "small",
    icon: "📋",
    title: "SQLite Baseline",
    description: "Persistent finding history stored locally. Tracks what was new, what was fixed, and when.",
    demo: [
      { color: "text-slate-400", text: "$ svc history" },
      { color: "text-green-400", text: "23 findings · 8 new · 15 resolved" },
    ],
  },
  {
    id: "crossplatform",
    size: "small",
    icon: "🌐",
    title: "Cross-Platform",
    description: "Runs on Linux, macOS, and Windows. Python 3.9+ compatible. CI-friendly.",
    demo: [
      { color: "text-slate-400", text: "🐧 Linux  ✓" },
      { color: "text-slate-400", text: " macOS ✓" },
      { color: "text-slate-400", text: "🪟 Windows ✓" },
    ],
  },
  {
    id: "open",
    size: "small",
    icon: "🔓",
    title: "Open Source + MIT",
    description: "100% open source. No telemetry, no SaaS, no subscription. Your secrets stay local.",
    demo: [
      { color: "text-green-400", text: "MIT License" },
      { color: "text-slate-400", text: "No telemetry · No cloud" },
    ],
  },
];

export default function FeatureGrid() {
  return (
    <section id="features" className="px-4 py-24">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="text-center mb-16">
          <p className="text-green-400 text-sm font-semibold mb-3 tracking-widest uppercase">
            Features
          </p>
          <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">
            Built different.
          </h2>
          <p className="text-slate-400 max-w-lg mx-auto">
            Not another wrapper around Gitleaks. A full evidence pipeline
            that explains every decision.
          </p>
        </div>

        {/* Bento grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 auto-rows-min">
          {/* Large card — diff-aware */}
          <div className="lg:col-span-2 lg:row-span-2 rounded-2xl border border-slate-700/50 bg-[#111118] p-6 bento-card">
            <div className="text-3xl mb-4">{FEATURES[0].icon}</div>
            <h3 className="text-xl font-bold text-white mb-2">{FEATURES[0].title}</h3>
            <p className="text-slate-400 text-sm mb-5 leading-relaxed">{FEATURES[0].description}</p>
            <div className="bg-[#0d0d14] rounded-xl border border-slate-700/40 p-4 font-mono text-xs space-y-1">
              {FEATURES[0].demo.map((line, i) => (
                <div key={i} className={line.color}>{line.text}</div>
              ))}
            </div>
          </div>

          {/* Gemma card — medium */}
          <div className="lg:col-span-2 rounded-2xl border border-purple-500/20 bg-[#111118] p-6 bento-card relative overflow-hidden">
            <div className="absolute top-3 right-3 px-2 py-0.5 rounded-full bg-purple-500/10 border border-purple-500/20 text-purple-400 text-xs">
              {FEATURES[1].badge}
            </div>
            <div className="text-3xl mb-4">{FEATURES[1].icon}</div>
            <h3 className="text-lg font-bold text-white mb-2">{FEATURES[1].title}</h3>
            <p className="text-slate-400 text-sm mb-4 leading-relaxed">{FEATURES[1].description}</p>
            <div className="bg-[#0d0d14] rounded-xl border border-purple-500/10 p-3 font-mono text-xs space-y-1">
              {FEATURES[1].demo.map((line, i) => (
                <div key={i} className={line.color}>{line.text}</div>
              ))}
            </div>
            {/* Decorative glow */}
            <div className="absolute bottom-0 right-0 w-32 h-32 bg-purple-500/5 rounded-full blur-2xl pointer-events-none" />
          </div>

          {/* LR Classifier card — medium */}
          <div className="lg:col-span-2 rounded-2xl border border-cyan-500/20 bg-[#111118] p-6 bento-card">
            <div className="text-3xl mb-4">{FEATURES[2].icon}</div>
            <h3 className="text-lg font-bold text-white mb-2">{FEATURES[2].title}</h3>
            <p className="text-slate-400 text-sm mb-4 leading-relaxed">{FEATURES[2].description}</p>
            <div className="bg-[#0d0d14] rounded-xl border border-cyan-500/10 p-3 font-mono text-xs space-y-1">
              {FEATURES[2].demo.map((line, i) => (
                <div key={i} className={line.color}>{line.text}</div>
              ))}
            </div>
          </div>

          {/* Small cards */}
          {FEATURES.slice(3).map((feat) => (
            <div
              key={feat.id}
              className="rounded-2xl border border-slate-700/50 bg-[#111118] p-5 bento-card"
            >
              <div className="text-2xl mb-3">{feat.icon}</div>
              <h3 className="text-sm font-bold text-white mb-1">{feat.title}</h3>
              <p className="text-slate-500 text-xs mb-3 leading-relaxed">{feat.description}</p>
              <div className="bg-[#0d0d14] rounded-lg border border-slate-700/30 p-2 font-mono text-xs space-y-0.5">
                {feat.demo.map((line, i) => (
                  <div key={i} className={line.color}>{line.text}</div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

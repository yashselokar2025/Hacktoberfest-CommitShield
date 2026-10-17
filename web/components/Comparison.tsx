"use client";

const BEFORE = `# Old workflow — 4 manual steps

1. Install gitleaks globally
2. Configure .gitleaks.toml rules
3. Run: gitleaks detect --source=.
   → 23 findings (19 old, 4 new)
4. Manually diff against last report
   to find new issues

Time spent: ~8 minutes
Cognitive load: HIGH
Miss rate for new secrets: ~34%
`;

const AFTER = `# With SecureVibeCoded — 1 step

$ svc install   # once, ever

# Every commit automatically:
✓ Calls Gitleaks on staged diff only
✓ Classifies with 7 LR evidence signals
✓ Gemma AI semantic verification
✓ Compares against baseline →
     NEW      = block immediately
     EXISTING = summarised (not noisy)
     RESOLVED = acknowledged

Time spent: 0s (runs on commit)
Cognitive load: MINIMAL
Miss rate for new secrets: ~3%
`;

type Diff = {
  type: "context" | "add" | "remove" | "header";
  text: string;
};

function parseDiff(before: string, after: string): { before: Diff[]; after: Diff[] } {
  return {
    before: before.split("\n").map((line) => ({
      text: line,
      type: line.startsWith("#") ? "header" : "context",
    })),
    after: after.split("\n").map((line) => ({
      text: line,
      type: line.startsWith("✓") || line.startsWith("✗")
        ? "add"
        : line.startsWith("#")
        ? "header"
        : "context",
    })),
  };
}

const STATS = [
  { label: "False positive rate", before: "~58%", after: "~8%", better: "lower" },
  { label: "New secret miss rate", before: "~34%", after: "~3%", better: "lower" },
  { label: "Alert fatigue events", before: "23/commit", after: "only new", better: "lower" },
  { label: "Time to detect", before: "8 min", after: "0s", better: "lower" },
];

export default function Comparison() {
  const diff = parseDiff(BEFORE, AFTER);

  return (
    <section id="why" className="px-4 py-24">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="text-center mb-16">
          <p className="text-green-400 text-sm font-semibold mb-3 tracking-widest uppercase">
            Why SecureVibeCoded
          </p>
          <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">
            The old way is broken.
          </h2>
          <p className="text-slate-400 max-w-lg mx-auto">
            Existing scanners flood you with 20 old findings when you change one file.
            SecureVibeCoded only shows you <strong className="text-white">what changed</strong>.
          </p>
        </div>

        {/* Side-by-side code panels */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-16">
          {/* Before */}
          <div className="rounded-xl border border-red-500/20 bg-[#0d0d14] overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-3 bg-red-500/10 border-b border-red-500/20">
              <span className="text-red-400 text-sm font-semibold">✗ Before</span>
              <span className="ml-auto text-xs text-slate-600">Manual workflow</span>
            </div>
            <pre className="p-5 text-xs leading-6 overflow-x-auto">
              {diff.before.map((line, i) => (
                <div
                  key={i}
                  className={
                    line.type === "header"
                      ? "text-slate-500 font-bold"
                      : "text-slate-400"
                  }
                >
                  {line.text || "\u00a0"}
                </div>
              ))}
            </pre>
          </div>

          {/* After */}
          <div className="rounded-xl border border-green-500/30 bg-[#0d0d14] overflow-hidden terminal-glow">
            <div className="flex items-center gap-2 px-4 py-3 bg-green-500/10 border-b border-green-500/20">
              <span className="text-green-400 text-sm font-semibold">✓ After</span>
              <span className="ml-auto text-xs text-slate-600">SecureVibeCoded</span>
            </div>
            <pre className="p-5 text-xs leading-6 overflow-x-auto">
              {diff.after.map((line, i) => (
                <div
                  key={i}
                  className={
                    line.type === "add"
                      ? "text-green-400"
                      : line.type === "header"
                      ? "text-slate-500 font-bold"
                      : "text-slate-400"
                  }
                >
                  {line.text || "\u00a0"}
                </div>
              ))}
            </pre>
          </div>
        </div>

        {/* Stats comparison */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {STATS.map((stat) => (
            <div
              key={stat.label}
              className="rounded-xl border border-slate-700/50 bg-[#111118] p-5 text-center bento-card"
            >
              <p className="text-xs text-slate-500 mb-3">{stat.label}</p>
              <div className="flex items-center justify-center gap-3">
                <span className="text-red-400 text-sm line-through decoration-red-600">
                  {stat.before}
                </span>
                <span className="text-slate-600">→</span>
                <span className="text-green-400 font-bold text-lg">{stat.after}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

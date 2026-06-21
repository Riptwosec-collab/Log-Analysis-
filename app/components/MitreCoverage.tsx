"use client";

import type { Finding } from "@/lib/logAnalyzer";
import type { Language } from "@/lib/i18n";

interface Props {
  findings: Finding[];
  mitreTechniques: string[];
  language: Language;
  t: Record<string, string>;
}

type TacticGroup = {
  tactic: string;
  emoji: string;
  color: string;
  borderColor: string;
  techniques: Array<{
    name: string;
    count: number;
    severity: string;
    techniqueId?: string;
  }>;
};

const TACTIC_META: Record<string, { emoji: string; color: string; border: string }> = {
  "Reconnaissance":       { emoji: "🔍", color: "bg-blue-950/40",   border: "border-blue-800" },
  "Initial Access":       { emoji: "🚪", color: "bg-purple-950/40", border: "border-purple-800" },
  "Credential Access":    { emoji: "🔑", color: "bg-yellow-950/40", border: "border-yellow-800" },
  "Discovery":            { emoji: "🗺️",  color: "bg-sky-950/40",    border: "border-sky-800" },
  "Lateral Movement":     { emoji: "↔️",  color: "bg-orange-950/40", border: "border-orange-800" },
  "Execution":            { emoji: "⚡",  color: "bg-red-950/40",    border: "border-red-800" },
  "Persistence":          { emoji: "📌",  color: "bg-pink-950/40",   border: "border-pink-800" },
  "Privilege Escalation": { emoji: "⬆️",  color: "bg-amber-950/40",  border: "border-amber-800" },
  "Defense Evasion":      { emoji: "🛡️",  color: "bg-teal-950/40",   border: "border-teal-800" },
  "Collection":           { emoji: "📦",  color: "bg-indigo-950/40", border: "border-indigo-800" },
  "Exfiltration":         { emoji: "📤",  color: "bg-rose-950/40",   border: "border-rose-800" },
  "Impact":               { emoji: "💥",  color: "bg-zinc-800/40",   border: "border-zinc-700" },
};

const SEV_DOT: Record<string, string> = {
  Critical: "bg-red-500",
  High:     "bg-orange-500",
  Medium:   "bg-yellow-500",
  Low:      "bg-green-500",
};

function buildTacticGroups(findings: Finding[], mitreTechniques: string[]): TacticGroup[] {
  // Build technique → {count, severity, tactic} from findings
  const techMap = new Map<string, { count: number; severity: string; tactic: string }>();

  for (const f of findings) {
    if (!f.technique) continue;
    const existing = techMap.get(f.technique);
    const sevRank = { Low: 1, Medium: 2, High: 3, Critical: 4 };
    if (!existing) {
      techMap.set(f.technique, { count: 1, severity: f.severity, tactic: f.tactic });
    } else {
      techMap.set(f.technique, {
        count: existing.count + 1,
        severity: (sevRank[f.severity as keyof typeof sevRank] ?? 0) > (sevRank[existing.severity as keyof typeof sevRank] ?? 0)
          ? f.severity
          : existing.severity,
        tactic: f.tactic,
      });
    }
  }

  // Add techniques from summary that aren't in findings
  for (const t of mitreTechniques) {
    if (!Array.from(techMap.keys()).some((k) => k.includes(t) || t.includes(k))) {
      techMap.set(t, { count: 1, severity: "Medium", tactic: "Unknown" });
    }
  }

  // Group by tactic
  const tacticMap = new Map<string, TacticGroup>();
  for (const [techName, data] of techMap) {
    const meta = TACTIC_META[data.tactic] ?? TACTIC_META["Impact"];
    if (!tacticMap.has(data.tactic)) {
      tacticMap.set(data.tactic, {
        tactic: data.tactic,
        emoji: meta.emoji,
        color: meta.color,
        borderColor: meta.border,
        techniques: [],
      });
    }
    tacticMap.get(data.tactic)!.techniques.push({
      name: techName,
      count: data.count,
      severity: data.severity,
    });
  }

  return Array.from(tacticMap.values()).sort((a, b) => {
    const order = Object.keys(TACTIC_META);
    return (order.indexOf(a.tactic) || 99) - (order.indexOf(b.tactic) || 99);
  });
}

export default function MitreCoverage({ findings, mitreTechniques, language, t }: Props) {
  const groups = buildTacticGroups(findings, mitreTechniques);

  if (groups.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <p className="text-4xl">🛡️</p>
        <p className="mt-3 text-zinc-400">No MITRE techniques detected</p>
        <p className="text-sm text-zinc-600">Run analysis to see ATT&CK coverage</p>
      </div>
    );
  }

  const totalTechniques = groups.reduce((s, g) => s + g.techniques.length, 0);
  const totalAlerts = groups.reduce((s, g) => s + g.techniques.reduce((ss, t) => ss + t.count, 0), 0);

  return (
    <div className="space-y-4">
      {/* Stats row */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: "Tactics Covered",    value: groups.length },
          { label: "Techniques Detected", value: totalTechniques },
          { label: "Total Alert Hits",   value: totalAlerts },
        ].map(({ label, value }) => (
          <div key={label} className="rounded-lg border border-zinc-800 bg-zinc-900 p-3 text-center card-3d-sm">
            <p className="text-2xl font-bold text-white">{value}</p>
            <p className="mt-0.5 text-xs text-zinc-500">{label}</p>
          </div>
        ))}
      </div>

      {/* Tactic groups */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {groups.map((group) => (
          <div
            key={group.tactic}
            className={`rounded-xl border p-4 card-3d ${group.color} ${group.borderColor}`}
          >
            <div className="mb-3 flex items-center gap-2">
              <span className="text-xl">{group.emoji}</span>
              <span className="text-sm font-semibold text-white">{group.tactic}</span>
              <span className="ml-auto rounded-full bg-zinc-800 px-2 py-0.5 text-xs text-zinc-400">
                {group.techniques.length}
              </span>
            </div>
            <div className="space-y-1.5">
              {group.techniques.map((tech) => (
                <div key={tech.name} className="flex items-center gap-2 rounded-md border border-zinc-800 bg-zinc-950/50 px-2.5 py-1.5">
                  <span className={`h-2 w-2 shrink-0 rounded-full ${SEV_DOT[tech.severity] ?? "bg-zinc-500"}`} />
                  <span className="flex-1 min-w-0 text-xs text-zinc-300 truncate">{tech.name}</span>
                  <span className="shrink-0 rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-500">×{tech.count}</span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* ATT&CK link */}
      <div className="text-center">
        <a
          href="https://attack.mitre.org/"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1.5 rounded-md border border-violet-800 bg-violet-950/20 px-4 py-2 text-sm text-violet-300 hover:border-violet-600 hover:text-violet-200"
        >
          🛡️ View Full MITRE ATT&CK Framework ↗
        </a>
      </div>
    </div>
  );
}

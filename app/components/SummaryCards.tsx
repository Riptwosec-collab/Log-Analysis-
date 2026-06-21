"use client";

import type { AnalysisSummary, Severity } from "@/lib/logAnalyzer";
import type { Language } from "@/lib/i18n";
import { severityLabel, barClass } from "@/lib/i18n";

interface Props {
  summary: AnalysisSummary;
  language: Language;
  t: Record<string, string>;
}

function Metric({
  label,
  value,
  tone = "default",
}: {
  label: string;
  value: string;
  tone?: "default" | "critical" | "warning";
}) {
  const color =
    tone === "critical"
      ? "text-red-300"
      : tone === "warning"
      ? "text-amber-300"
      : "text-white";
  return (
    <div className={`rounded-md border border-zinc-800 bg-black p-3 card-3d-sm${tone === "critical" ? " critical-glow" : ""}`}>
      <p className="text-xs uppercase tracking-[0.16em] text-zinc-500">{label}</p>
      <p className={`mt-2 font-mono text-2xl font-semibold ${color}`}>{value}</p>
    </div>
  );
}

function SeverityBars({
  counts,
  language,
}: {
  counts?: Record<Severity, number>;
  language: Language;
}) {
  const safeCounts = counts || { Low: 0, Medium: 0, High: 0, Critical: 0 };
  const max = Math.max(1, ...Object.values(safeCounts));

  return (
    <div className="mt-4 space-y-3">
      {(Object.keys(safeCounts) as Severity[]).map((level) => (
        <div key={level}>
          <div className="mb-1 flex justify-between text-xs text-zinc-400">
            <span>{severityLabel(level, language)}</span>
            <span>{safeCounts[level]}</span>
          </div>
          <div className="h-2 rounded bg-zinc-800">
            <div
              className={`h-2 rounded ${barClass(level)}`}
              style={{ width: `${(safeCounts[level] / max) * 100}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

export default function SummaryCards({ summary, language, t }: Props) {
  return (
    <aside className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 card-3d">
      <h2 className="text-lg font-semibold text-white">{t.overview}</h2>
      <div className="mt-4 grid grid-cols-2 gap-3">
        <Metric
          label={t.riskScore}
          value={String(summary.riskScore)}
          tone={summary.riskLevel === "Critical" ? "critical" : "warning"}
        />
        <Metric label={t.totalEvents} value={String(summary.totalEvents)} />
        <Metric label={t.suspicious} value={String(summary.suspiciousEvents)} />
        <Metric label={t.critical} value={String(summary.criticalAlerts)} tone="critical" />
        <Metric label={t.failedLogin} value={String(summary.failedLogins)} tone="warning" />
        <Metric label={t.correlation} value={String(summary.correlations.length)} />
      </div>
      <div className="mt-4 rounded-md border border-zinc-800 bg-black p-3">
        <p className="text-xs uppercase tracking-[0.18em] text-zinc-500">{t.topSourceIp}</p>
        <p className="mt-2 font-mono text-lg text-cyan-300">
          {summary.topSourceIp || t.none}
        </p>
      </div>
      <div className="mt-3 grid grid-cols-3 gap-2">
        <Metric label="IOC" value={String(summary.iocHits)} tone="critical" />
        <Metric label="Public IP" value={String(summary.publicIpCount)} />
        <Metric label="Private IP" value={String(summary.privateIpCount)} />
      </div>
      <SeverityBars counts={summary.severityCounts} language={language} />
    </aside>
  );
}

"use client";

import { useState } from "react";
import type { AnalysisResult } from "@/lib/logAnalyzer";
import type { Language } from "@/lib/i18n";
import { localize } from "@/lib/i18n";

interface Props {
  result: AnalysisResult;
  language: Language;
}

type Tab = "what" | "mitre" | "actions" | "next";

const TAB_META: Array<{ id: Tab; label: string; emoji: string }> = [
  { id: "what",    label: "What Happened",    emoji: "🔍" },
  { id: "mitre",   label: "MITRE Mapping",    emoji: "🛡️" },
  { id: "actions", label: "Actions",          emoji: "🔧" },
  { id: "next",    label: "Next Steps",       emoji: "📋" },
];

const VERDICT_STYLE: Record<string, { bg: string; border: string; text: string; icon: string }> = {
  Critical:   { bg: "bg-red-950/50",    border: "border-red-700",    text: "text-red-300",    icon: "🚨" },
  Malicious:  { bg: "bg-red-950/50",    border: "border-red-700",    text: "text-red-300",    icon: "☠️" },
  High:       { bg: "bg-orange-950/50", border: "border-orange-700", text: "text-orange-300", icon: "⚠️" },
  Suspicious: { bg: "bg-yellow-950/50", border: "border-yellow-700", text: "text-yellow-300", icon: "🟡" },
  Medium:     { bg: "bg-yellow-950/50", border: "border-yellow-700", text: "text-yellow-300", icon: "🟡" },
  Low:        { bg: "bg-green-950/50",  border: "border-green-700",  text: "text-green-300",  icon: "✅" },
  Benign:     { bg: "bg-green-950/50",  border: "border-green-700",  text: "text-green-300",  icon: "✅" },
};

function buildWhatHappened(result: AnalysisResult, language: Language): string {
  const { summary } = result;
  const highAlerts = summary.severityCounts?.High ?? 0;
  const mediumAlerts = summary.severityCounts?.Medium ?? 0;
  const parts: string[] = [];
  if (summary.criticalAlerts > 0) parts.push(`${summary.criticalAlerts} Critical`);
  if (highAlerts > 0) parts.push(`${highAlerts} High`);
  if (mediumAlerts > 0) parts.push(`${mediumAlerts} Medium`);
  const alertStr = parts.length > 0 ? `${parts.join(", ")} severity alerts` : "alerts";

  return localize(summary.incidentNarrative, language) ||
    `Analyzed ${summary.totalEvents} log events and detected ${alertStr}. ` +
    `${summary.failedLogins > 0 ? `Found ${summary.failedLogins} failed login attempts. ` : ""}` +
    `${summary.correlations.length > 0 ? `Identified ${summary.correlations.length} correlated incidents. ` : ""}` +
    `${summary.topSourceIp ? `Primary threat actor: ${summary.topSourceIp}.` : ""}`;
}

function buildMitreSection(result: AnalysisResult): string {
  const techs = result.summary.mitreTechniques;
  if (!techs.length) return "No MITRE ATT&CK techniques detected in the analyzed logs.";
  return `Detected ${techs.length} technique(s):\n${techs.map((t) => `• ${t}`).join("\n")}`;
}

export default function AiSummary({ result, language }: Props) {
  const [tab, setTab] = useState<Tab>("what");
  const { summary } = result;
  const highAlerts = summary.severityCounts?.High ?? 0;

  const verdict = summary.riskLevel;
  const vs = VERDICT_STYLE[verdict] ?? VERDICT_STYLE["Suspicious"];

  const whatHappened = buildWhatHappened(result, language);
  const mitreSection = buildMitreSection(result);
  const actions = summary.recommendedActions ?? [];
  const nextSteps = [
    summary.topSourceIp ? `Block or investigate source IP: ${summary.topSourceIp}` : null,
    summary.failedLogins > 5 ? "Enable account lockout and review authentication logs" : null,
    summary.criticalAlerts > 0 ? "Escalate to Tier 2 / IR team immediately" : null,
    summary.correlations.length > 0 ? "Review correlated incidents for attack chain reconstruction" : null,
    summary.mitreTechniques.length > 0 ? "Map detections to MITRE ATT&CK and update detection rules" : null,
    "Preserve evidence and update incident ticket",
    "Schedule post-incident review within 48h",
  ].filter(Boolean) as string[];

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900 overflow-hidden card-3d">
      {/* Header */}
      <div className={`border-b ${vs.border} ${vs.bg} p-4`}>
        <div className="flex items-start gap-3">
          <div className="text-3xl">{vs.icon}</div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs uppercase tracking-wider text-zinc-400">🤖 AI SOC Analyst</span>
              <span className={`rounded-full border px-2.5 py-0.5 text-xs font-bold ${vs.border} ${vs.bg} ${vs.text}`}>
                {verdict} Risk
              </span>
              <span className="text-xs text-zinc-500">Score: {summary.riskScore}/100</span>
            </div>
            <h3 className="mt-1 text-base font-semibold text-white leading-tight">
              {summary.criticalAlerts > 0
                ? "Critical threat activity detected — immediate action required"
                : highAlerts > 0
                ? "High-severity threats detected — investigate promptly"
                : summary.suspiciousEvents > 0
                ? "Suspicious activity detected — monitor and investigate"
                : "No significant threats detected in analyzed logs"}
            </h3>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-zinc-800">
        {TAB_META.map(({ id, label, emoji }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={`flex-1 px-2 py-2.5 text-xs font-medium transition-colors ${
              tab === id
                ? "border-b-2 border-cyan-500 bg-cyan-500/5 text-cyan-300"
                : "text-zinc-500 hover:text-zinc-300"
            }`}
          >
            <span className="hidden sm:inline">{emoji} </span>{label}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="p-4 min-h-40">
        {tab === "what" && (
          <div className="space-y-3">
            <p className="text-sm text-zinc-300 leading-6">{whatHappened}</p>
            {summary.affectedUsers.length > 0 && (
              <div>
                <p className="text-xs uppercase tracking-wider text-zinc-500 mb-1.5">Affected Accounts</p>
                <div className="flex flex-wrap gap-1.5">
                  {summary.affectedUsers.slice(0, 6).map((u) => (
                    <span key={u} className="rounded border border-zinc-700 bg-zinc-800 px-2 py-0.5 text-xs text-zinc-300 font-mono">
                      {u}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {summary.topSourceIp && (
              <div className="rounded-md border border-red-900/50 bg-red-950/20 p-3">
                <p className="text-xs text-red-400 uppercase tracking-wider mb-1">Primary Threat Actor</p>
                <p className="font-mono text-sm text-red-300">{summary.topSourceIp}</p>
              </div>
            )}
          </div>
        )}

        {tab === "mitre" && (
          <div>
            <pre className="text-sm text-zinc-300 leading-6 whitespace-pre-wrap font-sans">{mitreSection}</pre>
            {summary.topRules.length > 0 && (
              <div className="mt-3">
                <p className="text-xs uppercase tracking-wider text-zinc-500 mb-2">Top Triggered Rules</p>
                <div className="space-y-1.5">
                  {summary.topRules.slice(0, 5).map((r) => (
                    <div key={r.rule} className="flex items-center justify-between gap-3 rounded-md border border-zinc-800 bg-zinc-950 px-3 py-1.5">
                      <span className="text-xs text-zinc-300 truncate">{r.rule}</span>
                      <span className="shrink-0 rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-500">×{r.count}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {tab === "actions" && (
          <div className="space-y-2">
            {actions.length > 0 ? (
              actions.slice(0, 8).map((a, i) => (
                <div key={i} className="flex items-start gap-2.5">
                  <span className="mt-1 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-cyan-500/20 text-[10px] font-bold text-cyan-400">
                    {i + 1}
                  </span>
                  <p className="text-sm text-zinc-300 leading-5">{localize(a, language)}</p>
                </div>
              ))
            ) : (
              <p className="text-sm text-zinc-500">No critical actions required. Continue normal monitoring.</p>
            )}
          </div>
        )}

        {tab === "next" && (
          <div className="space-y-2">
            {nextSteps.map((step, i) => (
              <div key={i} className="flex items-start gap-2.5 rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2">
                <span className="shrink-0 text-sm">→</span>
                <p className="text-sm text-zinc-300 leading-5">{step}</p>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Analyst report tabs note */}
      <div className="border-t border-zinc-800 bg-zinc-950 px-4 py-2">
        <p className="text-xs text-zinc-600">
          Detailed analyst reports available in the main panel → Analyst Mode
        </p>
      </div>
    </div>
  );
}

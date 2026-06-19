"use client";
import type { Finding } from "@/lib/logAnalyzer";
import type { Language } from "@/lib/i18n";
import { useState } from "react";

type Props = {
  mitreTechniques: string[];
  findings: Finding[];
  language: Language;
  t: Record<string, string>;
};

type Severity = "Low" | "Medium" | "High" | "Critical";

const MATRIX = [
  {
    tactic: "Reconnaissance",
    techniques: [
      { id: "T1595", name: "Active Scanning" },
      { id: "T1592", name: "Gather Host Info" },
      { id: "T1589", name: "Gather Identity" },
    ],
  },
  {
    tactic: "Initial Access",
    techniques: [
      { id: "T1190", name: "Exploit Public App" },
      { id: "T1078", name: "Valid Accounts" },
      { id: "T1133", name: "External Remote Svc" },
    ],
  },
  {
    tactic: "Execution",
    techniques: [
      { id: "T1059", name: "Command & Script" },
      { id: "T1203", name: "Exploit for Exec" },
      { id: "T1072", name: "Software Deployment" },
    ],
  },
  {
    tactic: "Persistence",
    techniques: [
      { id: "T1136", name: "Create Account" },
      { id: "T1543", name: "Create/Mod Service" },
      { id: "T1053", name: "Scheduled Task" },
    ],
  },
  {
    tactic: "Privilege Esc",
    techniques: [
      { id: "T1068", name: "Exploit Priv Esc" },
      { id: "T1134", name: "Token Manipulation" },
      { id: "T1548", name: "Abuse Elevation" },
    ],
  },
  {
    tactic: "Defense Evasion",
    techniques: [
      { id: "T1055", name: "Process Injection" },
      { id: "T1562", name: "Impair Defenses" },
      { id: "T1070", name: "Indicator Removal" },
    ],
  },
  {
    tactic: "Credential Access",
    techniques: [
      { id: "T1110", name: "Brute Force" },
      { id: "T1003", name: "Credential Dump" },
      { id: "T1558", name: "Kerberoasting" },
    ],
  },
  {
    tactic: "Discovery",
    techniques: [
      { id: "T1046", name: "Network Scan" },
      { id: "T1082", name: "System Info" },
      { id: "T1083", name: "File Discovery" },
    ],
  },
  {
    tactic: "Lateral Movement",
    techniques: [
      { id: "T1021", name: "Remote Services" },
      { id: "T1550", name: "Alt Auth Material" },
      { id: "T1080", name: "Taint Shared" },
    ],
  },
  {
    tactic: "Exfiltration",
    techniques: [
      { id: "T1048", name: "Exfil Alt Channel" },
      { id: "T1041", name: "Exfil over C2" },
      { id: "T1052", name: "Physical Exfil" },
    ],
  },
  {
    tactic: "Impact",
    techniques: [
      { id: "T1486", name: "Data Encrypted" },
      { id: "T1499", name: "Endpoint DoS" },
      { id: "T1489", name: "Service Stop" },
    ],
  },
];

const SEVERITY_BG: Record<Severity, string> = {
  Critical: "bg-red-900 border-red-700 text-red-200",
  High: "bg-orange-900 border-orange-700 text-orange-200",
  Medium: "bg-yellow-900 border-yellow-700 text-yellow-200",
  Low: "bg-green-900 border-green-700 text-green-200",
};

export default function MitreMatrix({ mitreTechniques, findings, language }: Props) {
  const [tooltip, setTooltip] = useState<{
    id: string;
    name: string;
    tactic: string;
    severity: Severity | null;
    x: number;
    y: number;
  } | null>(null);

  // Build map: techniqueId → max severity among matching findings
  const ranks: Record<Severity, number> = { Low: 1, Medium: 2, High: 3, Critical: 4 };
  const detectedMap: Record<string, Severity> = {};

  findings.forEach((f) => {
    MATRIX.forEach((col) =>
      col.techniques.forEach((tech) => {
        if (f.technique && f.technique.includes(tech.id)) {
          if (!detectedMap[tech.id] || ranks[f.severity] > ranks[detectedMap[tech.id]]) {
            detectedMap[tech.id] = f.severity as Severity;
          }
        }
      })
    );
  });

  // Also check mitreTechniques strings
  mitreTechniques.forEach((mt) => {
    MATRIX.forEach((col) =>
      col.techniques.forEach((tech) => {
        if (mt.includes(tech.id) && !detectedMap[tech.id]) {
          detectedMap[tech.id] = "Low";
        }
      })
    );
  });

  const totalTechniques = MATRIX.reduce((s, col) => s + col.techniques.length, 0);
  const detectedCount = Object.keys(detectedMap).length;
  const detectedTactics = new Set(
    MATRIX.filter((col) => col.techniques.some((t) => detectedMap[t.id])).map((col) => col.tactic)
  ).size;

  const title = language === "th" ? "เมทริกซ์ MITRE ATT&CK" : "MITRE ATT&CK Matrix";
  const summaryText =
    language === "th"
      ? `ตรวจพบ ${detectedCount} / ${totalTechniques} เทคนิค ใน ${detectedTactics} ยุทธวิธี`
      : `${detectedCount} / ${totalTechniques} techniques detected across ${detectedTactics} tactics`;

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-base font-semibold text-white">{title}</h3>
        <p className="text-xs text-zinc-400">{summaryText}</p>
      </div>

      {/* Legend */}
      <div className="mb-3 flex flex-wrap gap-2 text-xs">
        {(["Critical", "High", "Medium", "Low"] as Severity[]).map((sev) => (
          <span key={sev} className={`rounded border px-2 py-0.5 ${SEVERITY_BG[sev]}`}>
            {sev}
          </span>
        ))}
        <span className="rounded border border-zinc-700 bg-zinc-900 px-2 py-0.5 text-zinc-500">
          Not detected
        </span>
      </div>

      <div className="overflow-x-auto rounded-md border border-zinc-800">
        <div className="flex" style={{ minWidth: 880 }}>
          {MATRIX.map((col) => (
            <div key={col.tactic} className="flex min-w-[80px] flex-1 flex-col border-r border-zinc-800 last:border-r-0">
              {/* Tactic header */}
              <div className="border-b border-zinc-700 bg-blue-950 px-2 py-2 text-center">
                <p className="text-[10px] font-semibold uppercase tracking-wide text-blue-200">
                  {col.tactic}
                </p>
              </div>

              {/* Technique cells */}
              <div className="flex flex-col gap-1 p-1">
                {col.techniques.map((tech) => {
                  const sev = detectedMap[tech.id] ?? null;
                  const cellClass = sev
                    ? SEVERITY_BG[sev]
                    : "bg-zinc-900 border-zinc-800 text-zinc-600";

                  return (
                    <div
                      key={tech.id}
                      className={`relative cursor-default rounded border px-1.5 py-1.5 transition-opacity hover:opacity-80 ${cellClass}`}
                      onMouseEnter={(e) => {
                        const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
                        setTooltip({
                          id: tech.id,
                          name: tech.name,
                          tactic: col.tactic,
                          severity: sev,
                          x: rect.left,
                          y: rect.top,
                        });
                      }}
                      onMouseLeave={() => setTooltip(null)}
                    >
                      <p className="font-mono text-[10px] leading-tight opacity-70">{tech.id}</p>
                      <p className="mt-0.5 text-[10px] leading-tight">{tech.name}</p>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Tooltip */}
      {tooltip && (
        <div
          className="pointer-events-none fixed z-50 max-w-[200px] rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-xs shadow-xl"
          style={{
            left: tooltip.x + 10,
            top: tooltip.y - 8,
            transform: "translateY(-100%)",
          }}
        >
          <p className="font-mono font-semibold text-cyan-300">{tooltip.id}</p>
          <p className="mt-0.5 font-medium text-white">{tooltip.name}</p>
          <p className="mt-1 text-zinc-400">Tactic: {tooltip.tactic}</p>
          {tooltip.severity ? (
            <p className={`mt-1 font-semibold ${
              tooltip.severity === "Critical" ? "text-red-300" :
              tooltip.severity === "High" ? "text-orange-300" :
              tooltip.severity === "Medium" ? "text-yellow-300" : "text-green-300"
            }`}>
              Detected — {tooltip.severity}
            </p>
          ) : (
            <p className="mt-1 text-zinc-500">Not detected</p>
          )}
        </div>
      )}
    </div>
  );
}

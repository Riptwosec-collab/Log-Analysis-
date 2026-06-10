"use client";

import { useMemo, useState } from "react";

type Severity = "Low" | "Medium" | "High" | "Critical";

type Finding = {
  id: string;
  lineNumber: number;
  timestamp: string | null;
  severity: Severity;
  logType: string;
  rule: string;
  detectedKeywords: string[];
  possibleRootCause: string;
  impact: string;
  recommendedFix: string;
  sourceIp: string | null;
  raw: string;
  repeatedCount: number;
};

type AnalysisResult = {
  generatedAt: string;
  summary: {
    totalEvents: number;
    suspiciousEvents: number;
    criticalAlerts: number;
    failedLogins: number;
    topSourceIp: string | null;
    logTypes: Record<string, number>;
    severityCounts: Record<Severity, number>;
    timeline: Array<{ timestamp: string; count: number; severity: Severity }>;
  };
  findings: Finding[];
};

const demoLog = `Jun 10 21:14:02 web-01 sshd[1204]: Failed password for invalid user admin from 185.220.101.21 port 55110 ssh2
Jun 10 21:14:08 web-01 sshd[1208]: Failed password for root from 185.220.101.21 port 55116 ssh2
2026-06-10T21:16:40Z 198.51.100.44 "GET /login.php?id=1 UNION SELECT password FROM users HTTP/1.1" 403
2026-06-10T21:17:11Z 203.0.113.9 "GET /download?file=../../../../etc/passwd HTTP/1.1" 400
2026-06-10T21:18:27Z firewall DROP SRC=45.77.10.2 DST=10.0.0.12 PROTO=TCP DPT=22 SYN
06/10/2026 09:19:44 PM Event ID 4625 Audit Failure Account Name: svc-backup Source Network Address: 192.0.2.71`;

const severityOptions: Array<Severity | "All"> = ["All", "Critical", "High", "Medium", "Low"];

export default function SOCDashboard() {
  const [logInput, setLogInput] = useState(demoLog);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<Severity | "All">("All");
  const [logType, setLogType] = useState("All");
  const [timestampFilter, setTimestampFilter] = useState("");

  const analyzeText = async (log: string) => {
    setIsAnalyzing(true);
    setError("");

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ log }),
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Analyze request failed.");
      setResult(data);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Analyze request failed.");
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const content = await file.text();
    setLogInput(content);
    await analyzeText(content);
  };

  const logTypes = useMemo(() => {
    if (!result) return ["All"];
    return ["All", ...Object.keys(result.summary.logTypes).sort()];
  }, [result]);

  const filteredFindings = useMemo(() => {
    if (!result) return [];
    const needle = query.toLowerCase().trim();

    return result.findings.filter((finding) => {
      const matchesQuery =
        !needle ||
        [
          finding.id,
          finding.rule,
          finding.raw,
          finding.sourceIp || "",
          finding.detectedKeywords.join(" "),
          finding.possibleRootCause,
          finding.recommendedFix,
        ]
          .join(" ")
          .toLowerCase()
          .includes(needle);
      const matchesSeverity = severity === "All" || finding.severity === severity;
      const matchesType = logType === "All" || finding.logType === logType;
      const matchesTimestamp = !timestampFilter || (finding.timestamp || "").includes(timestampFilter);
      return matchesQuery && matchesSeverity && matchesType && matchesTimestamp;
    });
  }, [logType, query, result, severity, timestampFilter]);

  const exportReport = (format: "json" | "csv" | "txt") => {
    if (!result) return;

    const filename = `soc-report-${new Date().toISOString().slice(0, 10)}.${format}`;
    const content = buildExport(format, result, filteredFindings);
    const type = format === "json" ? "application/json" : "text/plain";
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <main className="min-h-screen bg-zinc-950 text-zinc-100">
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-6 px-4 py-6 sm:px-6 lg:px-8">
        <header className="flex flex-col gap-4 border-b border-zinc-800 pb-5 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <p className="text-sm font-medium uppercase tracking-[0.2em] text-cyan-300">Log Analysis</p>
            <h1 className="mt-2 text-3xl font-semibold text-white sm:text-4xl">SOC Analytics Dashboard</h1>
            <p className="mt-2 max-w-2xl text-sm text-zinc-400">
              Analyze Apache/Nginx, SSH auth, firewall, Windows Event, Linux syslog, and generic application logs.
            </p>
          </div>
          <div className="grid grid-cols-3 gap-2 text-right text-xs text-zinc-400 sm:min-w-80">
            <Metric label="Rules" value="8" />
            <Metric label="Types" value="6" />
            <Metric label="Export" value="3" />
          </div>
        </header>

        <section className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_340px]">
          <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
            <div className="mb-3 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <h2 className="text-lg font-semibold text-white">Log Input</h2>
              <label className="inline-flex cursor-pointer items-center justify-center rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm font-medium text-zinc-200 hover:border-cyan-500">
                Upload .log/.txt
                <input className="sr-only" type="file" accept=".log,.txt,.csv" onChange={handleFileUpload} />
              </label>
            </div>
            <textarea
              className="h-72 w-full resize-y rounded-md border border-zinc-800 bg-black p-3 font-mono text-sm leading-6 text-zinc-200 outline-none ring-cyan-500 focus:ring-2"
              value={logInput}
              onChange={(event) => setLogInput(event.target.value)}
              spellCheck={false}
            />
            <div className="mt-3 flex flex-col gap-2 sm:flex-row">
              <button
                className="rounded-md bg-cyan-500 px-4 py-2 text-sm font-semibold text-zinc-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-60"
                onClick={() => analyzeText(logInput)}
                disabled={isAnalyzing}
              >
                {isAnalyzing ? "Analyzing..." : "Analyze Log"}
              </button>
              <button
                className="rounded-md border border-zinc-700 px-4 py-2 text-sm font-semibold text-zinc-200 hover:border-zinc-500"
                onClick={() => {
                  setLogInput(demoLog);
                  setResult(null);
                  setError("");
                }}
              >
                Load Demo
              </button>
            </div>
            {error && <p className="mt-3 rounded-md border border-red-900 bg-red-950/60 p-3 text-sm text-red-200">{error}</p>}
          </div>

          <aside className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
            <h2 className="text-lg font-semibold text-white">Summary</h2>
            <div className="mt-4 grid grid-cols-2 gap-3">
              <Metric label="Total Events" value={String(result?.summary.totalEvents || 0)} />
              <Metric label="Suspicious" value={String(result?.summary.suspiciousEvents || 0)} />
              <Metric label="Critical" value={String(result?.summary.criticalAlerts || 0)} tone="critical" />
              <Metric label="Failed Login" value={String(result?.summary.failedLogins || 0)} tone="warning" />
            </div>
            <div className="mt-4 rounded-md border border-zinc-800 bg-black p-3">
              <p className="text-xs uppercase tracking-[0.18em] text-zinc-500">Top Source IP</p>
              <p className="mt-2 font-mono text-lg text-cyan-300">{result?.summary.topSourceIp || "None"}</p>
            </div>
            <SeverityBars counts={result?.summary.severityCounts} />
          </aside>
        </section>

        {result && (
          <>
            <section className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_340px]">
              <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
                <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                  <h2 className="text-lg font-semibold text-white">Suspicious Event Table</h2>
                  <div className="flex flex-wrap gap-2">
                    <button className="rounded-md border border-zinc-700 px-3 py-2 text-sm hover:border-cyan-500" onClick={() => exportReport("txt")}>
                      TXT
                    </button>
                    <button className="rounded-md border border-zinc-700 px-3 py-2 text-sm hover:border-cyan-500" onClick={() => exportReport("csv")}>
                      CSV
                    </button>
                    <button className="rounded-md border border-zinc-700 px-3 py-2 text-sm hover:border-cyan-500" onClick={() => exportReport("json")}>
                      JSON
                    </button>
                  </div>
                </div>

                <div className="mt-4 grid gap-2 md:grid-cols-4">
                  <input
                    className="rounded-md border border-zinc-800 bg-black px-3 py-2 text-sm outline-none focus:border-cyan-500"
                    placeholder="Search keyword, IP, rule"
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                  />
                  <select
                    className="rounded-md border border-zinc-800 bg-black px-3 py-2 text-sm outline-none focus:border-cyan-500"
                    value={severity}
                    onChange={(event) => setSeverity(event.target.value as Severity | "All")}
                  >
                    {severityOptions.map((option) => (
                      <option key={option}>{option}</option>
                    ))}
                  </select>
                  <select
                    className="rounded-md border border-zinc-800 bg-black px-3 py-2 text-sm outline-none focus:border-cyan-500"
                    value={logType}
                    onChange={(event) => setLogType(event.target.value)}
                  >
                    {logTypes.map((option) => (
                      <option key={option}>{option}</option>
                    ))}
                  </select>
                  <input
                    className="rounded-md border border-zinc-800 bg-black px-3 py-2 text-sm outline-none focus:border-cyan-500"
                    placeholder="Timestamp contains"
                    value={timestampFilter}
                    onChange={(event) => setTimestampFilter(event.target.value)}
                  />
                </div>

                <div className="mt-4 overflow-x-auto">
                  <table className="w-full min-w-[980px] border-collapse text-left text-sm">
                    <thead className="border-b border-zinc-800 text-xs uppercase tracking-[0.14em] text-zinc-500">
                      <tr>
                        <th className="py-3 pr-3">ID</th>
                        <th className="py-3 pr-3">Severity</th>
                        <th className="py-3 pr-3">Type</th>
                        <th className="py-3 pr-3">Timestamp</th>
                        <th className="py-3 pr-3">Source</th>
                        <th className="py-3 pr-3">Rule</th>
                        <th className="py-3 pr-3">Repeat</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredFindings.map((finding) => (
                        <tr key={finding.id} className="border-b border-zinc-900 align-top hover:bg-zinc-800/50">
                          <td className="py-3 pr-3 font-mono text-xs text-zinc-400">{finding.id}</td>
                          <td className="py-3 pr-3">
                            <span className={`rounded px-2 py-1 text-xs font-semibold ${severityClass(finding.severity)}`}>
                              {finding.severity}
                            </span>
                          </td>
                          <td className="py-3 pr-3 text-zinc-300">{finding.logType}</td>
                          <td className="py-3 pr-3 font-mono text-xs text-zinc-400">{finding.timestamp || "Unknown"}</td>
                          <td className="py-3 pr-3 font-mono text-xs text-cyan-300">{finding.sourceIp || "-"}</td>
                          <td className="py-3 pr-3">
                            <p className="font-medium text-white">{finding.rule}</p>
                            <p className="mt-1 max-w-xl text-xs leading-5 text-zinc-400">{finding.raw}</p>
                          </td>
                          <td className="py-3 pr-3 font-mono text-zinc-300">{finding.repeatedCount}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {filteredFindings.length === 0 && (
                    <p className="py-8 text-center text-sm text-zinc-500">No suspicious events match the current filters.</p>
                  )}
                </div>
              </div>

              <div className="space-y-4">
                <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
                  <h2 className="text-lg font-semibold text-white">Timeline</h2>
                  <div className="mt-4 space-y-3">
                    {result.summary.timeline.length === 0 && <p className="text-sm text-zinc-500">No timestamps were detected.</p>}
                    {result.summary.timeline.slice(0, 12).map((item) => (
                      <div key={item.timestamp}>
                        <div className="mb-1 flex justify-between text-xs text-zinc-400">
                          <span className="font-mono">{item.timestamp}</span>
                          <span>{item.count}</span>
                        </div>
                        <div className="h-2 rounded bg-zinc-800">
                          <div
                            className={`h-2 rounded ${barClass(item.severity)}`}
                            style={{ width: `${Math.min(100, item.count * 18)}%` }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
                  <h2 className="text-lg font-semibold text-white">Recommendations</h2>
                  <div className="mt-4 space-y-3">
                    {filteredFindings.slice(0, 4).map((finding) => (
                      <div key={`${finding.id}-fix`} className="border-l-2 border-cyan-500 pl-3">
                        <p className="text-sm font-semibold text-white">{finding.rule}</p>
                        <p className="mt-1 text-sm leading-5 text-zinc-400">{finding.recommendedFix}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </section>
          </>
        )}
      </div>
    </main>
  );
}

function Metric({ label, value, tone = "default" }: { label: string; value: string; tone?: "default" | "critical" | "warning" }) {
  const color = tone === "critical" ? "text-red-300" : tone === "warning" ? "text-amber-300" : "text-white";

  return (
    <div className="rounded-md border border-zinc-800 bg-black p-3">
      <p className="text-xs uppercase tracking-[0.16em] text-zinc-500">{label}</p>
      <p className={`mt-2 font-mono text-2xl font-semibold ${color}`}>{value}</p>
    </div>
  );
}

function SeverityBars({ counts }: { counts?: Record<Severity, number> }) {
  const safeCounts = counts || { Low: 0, Medium: 0, High: 0, Critical: 0 };
  const max = Math.max(1, ...Object.values(safeCounts));

  return (
    <div className="mt-4 space-y-3">
      {(Object.keys(safeCounts) as Severity[]).map((level) => (
        <div key={level}>
          <div className="mb-1 flex justify-between text-xs text-zinc-400">
            <span>{level}</span>
            <span>{safeCounts[level]}</span>
          </div>
          <div className="h-2 rounded bg-zinc-800">
            <div className={`h-2 rounded ${barClass(level)}`} style={{ width: `${(safeCounts[level] / max) * 100}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}

function severityClass(severity: Severity) {
  if (severity === "Critical") return "bg-red-500/20 text-red-200";
  if (severity === "High") return "bg-orange-500/20 text-orange-200";
  if (severity === "Medium") return "bg-amber-500/20 text-amber-200";
  return "bg-emerald-500/20 text-emerald-200";
}

function barClass(severity: Severity) {
  if (severity === "Critical") return "bg-red-500";
  if (severity === "High") return "bg-orange-500";
  if (severity === "Medium") return "bg-amber-500";
  return "bg-emerald-500";
}

function buildExport(format: "json" | "csv" | "txt", result: AnalysisResult, findings: Finding[]) {
  if (format === "json") {
    return JSON.stringify({ ...result, findings }, null, 2);
  }

  if (format === "csv") {
    const rows = [
      ["id", "line", "severity", "type", "timestamp", "source_ip", "rule", "repeat", "keywords", "recommendation"],
      ...findings.map((finding) => [
        finding.id,
        String(finding.lineNumber),
        finding.severity,
        finding.logType,
        finding.timestamp || "",
        finding.sourceIp || "",
        finding.rule,
        String(finding.repeatedCount),
        finding.detectedKeywords.join("|"),
        finding.recommendedFix,
      ]),
    ];
    return rows.map((row) => row.map(csvCell).join(",")).join("\n");
  }

  return [
    "SOC Log Analysis Report",
    `Generated: ${result.generatedAt}`,
    `Total events: ${result.summary.totalEvents}`,
    `Suspicious events: ${result.summary.suspiciousEvents}`,
    `Critical alerts: ${result.summary.criticalAlerts}`,
    `Top source IP: ${result.summary.topSourceIp || "None"}`,
    "",
    ...findings.flatMap((finding) => [
      `${finding.id} | ${finding.severity} | ${finding.logType} | ${finding.rule}`,
      `Timestamp: ${finding.timestamp || "Unknown"} | Source: ${finding.sourceIp || "-"}`,
      `Keywords: ${finding.detectedKeywords.join(", ") || "n/a"}`,
      `Root cause: ${finding.possibleRootCause}`,
      `Impact: ${finding.impact}`,
      `Fix: ${finding.recommendedFix}`,
      `Raw: ${finding.raw}`,
      "",
    ]),
  ].join("\n");
}

function csvCell(value: string) {
  return `"${value.replace(/"/g, '""')}"`;
}

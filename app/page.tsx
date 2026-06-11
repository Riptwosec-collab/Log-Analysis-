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
  destinationIp: string | null;
  destinationPort: string | null;
  username: string | null;
  asset: string | null;
  tactic: string;
  technique: string;
  confidence: number;
  evidence: string;
  raw: string;
  repeatedCount: number;
};

type Correlation = {
  title: string;
  severity: Severity;
  sourceIp: string | null;
  eventCount: number;
  description: string;
  recommendedAction: string;
};

type AnalysisResult = {
  generatedAt: string;
  summary: {
    totalEvents: number;
    suspiciousEvents: number;
    criticalAlerts: number;
    failedLogins: number;
    topSourceIp: string | null;
    riskScore: number;
    riskLevel: Severity;
    incidentNarrative: string;
    logTypes: Record<string, number>;
    severityCounts: Record<Severity, number>;
    timeline: Array<{ timestamp: string; count: number; severity: Severity }>;
    topRules: Array<{ rule: string; count: number; severity: Severity }>;
    affectedUsers: string[];
    targetPorts: string[];
    mitreTechniques: string[];
    recommendedActions: string[];
    correlations: Correlation[];
  };
  findings: Finding[];
};

const demoLog = `Jun 10 21:14:02 web-01 sshd[1204]: Failed password for invalid user admin from 185.220.101.21 port 55110 ssh2
Jun 10 21:14:08 web-01 sshd[1208]: Failed password for root from 185.220.101.21 port 55116 ssh2
Jun 10 21:14:14 web-01 sshd[1213]: Failed password for invalid user oracle from 185.220.101.21 port 55122 ssh2
Jun 10 21:14:20 web-01 sshd[1219]: Failed password for invalid user postgres from 185.220.101.21 port 55130 ssh2
2026-06-10T21:16:40Z 198.51.100.44 "GET /login.php?id=1 UNION SELECT password FROM users HTTP/1.1" 403
2026-06-10T21:17:11Z 203.0.113.9 "GET /download?file=../../../../etc/passwd HTTP/1.1" 400
2026-06-10T21:18:27Z firewall DROP SRC=45.77.10.2 DST=10.0.0.12 PROTO=TCP DPT=22 SYN
2026-06-10T21:18:31Z firewall DROP SRC=45.77.10.2 DST=10.0.0.12 PROTO=TCP DPT=80 SYN
2026-06-10T21:18:35Z firewall DROP SRC=45.77.10.2 DST=10.0.0.12 PROTO=TCP DPT=443 SYN
06/10/2026 09:19:44 PM Event ID 4625 Audit Failure Account Name: svc-backup Source Network Address: 192.0.2.71
Jun 10 21:20:01 SW-CORE-01 %SW_MATM-4-MACFLAP_NOTIF: Host 6c3b.e51f.fd9f in vlan 2 is flapping between port Gi1/0/12 and port Gi1/0/20
Jun 10 21:20:12 SW-CORE-01 %SW_DAI-4-DHCP_SNOOPING_DENY: 1 Invalid ARPs on Gi1/0/15, vlan 2.([6c3b.e51f.fd9f/10.10.2.55/0000.0000.0000/10.10.2.1/21:20:12])
Jun 10 21:20:30 SW-CORE-01 %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet1/0/24, changed state to down`;

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
      if (!response.ok) throw new Error(data.error || "วิเคราะห์ Log ไม่สำเร็จ");
      setResult(data);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "วิเคราะห์ Log ไม่สำเร็จ");
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
          finding.destinationPort || "",
          finding.username || "",
          finding.technique,
          finding.tactic,
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

  const exportReport = (format: "json" | "csv" | "txt" | "pdf") => {
    if (!result) return;

    if (format === "pdf") {
      openPrintableReport(result, filteredFindings);
      return;
    }

    const filename = `รายงาน-soc-${new Date().toISOString().slice(0, 10)}.${format}`;
    const content = buildExport(format, result, filteredFindings);
    const type = format === "json" ? "application/json" : "text/plain;charset=utf-8";
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
            <h1 className="mt-2 text-3xl font-semibold text-white sm:text-4xl">แดชบอร์ดวิเคราะห์ Log สำหรับ SOC</h1>
            <p className="mt-2 max-w-3xl text-sm text-zinc-400">
              วิเคราะห์และเชื่อมโยงเหตุการณ์จาก Apache/Nginx, SSH, Firewall, Windows Event, Linux Syslog, Cisco/Network Device และ Application Log พร้อมสรุป RCA / Impact / Fix เป็นภาษาไทย
            </p>
          </div>
          <div className="grid grid-cols-3 gap-2 text-right text-xs text-zinc-400 sm:min-w-80">
            <Metric label="Rules" value="18+" />
            <Metric label="Types" value="9" />
            <Metric label="Intel" value="MITRE" />
          </div>
        </header>

        <section className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_340px]">
          <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
            <div className="mb-3 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <h2 className="text-lg font-semibold text-white">ใส่ Log เพื่อวิเคราะห์</h2>
              <label className="inline-flex cursor-pointer items-center justify-center rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm font-medium text-zinc-200 hover:border-cyan-500">
                อัปโหลด .log/.txt/.csv
                <input className="sr-only" type="file" accept=".log,.txt,.csv" onChange={handleFileUpload} />
              </label>
            </div>
            <textarea
              className="h-72 w-full resize-y rounded-md border border-zinc-800 bg-black p-3 font-mono text-sm leading-6 text-zinc-200 outline-none ring-cyan-500 focus:ring-2"
              value={logInput}
              onChange={(event) => setLogInput(event.target.value)}
              spellCheck={false}
              placeholder="วาง Log ที่นี่ เช่น SSH, Firewall, Windows Event, Cisco, Web Access Log"
            />
            <div className="mt-3 flex flex-col gap-2 sm:flex-row">
              <button
                className="rounded-md bg-cyan-500 px-4 py-2 text-sm font-semibold text-zinc-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-60"
                onClick={() => analyzeText(logInput)}
                disabled={isAnalyzing}
              >
                {isAnalyzing ? "กำลังวิเคราะห์..." : "วิเคราะห์ Log"}
              </button>
              <button
                className="rounded-md border border-zinc-700 px-4 py-2 text-sm font-semibold text-zinc-200 hover:border-zinc-500"
                onClick={() => {
                  setLogInput(demoLog);
                  setResult(null);
                  setError("");
                }}
              >
                โหลด Log ตัวอย่าง
              </button>
            </div>
            {error && <p className="mt-3 rounded-md border border-red-900 bg-red-950/60 p-3 text-sm text-red-200">{error}</p>}
          </div>

          <aside className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
            <h2 className="text-lg font-semibold text-white">สรุปภาพรวม</h2>
            <div className="mt-4 grid grid-cols-2 gap-3">
              <Metric label="คะแนนเสี่ยง" value={String(result?.summary.riskScore || 0)} tone={result?.summary.riskLevel === "Critical" ? "critical" : "warning"} />
              <Metric label="Event ทั้งหมด" value={String(result?.summary.totalEvents || 0)} />
              <Metric label="น่าสงสัย" value={String(result?.summary.suspiciousEvents || 0)} />
              <Metric label="Critical" value={String(result?.summary.criticalAlerts || 0)} tone="critical" />
              <Metric label="Login Fail" value={String(result?.summary.failedLogins || 0)} tone="warning" />
              <Metric label="Correlation" value={String(result?.summary.correlations.length || 0)} />
            </div>
            <div className="mt-4 rounded-md border border-zinc-800 bg-black p-3">
              <p className="text-xs uppercase tracking-[0.18em] text-zinc-500">Source IP ที่พบมากที่สุด</p>
              <p className="mt-2 font-mono text-lg text-cyan-300">{result?.summary.topSourceIp || "ไม่มี"}</p>
            </div>
            <SeverityBars counts={result?.summary.severityCounts} />
          </aside>
        </section>

        {result && (
          <>
            <section className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_420px]">
              <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                  <div>
                    <h2 className="text-lg font-semibold text-white">สรุป Incident Intelligence</h2>
                    <p className="mt-2 text-sm leading-6 text-zinc-400">{result.summary.incidentNarrative}</p>
                  </div>
                  <span className={`w-fit rounded px-3 py-1 text-xs font-semibold ${severityClass(result.summary.riskLevel)}`}>
                    {severityLabel(result.summary.riskLevel)}
                  </span>
                </div>

                <div className="mt-4 grid gap-3 md:grid-cols-3">
                  <IntelList title="Rule ที่พบมากสุด" items={result.summary.topRules.map((item) => `${item.rule} (${item.count})`)} />
                  <IntelList title="MITRE Technique" items={result.summary.mitreTechniques} />
                  <IntelList title="User ที่ได้รับผลกระทบ" items={result.summary.affectedUsers.length ? result.summary.affectedUsers : ["ไม่มี"]} />
                </div>

                <div className="mt-4 rounded-md border border-zinc-800 bg-black p-3">
                  <p className="text-xs uppercase tracking-[0.18em] text-zinc-500">Action ที่ควรทำก่อน</p>
                  <div className="mt-3 grid gap-2 md:grid-cols-2">
                    {result.summary.recommendedActions.slice(0, 4).map((action) => (
                      <p key={action} className="border-l-2 border-cyan-500 pl-3 text-sm leading-5 text-zinc-300">
                        {action}
                      </p>
                    ))}
                  </div>
                </div>
              </div>

              <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
                <h2 className="text-lg font-semibold text-white">Correlation / เหตุการณ์ที่เชื่อมโยงกัน</h2>
                <div className="mt-4 space-y-3">
                  {result.summary.correlations.length === 0 && (
                    <p className="text-sm text-zinc-500">ไม่พบความเชื่อมโยงแบบหลายเหตุการณ์</p>
                  )}
                  {result.summary.correlations.map((item) => (
                    <div key={`${item.title}-${item.sourceIp || "global"}`} className="rounded-md border border-zinc-800 bg-black p-3">
                      <div className="flex items-center justify-between gap-3">
                        <p className="text-sm font-semibold text-white">{item.title}</p>
                        <span className={`rounded px-2 py-1 text-xs font-semibold ${severityClass(item.severity)}`}>
                          {severityLabel(item.severity)}
                        </span>
                      </div>
                      <p className="mt-2 text-sm leading-5 text-zinc-400">{item.description}</p>
                      <p className="mt-2 text-xs text-cyan-300">{item.recommendedAction}</p>
                    </div>
                  ))}
                </div>
              </div>
            </section>

            <section className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_340px]">
              <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
                <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                  <h2 className="text-lg font-semibold text-white">ตาราง Event ที่น่าสงสัย</h2>
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
                    <button className="rounded-md border border-zinc-700 px-3 py-2 text-sm hover:border-cyan-500" onClick={() => exportReport("pdf")}>
                      PDF
                    </button>
                  </div>
                </div>

                <div className="mt-4 grid gap-2 md:grid-cols-4">
                  <input
                    className="rounded-md border border-zinc-800 bg-black px-3 py-2 text-sm outline-none focus:border-cyan-500"
                    placeholder="ค้นหา keyword, IP, rule"
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                  />
                  <select
                    className="rounded-md border border-zinc-800 bg-black px-3 py-2 text-sm outline-none focus:border-cyan-500"
                    value={severity}
                    onChange={(event) => setSeverity(event.target.value as Severity | "All")}
                  >
                    {severityOptions.map((option) => (
                      <option key={option} value={option}>
                        {severityOptionLabel(option)}
                      </option>
                    ))}
                  </select>
                  <select
                    className="rounded-md border border-zinc-800 bg-black px-3 py-2 text-sm outline-none focus:border-cyan-500"
                    value={logType}
                    onChange={(event) => setLogType(event.target.value)}
                  >
                    {logTypes.map((option) => (
                      <option key={option} value={option}>
                        {option === "All" ? "ทุกประเภท Log" : option}
                      </option>
                    ))}
                  </select>
                  <input
                    className="rounded-md border border-zinc-800 bg-black px-3 py-2 text-sm outline-none focus:border-cyan-500"
                    placeholder="ค้นหาจากเวลา"
                    value={timestampFilter}
                    onChange={(event) => setTimestampFilter(event.target.value)}
                  />
                </div>

                <div className="mt-4 overflow-x-auto">
                  <table className="w-full min-w-[1280px] border-collapse text-left text-sm">
                    <thead className="border-b border-zinc-800 text-xs uppercase tracking-[0.14em] text-zinc-500">
                      <tr>
                        <th className="py-3 pr-3">ID</th>
                        <th className="py-3 pr-3">ความรุนแรง</th>
                        <th className="py-3 pr-3">ความมั่นใจ</th>
                        <th className="py-3 pr-3">ประเภท</th>
                        <th className="py-3 pr-3">เวลา</th>
                        <th className="py-3 pr-3">Source</th>
                        <th className="py-3 pr-3">User/Port</th>
                        <th className="py-3 pr-3">MITRE</th>
                        <th className="py-3 pr-3">Rule / RCA / Fix</th>
                        <th className="py-3 pr-3">ซ้ำ</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredFindings.map((finding) => (
                        <tr key={finding.id} className="border-b border-zinc-900 align-top hover:bg-zinc-800/50">
                          <td className="py-3 pr-3 font-mono text-xs text-zinc-400">{finding.id}</td>
                          <td className="py-3 pr-3">
                            <span className={`rounded px-2 py-1 text-xs font-semibold ${severityClass(finding.severity)}`}>
                              {severityLabel(finding.severity)}
                            </span>
                          </td>
                          <td className="py-3 pr-3 font-mono text-xs text-zinc-300">{finding.confidence}%</td>
                          <td className="py-3 pr-3 text-zinc-300">{finding.logType}</td>
                          <td className="py-3 pr-3 font-mono text-xs text-zinc-400">{finding.timestamp || "ไม่พบเวลา"}</td>
                          <td className="py-3 pr-3 font-mono text-xs text-cyan-300">{finding.sourceIp || "-"}</td>
                          <td className="py-3 pr-3 text-xs text-zinc-300">
                            <p>{finding.username || "-"}</p>
                            <p className="mt-1 font-mono text-zinc-500">{finding.destinationPort ? `:${finding.destinationPort}` : ""}</p>
                          </td>
                          <td className="py-3 pr-3">
                            <p className="text-xs font-medium text-zinc-200">{finding.technique}</p>
                            <p className="mt-1 text-xs text-zinc-500">{finding.tactic}</p>
                          </td>
                          <td className="py-3 pr-3">
                            <p className="font-medium text-white">{finding.rule}</p>
                            <p className="mt-1 text-xs text-cyan-300">หลักฐาน: {finding.evidence}</p>
                            <p className="mt-1 max-w-xl text-xs leading-5 text-zinc-400">สาเหตุ: {finding.possibleRootCause}</p>
                            <p className="mt-1 max-w-xl text-xs leading-5 text-zinc-400">ผลกระทบ: {finding.impact}</p>
                            <p className="mt-1 max-w-xl text-xs leading-5 text-emerald-300">วิธีแก้: {finding.recommendedFix}</p>
                            <p className="mt-2 max-w-xl font-mono text-xs leading-5 text-zinc-500">Raw: {finding.raw}</p>
                          </td>
                          <td className="py-3 pr-3 font-mono text-zinc-300">{finding.repeatedCount}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {filteredFindings.length === 0 && (
                    <p className="py-8 text-center text-sm text-zinc-500">ไม่มี Event ที่ตรงกับตัวกรองปัจจุบัน</p>
                  )}
                </div>
              </div>

              <div className="space-y-4">
                <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
                  <h2 className="text-lg font-semibold text-white">Timeline</h2>
                  <div className="mt-4 space-y-3">
                    {result.summary.timeline.length === 0 && <p className="text-sm text-zinc-500">ไม่พบ Timestamp ใน Log</p>}
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
                  <h2 className="text-lg font-semibold text-white">คำแนะนำ</h2>
                  <div className="mt-4 space-y-3">
                    {filteredFindings.slice(0, 4).map((finding) => (
                      <div key={`${finding.id}-fix`} className="border-l-2 border-cyan-500 pl-3">
                        <p className="text-sm font-semibold text-white">{finding.rule}</p>
                        <p className="mt-1 text-sm leading-5 text-zinc-400">{finding.recommendedFix}</p>
                      </div>
                    ))}
                    {filteredFindings.length === 0 && <p className="text-sm text-zinc-500">ยังไม่มีคำแนะนำจากผลการวิเคราะห์</p>}
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

function IntelList({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="rounded-md border border-zinc-800 bg-black p-3">
      <p className="text-xs uppercase tracking-[0.18em] text-zinc-500">{title}</p>
      <div className="mt-3 flex flex-wrap gap-2">
        {items.slice(0, 6).map((item) => (
          <span key={item} className="rounded border border-zinc-700 px-2 py-1 text-xs text-zinc-300">
            {item}
          </span>
        ))}
      </div>
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
            <span>{severityLabel(level)}</span>
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

function severityLabel(severity: Severity) {
  if (severity === "Critical") return "วิกฤต";
  if (severity === "High") return "สูง";
  if (severity === "Medium") return "ปานกลาง";
  return "ต่ำ";
}

function severityOptionLabel(option: Severity | "All") {
  if (option === "All") return "ทุกระดับความรุนแรง";
  return severityLabel(option);
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
      [
        "id",
        "line",
        "severity",
        "severity_th",
        "confidence",
        "type",
        "timestamp",
        "source_ip",
        "destination_ip",
        "destination_port",
        "username",
        "rule",
        "tactic",
        "technique",
        "repeat",
        "evidence",
        "root_cause",
        "impact",
        "recommendation",
      ],
      ...findings.map((finding) => [
        finding.id,
        String(finding.lineNumber),
        finding.severity,
        severityLabel(finding.severity),
        String(finding.confidence),
        finding.logType,
        finding.timestamp || "",
        finding.sourceIp || "",
        finding.destinationIp || "",
        finding.destinationPort || "",
        finding.username || "",
        finding.rule,
        finding.tactic,
        finding.technique,
        String(finding.repeatedCount),
        finding.evidence,
        finding.possibleRootCause,
        finding.impact,
        finding.recommendedFix,
      ]),
    ];
    return rows.map((row) => row.map(csvCell).join(",")).join("\n");
  }

  return [
    "รายงานวิเคราะห์ Log สำหรับ SOC",
    `สร้างเมื่อ: ${result.generatedAt}`,
    `จำนวน Event ทั้งหมด: ${result.summary.totalEvents}`,
    `จำนวน Event น่าสงสัย: ${result.summary.suspiciousEvents}`,
    `Critical Alert: ${result.summary.criticalAlerts}`,
    `คะแนนความเสี่ยง: ${result.summary.riskScore}/100 (${severityLabel(result.summary.riskLevel)})`,
    `Top Source IP: ${result.summary.topSourceIp || "ไม่มี"}`,
    `สรุป: ${result.summary.incidentNarrative}`,
    `MITRE Techniques: ${result.summary.mitreTechniques.join(", ") || "ไม่มี"}`,
    "",
    "Correlation / เหตุการณ์เชื่อมโยง",
    ...(result.summary.correlations.length
      ? result.summary.correlations.map((item) => `${severityLabel(item.severity)} | ${item.title} | ${item.description} | ${item.recommendedAction}`)
      : ["ไม่มี"]),
    "",
    "Findings / รายการที่พบ",
    ...findings.flatMap((finding) => [
      `${finding.id} | ${severityLabel(finding.severity)} | ${finding.confidence}% | ${finding.logType} | ${finding.rule}`,
      `เวลา: ${finding.timestamp || "ไม่พบ"} | Source: ${finding.sourceIp || "-"} | User: ${finding.username || "-"} | Port: ${finding.destinationPort || "-"}`,
      `MITRE: ${finding.technique} | Tactic: ${finding.tactic}`,
      `หลักฐาน: ${finding.evidence}`,
      `Keyword: ${finding.detectedKeywords.join(", ") || "ไม่มี"}`,
      `สาเหตุ: ${finding.possibleRootCause}`,
      `ผลกระทบ: ${finding.impact}`,
      `วิธีแก้: ${finding.recommendedFix}`,
      `Raw: ${finding.raw}`,
      "",
    ]),
  ].join("\n");
}

function openPrintableReport(result: AnalysisResult, findings: Finding[]) {
  const printable = window.open("", "_blank", "width=1100,height=800");
  if (!printable) return;

  const rows = findings
    .map(
      (finding) => `
        <tr>
          <td>${escapeHtml(finding.id)}</td>
          <td>${escapeHtml(severityLabel(finding.severity))}</td>
          <td>${escapeHtml(finding.logType)}</td>
          <td>${escapeHtml(finding.timestamp || "ไม่พบ")}</td>
          <td>${escapeHtml(finding.sourceIp || "-")}</td>
          <td>${escapeHtml(finding.rule)}</td>
          <td>${escapeHtml(finding.possibleRootCause)}</td>
          <td>${escapeHtml(finding.impact)}</td>
          <td>${escapeHtml(finding.recommendedFix)}</td>
        </tr>`
    )
    .join("");

  printable.document.write(`
    <html>
      <head>
        <title>รายงานวิเคราะห์ SOC</title>
        <meta charset="utf-8" />
        <style>
          body { font-family: Arial, sans-serif; padding: 24px; color: #111827; }
          h1 { margin-bottom: 4px; }
          .muted { color: #6b7280; }
          .summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 18px 0; }
          .card { border: 1px solid #d1d5db; border-radius: 8px; padding: 12px; }
          table { width: 100%; border-collapse: collapse; font-size: 12px; }
          th, td { border: 1px solid #d1d5db; padding: 8px; vertical-align: top; }
          th { background: #f3f4f6; }
        </style>
      </head>
      <body>
        <h1>รายงานวิเคราะห์ Log สำหรับ SOC</h1>
        <p class="muted">สร้างเมื่อ: ${escapeHtml(result.generatedAt)}</p>
        <p>${escapeHtml(result.summary.incidentNarrative)}</p>
        <div class="summary">
          <div class="card"><b>Risk Score</b><br />${result.summary.riskScore}/100</div>
          <div class="card"><b>ระดับความเสี่ยง</b><br />${escapeHtml(severityLabel(result.summary.riskLevel))}</div>
          <div class="card"><b>Event น่าสงสัย</b><br />${result.summary.suspiciousEvents}</div>
          <div class="card"><b>Top Source IP</b><br />${escapeHtml(result.summary.topSourceIp || "ไม่มี")}</div>
        </div>
        <h2>ตาราง Event ที่น่าสงสัย</h2>
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Severity</th>
              <th>Type</th>
              <th>Timestamp</th>
              <th>Source IP</th>
              <th>Rule</th>
              <th>Root Cause</th>
              <th>Impact</th>
              <th>Fix</th>
            </tr>
          </thead>
          <tbody>${rows || '<tr><td colspan="9">ไม่พบ Event ที่น่าสงสัย</td></tr>'}</tbody>
        </table>
        <script>window.print();</script>
      </body>
    </html>
  `);
  printable.document.close();
}

function csvCell(value: string) {
  return `"${value.replace(/"/g, '""')}"`;
}

function escapeHtml(value: string) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

"use client";

import { useMemo, useState } from "react";

type Severity = "Low" | "Medium" | "High" | "Critical";
type Language = "th" | "en";

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
  interfaceName?: string | null;
  vlan?: string | null;
  macAddress?: string | null;
  domain?: string | null;
  fileHash?: string | null;
  iocType?: string | null;
  iocRisk?: Severity | null;
  iocDescription?: string | null;
  geoCountry?: string | null;
  asn?: string | null;
  abuseScore?: number | null;
};

type Correlation = {
  title: string;
  severity: Severity;
  sourceIp: string | null;
  eventCount: number;
  description: string;
  recommendedAction: string;
  confidence?: number;
  mitreTechniques?: string[];
  incidentType?: string;
};

type AnalystReport = {
  socAnalyst: string;
  rca: string;
  managerSummary: string;
  fixCommand: string;
  ticket: string;
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
    iocHits: number;
    publicIpCount: number;
    privateIpCount: number;
    reservedIpCount: number;
    vendorCounts: Record<string, number>;
    analystReport: AnalystReport;
  };
  findings: Finding[];
};

type AnalystMode = keyof AnalystReport;

const demoLog = `Jun 10 21:14:02 web-01 sshd[1204]: Failed password for invalid user admin from 185.220.101.21 port 55110 ssh2
Jun 10 21:14:18 web-01 sshd[1208]: Failed password for root from 185.220.101.21 port 55116 ssh2
Jun 10 21:15:04 web-01 sshd[1213]: Failed password for invalid user oracle from 185.220.101.21 port 55122 ssh2
Jun 10 21:15:35 web-01 sshd[1219]: Failed password for invalid user postgres from 185.220.101.21 port 55130 ssh2
Jun 10 21:16:02 web-01 sshd[1220]: Failed password for invalid user test from 185.220.101.21 port 55134 ssh2
2026-06-10T21:16:40Z 185.220.101.21 "GET /login.php?id=1 UNION SELECT password FROM users HTTP/1.1" 403
2026-06-10T21:17:11Z 185.220.101.21 "GET /download?file=../../../../etc/passwd HTTP/1.1" 400
2026-06-10T21:18:27Z firewall DROP SRC=185.220.101.21 DST=10.0.0.12 PROTO=TCP DPT=22 SYN
2026-06-10T21:18:31Z firewall DROP SRC=185.220.101.21 DST=10.0.0.12 PROTO=TCP DPT=80 SYN
2026-06-10T21:18:35Z firewall DROP SRC=185.220.101.21 DST=10.0.0.12 PROTO=TCP DPT=443 SYN
2026-06-10T21:18:39Z firewall DROP SRC=185.220.101.21 DST=10.0.0.12 PROTO=TCP DPT=3389 SYN
2026-06-10T21:18:42Z firewall DROP SRC=185.220.101.21 DST=10.0.0.12 PROTO=TCP DPT=445 SYN
06/10/2026 09:19:44 PM Event ID 4625 Audit Failure Account Name: svc-backup Source Network Address: 192.0.2.71
06/10/2026 09:20:44 PM Event ID 4672 Special privileges assigned to new logon Account Name: admin Source Network Address: 192.0.2.71
06/10/2026 09:21:44 PM Event ID 4720 A user account was created Account Name: temp-admin Source Network Address: 192.0.2.71
06/10/2026 09:22:44 PM Event ID 4740 A user account was locked out Account Name: finance01 Source Network Address: 192.0.2.71
06/10/2026 09:23:00 PM Event ID 4688 New Process Name: powershell.exe CommandLine: powershell -EncodedCommand SQBFAFgA
2026-06-10T21:24:01Z endpoint alert file_hash=44d88612fea8a8f36de82e1278abb02f domain=evil.example.com
Jun 10 21:25:01 SW-CORE-01 %SW_MATM-4-MACFLAP_NOTIF: Host 6c3b.e51f.fd9f in vlan 2 is flapping between port Gi1/0/12 and port Gi1/0/20
Jun 10 21:25:12 SW-CORE-01 %SW_DAI-4-DHCP_SNOOPING_DENY: 1 Invalid ARPs on Gi1/0/15, vlan 2
Jun 10 21:25:30 SW-CORE-01 %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet1/0/24, changed state to down`;

const vendorSamples: Record<string, string> = {
  Auto: demoLog,
  Cisco: `Jun 10 21:25:01 SW-CORE-01 %SW_MATM-4-MACFLAP_NOTIF: Host 6c3b.e51f.fd9f in vlan 2 is flapping between port Gi1/0/12 and port Gi1/0/20
Jun 10 21:25:12 SW-CORE-01 %SW_DAI-4-DHCP_SNOOPING_DENY: 1 Invalid ARPs on Gi1/0/15, vlan 2
Jun 10 21:25:30 SW-CORE-01 %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet1/0/24, changed state to down
Jun 10 21:25:40 SW-CORE-01 %SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on PortFast port Gi1/0/10. Disabling port`,
  FortiGate: `date=2026-06-10 time=21:18:27 devname=FGT-EDGE type=traffic subtype=forward action=deny srcip=45.77.10.2 dstip=10.0.0.12 dstport=22 proto=6 policyid=10
date=2026-06-10 time=21:18:31 devname=FGT-EDGE type=traffic subtype=forward action=deny srcip=45.77.10.2 dstip=10.0.0.12 dstport=80 proto=6 policyid=10
date=2026-06-10 time=21:18:35 devname=FGT-EDGE type=traffic subtype=forward action=deny srcip=45.77.10.2 dstip=10.0.0.12 dstport=443 proto=6 policyid=10
date=2026-06-10 time=21:18:39 devname=FGT-EDGE type=traffic subtype=forward action=deny srcip=45.77.10.2 dstip=10.0.0.12 dstport=3389 proto=6 policyid=10`,
  "Palo Alto": `2026/06/10 21:18:27 TRAFFIC deny src=45.77.10.2 dst=10.0.0.12 dport=22 app=ssh action=deny
2026/06/10 21:18:31 TRAFFIC deny src=45.77.10.2 dst=10.0.0.12 dport=80 app=web-browsing action=deny
2026/06/10 21:18:35 THREAT vulnerability src=198.51.100.44 dst=10.0.0.20 url=/login.php?id=1 UNION SELECT password FROM users action=reset-both`,
  "Windows Event": `06/10/2026 09:19:44 PM Event ID 4625 Audit Failure Account Name: svc-backup Source Network Address: 192.0.2.71
06/10/2026 09:19:48 PM Event ID 4625 Audit Failure Account Name: admin Source Network Address: 192.0.2.71
06/10/2026 09:19:52 PM Event ID 4625 Audit Failure Account Name: finance01 Source Network Address: 192.0.2.71
06/10/2026 09:20:44 PM Event ID 4672 Special privileges assigned Account Name: admin Source Network Address: 192.0.2.71
06/10/2026 09:21:44 PM Event ID 4720 A user account was created Account Name: temp-admin Source Network Address: 192.0.2.71
06/10/2026 09:22:44 PM Event ID 4740 A user account was locked out Account Name: finance01 Source Network Address: 192.0.2.71`,
  "Linux Auth": `Jun 10 21:14:02 web-01 sshd[1204]: Failed password for invalid user admin from 185.220.101.21 port 55110 ssh2
Jun 10 21:14:18 web-01 sshd[1208]: Failed password for root from 185.220.101.21 port 55116 ssh2
Jun 10 21:15:04 web-01 sshd[1213]: Failed password for invalid user oracle from 185.220.101.21 port 55122 ssh2
Jun 10 21:15:35 web-01 sshd[1219]: Failed password for invalid user postgres from 185.220.101.21 port 55130 ssh2
Jun 10 21:16:02 web-01 sshd[1220]: Failed password for invalid user test from 185.220.101.21 port 55134 ssh2`,
  Apache: `2026-06-10T21:16:40Z 198.51.100.44 "GET /login.php?id=1 UNION SELECT password FROM users HTTP/1.1" 403
2026-06-10T21:17:11Z 203.0.113.9 "GET /download?file=../../../../etc/passwd HTTP/1.1" 400
2026-06-10T21:17:22Z 198.51.100.44 "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200`,
  Nginx: `198.51.100.44 - - [10/Jun/2026:21:16:40 +0700] "GET /login.php?id=1 UNION SELECT password FROM users HTTP/1.1" 403
203.0.113.9 - - [10/Jun/2026:21:17:11 +0700] "GET /download?file=../../../../etc/passwd HTTP/1.1" 400`,
  Meraki: `2026-06-10T21:18:27Z meraki event type=8021x_auth_failed client_mac=6c:3b:e5:1f:fd:9f src=192.168.10.55 ssid=Corp
2026-06-10T21:18:31Z meraki firewall deny src=45.77.10.2 dst=10.0.0.12 dst_port=443`,
  Sophos: `2026-06-10 21:18:27 Sophos Firewall log_subtype=Firewall action=Denied src_ip=45.77.10.2 dst_ip=10.0.0.12 dst_port=22
2026-06-10 21:18:31 Sophos Firewall log_subtype=Firewall action=Denied src_ip=45.77.10.2 dst_ip=10.0.0.12 dst_port=445`,
  Cloudflare: `2026-06-10T21:16:40Z Cloudflare WAFAction=block ClientIP=198.51.100.44 Host=app.example.com URI=/login.php?id=1 UNION SELECT password FROM users EdgeResponseStatus=403 cf-ray=abc
2026-06-10T21:17:11Z Cloudflare WAFAction=block ClientIP=203.0.113.9 Host=app.example.com URI=/download?file=../../../../etc/passwd EdgeResponseStatus=403`,
  "Microsoft 365": `2026-06-10T21:19:44Z Microsoft 365 UserLoggedIn user=admin@contoso.com src=185.220.101.21 riskLevel=high ConditionalAccess=failure
2026-06-10T21:20:10Z Entra ID risky user user=admin@contoso.com riskLevel=high impossible travel
2026-06-10T21:21:00Z AzureAD SignIn user=finance@contoso.com mfa denied legacy authentication src=185.220.101.21`,
};

const vendorOptions = Object.keys(vendorSamples);
const severityOptions: Array<Severity | "All"> = ["All", "Critical", "High", "Medium", "Low"];

const analystModeOrder: AnalystMode[] = ["socAnalyst", "rca", "managerSummary", "fixCommand", "ticket"];

const UI: Record<Language, Record<string, string>> = {
  th: {
    language: "ภาษา",
    thai: "ไทย",
    english: "English",
    title: "แดชบอร์ดวิเคราะห์ Log สำหรับ SOC",
    subtitle:
      "วิเคราะห์และเชื่อมโยงเหตุการณ์จาก Apache/Nginx, SSH, Firewall, Windows Event, Linux Syslog, Cisco/Network Device และ Application Log พร้อมสรุป RCA / Impact / Fix ได้ทั้งภาษาไทยและอังกฤษ",
    inputTitle: "ใส่ Log เพื่อวิเคราะห์",
    upload: "อัปโหลด .log/.txt/.csv",
    textareaPlaceholder: "วาง Log ที่นี่ เช่น SSH, Firewall, Windows Event, Cisco, Web Access Log",
    analyze: "วิเคราะห์ Log",
    analyzing: "กำลังวิเคราะห์...",
    loadDemo: "โหลด Log ตัวอย่าง",
    overview: "สรุปภาพรวม",
    riskScore: "คะแนนเสี่ยง",
    totalEvents: "Event ทั้งหมด",
    suspicious: "น่าสงสัย",
    critical: "Critical",
    failedLogin: "Login Fail",
    correlation: "Correlation",
    topSourceIp: "Source IP ที่พบมากที่สุด",
    none: "ไม่มี",
    incidentIntel: "สรุป Incident Intelligence",
    topRules: "Rule ที่พบมากสุด",
    mitreTechnique: "MITRE Technique",
    affectedUsers: "User ที่ได้รับผลกระทบ",
    priorityAction: "Action ที่ควรทำก่อน",
    analystMode: "AI Analyst Mode",
    copyOutput: "Copy Output",
    copied: "คัดลอกแล้ว",
    copyFailed: "คัดลอกไม่สำเร็จ",
    correlationTitle: "Correlation / เหตุการณ์ที่เชื่อมโยงกัน",
    noCorrelation: "ไม่พบความเชื่อมโยงแบบหลายเหตุการณ์",
    eventTable: "ตาราง Event ที่น่าสงสัย",
    copyRca: "Copy RCA",
    copySummary: "Copy Summary",
    searchPlaceholder: "ค้นหา keyword, IP, rule",
    allSeverity: "ทุกระดับความรุนแรง",
    allLogTypes: "ทุกประเภท Log",
    timestampSearch: "ค้นหาจากเวลา",
    severity: "ความรุนแรง",
    confidence: "ความมั่นใจ",
    type: "ประเภท",
    time: "เวลา",
    userPort: "User/Port",
    assetIoc: "Asset / IOC",
    ruleRcaFix: "Rule / RCA / Fix",
    repeat: "ซ้ำ",
    evidence: "หลักฐาน",
    rootCause: "สาเหตุ",
    impact: "ผลกระทบ",
    fix: "วิธีแก้",
    notFoundTime: "ไม่พบเวลา",
    noMatchingEvents: "ไม่มี Event ที่ตรงกับตัวกรองปัจจุบัน",
    timeline: "Timeline",
    noTimestamp: "ไม่พบ Timestamp ใน Log",
    recommendations: "คำแนะนำ",
    noRecommendation: "ยังไม่มีคำแนะนำจากผลการวิเคราะห์",
    reportTitle: "รายงานวิเคราะห์ Log สำหรับ SOC",
    generatedAt: "สร้างเมื่อ",
    managerSummary: "สรุปสำหรับหัวหน้า",
    recommendedAction: "Recommended Action",
  },
  en: {
    language: "Language",
    thai: "ไทย",
    english: "English",
    title: "SOC Log Analysis Dashboard",
    subtitle:
      "Analyze and correlate Apache/Nginx, SSH, Firewall, Windows Event, Linux Syslog, Cisco/Network Device, and Application logs with bilingual RCA / Impact / Fix outputs.",
    inputTitle: "Paste or upload logs",
    upload: "Upload .log/.txt/.csv",
    textareaPlaceholder: "Paste logs here, for example SSH, Firewall, Windows Event, Cisco, or Web Access logs",
    analyze: "Analyze Log",
    analyzing: "Analyzing...",
    loadDemo: "Load demo log",
    overview: "Overview",
    riskScore: "Risk Score",
    totalEvents: "Total Events",
    suspicious: "Suspicious",
    critical: "Critical",
    failedLogin: "Failed Login",
    correlation: "Correlation",
    topSourceIp: "Top Source IP",
    none: "None",
    incidentIntel: "Incident Intelligence Summary",
    topRules: "Top Rules",
    mitreTechnique: "MITRE Technique",
    affectedUsers: "Affected Users",
    priorityAction: "Priority Actions",
    analystMode: "AI Analyst Mode",
    copyOutput: "Copy Output",
    copied: "Copied",
    copyFailed: "Copy failed",
    correlationTitle: "Correlation / Linked Events",
    noCorrelation: "No multi-event correlation was detected.",
    eventTable: "Suspicious Event Table",
    copyRca: "Copy RCA",
    copySummary: "Copy Summary",
    searchPlaceholder: "Search keyword, IP, or rule",
    allSeverity: "All Severities",
    allLogTypes: "All Log Types",
    timestampSearch: "Timestamp contains",
    severity: "Severity",
    confidence: "Confidence",
    type: "Type",
    time: "Time",
    userPort: "User/Port",
    assetIoc: "Asset / IOC",
    ruleRcaFix: "Rule / RCA / Fix",
    repeat: "Repeat",
    evidence: "Evidence",
    rootCause: "Root Cause",
    impact: "Impact",
    fix: "Fix",
    notFoundTime: "Unknown",
    noMatchingEvents: "No suspicious events match the current filters.",
    timeline: "Timeline",
    noTimestamp: "No timestamps were detected.",
    recommendations: "Recommendations",
    noRecommendation: "No recommendations yet from the current analysis.",
    reportTitle: "SOC Log Analysis Report",
    generatedAt: "Generated",
    managerSummary: "Manager Summary",
    recommendedAction: "Recommended Action",
  },
};

const analystModeLabels: Record<Language, Record<AnalystMode, string>> = {
  th: {
    socAnalyst: "Explain Like SOC Analyst",
    rca: "Generate RCA",
    managerSummary: "Generate Manager Summary",
    fixCommand: "Generate Fix Command",
    ticket: "Generate Ticket",
  },
  en: {
    socAnalyst: "Explain Like SOC Analyst",
    rca: "Generate RCA",
    managerSummary: "Generate Manager Summary",
    fixCommand: "Generate Fix Command",
    ticket: "Generate Ticket",
  },
};

export default function SOCDashboard() {
  const [language, setLanguage] = useState<Language>("th");
  const [logInput, setLogInput] = useState(demoLog);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<Severity | "All">("All");
  const [logType, setLogType] = useState("All");
  const [timestampFilter, setTimestampFilter] = useState("");
  const [vendorPreset, setVendorPreset] = useState("Auto");
  const [analystMode, setAnalystMode] = useState<AnalystMode>("socAnalyst");
  const [copyStatus, setCopyStatus] = useState("");

  const t = UI[language];

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
      if (!response.ok) throw new Error(data.error || (language === "th" ? "วิเคราะห์ Log ไม่สำเร็จ" : "Log analysis failed"));
      setResult(data);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : language === "th" ? "วิเคราะห์ Log ไม่สำเร็จ" : "Log analysis failed");
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

  const handleVendorPreset = (preset: string) => {
    setVendorPreset(preset);
    const sample = vendorSamples[preset] || demoLog;
    setLogInput(sample);
    setResult(null);
    setError("");
  };

  const copyText = async (label: string, content: string) => {
    try {
      await navigator.clipboard.writeText(localize(content, language));
      setCopyStatus(`${label}: ${t.copied}`);
      window.setTimeout(() => setCopyStatus(""), 1800);
    } catch {
      setCopyStatus(t.copyFailed);
    }
  };

  const logTypes = useMemo(() => {
    if (!result) return ["All"];
    return ["All", ...Object.keys(result.summary.logTypes).sort()];
  }, [result]);

  const filteredFindings = useMemo(() => {
    if (!result) return [];
    const needle = query.toLowerCase().trim();

    return result.findings.filter((finding) => {
      const localizedSearchBlob = [
        finding.id,
        localize(finding.rule, language),
        finding.raw,
        finding.sourceIp || "",
        finding.destinationPort || "",
        finding.username || "",
        finding.technique,
        finding.tactic,
        finding.detectedKeywords.join(" "),
        localize(finding.possibleRootCause, language),
        localize(finding.recommendedFix, language),
      ]
        .join(" ")
        .toLowerCase();

      const matchesQuery = !needle || localizedSearchBlob.includes(needle);
      const matchesSeverity = severity === "All" || finding.severity === severity;
      const matchesType = logType === "All" || finding.logType === logType;
      const matchesTimestamp = !timestampFilter || (finding.timestamp || "").includes(timestampFilter);
      return matchesQuery && matchesSeverity && matchesType && matchesTimestamp;
    });
  }, [language, logType, query, result, severity, timestampFilter]);

  const exportReport = (format: "json" | "csv" | "txt" | "pdf") => {
    if (!result) return;

    if (format === "pdf") {
      openPrintableReport(result, filteredFindings, language);
      return;
    }

    const filenamePrefix = language === "th" ? "รายงาน-soc" : "soc-report";
    const filename = `${filenamePrefix}-${new Date().toISOString().slice(0, 10)}.${format}`;
    const content = buildExport(format, result, filteredFindings, language);
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
            <div className="flex flex-wrap items-center gap-3">
              <p className="text-sm font-medium uppercase tracking-[0.2em] text-cyan-300">Log Analysis</p>
              <div className="flex items-center rounded-lg border border-zinc-800 bg-black p-1 text-xs">
                <span className="px-2 text-zinc-500">{t.language}</span>
                <button
                  className={`rounded-md px-3 py-1 ${language === "th" ? "bg-cyan-500 text-zinc-950" : "text-zinc-300 hover:text-white"}`}
                  onClick={() => setLanguage("th")}
                >
                  {t.thai}
                </button>
                <button
                  className={`rounded-md px-3 py-1 ${language === "en" ? "bg-cyan-500 text-zinc-950" : "text-zinc-300 hover:text-white"}`}
                  onClick={() => setLanguage("en")}
                >
                  {t.english}
                </button>
              </div>
            </div>
            <h1 className="mt-2 text-3xl font-semibold text-white sm:text-4xl">{t.title}</h1>
            <p className="mt-2 max-w-3xl text-sm text-zinc-400">{t.subtitle}</p>
          </div>
          <div className="grid grid-cols-3 gap-2 text-right text-xs text-zinc-400 sm:min-w-80">
            <Metric label="Rules" value="30+" />
            <Metric label="Types" value="15" />
            <Metric label="Intel" value="MITRE" />
          </div>
        </header>

        <section className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_340px]">
          <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
            <div className="mb-3 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <h2 className="text-lg font-semibold text-white">{t.inputTitle}</h2>
              <div className="flex flex-wrap gap-2">
                <select
                  className="rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 outline-none hover:border-cyan-500"
                  value={vendorPreset}
                  onChange={(event) => handleVendorPreset(event.target.value)}
                >
                  {vendorOptions.map((option) => (
                    <option key={option} value={option}>
                      Preset: {option}
                    </option>
                  ))}
                </select>
                <label className="inline-flex cursor-pointer items-center justify-center rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm font-medium text-zinc-200 hover:border-cyan-500">
                  {t.upload}
                  <input className="sr-only" type="file" accept=".log,.txt,.csv" onChange={handleFileUpload} />
                </label>
              </div>
            </div>
            <textarea
              className="h-72 w-full resize-y rounded-md border border-zinc-800 bg-black p-3 font-mono text-sm leading-6 text-zinc-200 outline-none ring-cyan-500 focus:ring-2"
              value={logInput}
              onChange={(event) => setLogInput(event.target.value)}
              spellCheck={false}
              placeholder={t.textareaPlaceholder}
            />
            <div className="mt-3 flex flex-col gap-2 sm:flex-row">
              <button
                className="rounded-md bg-cyan-500 px-4 py-2 text-sm font-semibold text-zinc-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-60"
                onClick={() => analyzeText(logInput)}
                disabled={isAnalyzing}
              >
                {isAnalyzing ? t.analyzing : t.analyze}
              </button>
              <button
                className="rounded-md border border-zinc-700 px-4 py-2 text-sm font-semibold text-zinc-200 hover:border-zinc-500"
                onClick={() => {
                  setLogInput(demoLog);
                  setResult(null);
                  setError("");
                }}
              >
                {t.loadDemo}
              </button>
            </div>
            {copyStatus && <p className="mt-3 text-sm text-cyan-300">{copyStatus}</p>}
            {error && <p className="mt-3 rounded-md border border-red-900 bg-red-950/60 p-3 text-sm text-red-200">{error}</p>}
          </div>

          <aside className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
            <h2 className="text-lg font-semibold text-white">{t.overview}</h2>
            <div className="mt-4 grid grid-cols-2 gap-3">
              <Metric label={t.riskScore} value={String(result?.summary.riskScore || 0)} tone={result?.summary.riskLevel === "Critical" ? "critical" : "warning"} />
              <Metric label={t.totalEvents} value={String(result?.summary.totalEvents || 0)} />
              <Metric label={t.suspicious} value={String(result?.summary.suspiciousEvents || 0)} />
              <Metric label={t.critical} value={String(result?.summary.criticalAlerts || 0)} tone="critical" />
              <Metric label={t.failedLogin} value={String(result?.summary.failedLogins || 0)} tone="warning" />
              <Metric label={t.correlation} value={String(result?.summary.correlations.length || 0)} />
            </div>
            <div className="mt-4 rounded-md border border-zinc-800 bg-black p-3">
              <p className="text-xs uppercase tracking-[0.18em] text-zinc-500">{t.topSourceIp}</p>
              <p className="mt-2 font-mono text-lg text-cyan-300">{result?.summary.topSourceIp || t.none}</p>
            </div>
            <div className="mt-3 grid grid-cols-3 gap-2">
              <Metric label="IOC" value={String(result?.summary.iocHits || 0)} tone="critical" />
              <Metric label="Public IP" value={String(result?.summary.publicIpCount || 0)} />
              <Metric label="Private IP" value={String(result?.summary.privateIpCount || 0)} />
            </div>
            <SeverityBars counts={result?.summary.severityCounts} language={language} />
          </aside>
        </section>

        {result && (
          <>
            <section className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_420px]">
              <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                  <div>
                    <h2 className="text-lg font-semibold text-white">{t.incidentIntel}</h2>
                    <p className="mt-2 text-sm leading-6 text-zinc-400">{localize(result.summary.incidentNarrative, language)}</p>
                  </div>
                  <span className={`w-fit rounded px-3 py-1 text-xs font-semibold ${severityClass(result.summary.riskLevel)}`}>
                    {severityLabel(result.summary.riskLevel, language)}
                  </span>
                </div>

                <div className="mt-4 grid gap-3 md:grid-cols-3">
                  <IntelList title={t.topRules} items={result.summary.topRules.map((item) => `${localize(item.rule, language)} (${item.count})`)} />
                  <IntelList title={t.mitreTechnique} items={result.summary.mitreTechniques} />
                  <IntelList title={t.affectedUsers} items={result.summary.affectedUsers.length ? result.summary.affectedUsers : [t.none]} />
                </div>

                <div className="mt-4 rounded-md border border-zinc-800 bg-black p-3">
                  <p className="text-xs uppercase tracking-[0.18em] text-zinc-500">{t.priorityAction}</p>
                  <div className="mt-3 grid gap-2 md:grid-cols-2">
                    {result.summary.recommendedActions.slice(0, 4).map((action) => (
                      <p key={action} className="border-l-2 border-cyan-500 pl-3 text-sm leading-5 text-zinc-300">
                        {localize(action, language)}
                      </p>
                    ))}
                  </div>
                </div>

                <div className="mt-4 rounded-md border border-zinc-800 bg-black p-3">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                    <p className="text-xs uppercase tracking-[0.18em] text-zinc-500">{t.analystMode}</p>
                    <button
                      className="rounded-md border border-zinc-700 px-3 py-2 text-xs hover:border-cyan-500"
                      onClick={() => copyText(analystModeLabels[language][analystMode], result.summary.analystReport[analystMode])}
                    >
                      {t.copyOutput}
                    </button>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {analystModeOrder.map((mode) => (
                      <button
                        key={mode}
                        className={`rounded-md border px-3 py-2 text-xs ${analystMode === mode ? "border-cyan-500 bg-cyan-500/10 text-cyan-200" : "border-zinc-700 text-zinc-300 hover:border-cyan-500"}`}
                        onClick={() => setAnalystMode(mode)}
                      >
                        {analystModeLabels[language][mode]}
                      </button>
                    ))}
                  </div>
                  <pre className="mt-3 max-h-72 overflow-auto whitespace-pre-wrap rounded-md border border-zinc-800 bg-zinc-950 p-3 text-sm leading-6 text-zinc-200">
                    {localize(result.summary.analystReport[analystMode], language)}
                  </pre>
                </div>
              </div>

              <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
                <h2 className="text-lg font-semibold text-white">{t.correlationTitle}</h2>
                <div className="mt-4 space-y-3">
                  {result.summary.correlations.length === 0 && <p className="text-sm text-zinc-500">{t.noCorrelation}</p>}
                  {result.summary.correlations.map((item) => (
                    <div key={`${item.title}-${item.sourceIp || "global"}`} className="rounded-md border border-zinc-800 bg-black p-3">
                      <div className="flex items-center justify-between gap-3">
                        <p className="text-sm font-semibold text-white">{localize(item.title, language)}</p>
                        <span className={`rounded px-2 py-1 text-xs font-semibold ${severityClass(item.severity)}`}>
                          {severityLabel(item.severity, language)}
                        </span>
                      </div>
                      <p className="mt-2 text-sm leading-5 text-zinc-400">{localize(item.description, language)}</p>
                      <div className="mt-2 flex flex-wrap gap-2 text-xs text-zinc-400">
                        {item.confidence !== undefined && <span>Confidence: {item.confidence}%</span>}
                        {item.incidentType && <span>Type: {localize(item.incidentType, language)}</span>}
                        {item.mitreTechniques?.slice(0, 3).map((technique) => (
                          <span key={technique} className="rounded border border-zinc-700 px-2 py-1">
                            {technique}
                          </span>
                        ))}
                      </div>
                      <p className="mt-2 text-xs text-cyan-300">{localize(item.recommendedAction, language)}</p>
                    </div>
                  ))}
                </div>
              </div>
            </section>

            <section className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_340px]">
              <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
                <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                  <h2 className="text-lg font-semibold text-white">{t.eventTable}</h2>
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
                    <button className="rounded-md border border-zinc-700 px-3 py-2 text-sm hover:border-cyan-500" onClick={() => copyText("RCA", result.summary.analystReport.rca)}>
                      {t.copyRca}
                    </button>
                    <button className="rounded-md border border-zinc-700 px-3 py-2 text-sm hover:border-cyan-500" onClick={() => copyText("Incident Summary", result.summary.analystReport.managerSummary)}>
                      {t.copySummary}
                    </button>
                  </div>
                </div>

                <div className="mt-4 grid gap-2 md:grid-cols-4">
                  <input
                    className="rounded-md border border-zinc-800 bg-black px-3 py-2 text-sm outline-none focus:border-cyan-500"
                    placeholder={t.searchPlaceholder}
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
                        {severityOptionLabel(option, language)}
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
                        {option === "All" ? t.allLogTypes : option}
                      </option>
                    ))}
                  </select>
                  <input
                    className="rounded-md border border-zinc-800 bg-black px-3 py-2 text-sm outline-none focus:border-cyan-500"
                    placeholder={t.timestampSearch}
                    value={timestampFilter}
                    onChange={(event) => setTimestampFilter(event.target.value)}
                  />
                </div>

                <div className="mt-4 overflow-x-auto">
                  <table className="w-full min-w-[1280px] border-collapse text-left text-sm">
                    <thead className="border-b border-zinc-800 text-xs uppercase tracking-[0.14em] text-zinc-500">
                      <tr>
                        <th className="py-3 pr-3">ID</th>
                        <th className="py-3 pr-3">{t.severity}</th>
                        <th className="py-3 pr-3">{t.confidence}</th>
                        <th className="py-3 pr-3">{t.type}</th>
                        <th className="py-3 pr-3">{t.time}</th>
                        <th className="py-3 pr-3">Source</th>
                        <th className="py-3 pr-3">{t.userPort}</th>
                        <th className="py-3 pr-3">MITRE</th>
                        <th className="py-3 pr-3">{t.assetIoc}</th>
                        <th className="py-3 pr-3">{t.ruleRcaFix}</th>
                        <th className="py-3 pr-3">{t.repeat}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredFindings.map((finding) => (
                        <tr key={finding.id} className="border-b border-zinc-900 align-top hover:bg-zinc-800/50">
                          <td className="py-3 pr-3 font-mono text-xs text-zinc-400">{finding.id}</td>
                          <td className="py-3 pr-3">
                            <span className={`rounded px-2 py-1 text-xs font-semibold ${severityClass(finding.severity)}`}>
                              {severityLabel(finding.severity, language)}
                            </span>
                          </td>
                          <td className="py-3 pr-3 font-mono text-xs text-zinc-300">{finding.confidence}%</td>
                          <td className="py-3 pr-3 text-zinc-300">{finding.logType}</td>
                          <td className="py-3 pr-3 font-mono text-xs text-zinc-400">{finding.timestamp || t.notFoundTime}</td>
                          <td className="py-3 pr-3 font-mono text-xs text-cyan-300">{finding.sourceIp || "-"}</td>
                          <td className="py-3 pr-3 text-xs text-zinc-300">
                            <p>{finding.username || "-"}</p>
                            <p className="mt-1 font-mono text-zinc-500">{finding.destinationPort ? `:${finding.destinationPort}` : ""}</p>
                          </td>
                          <td className="py-3 pr-3">
                            <p className="text-xs font-medium text-zinc-200">{finding.technique}</p>
                            <p className="mt-1 text-xs text-zinc-500">{finding.tactic}</p>
                          </td>
                          <td className="py-3 pr-3 text-xs text-zinc-300">
                            <p>{finding.asset || "-"}</p>
                            {finding.interfaceName && <p className="mt-1 font-mono text-zinc-500">IF: {finding.interfaceName}</p>}
                            {finding.vlan && <p className="mt-1 font-mono text-zinc-500">VLAN: {finding.vlan}</p>}
                            {finding.macAddress && <p className="mt-1 font-mono text-zinc-500">MAC: {finding.macAddress}</p>}
                            {finding.iocType && <p className="mt-2 rounded border border-red-800 bg-red-950/40 px-2 py-1 text-red-200">IOC: {localize(finding.iocType, language)}</p>}
                            {finding.abuseScore !== null && finding.abuseScore !== undefined && <p className="mt-1 text-red-300">Abuse: {finding.abuseScore}</p>}
                          </td>
                          <td className="py-3 pr-3">
                            <p className="font-medium text-white">{localize(finding.rule, language)}</p>
                            <p className="mt-1 text-xs text-cyan-300">{t.evidence}: {localize(finding.evidence, language)}</p>
                            <p className="mt-1 max-w-xl text-xs leading-5 text-zinc-400">{t.rootCause}: {localize(finding.possibleRootCause, language)}</p>
                            <p className="mt-1 max-w-xl text-xs leading-5 text-zinc-400">{t.impact}: {localize(finding.impact, language)}</p>
                            <p className="mt-1 max-w-xl text-xs leading-5 text-emerald-300">{t.fix}: {localize(finding.recommendedFix, language)}</p>
                            {finding.iocDescription && <p className="mt-1 max-w-xl text-xs leading-5 text-red-200">Threat Intel: {localize(finding.iocDescription, language)}</p>}
                            <p className="mt-2 max-w-xl font-mono text-xs leading-5 text-zinc-500">Raw: {finding.raw}</p>
                          </td>
                          <td className="py-3 pr-3 font-mono text-zinc-300">{finding.repeatedCount}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {filteredFindings.length === 0 && <p className="py-8 text-center text-sm text-zinc-500">{t.noMatchingEvents}</p>}
                </div>
              </div>

              <div className="space-y-4">
                <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
                  <h2 className="text-lg font-semibold text-white">{t.timeline}</h2>
                  <div className="mt-4 space-y-3">
                    {result.summary.timeline.length === 0 && <p className="text-sm text-zinc-500">{t.noTimestamp}</p>}
                    {result.summary.timeline.slice(0, 12).map((item) => (
                      <div key={item.timestamp}>
                        <div className="mb-1 flex justify-between text-xs text-zinc-400">
                          <span className="font-mono">{item.timestamp}</span>
                          <span>{item.count}</span>
                        </div>
                        <div className="h-2 rounded bg-zinc-800">
                          <div className={`h-2 rounded ${barClass(item.severity)}`} style={{ width: `${Math.min(100, item.count * 18)}%` }} />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
                  <h2 className="text-lg font-semibold text-white">{t.recommendations}</h2>
                  <div className="mt-4 space-y-3">
                    {filteredFindings.slice(0, 4).map((finding) => (
                      <div key={`${finding.id}-fix`} className="border-l-2 border-cyan-500 pl-3">
                        <p className="text-sm font-semibold text-white">{localize(finding.rule, language)}</p>
                        <p className="mt-1 text-sm leading-5 text-zinc-400">{localize(finding.recommendedFix, language)}</p>
                      </div>
                    ))}
                    {filteredFindings.length === 0 && <p className="text-sm text-zinc-500">{t.noRecommendation}</p>}
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

function SeverityBars({ counts, language }: { counts?: Record<Severity, number>; language: Language }) {
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
            <div className={`h-2 rounded ${barClass(level)}`} style={{ width: `${(safeCounts[level] / max) * 100}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}

function severityLabel(severity: Severity, language: Language) {
  if (language === "en") return severity;
  if (severity === "Critical") return "วิกฤต";
  if (severity === "High") return "สูง";
  if (severity === "Medium") return "ปานกลาง";
  return "ต่ำ";
}

function severityOptionLabel(option: Severity | "All", language: Language) {
  if (option === "All") return language === "th" ? "ทุกระดับความรุนแรง" : "All Severities";
  return severityLabel(option, language);
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

function buildExport(format: "json" | "csv" | "txt", result: AnalysisResult, findings: Finding[], language: Language) {
  if (format === "json") {
    const localized = {
      generatedAt: result.generatedAt,
      language,
      summary: {
        ...result.summary,
        incidentNarrative: localize(result.summary.incidentNarrative, language),
        recommendedActions: result.summary.recommendedActions.map((item) => localize(item, language)),
        correlations: result.summary.correlations.map((item) => ({
          ...item,
          title: localize(item.title, language),
          description: localize(item.description, language),
          recommendedAction: localize(item.recommendedAction, language),
        })),
        analystReport: {
          socAnalyst: localize(result.summary.analystReport.socAnalyst, language),
          rca: localize(result.summary.analystReport.rca, language),
          managerSummary: localize(result.summary.analystReport.managerSummary, language),
          fixCommand: localize(result.summary.analystReport.fixCommand, language),
          ticket: localize(result.summary.analystReport.ticket, language),
        },
      },
      findings: findings.map((finding) => ({
        ...finding,
        rule: localize(finding.rule, language),
        possibleRootCause: localize(finding.possibleRootCause, language),
        impact: localize(finding.impact, language),
        recommendedFix: localize(finding.recommendedFix, language),
        iocDescription: localize(finding.iocDescription || "", language),
      })),
    };
    return JSON.stringify(localized, null, 2);
  }

  if (format === "csv") {
    const rows = [
      [
        "id",
        "line",
        "severity",
        "confidence",
        "type",
        "timestamp",
        "source_ip",
        "destination_ip",
        "destination_port",
        "username",
        "asset",
        "interface",
        "vlan",
        "mac",
        "ioc_type",
        "ioc_risk",
        "ioc_description",
        "country",
        "asn",
        "abuse_score",
        "rule",
        "tactic",
        "technique",
        "repeat",
        "evidence",
        "root_cause",
        "impact",
        "recommendation",
        "raw",
      ],
      ...findings.map((finding) => [
        finding.id,
        String(finding.lineNumber),
        severityLabel(finding.severity, language),
        String(finding.confidence),
        finding.logType,
        finding.timestamp || "",
        finding.sourceIp || "",
        finding.destinationIp || "",
        finding.destinationPort || "",
        finding.username || "",
        finding.asset || "",
        finding.interfaceName || "",
        finding.vlan || "",
        finding.macAddress || "",
        localize(finding.iocType || "", language),
        finding.iocRisk || "",
        localize(finding.iocDescription || "", language),
        finding.geoCountry || "",
        finding.asn || "",
        finding.abuseScore !== null && finding.abuseScore !== undefined ? String(finding.abuseScore) : "",
        localize(finding.rule, language),
        finding.tactic,
        finding.technique,
        String(finding.repeatedCount),
        localize(finding.evidence, language),
        localize(finding.possibleRootCause, language),
        localize(finding.impact, language),
        localize(finding.recommendedFix, language),
        finding.raw,
      ]),
    ];
    return rows.map((row) => row.map(csvCell).join(",")).join("\n");
  }

  const u = UI[language];
  const criticalFindings = findings.filter((finding) => finding.severity === "Critical");
  const iocFindings = findings.filter((finding) => finding.iocType);

  return [
    u.reportTitle,
    "",
    "Executive Summary",
    `${u.generatedAt}: ${result.generatedAt}`,
    `${u.totalEvents}: ${result.summary.totalEvents}`,
    `${u.suspicious}: ${result.summary.suspiciousEvents}`,
    `${u.critical}: ${result.summary.criticalAlerts}`,
    `IOC Hits: ${result.summary.iocHits}`,
    `${u.riskScore}: ${result.summary.riskScore}/100 (${severityLabel(result.summary.riskLevel, language)})`,
    `${u.topSourceIp}: ${result.summary.topSourceIp || u.none}`,
    `${language === "th" ? "สรุป" : "Summary"}: ${localize(result.summary.incidentNarrative, language)}`,
    "",
    "AI Analyst Summary",
    localize(result.summary.analystReport.socAnalyst, language),
    "",
    u.managerSummary,
    localize(result.summary.analystReport.managerSummary, language),
    "",
    "Timeline",
    ...(result.summary.timeline.length
      ? result.summary.timeline.map((item) => `${item.timestamp} | ${item.count} events | ${severityLabel(item.severity, language)}`)
      : [u.noTimestamp]),
    "",
    "Top Source IP / IP Profile",
    `${u.topSourceIp}: ${result.summary.topSourceIp || u.none}`,
    `Public IP Events: ${result.summary.publicIpCount}`,
    `Private IP Events: ${result.summary.privateIpCount}`,
    `Reserved IP Events: ${result.summary.reservedIpCount}`,
    "",
    "Critical Events",
    ...(criticalFindings.length
      ? criticalFindings.map((finding) => `${finding.id} | ${localize(finding.rule, language)} | ${finding.sourceIp || "-"} | ${localize(finding.evidence, language)}`)
      : [u.none]),
    "",
    "MITRE Mapping",
    ...(result.summary.mitreTechniques.length ? result.summary.mitreTechniques : [u.none]),
    "",
    "IOC / Threat Intelligence",
    ...(iocFindings.length
      ? iocFindings.map((finding) => `${finding.id} | ${localize(finding.iocType || "", language)} | Risk=${finding.iocRisk} | Abuse=${finding.abuseScore ?? "-"} | ${localize(finding.iocDescription || "", language)}`)
      : [u.none]),
    "",
    u.correlationTitle,
    ...(result.summary.correlations.length
      ? result.summary.correlations.map((item) => `${severityLabel(item.severity, language)} | ${localize(item.title, language)} | Confidence ${item.confidence ?? "-"}% | MITRE ${(item.mitreTechniques || []).join(", ")} | ${localize(item.description, language)} | ${localize(item.recommendedAction, language)}`)
      : [u.none]),
    "",
    "Root Cause / Impact / Recommended Action",
    localize(result.summary.analystReport.rca, language),
    "",
    "Fix Command / Checklist",
    localize(result.summary.analystReport.fixCommand, language),
    "",
    "Incident Ticket",
    localize(result.summary.analystReport.ticket, language),
    "",
    "Raw Evidence / Findings",
    ...findings.flatMap((finding) => [
      `${finding.id} | ${severityLabel(finding.severity, language)} | ${finding.confidence}% | ${finding.logType} | ${localize(finding.rule, language)}`,
      `${u.time}: ${finding.timestamp || u.notFoundTime} | Source: ${finding.sourceIp || "-"} | User: ${finding.username || "-"} | Port: ${finding.destinationPort || "-"} | Asset: ${finding.asset || "-"}`,
      `MITRE: ${finding.technique} | Tactic: ${finding.tactic}`,
      `${u.evidence}: ${localize(finding.evidence, language)}`,
      `Keyword: ${finding.detectedKeywords.join(", ") || u.none}`,
      `IOC: ${localize(finding.iocType || u.none, language)} | Country: ${finding.geoCountry || "-"} | ASN: ${finding.asn || "-"} | Abuse: ${finding.abuseScore ?? "-"}`,
      `${u.rootCause}: ${localize(finding.possibleRootCause, language)}`,
      `${u.impact}: ${localize(finding.impact, language)}`,
      `${u.fix}: ${localize(finding.recommendedFix, language)}`,
      `Raw: ${finding.raw}`,
      "",
    ]),
  ].join("\n");
}

function openPrintableReport(result: AnalysisResult, findings: Finding[], language: Language) {
  const printable = window.open("", "_blank", "width=1100,height=800");
  if (!printable) return;

  const u = UI[language];

  const rows = findings
    .map(
      (finding) => `
        <tr>
          <td>${escapeHtml(finding.id)}</td>
          <td>${escapeHtml(severityLabel(finding.severity, language))}</td>
          <td>${escapeHtml(finding.logType)}</td>
          <td>${escapeHtml(finding.timestamp || u.notFoundTime)}</td>
          <td>${escapeHtml(finding.sourceIp || "-")}</td>
          <td>${escapeHtml(localize(finding.rule, language))}</td>
          <td>${escapeHtml(localize(finding.possibleRootCause, language))}</td>
          <td>${escapeHtml(localize(finding.impact, language))}</td>
          <td>${escapeHtml(localize(finding.recommendedFix, language))}</td>
        </tr>`
    )
    .join("");

  printable.document.write(`
    <html>
      <head>
        <title>${escapeHtml(u.reportTitle)}</title>
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
          pre { white-space: pre-wrap; border: 1px solid #d1d5db; padding: 12px; border-radius: 8px; }
        </style>
      </head>
      <body>
        <h1>${escapeHtml(u.reportTitle)}</h1>
        <p class="muted">${escapeHtml(u.generatedAt)}: ${escapeHtml(result.generatedAt)}</p>
        <p>${escapeHtml(localize(result.summary.incidentNarrative, language))}</p>
        <h2>${escapeHtml(u.managerSummary)}</h2>
        <p>${escapeHtml(localize(result.summary.analystReport.managerSummary, language))}</p>
        <h2>${escapeHtml(u.recommendedAction)}</h2>
        <pre>${escapeHtml(localize(result.summary.analystReport.fixCommand, language))}</pre>
        <div class="summary">
          <div class="card"><b>Risk Score</b><br />${result.summary.riskScore}/100</div>
          <div class="card"><b>${escapeHtml(u.severity)}</b><br />${escapeHtml(severityLabel(result.summary.riskLevel, language))}</div>
          <div class="card"><b>${escapeHtml(u.suspicious)}</b><br />${result.summary.suspiciousEvents}</div>
          <div class="card"><b>${escapeHtml(u.topSourceIp)}</b><br />${escapeHtml(result.summary.topSourceIp || u.none)}</div>
        </div>
        <h2>${escapeHtml(u.eventTable)}</h2>
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>${escapeHtml(u.severity)}</th>
              <th>${escapeHtml(u.type)}</th>
              <th>${escapeHtml(u.time)}</th>
              <th>Source IP</th>
              <th>Rule</th>
              <th>${escapeHtml(u.rootCause)}</th>
              <th>${escapeHtml(u.impact)}</th>
              <th>${escapeHtml(u.fix)}</th>
            </tr>
          </thead>
          <tbody>${rows || `<tr><td colspan="9">${escapeHtml(u.noMatchingEvents)}</td></tr>`}</tbody>
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
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function localize(value: string | null | undefined, language: Language): string {
  if (!value) return "";
  if (language === "th") return value;
  return toEnglish(value);
}

const EN_MAP: Record<string, string> = {
  "ไม่พบ": "Not found",
  "ไม่มี": "None",
  "ไม่พบเวลา": "Unknown",
  "พบบัญชี Windows เข้าสู่ระบบสำเร็จ": "A Windows account logged on successfully.",
  "โดยทั่วไปอาจเป็นเหตุการณ์ปกติ แต่ควรตรวจสอบถ้าเกิดหลังจาก login fail หลายครั้ง หรือมาจากแหล่งที่ผิดปกติ": "Usually normal, but suspicious if it follows many failed logons or comes from an unusual source.",
  "ตรวจสอบ Source IP, Account Name, Logon Type และเหตุการณ์ login fail ในช่วงเวลาใกล้เคียง": "Review source IP, account name, logon type, and nearby failed logon events.",
  "พบบัญชี Windows พยายามยืนยันตัวตนไม่สำเร็จ": "A Windows account authentication attempt failed.",
  "ถ้าเกิดซ้ำหลายครั้ง อาจเป็น Brute Force, Password Spray, รหัสผ่าน Service ผิด หรือ Credential ถูกล็อก": "Repeated failures may indicate brute force, password spray, service password mismatch, or locked credentials.",
  "ตรวจสอบบัญชี, Source IP, Logon Type, สถานะ Lockout และ login สำเร็จหลังจากเหตุการณ์ล้มเหลว": "Check account, source IP, logon type, lockout status, and successful logons after failures.",
  "พบบัญชีสิทธิ์สูงเข้าสู่ระบบและได้รับสิทธิ์พิเศษ": "A privileged account logged on and received special privileges.",
  "ถ้าไม่ได้คาดหมาย อาจเป็นการใช้งานบัญชีผู้ดูแลระบบผิดปกติ หรือการยกระดับสิทธิ์": "If unexpected, this may indicate administrator account misuse or privilege escalation.",
  "ตรวจสอบผู้ใช้ admin, เครื่องต้นทาง, เอกสารอนุมัติ และกิจกรรมหลังจาก login": "Validate the admin user, source host, approval record, and activity performed after logon.",
  "พบการสร้าง Process ใหม่บนเครื่อง Windows": "A new process was created on a Windows endpoint.",
  "อาจน่าสงสัยถ้าเกี่ยวข้องกับ PowerShell, encoded command หรือ parent process ที่ผิดปกติ": "Suspicious when paired with PowerShell, encoded commands, or an unusual parent process.",
  "ตรวจสอบ command line, parent process, user, hash และข้อมูลจาก Endpoint Security": "Check command line, parent process, user, hash, and endpoint telemetry.",
  "พบการสร้างบัญชี Windows ใหม่": "A new Windows account was created.",
  "อาจเป็นงานดูแลระบบปกติ หรือเป็นการสร้างบัญชีเพื่อฝังตัวของผู้โจมตี": "Could be normal administration or attacker persistence.",
  "ตรวจสอบ Change Request, ผู้สร้างบัญชี, Group Membership และการใช้งานบัญชีนั้น": "Confirm change request, creator account, group membership, and account usage.",
  "พบการเพิ่มผู้ใช้เข้ากลุ่มที่มีผลต่อสิทธิ์ความปลอดภัย": "A user was added to a security-enabled privileged group.",
  "อาจทำให้ผู้ใช้ได้รับสิทธิ์สูงขึ้น หรือใช้เป็นช่องทางคงสิทธิ์ในระบบ": "Could grant elevated access or enable persistence.",
  "ตรวจสอบผู้ร้องขอ, กลุ่ม, ผู้ใช้เป้าหมาย และลบสิทธิ์ทันทีถ้าไม่ได้รับอนุญาต": "Verify requester, group, target user, and remove unauthorized membership immediately.",
  "พบการเพิ่มผู้ใช้เข้ากลุ่มภายในเครื่อง": "A user was added to a local group.",
  "ถ้ากลุ่มนั้นมีสิทธิ์สูง ผู้ใช้อาจได้รับสิทธิ์ Local Admin": "If the group is privileged, the user may gain local administrator capability.",
  "ตรวจสอบชื่อกลุ่ม, ผู้ใช้เป้าหมาย, ผู้อนุมัติ และกิจกรรมบนเครื่อง": "Review local group name, target user, approving admin, and endpoint activity.",
  "พบบัญชี Windows ถูกล็อกจากการยืนยันตัวตนผิดพลาด": "A Windows account was locked out after failed authentication.",
  "อาจเกิดจาก Brute Force, Password Spray, Service ใช้รหัสผ่านเก่า หรือผู้ใช้กรอกรหัสผิด": "May indicate brute force, password spray, stale service password, or user error.",
  "หาแหล่งที่ทำให้บัญชีล็อก ตรวจสอบ Scheduled Task/Service และรีเซ็ตรหัสผ่านถ้าจำเป็น": "Identify lockout source, check scheduled tasks/services, and reset credentials if needed.",
  "พบการขอ Kerberos TGT": "A Kerberos TGT request occurred.",
  "มักเป็นเหตุการณ์ปกติ แต่ควรตรวจสอบถ้าเกิดจำนวนมาก หรือมี pre-auth/encryption ผิดปกติ": "Often normal, but suspicious in bulk or with unusual pre-auth/encryption errors.",
  "ตรวจสอบบัญชี, เครื่องต้นทาง, Failure Code และปริมาณที่ผิดปกติ": "Review account, source host, failure code, and abnormal volume.",
  "พบการขอ Kerberos Service Ticket": "A Kerberos service ticket request occurred.",
  "อาจเป็นเหตุการณ์ปกติ หรือเป็นสัญญาณ Kerberoasting ถ้ามีการขอ ticket จำนวนมาก": "Could be normal or indicate Kerberoasting when many service tickets are requested.",
  "ตรวจสอบ Service Account, Encryption Type, ปริมาณ และเครื่องที่ร้องขอผิดปกติ": "Check service accounts, encryption type, volume, and suspicious requesting hosts.",
  "พบการยืนยันตัวตน SSH ล้มเหลวซ้ำหลายครั้ง": "Repeated SSH authentication failures were detected.",
  "บัญชีหรือ Server เป้าหมายอาจกำลังถูก Brute Force หรือ Password Spray": "The targeted account or server may be under brute force or password spraying attack.",
  "Block หรือจำกัดความถี่ Source IP, ตรวจสอบ login สำเร็จจาก IP เดียวกัน, เปิดใช้ MFA, ปิด password login และจำกัด SSH ให้เข้าได้เฉพาะ VPN/Management IP": "Block or rate-limit the source IP, review successful logons from the same IP, enforce MFA, disable password login, and restrict SSH to VPN or management IPs.",
  "พบการเข้าสู่ระบบผ่าน SSH สำเร็จ": "An SSH login succeeded.",
  "อาจเป็นเหตุการณ์ปกติ แต่ควรตรวจสอบถ้าเกิดหลังจากพยายาม login fail หลายครั้ง หรือมาจากบัญชี/IP ที่ผิดปกติ": "May be normal, but suspicious if it follows many failed attempts or uses an unusual account/source.",
  "ตรวจสอบผู้ใช้, Source IP, ตำแหน่งที่มา และคำสั่งที่รันหลังจาก login": "Validate user, source IP, geolocation, and commands executed after login.",
  "พบ Request ที่มีรูปแบบ Payload ที่ใช้โจมตี SQL Injection": "The request contained payloads commonly used for SQL injection.",
  "ระบบอาจเสี่ยงต่อการถูกอ่านข้อมูลจาก Database, Bypass Login หรือแก้ไขข้อมูล": "The application may be exposed to database extraction, login bypass, or data modification.",
  "ใช้ Prepared Statement, ตรวจสอบ Input, Review Code ของ Endpoint ที่เกี่ยวข้อง, เพิ่ม WAF Rule และตรวจสอบ Database Log ว่ามี Query สำเร็จหรือไม่": "Use prepared statements, validate input, review vulnerable endpoint code, add WAF rules, and inspect database logs for successful queries.",
  "พบ Request ที่พยายามเข้าถึงไฟล์นอก Directory ที่เว็บอนุญาต": "The request attempted to access files outside the intended web directory.",
  "ผู้โจมตีอาจอ่านไฟล์สำคัญ เช่น Config, Secret หรือไฟล์ระบบ": "Attackers may read sensitive files, configuration secrets, or system files.",
  "Normalize Path, Block Pattern ที่ WAF, ใช้ Allowlist สำหรับ Path และตรวจสอบ Endpoint ดาวน์โหลดไฟล์": "Normalize paths, block traversal patterns at WAF, enforce allowlisted paths, and review file download endpoints.",
  "พบ Request ที่มี Payload สำหรับ Cross-site Scripting": "The request contained a cross-site scripting payload.",
  "ผู้ใช้อาจเสี่ยงถูกขโมย Session, Redirect ไปเว็บอันตราย หรือรัน Script ฝั่ง Browser": "Users may be exposed to session theft, malicious redirects, or browser-side execution.",
  "Escape Output, ใช้ Content Security Policy, Validate Input และตรวจสอบ Parameter ที่เกี่ยวข้อง": "Escape output, apply Content Security Policy, validate input, and review affected parameters.",
  "พบ Request หรือ Process ที่มีตัวบ่งชี้การสั่งรันคำสั่งระบบ": "The request or process contained command execution indicators.",
  "ผู้โจมตีอาจรันคำสั่งบน Server และยกระดับเป็น Remote Code Execution": "Attackers may execute commands on the server and gain remote code execution.",
  "หลีกเลี่ยงการเรียก Shell, ใช้ API ที่ปลอดภัย, Validate Input, Block Payload ที่ WAF และตรวจสอบ Process ที่ถูก Spawn บนเครื่อง": "Avoid shell execution, use safe APIs, validate input, block payloads at WAF, and check spawned processes on the host.",
  "พบ Traffic ถูก Firewall หรือ Security Policy ปฏิเสธ": "Traffic was blocked by a firewall or security policy.",
  "อาจเป็นการสแกนระบบ, Traffic ของแอปที่ถูกปฏิเสธ หรือ Policy ตั้งค่าผิด": "May indicate scanning, denied application traffic, or policy misconfiguration.",
  "ตรวจสอบ Source/Destination, Port, Policy ID, NAT, Change ล่าสุด และยืนยันว่า Traffic นี้ควรถูก Block หรือไม่": "Review source/destination, port, policy ID, NAT, recent changes, and whether this traffic should be blocked.",
  "พบ Source พยายาม Probe หรือสแกน Service ปลายทาง": "A source appears to probe or scan destination services.",
  "อาจเป็นขั้นตอน Recon ก่อนโจมตีจริง หรือเป็นการสแกนช่องโหว่โดยไม่ได้รับอนุญาต": "Could be reconnaissance before exploitation or unauthorized vulnerability scanning.",
  "Rate-limit หรือ Block Source, ตรวจสอบ Service ที่เปิดเผย และค้นหาเหตุการณ์โจมตีต่อเนื่องจาก IP เดียวกัน": "Rate-limit or block the source, verify exposed services, and search for follow-on exploit attempts.",
  "พบกิจกรรม PowerShell ที่มีรูปแบบน่าสงสัยหรือมีการ Obfuscation": "PowerShell activity contains suspicious execution or obfuscation indicators.",
  "อาจเป็นการรัน Malware, Script-based Intrusion หรือ Lateral Movement": "May indicate malware execution, script-based intrusion, or lateral movement.",
  "เก็บ Command Line, Parent Process, User, Script Block Log, Endpoint Alert และแยกเครื่องออกจากเครือข่ายถ้ายืนยันว่าเป็นอันตราย": "Collect command line, parent process, user, script block logs, endpoint alerts, and isolate the host if confirmed malicious.",
  "พบผู้ใช้ Linux พยายามใช้สิทธิ์สูงแต่ไม่สำเร็จ": "A Linux user attempted privileged access and failed.",
  "อาจเป็นผู้ใช้กรอกรหัสผิด หรือผู้โจมตีพยายามยกระดับสิทธิ์": "Could be user error or an attacker attempting privilege escalation.",
  "ตรวจสอบผู้ใช้, Session ต้นทาง, Sudo Policy และคำสั่งสิทธิ์สูงที่สำเร็จในช่วงเวลาใกล้เคียง": "Validate user, source session, sudo policy, and nearby successful privileged commands.",
  "พบ Service, Host หรือ Dependency มีปัญหาด้าน Availability": "A service, host, or dependency reported availability problems.",
  "ผู้ใช้อาจเจอระบบช้า, เชื่อมต่อไม่ได้ หรือมีอาการระบบล่ม": "Users may experience slowness, failed connections, or outage symptoms.",
  "ตรวจสอบ Change ล่าสุด, CPU/Memory/Interface Utilization, Dependency, Routing, DNS และ Error Rate ของแอป": "Check recent changes, CPU/memory/interface utilization, dependencies, routing, DNS, and application error rate.",
  "พบ MAC Address เดียวกันย้ายไปมาระหว่าง Port บน Switch": "The same MAC address is moving between switch ports.",
  "อาจเกิดจาก Layer 2 Loop, Unmanaged Switch วนลูป, เสียบสายผิด, AP Bridge Loop หรือ STP ไม่เสถียร": "May indicate a Layer 2 loop, unmanaged switch loop, wrong cabling, AP bridge loop, or STP instability.",
  "ไล่ MAC Address, ตรวจสอบ Port ทั้งสองฝั่ง, ตรวจสาย, ตรวจ STP Root/Blocked Port และตัด Loop จาก Unmanaged Switch": "Trace the MAC address, check both ports, inspect cabling, verify STP root/blocked ports, and remove unmanaged switch loops.",
  "Switch ตรวจพบเหตุการณ์ DHCP Snooping หรือ Dynamic ARP Inspection": "The switch detected DHCP Snooping or Dynamic ARP Inspection activity.",
  "อาจเกิดจาก Rogue DHCP, ARP Spoofing, ตั้ง Trusted Uplink ผิด, Binding หาย หรือ Endpoint ตั้งค่าผิด": "Possible rogue DHCP, ARP spoofing, wrong trusted uplink, missing binding, or endpoint misconfiguration.",
  "ตรวจสอบ Trusted Uplink, DHCP Snooping Binding Table, VLAN, ARP Inspection Log และ Change ล่าสุดบน Switch": "Check trusted uplinks, DHCP Snooping binding table, VLAN configuration, ARP inspection logs, and recent switch changes.",
  "Spanning Tree ตรวจพบ Topology Change, BPDU Event หรือ Port State เปลี่ยน": "Spanning Tree detected a topology change, BPDU event, or port state transition.",
  "Network อาจมี Packet Loss ชั่วคราว, Port ถูก Block หรือเส้นทาง Layer 2 ไม่เสถียร": "Network may experience temporary packet loss, blocked ports, or unstable Layer 2 paths.",
  "ตรวจสอบ Root Bridge, PortFast, BPDU Guard, Loop Guard, Uplink Topology และ Port ที่เปลี่ยนสถานะ": "Check root bridge, PortFast, BPDU Guard, Loop Guard, uplink topology, and the port that changed state.",
  "พบ Interface เปลี่ยนสถานะหรือถูก Disable": "A network interface changed state or was disabled.",
  "ผู้ใช้, AP, Uplink, Switch ปลายทาง หรือ Server ที่เชื่อมต่อกับ Port นี้อาจหลุดจากระบบ": "Connected users, APs, uplinks, downstream switches, or servers may lose connectivity.",
  "ตรวจสอบสาย, SFP, Port Error, ไฟเลี้ยงอุปกรณ์ปลายทาง, Interface Counter, สาเหตุ Err-disable และ Maintenance ล่าสุด": "Check cable, SFP, port errors, remote device power, interface counters, err-disable reason, and recent maintenance.",
  "Port Security ตรวจพบ MAC Address ที่ไม่ได้รับอนุญาตหรือเกิด Violation": "Port security detected an unauthorized MAC address or violation.",
  "Port อาจถูก Restrict หรือ Shutdown ทำให้อุปกรณ์ใช้งานไม่ได้ หรืออาจมีอุปกรณ์ไม่ได้รับอนุญาตมาต่อเข้าระบบ": "The switch port may be restricted or shut down, causing outage or indicating an unauthorized device.",
  "ตรวจสอบอุปกรณ์ที่ต่ออยู่, MAC Address ที่เรียนรู้, ค่า Port-Security, Violation Mode และ Clear Err-disable หลังยืนยันว่าอุปกรณ์ถูกต้องเท่านั้น": "Verify connected device, learned MAC, port-security settings, violation mode, and clear err-disable only after confirming legitimacy.",
  "พบ Routing Neighbor หรือ Gateway Redundancy เปลี่ยนสถานะ": "A routing or gateway redundancy adjacency changed state.",
  "Traffic อาจเปลี่ยนเส้นทาง, Failover, Flap หรือขาดการเชื่อมต่อ ขึ้นอยู่กับ Topology": "Traffic may reroute, fail over, flap, or lose reachability depending on topology.",
  "ตรวจสอบ Physical Link, Peer Reachability, Timer, Authentication, Routing Policy, CPU, Interface Error และ Change ล่าสุด": "Check physical link, peer reachability, timers, authentication, routing policy, CPU, interface errors, and recent changes.",
  "พบตัวบ่งชี้การพยายามดึง Credential หรือ Dump ข้อมูลยืนยันตัวตน": "Credential dumping indicators were detected.",
  "อาจทำให้รหัสผ่าน Hash, Token หรือ Credential ถูกนำไปใช้โจมตีต่อ": "Password hashes, tokens, or credentials may be stolen and reused.",
  "Isolate เครื่องที่เกี่ยวข้อง, เก็บ Memory/Process Evidence, ตรวจสอบบัญชีที่ใช้งานบนเครื่อง และบังคับเปลี่ยนรหัสผ่านบัญชีที่เสี่ยง": "Isolate affected host, collect memory/process evidence, review accounts used on the host, and force password changes for at-risk accounts.",
  "พบตัวบ่งชี้การเคลื่อนที่ภายในเครือข่ายหรือ Remote Execution": "Indicators of lateral movement or remote execution were detected.",
  "ผู้โจมตีอาจใช้บัญชีที่ได้มาเพื่อเข้าถึงเครื่องอื่นในระบบ": "Attackers may use obtained accounts to access other systems.",
  "ตรวจสอบ Source/Destination Host, Account ที่ใช้, SMB/RDP/WinRM Log, Endpoint Alert และจำกัดการเชื่อมต่อ East-West ที่ไม่จำเป็น": "Review source/destination hosts, account used, SMB/RDP/WinRM logs, endpoint alerts, and restrict unnecessary east-west connectivity.",
  "พบ Hash, Domain หรือ Indicator ที่ตรงกับ IOC ภายในระบบ": "Hash, domain, or indicator matched the local IOC list.",
  "อาจเกี่ยวข้องกับ Malware, C2, Phishing หรือไฟล์ต้องสงสัย": "May be related to malware, C2, phishing, or a suspicious file.",
  "กักกันไฟล์หรือเครื่องที่เกี่ยวข้อง, ตรวจสอบ Hash/Domain Reputation, ค้นหา Indicator เดียวกันทั้งองค์กร และบันทึก IOC ลง Incident Ticket": "Quarantine affected file/host, check hash/domain reputation, hunt the indicator across the organization, and document it in the incident ticket.",
  "พบ Sign-in หรือ Identity Event ที่มีความเสี่ยงบน Microsoft 365 / Entra ID": "Risky sign-in or identity events were detected in Microsoft 365 / Entra ID.",
  "บัญชีอาจถูกโจมตีด้วย Credential Stuffing, MFA Fatigue หรือ Login จากตำแหน่งผิดปกติ": "Accounts may be targeted by credential stuffing, MFA fatigue, or anomalous-location login.",
  "ตรวจสอบ Sign-in Log, Conditional Access, MFA Method, Risky Users และบังคับ Reset Password/Revoke Session หากจำเป็น": "Review sign-in logs, Conditional Access, MFA methods, risky users, and reset passwords/revoke sessions if needed.",
  "IP นี้อยู่ในรายการ IOC ภายใน เป็นแหล่งที่ควรตรวจสอบเพิ่มเติม": "This IP is listed in the local IOC list and should be investigated.",
  "IP นี้มีพฤติกรรมสแกนพอร์ตหรือ Probe Service": "This IP has scanning or service probing behavior.",
  "IP นี้ถูกใช้เป็นตัวอย่าง IOC สำหรับ Web Attack": "This IP is an IOC example for web attack activity.",
  "IP ตัวอย่างสำหรับ Path Traversal / Web Recon": "Example IP for path traversal / web reconnaissance.",
  "Domain นี้อยู่ในรายการ IOC ภายใน อาจเกี่ยวข้องกับ Malware C2 หรือ Phishing": "This domain is in the local IOC list and may be related to malware C2 or phishing.",
  "Domain นี้ถูกจัดเป็น C2 Indicator สำหรับทดสอบ Threat Intelligence": "This domain is classified as a C2 indicator for threat-intelligence testing.",
  "Hash นี้อยู่ใน IOC ภายใน อาจเป็นไฟล์ Malware หรือ Tool ที่ไม่ควรพบในระบบ": "This hash is in the local IOC list and may be malware or an unauthorized tool.",
  "Hash ตัวอย่างสำหรับทดสอบ Hash Reputation": "Example hash for hash reputation testing.",
  "พบ IOC ตรงกับรายการ": "IOC matched",
  "ข้อมูล IOC": "IOC context",
  "ไม่พบรูปแบบที่น่าสงสัยใน Log ที่ส่งเข้ามาวิเคราะห์": "No suspicious patterns were detected in the submitted log window.",
  "คะแนนความเสี่ยง": "Risk score",
  "ประเด็นหลักที่ควรสนใจ": "Primary concern",
  "แหล่งที่พบมากที่สุด": "Top source",
  "เทคนิคที่พบ": "Observed techniques",
  "สรุปแบบ SOC Analyst": "SOC Analyst summary",
  "พบ": "Detected",
  "เหตุการณ์น่าสงสัย": "suspicious events",
  "ระดับความเสี่ยง": "risk level",
  "ประเด็นหลักคือ": "primary concern",
  "MITRE ที่เกี่ยวข้อง": "related MITRE techniques",
  "ยังไม่พบหลักฐานเพียงพอในการระบุสาเหตุ": "Insufficient evidence to determine a root cause",
  "หลักฐานสำคัญคือ": "key evidence",
  "จากบรรทัด": "from line",
  "สรุปสำหรับหัวหน้า": "Manager summary",
  "ระบบพบความเสี่ยงระดับ": "The system detected",
  "มี Critical": "with Critical",
  "รายการ และ High": "items and High",
  "รายการ": "items",
  "แนะนำให้ดำเนินการ": "recommended action",
  "ตรวจสอบ Log เพิ่มเติม": "review additional logs",
  "ตรวจสอบ Top Source IP จาก Event Table": "Check top source IP from the event table",
  "ตรวจ successful login หลังจาก failed attempts และ reset password บัญชีเสี่ยง": "Check successful logins after failed attempts and reset risky accounts",
  "ตรวจ Event ID 4624/4625/4672/4720/4740 ในช่วงเวลาเดียวกัน": "Check Event IDs 4624/4625/4672/4720/4740 in the same time window",
  "ตรวจ Firewall deny/drop, port scan และ interface/STP log ที่เกี่ยวข้อง": "Check firewall deny/drop, port scan, and related interface/STP logs",
  "ตรวจ access log, application log, database log และ WAF event รอบเวลาเดียวกัน": "Check access logs, application logs, database logs, and WAF events in the same time window",
  "หากไม่ใช่ traffic ที่จำเป็น": "if it is not required traffic",
  "ตรวจสอบและพิจารณา Block หากไม่กระทบงาน": "investigate and consider blocking if business impact is acceptable",
  "อยู่ใน IOC ภายใน": "is in the local IOC list",
  "ควรตรวจสอบเพิ่มเติม": "should be investigated further",
  "แหล่งที่ควรตรวจสอบเพิ่มเติม": "source that should be investigated further",
  "หรือ": "or",
  "และ": "and",
  "จาก": "from",
};

const EN_RULE_MAP: Record<string, string> = {
  "Windows: เข้าสู่ระบบสำเร็จ": "Windows: Successful Logon",
  "Windows: เข้าสู่ระบบไม่สำเร็จ": "Windows: Failed Logon",
  "Windows: มีการใช้สิทธิ์พิเศษ": "Windows: Special Privileges Assigned",
  "Windows: มีการสร้าง Process": "Windows: Process Creation",
  "Windows: มีการสร้างบัญชีใหม่": "Windows: Account Created",
  "Windows: เพิ่มผู้ใช้เข้ากลุ่มสิทธิ์สูง": "Windows: User Added to Privileged Group",
  "Windows: เพิ่มผู้ใช้เข้ากลุ่ม Local": "Windows: User Added to Local Group",
  "Windows: บัญชีถูกล็อก": "Windows: Account Locked",
  "Kerberos: มีการขอ Authentication Ticket": "Kerberos: Authentication Ticket Requested",
  "Kerberos: มีการขอ Service Ticket": "Kerberos: Service Ticket Requested",
  "SSH: พยายามเดารหัสผ่าน": "SSH Brute Force",
  "SSH: เข้าสู่ระบบสำเร็จ": "SSH Successful Login",
  "Firewall: Drop/Deny Traffic": "Firewall Drop / Deny Traffic",
  "Windows: PowerShell น่าสงสัย": "Windows Suspicious PowerShell",
  "Linux: พยายามใช้สิทธิ์สูงไม่สำเร็จ": "Linux Privilege / Sudo Failure",
  "Cisco: MAC Flapping": "Cisco MAC Flapping",
  "Cisco: DHCP Snooping / DAI Violation": "Cisco DHCP Snooping / DAI Violation",
  "Cisco: STP Topology Change": "Cisco STP Topology Change",
  "Cisco: Interface Down": "Cisco Interface Down",
  "Cisco: Port Security Violation": "Cisco Port Security Violation",
  "Routing: Adjacency Down": "Routing Adjacency Down",
  "Credential Dumping": "Credential Dumping",
  "Lateral Movement / Remote Services": "Lateral Movement / Remote Services",
  "Malware Indicator / IOC Match": "Malware Indicator / IOC Match",
  "Microsoft 365 Risky Sign-in": "Microsoft 365 Risky Sign-in",
  "Known Tor Exit Node / Suspicious Source": "Known Tor Exit Node / Suspicious Source",
  "Scanner / Recon Source": "Scanner / Recon Source",
  "Web Attack Source": "Web Attack Source",
  "Path Traversal Source": "Path Traversal Source",
  "Malicious Domain": "Malicious Domain",
  "Command and Control Domain": "Command and Control Domain",
  "Malware Hash": "Malware Hash",
  "Suspicious Hash": "Suspicious Hash",
  "SSH Brute Force": "SSH Brute Force",
  "Windows Brute Force": "Windows Brute Force",
  "Password Spray": "Password Spray",
  "Firewall Attack Burst": "Firewall Attack Burst",
  "Port Scan": "Port Scan",
  "Brute Force + Web Recon": "Brute Force + Web Recon",
  "Web Exploitation Chain": "Web Exploitation Chain",
  "IOC / Threat Intel Match": "IOC / Threat Intel Match",
  "Layer 2 Instability Cluster": "Layer 2 Instability Cluster",
  "Privilege Escalation Cluster": "Privilege Escalation Cluster",
  "Availability Degradation Spike": "Availability Degradation Spike",
};

function toEnglish(value: string): string {
  let output = value;

  Object.entries(EN_RULE_MAP)
    .sort((a, b) => b[0].length - a[0].length)
    .forEach(([thai, english]) => {
      output = output.split(thai).join(english);
    });

  Object.entries(EN_MAP)
    .sort((a, b) => b[0].length - a[0].length)
    .forEach(([thai, english]) => {
      output = output.split(thai).join(english);
    });

  output = output
    .replace(/(\d+) ครั้งภายใน 5 นาที/g, "$1 times within 5 minutes")
    .replace(/(\d+) ครั้ง/g, "$1 times")
    .replace(/(\d+) users/g, "$1 users")
    .replace(/(\d+) ports/g, "$1 ports")
    .replace(/แนะนำให้/g, "Recommended to")
    .replace(/ควร/g, "should")
    .replace(/ถูก Firewall Drop\/Deny ซ้ำ/g, "was repeatedly dropped/denied by the firewall")
    .replace(/พยายาม Login กับหลายบัญชี/g, "attempted login against multiple accounts")
    .replace(/เข้าข่าย Password Spray/g, "indicating password spraying")
    .replace(/บ่งชี้การสแกน Service/g, "indicating service scanning")
    .replace(/มีทั้ง Authentication Failure, Firewall\/Port Probe และ Web Attack ในชุด Log เดียวกัน เข้าข่าย Possible Coordinated Attack/g, "has authentication failures, firewall/port probes, and web attacks in the same log set, indicating a possible coordinated attack")
    .replace(/พยายามโจมตีเว็บหลายประเภท/g, "attempted multiple web attack classes")
    .replace(/ตรงกับ IOC หรือเกี่ยวข้องกับ Indicator ภายในจำนวน/g, "matched local IOC context or related indicators")
    .replace(/สัญญาณ Layer 2 หรือ Interface ไม่เสถียร/g, "Layer 2 or interface instability signals")
    .replace(/เหตุการณ์ที่เกี่ยวข้องกับ Availability จำนวน/g, "availability-related events")
    .replace(/เหตุการณ์เกี่ยวกับสิทธิ์สูง/g, "privilege-related events")
    .replace(/เช่น Event ID 4672 หรือการเพิ่มผู้ใช้เข้ากลุ่ม/g, "such as Event ID 4672 or group membership changes")
    .replace(/เข้าสู่ระบบ/g, "logon")
    .replace(/สำเร็จ/g, "successful")
    .replace(/ไม่สำเร็จ/g, "failed")
    .replace(/สร้าง/g, "created")
    .replace(/ตรวจสอบ/g, "review")
    .replace(/ผู้โจมตี/g, "attacker")
    .replace(/บัญชี/g, "account")
    .replace(/เครื่อง/g, "host");

  return output;
}

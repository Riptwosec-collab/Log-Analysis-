"use client";

import { useState, useEffect, useRef } from "react";
import Link from "next/link";
import type { AnalysisResult, Finding } from "@/lib/logAnalyzer";
import type { AnalysisSummary } from "@/lib/logAnalyzer";
import type { Language } from "@/lib/i18n";
import { UI, localize, severityLabel, severityClass, barClass } from "@/lib/i18n";
import SummaryCards from "./components/SummaryCards";
import CorrelationPanel from "./components/CorrelationPanel";
import FindingsTable from "./components/FindingsTable";
import ExportMenu from "./components/ExportMenu";
import TimelineChart from "./components/TimelineChart";
import WorldMap from "./components/WorldMap";
import MitreMatrix from "./components/MitreMatrix";
import CustomRulesEditor, { useCustomRules, serializeCustomRules } from "./components/CustomRulesEditor";
import IocManager, { useCustomIocs } from "./components/IocManager";
import WebhookSettings, { getWebhookConfig } from "./components/WebhookSettings";
import AuditLog from "./components/AuditLog";
import LogInputPanel from "./components/LogInputPanel";
import EvidenceDrawer from "./components/EvidenceDrawer";
import MitreCoverage from "./components/MitreCoverage";
import AiSummary from "./components/AiSummary";

type AnalystMode = keyof AnalysisSummary["analystReport"];
type Theme = "dark" | "light" | "cyberpunk" | "ocean" | "inferno" | "matrix";

const THEMES: Theme[] = ["dark", "light", "cyberpunk", "ocean", "inferno", "matrix"];
const THEME_META: Record<Theme, { icon: string; label: string; color: string }> = {
  dark:      { icon: "🌙", label: "Dark",      color: "#06b6d4" },
  light:     { icon: "☀️", label: "Light",     color: "#0891b2" },
  cyberpunk: { icon: "⚡", label: "Cyberpunk", color: "#a855f7" },
  ocean:     { icon: "🌊", label: "Ocean",     color: "#0ea5e9" },
  inferno:   { icon: "🔥", label: "Inferno",   color: "#ef4444" },
  matrix:    { icon: "💻", label: "Matrix",    color: "#00ff41" },
};

type HistoryEntry = {
  id: string;
  label: string;
  timestamp: string;
  riskScore: number;
  riskLevel: string;
  findingCount: number;
  result: AnalysisResult;
};

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

const analystModeOrder: AnalystMode[] = ["socAnalyst", "rca", "managerSummary", "fixCommand", "ticket"];

const analystModeLabels: Record<Language, Record<AnalystMode, string>> = {
  th: { socAnalyst: "Explain Like SOC Analyst", rca: "Generate RCA", managerSummary: "Generate Manager Summary", fixCommand: "Generate Fix Command", ticket: "Generate Ticket" },
  en: { socAnalyst: "Explain Like SOC Analyst", rca: "Generate RCA", managerSummary: "Generate Manager Summary", fixCommand: "Generate Fix Command", ticket: "Generate Ticket" },
};

function Metric({ label, value, tone = "default" }: { label: string; value: string; tone?: "default" | "critical" | "warning" }) {
  const color = tone === "critical" ? "text-red-300" : tone === "warning" ? "text-amber-300" : "text-white";
  return (
    <div className={`rounded-md border border-zinc-800 bg-black p-3 card-3d-sm${tone === "critical" ? " critical-glow" : ""}`}>
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
          <span key={item} className="rounded border border-zinc-700 px-2 py-1 text-xs text-zinc-300">{item}</span>
        ))}
      </div>
    </div>
  );
}

export default function SOCDashboard() {
  const [language, setLanguage] = useState<Language>("th");
  const [logInput, setLogInput] = useState(demoLog);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState("");
  const [vendorPreset, setVendorPreset] = useState("Auto");
  const [analystMode, setAnalystMode] = useState<AnalystMode>("socAnalyst");
  const [copyStatus, setCopyStatus] = useState("");
  const abortRef = useRef<AbortController | null>(null);

  const [theme, setTheme] = useState<Theme>("dark");
  const [showThemePicker, setShowThemePicker] = useState(false);
  const [progress, setProgress] = useState(0);
  const progressTimersRef = useRef<ReturnType<typeof setTimeout>[]>([]);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [fileLabels, setFileLabels] = useState<string[]>([]);
  const [vizTab, setVizTab] = useState<"geo" | "mitre" | "coverage">("geo");
  const [selectedFinding, setSelectedFinding] = useState<import("@/lib/logAnalyzer").Finding | null>(null);
  const [toolsTab, setToolsTab] = useState<"rules" | "ioc" | "webhook" | "audit">("rules");
  const [showTools, setShowTools] = useState(false);

  const { rules } = useCustomRules();
  const { iocs } = useCustomIocs();
  const t = UI[language];

  // Theme system
  useEffect(() => {
    const html = document.documentElement;
    html.classList.remove("light", "theme-cyberpunk", "theme-ocean", "theme-inferno", "theme-matrix");
    if (theme === "light") html.classList.add("light");
    else if (theme !== "dark") html.classList.add(`theme-${theme}`);
    localStorage.setItem("soc_theme", theme);
  }, [theme]);
  useEffect(() => {
    const saved = localStorage.getItem("soc_theme") as Theme | null;
    if (saved && THEMES.includes(saved)) { setTheme(saved); return; }
    // backward compat with old soc_dark key
    if (localStorage.getItem("soc_dark") === "0") setTheme("light");
  }, []);

  // History
  useEffect(() => {
    const h = localStorage.getItem("soc_history");
    if (h) { try { setHistory(JSON.parse(h)); } catch {} }
  }, []);

  // Persist last result
  useEffect(() => {
    const saved = localStorage.getItem("soc_last_result");
    if (saved) { try { setResult(JSON.parse(saved)); } catch {} }
  }, []);
  useEffect(() => {
    if (result) localStorage.setItem("soc_last_result", JSON.stringify(result));
  }, [result]);

  // Save history + auto-send webhook after analysis
  useEffect(() => {
    if (!result) return;
    const entry: HistoryEntry = {
      id: Date.now().toString(),
      label: logInput.slice(0, 50).replace(/\n/g, " "),
      timestamp: new Date().toLocaleString(),
      riskScore: result.summary.riskScore,
      riskLevel: result.summary.riskLevel,
      findingCount: result.findings.length,
      result,
    };
    setHistory((prev) => {
      const updated = [entry, ...prev].slice(0, 10);
      localStorage.setItem("soc_history", JSON.stringify(updated));
      return updated;
    });
    // Webhook auto-send
    try {
      const cfg = getWebhookConfig();
      const ranks: Record<string, number> = { Low: 1, Medium: 2, High: 3, Critical: 4 };
      if (cfg.enabled && cfg.url && result.summary.riskScore >= cfg.threshold &&
          ranks[result.summary.riskLevel] >= ranks[cfg.minSeverity]) {
        fetch("/api/webhook", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            webhookUrl: cfg.url,
            slackFormat: cfg.slackFormat,
            payload: {
              riskScore: result.summary.riskScore,
              riskLevel: result.summary.riskLevel,
              criticalAlerts: result.summary.criticalAlerts,
              findingCount: result.findings.length,
              topSourceIp: result.summary.topSourceIp,
              narrative: result.summary.incidentNarrative,
              generatedAt: result.generatedAt,
            },
          }),
        }).catch(() => {});
      }
    } catch {}
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [result]);

  async function analyzeText(log: string) {
    if (abortRef.current) abortRef.current.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setIsAnalyzing(true);
    setError("");
    setProgress(0);
    const steps = [8, 20, 35, 52, 68, 82, 93];
    const delays = [150, 400, 800, 1500, 2500, 4000, 6000];
    progressTimersRef.current.forEach(clearTimeout);
    progressTimersRef.current = steps.map((p, i) => setTimeout(() => setProgress(p), delays[i]));
    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ log, customRules: serializeCustomRules(rules), customIocs: iocs }),
        signal: controller.signal,
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || (language === "th" ? "วิเคราะห์ Log ไม่สำเร็จ" : "Log analysis failed"));
      }
      setResult(await res.json());
    } catch (e: any) {
      if (e.name !== "AbortError") setError(e.message || (language === "th" ? "วิเคราะห์ Log ไม่สำเร็จ" : "Log analysis failed"));
    } finally {
      progressTimersRef.current.forEach(clearTimeout);
      setProgress(100);
      setTimeout(() => setProgress(0), 600);
      setIsAnalyzing(false);
    }
  }

  function cancelAnalysis() {
    if (abortRef.current) abortRef.current.abort();
    progressTimersRef.current.forEach(clearTimeout);
    setProgress(0);
    setIsAnalyzing(false);
  }

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files ?? []);
    if (!files.length) return;
    const contents = await Promise.all(files.map((f) => f.text()));
    const combined = contents.join("\n");
    setLogInput(combined);
    setFileLabels(files.map((f) => f.name));
    await analyzeText(combined);
  };

  const handleVendorPreset = (preset: string) => {
    setVendorPreset(preset);
    setLogInput(vendorSamples[preset] || demoLog);
    setFileLabels([]);
    setResult(null);
    setError("");
  };

  const copyText = async (label: string, content: string) => {
    try {
      await navigator.clipboard.writeText(localize(content, language));
      setCopyStatus(`${label}: ${t.copied}`);
      window.setTimeout(() => setCopyStatus(""), 1800);
    } catch { setCopyStatus(t.copyFailed); }
  };

  const allFindings: Finding[] = result?.findings ?? [];
  const topFindings = allFindings.slice(0, 4);

  return (
    <main className="min-h-screen bg-zinc-950 text-zinc-100" style={{ backgroundColor: "var(--bg-primary)", color: "var(--text-primary)" }}>
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-6 px-4 py-6 sm:px-6 lg:px-8">

        {/* ── Header ── */}
        <header className="flex flex-col gap-4 border-b border-zinc-800 pb-5 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <div className="flex flex-wrap items-center gap-3">
              <p className="text-sm font-medium uppercase tracking-[0.2em] text-cyan-300">Log Analysis</p>
              <div className="flex items-center rounded-lg border border-zinc-800 bg-black p-1 text-xs">
                <span className="px-2 text-zinc-500">{t.language}</span>
                {(["th", "en"] as Language[]).map((lang) => (
                  <button key={lang} onClick={() => setLanguage(lang)}
                    className={`rounded-md px-3 py-1 ${language === lang ? "bg-cyan-500 text-zinc-950" : "text-zinc-300 hover:text-white"}`}>
                    {lang === "th" ? t.thai : t.english}
                  </button>
                ))}
              </div>
              <div className="relative">
                <button onClick={() => setShowThemePicker((s) => !s)}
                  className="rounded-md border border-zinc-700 bg-black px-3 py-1 text-sm hover:border-cyan-500 flex items-center gap-1.5"
                  title="Change theme">
                  <span>{THEME_META[theme].icon}</span>
                  <span className="text-zinc-300">{THEME_META[theme].label}</span>
                  <span className="text-zinc-600">▾</span>
                </button>
                {showThemePicker && (
                  <div className="absolute top-full left-0 mt-1 z-50 rounded-lg border border-zinc-700 bg-zinc-900 p-2 shadow-2xl grid grid-cols-2 gap-1 min-w-44"
                    onMouseLeave={() => setShowThemePicker(false)}>
                    {THEMES.map((t) => (
                      <button key={t} onClick={() => { setTheme(t); setShowThemePicker(false); }}
                        className={`rounded-md px-3 py-2 text-xs font-medium flex items-center gap-2 transition-colors ${theme === t ? "bg-cyan-500 text-zinc-950" : "hover:bg-zinc-800 text-zinc-300"}`}>
                        <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: THEME_META[t].color }} />
                        {THEME_META[t].icon} {THEME_META[t].label}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <button onClick={() => setShowHistory((s) => !s)}
                className={`rounded-md border px-3 py-1 text-sm ${showHistory ? "border-cyan-500 bg-cyan-500/10 text-cyan-200" : "border-zinc-700 bg-black text-zinc-300 hover:border-cyan-500"}`}>
                📋 History ({history.length})
              </button>
              <button onClick={() => setShowTools((s) => !s)}
                className={`rounded-md border px-3 py-1 text-sm ${showTools ? "border-violet-500 bg-violet-500/10 text-violet-200" : "border-zinc-700 bg-black text-zinc-300 hover:border-violet-500"}`}>
                ⚙️ Tools ({rules.filter((r) => r.enabled).length} rules · {iocs.length} IOCs)
              </button>
              <Link href="/review"
                className="rounded-md border border-zinc-700 bg-black px-3 py-1 text-sm text-zinc-300 hover:border-amber-500 hover:text-amber-300">
                ⭐ Reviews
              </Link>
              <Link href="/rules"
                className="rounded-md border border-zinc-700 bg-black px-3 py-1 text-sm text-zinc-300 hover:border-violet-500 hover:text-violet-300">
                📋 Rules
              </Link>
            </div>
            <h1 className="mt-2 text-3xl font-semibold text-white sm:text-4xl">{t.title}</h1>
            <p className="mt-2 max-w-3xl text-sm text-zinc-400">{t.subtitle}</p>
          </div>
          <div className="grid grid-cols-3 gap-2 sm:min-w-80">
            <Metric label="Rules" value="30+" />
            <Metric label="Types" value="15" />
            <Metric label="Intel" value="MITRE" />
          </div>
        </header>

        {/* ── History panel ── */}
        {showHistory && (
          <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 card-3d">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-lg font-semibold text-white">Session History</h2>
              <button onClick={() => { setHistory([]); localStorage.removeItem("soc_history"); }}
                className="text-xs text-red-400 hover:text-red-300">Clear All</button>
            </div>
            {history.length === 0 ? (
              <p className="text-sm text-zinc-500">No sessions yet.</p>
            ) : (
              <div className="space-y-2 max-h-80 overflow-y-auto">
                {history.map((entry) => (
                  <div key={entry.id}
                    className="flex items-center justify-between rounded-md border border-zinc-800 bg-black p-3 cursor-pointer hover:border-cyan-700"
                    onClick={() => { setResult(entry.result); setShowHistory(false); }}>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-zinc-200 truncate">{entry.label}</p>
                      <p className="text-xs text-zinc-500 mt-1">{entry.timestamp} · {entry.findingCount} findings</p>
                    </div>
                    <div className="flex items-center gap-3 ml-4 shrink-0">
                      <span className={`text-xs font-semibold px-2 py-1 rounded ${
                        entry.riskLevel === "Critical" ? "bg-red-900 text-red-200" :
                        entry.riskLevel === "High" ? "bg-orange-900 text-orange-200" :
                        entry.riskLevel === "Medium" ? "bg-yellow-900 text-yellow-200" : "bg-green-900 text-green-200"}`}>
                        {entry.riskLevel} {entry.riskScore}
                      </span>
                      <button onClick={(e) => { e.stopPropagation(); const u = history.filter((h) => h.id !== entry.id); setHistory(u); localStorage.setItem("soc_history", JSON.stringify(u)); }}
                        className="text-zinc-600 hover:text-red-400 text-lg leading-none">×</button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ── Tools panel ── */}
        {showTools && (
          <div className="rounded-lg border border-violet-900 bg-zinc-900 p-4 card-3d">
            <div className="flex flex-wrap gap-2 mb-4">
              {(["rules", "ioc", "webhook", "audit"] as const).map((tab) => (
                <button key={tab} onClick={() => setToolsTab(tab)}
                  className={`rounded-md px-4 py-2 text-sm font-medium ${toolsTab === tab ? "bg-violet-600 text-white" : "border border-zinc-700 text-zinc-300 hover:border-violet-500"}`}>
                  {tab === "rules" ? "📋 Custom Rules" : tab === "ioc" ? "🎯 IOC Watchlist" : tab === "webhook" ? "🔔 Alerts" : "📊 Audit Log"}
                </button>
              ))}
            </div>
            {toolsTab === "rules" && <CustomRulesEditor language={language} t={t} />}
            {toolsTab === "ioc" && <IocManager language={language} t={t} />}
            {toolsTab === "webhook" && <WebhookSettings language={language} t={t} />}
            {toolsTab === "audit" && <AuditLog language={language} t={t} />}
          </div>
        )}

        {/* ── Log Input ── */}
        <section className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_340px]">
          <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 card-3d">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-white">{t.inputTitle}</h2>
              <span className="text-xs text-zinc-600">Apache · Nginx · SSH · Firewall · Windows · Syslog</span>
            </div>

            <LogInputPanel
              value={logInput}
              onChange={setLogInput}
              onAnalyze={() => analyzeText(logInput)}
              onClear={() => { setLogInput(""); setFileLabels([]); setResult(null); setError(""); }}
              isAnalyzing={isAnalyzing}
              language={language}
              fileLabels={fileLabels}
              setFileLabels={setFileLabels}
            />

            <div className="mt-3 flex flex-col gap-2 sm:flex-row">
              <button onClick={() => analyzeText(logInput)} disabled={isAnalyzing}
                className="rounded-md bg-cyan-500 px-5 py-2.5 text-sm font-semibold text-zinc-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-60 btn-3d">
                {isAnalyzing ? t.analyzing : `🔍 ${t.analyze}`}
              </button>
              {isAnalyzing && (
                <button onClick={cancelAnalysis}
                  className="rounded-md border border-red-700 px-4 py-2 text-sm font-semibold text-red-300 hover:border-red-500">
                  {t.cancel} ×
                </button>
              )}
            </div>

            {(isAnalyzing || progress > 0) && (
              <div className="mt-3">
                <div className="flex justify-between text-xs text-zinc-400 mb-1">
                  <span>{progress < 30 ? "Parsing lines..." : progress < 60 ? "Matching rules..." : progress < 88 ? "Correlating events..." : "Building report..."}</span>
                  <span>{progress}%</span>
                </div>
                <div className="w-full h-1.5 rounded-full bg-zinc-800">
                  <div className="h-1.5 rounded-full transition-all duration-500"
                    style={{ width: `${progress}%`, background: progress < 50 ? "var(--accent)" : progress < 85 ? "#8b5cf6" : "#10b981" }} />
                </div>
              </div>
            )}

            {copyStatus && <p className="mt-3 text-sm text-cyan-300">{copyStatus}</p>}
            {error && <p className="mt-3 rounded-md border border-red-900 bg-red-950/60 p-3 text-sm text-red-200">{error}</p>}
          </div>

          {result ? (
            <SummaryCards summary={result.summary} language={language} t={t} />
          ) : (
            <aside className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 card-3d">
              <h2 className="text-lg font-semibold text-white">{t.overview}</h2>
              <div className="mt-4 grid grid-cols-2 gap-3">
                <Metric label={t.riskScore} value="0" />
                <Metric label={t.totalEvents} value="0" />
                <Metric label={t.suspicious} value="0" />
                <Metric label={t.critical} value="0" tone="critical" />
                <Metric label={t.failedLogin} value="0" tone="warning" />
                <Metric label={t.correlation} value="0" />
              </div>
              <div className="mt-4 rounded-md border border-zinc-800 bg-black p-3">
                <p className="text-xs uppercase tracking-[0.18em] text-zinc-500">{t.topSourceIp}</p>
                <p className="mt-2 font-mono text-lg text-cyan-300">{t.none}</p>
              </div>
            </aside>
          )}
        </section>

        {result && (
          <>
            {/* ── Incident Intel + Correlations ── */}
            <section className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_420px]">
              <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 card-3d">
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
                  <IntelList title={t.topRules} items={result.summary.topRules.map((r) => `${localize(r.rule, language)} (${r.count})`)} />
                  <IntelList title={t.mitreTechnique} items={result.summary.mitreTechniques} />
                  <IntelList title={t.affectedUsers} items={result.summary.affectedUsers.length ? result.summary.affectedUsers : [t.none]} />
                </div>
                <div className="mt-4 rounded-md border border-zinc-800 bg-black p-3">
                  <p className="text-xs uppercase tracking-[0.18em] text-zinc-500">{t.priorityAction}</p>
                  <div className="mt-3 grid gap-2 md:grid-cols-2">
                    {result.summary.recommendedActions.slice(0, 4).map((action) => (
                      <p key={action} className="border-l-2 border-cyan-500 pl-3 text-sm leading-5 text-zinc-300">{localize(action, language)}</p>
                    ))}
                  </div>
                </div>
                <div className="mt-4 rounded-md border border-zinc-800 bg-black p-3">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                    <p className="text-xs uppercase tracking-[0.18em] text-zinc-500">{t.analystMode}</p>
                    <button className="rounded-md border border-zinc-700 px-3 py-2 text-xs hover:border-cyan-500"
                      onClick={() => copyText(analystModeLabels[language][analystMode], result.summary.analystReport[analystMode])}>
                      {t.copyOutput}
                    </button>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {analystModeOrder.map((mode) => (
                      <button key={mode} onClick={() => setAnalystMode(mode)}
                        className={`rounded-md border px-3 py-2 text-xs ${analystMode === mode ? "border-cyan-500 bg-cyan-500/10 text-cyan-200" : "border-zinc-700 text-zinc-300 hover:border-cyan-500"}`}>
                        {analystModeLabels[language][mode]}
                      </button>
                    ))}
                  </div>
                  <pre className="mt-3 max-h-72 overflow-auto whitespace-pre-wrap rounded-md border border-zinc-800 bg-zinc-950 p-3 text-sm leading-6 text-zinc-200">
                    {localize(result.summary.analystReport[analystMode], language)}
                  </pre>
                </div>
              </div>
              <CorrelationPanel correlations={result.summary.correlations} language={language} t={t} />
            </section>

            {/* ── AI Summary ── */}
            <AiSummary result={result} language={language} />

            {/* ── Geo Map / MITRE Matrix / Coverage ── */}
            <section className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 card-3d">
              <div className="flex flex-wrap gap-2 mb-4">
                {([
                  { id: "geo",      label: "🌍 Geo Map" },
                  { id: "mitre",    label: "🗂️ MITRE Matrix" },
                  { id: "coverage", label: "🛡️ ATT&CK Coverage" },
                ] as const).map(({ id, label }) => (
                  <button key={id} onClick={() => setVizTab(id)}
                    className={`rounded-md px-4 py-2 text-sm font-medium ${vizTab === id ? "bg-cyan-500 text-zinc-950" : "border border-zinc-700 text-zinc-300 hover:border-cyan-500"}`}>
                    {label}
                  </button>
                ))}
              </div>
              {vizTab === "geo" && <WorldMap findings={result.findings} language={language} t={t} />}
              {vizTab === "mitre" && <MitreMatrix mitreTechniques={result.summary.mitreTechniques} findings={result.findings} language={language} t={t} />}
              {vizTab === "coverage" && <MitreCoverage findings={result.findings} mitreTechniques={result.summary.mitreTechniques} language={language} t={t} />}
            </section>

            {/* ── Findings Table + Timeline/Recommendations ── */}
            <section className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_340px]">
              <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 card-3d">
                <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                  <div className="flex items-center gap-3">
                    <h2 className="text-lg font-semibold text-white">{t.eventTable}</h2>
                    <button onClick={() => { localStorage.removeItem("soc_last_result"); setResult(null); }}
                      className="rounded-md border border-zinc-700 px-3 py-1 text-xs text-zinc-400 hover:border-red-500 hover:text-red-300">
                      {t.clearSession}
                    </button>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <ExportMenu result={result} findings={allFindings} language={language} t={t} />
                    <button onClick={() => copyText("RCA", result.summary.analystReport.rca)}
                      className="rounded-md border border-zinc-700 px-3 py-2 text-sm hover:border-cyan-500">{t.copyRca}</button>
                    <button onClick={() => copyText("Summary", result.summary.analystReport.managerSummary)}
                      className="rounded-md border border-zinc-700 px-3 py-2 text-sm hover:border-cyan-500">{t.copySummary}</button>
                  </div>
                </div>
                <FindingsTable findings={allFindings} language={language} t={t} localize={localize} onViewEvidence={(f) => setSelectedFinding(f)} />
              </div>

              <div className="space-y-4">
                <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 card-3d">
                  <h2 className="text-lg font-semibold text-white mb-3">{t.timeline}</h2>
                  {result.summary.timeline.length === 0 ? (
                    <p className="text-sm text-zinc-500">{t.noTimestamp}</p>
                  ) : (
                    <TimelineChart timeline={result.summary.timeline} language={language} t={t} />
                  )}
                </div>
                <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 card-3d">
                  <h2 className="text-lg font-semibold text-white">{t.recommendations}</h2>
                  <div className="mt-4 space-y-3">
                    {topFindings.map((finding) => (
                      <div key={`${finding.id}-fix`} className="border-l-2 border-cyan-500 pl-3">
                        <p className="text-sm font-semibold text-white">{localize(finding.rule, language)}</p>
                        <p className="mt-1 text-sm leading-5 text-zinc-400">{localize(finding.recommendedFix, language)}</p>
                      </div>
                    ))}
                    {allFindings.length === 0 && <p className="text-sm text-zinc-500">{t.noRecommendation}</p>}
                  </div>
                </div>
              </div>
            </section>
          </>
        )}
      </div>

      {/* ── Evidence Drawer ── */}
      <EvidenceDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        language={language}
      />
    </main>
  );
}

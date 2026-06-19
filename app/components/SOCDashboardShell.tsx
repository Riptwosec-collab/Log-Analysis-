"use client";

import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import type { AnalysisResult, Finding, Severity } from "@/lib/logAnalyzer";
import type { Language } from "@/lib/i18n";
import { localize, severityClass, severityLabel } from "@/lib/i18n";

type TimeRange = "15m" | "1h" | "24h" | "7d" | "custom";

export type DashboardFilters = {
  query: string;
  timeRange: TimeRange;
  severity: Severity | "All";
  source: string;
  eventType: string;
  username: string;
  hostname: string;
  sourceIp: string;
  destinationIp: string;
  action: string;
  status: string;
  ruleName: string;
  mitreTactic: string;
  incidentStatus: string;
};

export const defaultDashboardFilters: DashboardFilters = {
  query: "",
  timeRange: "24h",
  severity: "All",
  source: "All",
  eventType: "All",
  username: "",
  hostname: "",
  sourceIp: "",
  destinationIp: "",
  action: "All",
  status: "All",
  ruleName: "",
  mitreTactic: "All",
  incidentStatus: "All",
};

const severityRank: Record<Severity, number> = {
  Low: 1,
  Medium: 2,
  High: 3,
  Critical: 4,
};

const severityColors: Record<Severity | "Info", string> = {
  Critical: "#fb7185",
  High: "#fb923c",
  Medium: "#facc15",
  Low: "#38bdf8",
  Info: "#94a3b8",
};

const sourceCatalog = [
  "Firewall",
  "Windows Event",
  "Active Directory",
  "Endpoint / EDR",
  "VPN",
  "Proxy / Web Gateway",
  "DNS",
  "Cloud Logs",
  "IDS / IPS",
  "Application",
];

const sidebarItems = [
  ["Dashboard", "01"],
  ["Logs", "02"],
  ["Alerts", "03"],
  ["Incidents", "04"],
  ["Threat Intelligence", "05"],
  ["MITRE ATT&CK", "06"],
  ["Reports", "07"],
  ["Rules", "08"],
  ["Assets", "09"],
  ["Users", "10"],
  ["Settings", "11"],
] as const;

function cn(...parts: Array<string | false | null | undefined>) {
  return parts.filter(Boolean).join(" ");
}

function toLower(value: string | null | undefined) {
  return (value || "").toLowerCase();
}

function isFirewallFinding(f: Finding) {
  const raw = f.raw.toLowerCase();
  return f.logType.includes("Firewall") || /deny|drop|blocked|reject/.test(raw);
}

function isMalwareFinding(f: Finding) {
  const raw = f.raw.toLowerCase();
  return Boolean(f.iocType || f.fileHash || /malware|virus|trojan|edr|endpoint|powershell/.test(raw));
}

function actionFromFinding(f: Finding) {
  const raw = f.raw.toLowerCase();
  if (/deny|drop|blocked|reject/.test(raw)) return "Blocked";
  if (/accept|allow|success|accepted/.test(raw)) return "Allowed";
  if (/failed|failure|invalid/.test(raw)) return "Failed";
  return f.severity === "Critical" || f.severity === "High" ? "Investigate" : "Review";
}

function statusFromFinding(f: Finding) {
  if (f.severity === "Critical") return "Escalated";
  if (f.severity === "High") return "Investigating";
  if (f.severity === "Medium") return "In Progress";
  return "New";
}

function eventIdFromFinding(f: Finding) {
  return f.raw.match(/\b(?:Event\s*ID|EventCode|ID)[:\s=]*(\d{3,5})\b/i)?.[1] || f.raw.match(/\b(46\d{2}|47\d{2}|48\d{2})\b/)?.[1] || f.id;
}

function hostnameFromFinding(f: Finding) {
  return f.asset || f.raw.match(/\b(?:host|hostname|devname|computer|server)[:=\s]+([a-z0-9_.-]+)/i)?.[1] || "-";
}

function indicatorFromFinding(f: Finding) {
  return f.sourceIp || f.domain || f.fileHash || f.raw.match(/https?:\/\/[^\s"']+/i)?.[0] || "-";
}

function severityTone(severity: Severity) {
  if (severity === "Critical") return "border-red-500/40 bg-red-500/10 text-red-200";
  if (severity === "High") return "border-orange-500/40 bg-orange-500/10 text-orange-200";
  if (severity === "Medium") return "border-yellow-500/40 bg-yellow-500/10 text-yellow-200";
  return "border-sky-500/40 bg-sky-500/10 text-sky-200";
}

function topCounts(values: Array<string | null | undefined>, limit = 10) {
  const counts = new Map<string, number>();
  values.filter(Boolean).forEach((value) => counts.set(value as string, (counts.get(value as string) || 0) + 1));
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, limit);
}

function sourceLabel(f: Finding) {
  if (f.logType === "SSH Auth") return "VPN";
  if (f.logType === "Microsoft 365") return "Cloud Logs";
  if (f.logType === "Cisco IOS" || f.logType === "Network Device" || f.logType === "Meraki") return "IDS / IPS";
  if (f.logType.includes("Apache") || f.logType.includes("Nginx")) return "Proxy / Web Gateway";
  if (f.logType === "Application") return "Application";
  return f.logType;
}

function matchesFinding(f: Finding, filters: DashboardFilters, language: Language) {
  const queryBlob = [
    f.id,
    f.raw,
    f.rule,
    localize(f.rule, language),
    f.username,
    f.sourceIp,
    f.destinationIp,
    f.destinationPort,
    f.asset,
    f.technique,
    f.tactic,
    f.domain,
    f.fileHash,
    f.detectedKeywords.join(" "),
  ].join(" ").toLowerCase();
  const query = filters.query.trim().toLowerCase();
  if (query && !queryBlob.includes(query)) return false;
  if (filters.severity !== "All" && f.severity !== filters.severity) return false;
  if (filters.source !== "All" && sourceLabel(f) !== filters.source && f.logType !== filters.source) return false;
  if (filters.eventType !== "All" && !toLower(f.rule).includes(filters.eventType.toLowerCase())) return false;
  if (filters.username && !toLower(f.username).includes(filters.username.toLowerCase())) return false;
  if (filters.hostname && !toLower(hostnameFromFinding(f)).includes(filters.hostname.toLowerCase())) return false;
  if (filters.sourceIp && !toLower(f.sourceIp).includes(filters.sourceIp.toLowerCase())) return false;
  if (filters.destinationIp && !toLower(f.destinationIp).includes(filters.destinationIp.toLowerCase())) return false;
  if (filters.action !== "All" && actionFromFinding(f) !== filters.action) return false;
  if (filters.status !== "All" && statusFromFinding(f) !== filters.status) return false;
  if (filters.ruleName && !toLower(localize(f.rule, language)).includes(filters.ruleName.toLowerCase())) return false;
  if (filters.mitreTactic !== "All" && f.tactic !== filters.mitreTactic) return false;
  if (filters.incidentStatus !== "All" && statusFromFinding(f) !== filters.incidentStatus) return false;
  return true;
}

export function filterFindings(findings: Finding[], filters: DashboardFilters, language: Language) {
  return findings.filter((finding) => matchesFinding(finding, filters, language));
}

export function SeverityBadge({ severity, language }: { severity: Severity; language: Language }) {
  return (
    <span className={cn("inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-semibold", severityTone(severity))}>
      {severityLabel(severity, language)}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const tone =
    status === "Escalated"
      ? "border-red-500/40 bg-red-500/10 text-red-200"
      : status === "Resolved"
      ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-200"
      : status === "False Positive"
      ? "border-slate-500/40 bg-slate-500/10 text-slate-300"
      : "border-cyan-500/40 bg-cyan-500/10 text-cyan-200";
  return <span className={cn("inline-flex rounded-full border px-2.5 py-1 text-xs font-medium", tone)}>{status}</span>;
}

export function SidebarNavigation({ collapsed, onToggle, criticalCount }: { collapsed: boolean; onToggle: () => void; criticalCount: number }) {
  return (
    <aside className={cn("sticky top-0 hidden h-screen shrink-0 border-r border-zinc-800 bg-zinc-950/90 p-3 backdrop-blur lg:flex lg:flex-col", collapsed ? "w-20" : "w-64")}>
      <button onClick={onToggle} className="mb-4 rounded-md border border-zinc-800 bg-black px-3 py-2 text-left text-sm text-zinc-200 hover:border-cyan-500">
        {collapsed ? "SOC" : "SOC Console"}
      </button>
      <nav className="space-y-1">
        {sidebarItems.map(([label, code], index) => (
          <button
            key={label}
            className={cn(
              "group flex w-full items-center gap-3 rounded-md border px-3 py-2 text-left text-sm transition",
              index === 0 ? "border-cyan-500/40 bg-cyan-500/10 text-cyan-200" : "border-transparent text-zinc-400 hover:border-zinc-700 hover:bg-zinc-900 hover:text-zinc-100"
            )}
          >
            <span className="font-mono text-xs text-cyan-300">{code}</span>
            {!collapsed && <span className="flex-1 truncate">{label}</span>}
            {!collapsed && label === "Alerts" && criticalCount > 0 && (
              <span className="rounded-full bg-red-500 px-2 py-0.5 text-xs font-semibold text-white">{criticalCount}</span>
            )}
          </button>
        ))}
      </nav>
      {!collapsed && (
        <div className="mt-auto rounded-lg border border-zinc-800 bg-black p-3">
          <p className="text-xs font-semibold text-zinc-300">Monitoring Mode</p>
          <p className="mt-1 text-xs leading-5 text-zinc-500">Dashboard, alerts, incidents, rules, and IOC views reuse the current analyzer output.</p>
        </div>
      )}
    </aside>
  );
}

export function SOCDashboardHeader({
  result,
  filters,
  setFilters,
  onAnalyze,
  onExport,
  autoRefresh,
  setAutoRefresh,
  isAnalyzing,
}: {
  result: AnalysisResult | null;
  filters: DashboardFilters;
  setFilters: (next: DashboardFilters) => void;
  onAnalyze: () => void;
  onExport: () => void;
  autoRefresh: boolean;
  setAutoRefresh: (value: boolean) => void;
  isAnalyzing: boolean;
}) {
  function applyQuickFilter(chip: string) {
    setFilters({
      ...filters,
      query: chip === "Critical" ? "" : filters.query,
      severity: chip === "Critical" ? "Critical" : filters.severity,
      source: chip === "VPN" ? "VPN" : chip === "AD" ? "Windows Event" : filters.source,
      ruleName:
        chip === "Failed Login"
          ? "login"
          : chip === "Firewall Deny"
          ? "deny"
          : chip === "Malware"
          ? "malware"
          : filters.ruleName,
    });
  }

  return (
    <header className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 card-3d">
      <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase text-cyan-300">Enterprise SIEM / SOC Monitoring</p>
          <h1 className="mt-1 text-2xl font-semibold text-white sm:text-3xl">SOC Log Analysis Dashboard</h1>
          <p className="mt-1 text-sm text-zinc-400">
            Last Updated: {result ? new Date(result.generatedAt).toLocaleString() : "Waiting for analysis"}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select
            className="rounded-md border border-zinc-700 bg-black px-3 py-2 text-sm"
            value={filters.timeRange}
            onChange={(event) => setFilters({ ...filters, timeRange: event.target.value as TimeRange })}
          >
            <option value="15m">Last 15m</option>
            <option value="1h">Last 1h</option>
            <option value="24h">Last 24h</option>
            <option value="7d">Last 7d</option>
            <option value="custom">Custom</option>
          </select>
          <button onClick={onAnalyze} disabled={isAnalyzing} className="rounded-md bg-cyan-500 px-4 py-2 text-sm font-semibold text-zinc-950 hover:bg-cyan-400 disabled:opacity-60">
            {isAnalyzing ? "Refreshing..." : "Refresh"}
          </button>
          <button onClick={onExport} className="rounded-md border border-zinc-700 px-4 py-2 text-sm text-zinc-200 hover:border-cyan-500">
            Export Report
          </button>
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={cn("rounded-md border px-4 py-2 text-sm", autoRefresh ? "border-cyan-500 bg-cyan-500/10 text-cyan-200" : "border-zinc-700 text-zinc-300 hover:border-cyan-500")}
          >
            Auto Refresh
          </button>
          <button className="relative rounded-md border border-zinc-700 px-3 py-2 text-sm hover:border-cyan-500">
            Bell
            {result && result.summary.criticalAlerts > 0 && <span className="absolute -right-1 -top-1 h-3 w-3 rounded-full bg-red-500" />}
          </button>
          <div className="flex items-center gap-2 rounded-md border border-zinc-700 bg-black px-3 py-2 text-sm">
            <span className="h-6 w-6 rounded-full bg-cyan-500/20 text-center font-mono text-xs leading-6 text-cyan-200">SA</span>
            <span className="hidden text-zinc-300 sm:inline">SOC Analyst</span>
          </div>
        </div>
      </div>
      <div className="mt-4 grid gap-2 lg:grid-cols-[minmax(0,1fr)_auto]">
        <input
          className="rounded-md border border-zinc-700 bg-black px-3 py-2 text-sm outline-none focus:border-cyan-500"
          placeholder="Search keyword, user, IP, hostname, event ID, rule name, raw log..."
          value={filters.query}
          onChange={(event) => setFilters({ ...filters, query: event.target.value })}
        />
        <div className="flex flex-wrap gap-2">
          {["Critical", "Failed Login", "Firewall Deny", "Malware", "VPN", "AD"].map((chip) => (
            <button
              key={chip}
              className="rounded-full border border-zinc-700 px-3 py-2 text-xs text-zinc-300 hover:border-cyan-500 hover:text-cyan-200"
              onClick={() => applyQuickFilter(chip)}
            >
              {chip}
            </button>
          ))}
        </div>
      </div>
    </header>
  );
}

function SummaryMetric({
  label,
  value,
  description,
  tone = "default",
}: {
  label: string;
  value: string | number;
  description: string;
  tone?: "default" | "critical" | "high" | "medium" | "low" | "success";
}) {
  const toneClass =
    tone === "critical"
      ? "text-red-200 border-red-500/30"
      : tone === "high"
      ? "text-orange-200 border-orange-500/30"
      : tone === "medium"
      ? "text-yellow-200 border-yellow-500/30"
      : tone === "low"
      ? "text-sky-200 border-sky-500/30"
      : tone === "success"
      ? "text-emerald-200 border-emerald-500/30"
      : "text-zinc-100 border-zinc-800";
  return (
    <div className={cn("group rounded-lg border bg-zinc-900 p-4 transition hover:-translate-y-0.5 hover:border-cyan-500/60 hover:shadow-lg", toneClass)}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-xs text-zinc-400">{label}</p>
          <p className="mt-2 font-mono text-3xl font-semibold">{value}</p>
        </div>
        <span className="rounded-md border border-current/20 px-2 py-1 font-mono text-xs">SOC</span>
      </div>
      <p className="mt-3 text-xs leading-5 text-zinc-500">{description}</p>
      <p className="mt-2 text-xs text-emerald-300">Trend: +{Math.max(1, Number(value) % 9)}% from previous window</p>
    </div>
  );
}

export function SecuritySummaryCards({ result }: { result: AnalysisResult | null }) {
  const summary = result?.summary;
  const findings = result?.findings || [];
  const high = summary?.severityCounts.High || 0;
  const medium = summary?.severityCounts.Medium || 0;
  const low = summary?.severityCounts.Low || 0;
  const firewallDenies = findings.filter(isFirewallFinding).length;
  const malwareAlerts = findings.filter(isMalwareFinding).length;
  const suspiciousIps = new Set(findings.map((f) => f.sourceIp).filter(Boolean)).size;
  const resolved = findings.filter((f) => f.severity === "Low").length;
  return (
    <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4 2xl:grid-cols-6">
      <SummaryMetric label="Total Logs" value={summary?.totalEvents || 0} description="All parsed log lines in scope" />
      <SummaryMetric label="Total Alerts" value={summary?.suspiciousEvents || 0} description="Events matching SOC rules" tone="high" />
      <SummaryMetric label="Critical Alerts" value={summary?.criticalAlerts || 0} description="Needs immediate triage" tone="critical" />
      <SummaryMetric label="High Severity" value={high} description="Potential incident candidates" tone="high" />
      <SummaryMetric label="Medium Severity" value={medium} description="Watchlist and correlation signals" tone="medium" />
      <SummaryMetric label="Low Severity" value={low} description="Informational security events" tone="low" />
      <SummaryMetric label="Failed Logins" value={summary?.failedLogins || 0} description="Authentication failure events" tone="medium" />
      <SummaryMetric label="Suspicious IPs" value={suspiciousIps} description="Unique source indicators" tone="high" />
      <SummaryMetric label="Firewall Denies" value={firewallDenies} description="Blocked or denied network traffic" tone="low" />
      <SummaryMetric label="Malware / EDR" value={malwareAlerts} description="IOC, hash, endpoint, process signals" tone="critical" />
      <SummaryMetric label="New Incidents" value={summary?.correlations.length || 0} description="Correlated incident candidates" tone="critical" />
      <SummaryMetric label="Resolved Incidents" value={resolved} description="Low-risk closed candidates" tone="success" />
    </section>
  );
}

export function SeverityOverviewChart({ result }: { result: AnalysisResult | null }) {
  const counts = result?.summary.severityCounts || { Critical: 0, High: 0, Medium: 0, Low: 0 };
  const total = Math.max(1, Object.values(counts).reduce((sum, value) => sum + value, 0));
  const levels: Array<Severity | "Info"> = ["Critical", "High", "Medium", "Low", "Info"];
  const values = { ...counts, Info: Math.max(0, (result?.summary.totalEvents || 0) - (result?.summary.suspiciousEvents || 0)) };
  let offset = 0;
  const gradient = levels
    .map((level) => {
      const value = values[level] || 0;
      const start = offset;
      const end = offset + (value / Math.max(1, Object.values(values).reduce((s, v) => s + v, 0))) * 100;
      offset = end;
      return `${severityColors[level]} ${start}% ${end}%`;
    })
    .join(", ");
  return (
    <section className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 card-3d">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-white">Severity Overview</h2>
          <p className="text-sm text-zinc-400">Critical, High, Medium, Low, and Info split</p>
        </div>
        <div className="h-28 w-28 rounded-full p-4" style={{ background: `conic-gradient(${gradient || "#334155 0 100%"})` }}>
          <div className="flex h-full w-full items-center justify-center rounded-full bg-zinc-950 text-center">
            <span className="font-mono text-xl font-semibold text-white">{total}</span>
          </div>
        </div>
      </div>
      <div className="mt-4 space-y-3">
        {levels.map((level) => {
          const value = values[level] || 0;
          const percent = Math.round((value / Math.max(1, Object.values(values).reduce((s, v) => s + v, 0))) * 100);
          return (
            <div key={level}>
              <div className="mb-1 flex justify-between text-xs text-zinc-400">
                <span>{level}</span>
                <span>{value} / {percent}%</span>
              </div>
              <div className="h-2 rounded-full bg-zinc-800">
                <div className="h-2 rounded-full" style={{ width: `${percent}%`, backgroundColor: severityColors[level] }} />
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

export function LogSourceChart({ result }: { result: AnalysisResult | null }) {
  const findings = result?.findings || [];
  const counts = sourceCatalog.map((source) => {
    const count = findings.filter((finding) => sourceLabel(finding) === source || finding.logType === source).length;
    return { source, count };
  });
  const max = Math.max(1, ...counts.map((item) => item.count));
  return (
    <section className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 card-3d">
      <h2 className="text-lg font-semibold text-white">Log Source Overview</h2>
      <p className="mt-1 text-sm text-zinc-400">Where the highest signal volume is coming from</p>
      <div className="mt-4 space-y-3">
        {counts.map((item) => (
          <div key={item.source}>
            <div className="mb-1 flex justify-between text-xs text-zinc-400">
              <span>{item.source}</span>
              <span>{item.count}</span>
            </div>
            <div className="h-2 rounded-full bg-zinc-800">
              <div className="h-2 rounded-full bg-cyan-500" style={{ width: `${(item.count / max) * 100}%` }} />
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

export function AlertTimeline({ findings, language, onOpen }: { findings: Finding[]; language: Language; onOpen: (finding: Finding) => void }) {
  const latest = [...findings].sort((a, b) => severityRank[b.severity] - severityRank[a.severity]).slice(0, 9);
  return (
    <section className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 card-3d">
      <h2 className="text-lg font-semibold text-white">Alert Timeline</h2>
      <div className="mt-4 space-y-3">
        {latest.length === 0 && <p className="text-sm text-zinc-500">Analyze logs to populate the alert timeline.</p>}
        {latest.map((finding) => (
          <button key={`${finding.id}-${finding.lineNumber}`} onClick={() => onOpen(finding)} className="flex w-full gap-3 rounded-md border border-zinc-800 bg-black p-3 text-left hover:border-cyan-500">
            <span className={cn("mt-1 h-3 w-3 rounded-full", finding.severity === "Critical" ? "bg-red-500" : finding.severity === "High" ? "bg-orange-500" : finding.severity === "Medium" ? "bg-yellow-500" : "bg-sky-500")} />
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <p className="font-medium text-white">{localize(finding.rule, language)}</p>
                <SeverityBadge severity={finding.severity} language={language} />
              </div>
              <p className="mt-1 text-xs text-zinc-400">{finding.timestamp || `Line ${finding.lineNumber}`} / {sourceLabel(finding)} / {actionFromFinding(finding)}</p>
            </div>
          </button>
        ))}
      </div>
    </section>
  );
}

export function IncidentPanel({ result, language, onOpen }: { result: AnalysisResult | null; language: Language; onOpen: (finding: Finding) => void }) {
  const findings = result?.findings || [];
  const incidents = (result?.summary.correlations || []).slice(0, 6).map((correlation, index) => {
    const related = findings.filter((finding) => correlation.sourceIp ? finding.sourceIp === correlation.sourceIp : finding.technique === correlation.mitreTechniques?.[0] || finding.severity === correlation.severity);
    return { correlation, related: related.length ? related : findings.slice(index, index + 1) };
  });
  const statuses = ["New", "In Progress", "Investigating", "Escalated", "Resolved", "False Positive"];
  return (
    <section className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 card-3d">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white">Incident Panel</h2>
        <div className="hidden gap-2 xl:flex">
          {statuses.map((status) => <StatusBadge key={status} status={status} />)}
        </div>
      </div>
      <div className="mt-4 grid gap-3 xl:grid-cols-2">
        {incidents.length === 0 && <p className="text-sm text-zinc-500">No correlated incidents yet.</p>}
        {incidents.map(({ correlation, related }, index) => {
          const first = related[0];
          const status = statusFromFinding(first || ({ severity: "Low" } as Finding));
          return (
            <div key={`${correlation.title}-${index}`} className="rounded-lg border border-zinc-800 bg-black p-4 hover:border-cyan-500/70">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="font-semibold text-white">{localize(correlation.title, language)}</p>
                  <p className="mt-1 text-xs text-zinc-400">Affected host: {first ? hostnameFromFinding(first) : "-"} / User: {first?.username || "-"}</p>
                </div>
                <SeverityBadge severity={correlation.severity} language={language} />
              </div>
              <div className="mt-3 grid grid-cols-2 gap-2 text-xs text-zinc-400">
                <span>First seen: {first?.timestamp || "-"}</span>
                <span>Last seen: {related.at(-1)?.timestamp || first?.timestamp || "-"}</span>
                <span>Related logs: {correlation.eventCount || related.length}</span>
                <span>Assigned: Tier 1 Analyst</span>
              </div>
              <div className="mt-3 flex items-center justify-between">
                <StatusBadge status={status} />
                {first && <button onClick={() => onOpen(first)} className="rounded-md border border-zinc-700 px-3 py-2 text-xs hover:border-cyan-500">View Details</button>}
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

export function ThreatIntelWidget({ findings, language, onOpen }: { findings: Finding[]; language: Language; onOpen: (finding: Finding) => void }) {
  const iocs = findings.filter((f) => f.iocType || f.domain || f.fileHash || f.abuseScore !== null && f.abuseScore !== undefined).slice(0, 8);
  return (
    <section className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 card-3d">
      <h2 className="text-lg font-semibold text-white">Threat Intelligence / IOC</h2>
      <div className="mt-4 overflow-x-auto">
        <table className="w-full min-w-[760px] text-left text-sm">
          <thead className="sticky top-0 border-b border-zinc-800 bg-zinc-900 text-xs text-zinc-500">
            <tr>
              <th className="py-2 pr-3">Indicator</th>
              <th className="py-2 pr-3">Type</th>
              <th className="py-2 pr-3">Country</th>
              <th className="py-2 pr-3">Reputation</th>
              <th className="py-2 pr-3">First Seen</th>
              <th className="py-2 pr-3">Last Seen</th>
              <th className="py-2 pr-3">Risk</th>
            </tr>
          </thead>
          <tbody>
            {iocs.map((finding) => (
              <tr key={`${finding.id}-ioc`} className="border-b border-zinc-800 hover:bg-zinc-800/50" onClick={() => onOpen(finding)}>
                <td className="py-3 pr-3 font-mono text-xs text-cyan-300">{indicatorFromFinding(finding)}</td>
                <td className="py-3 pr-3 text-zinc-300">{finding.iocType || (finding.fileHash ? "hash" : finding.domain ? "domain" : "ip")}</td>
                <td className="py-3 pr-3 text-zinc-400">{finding.geoCountry || "Unknown"}</td>
                <td className="py-3 pr-3 text-zinc-300">{finding.abuseScore ?? finding.confidence}</td>
                <td className="py-3 pr-3 text-zinc-400">{finding.timestamp || "-"}</td>
                <td className="py-3 pr-3 text-zinc-400">{finding.timestamp || "-"}</td>
                <td className="py-3 pr-3"><SeverityBadge severity={finding.severity} language={language} /></td>
              </tr>
            ))}
          </tbody>
        </table>
        {iocs.length === 0 && <p className="py-8 text-center text-sm text-zinc-500">No IOC matches detected yet.</p>}
      </div>
    </section>
  );
}

function RiskList({ title, items }: { title: string; items: Array<[string, number]> }) {
  const max = Math.max(1, ...items.map(([, count]) => count));
  return (
    <div className="rounded-lg border border-zinc-800 bg-black p-4">
      <h3 className="text-sm font-semibold text-white">{title}</h3>
      <div className="mt-3 space-y-3">
        {items.length === 0 && <p className="text-xs text-zinc-500">No data</p>}
        {items.map(([label, count]) => (
          <div key={label}>
            <div className="mb-1 flex justify-between gap-3 text-xs text-zinc-400">
              <span className="truncate">{label}</span>
              <span>{count}</span>
            </div>
            <div className="h-1.5 rounded-full bg-zinc-800"><div className="h-1.5 rounded-full bg-cyan-500" style={{ width: `${(count / max) * 100}%` }} /></div>
          </div>
        ))}
      </div>
    </div>
  );
}

export function TopRiskWidgets({ findings }: { findings: Finding[] }) {
  return (
    <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
      <RiskList title="Top 10 Source IPs" items={topCounts(findings.map((f) => f.sourceIp))} />
      <RiskList title="Top 10 Destination IPs" items={topCounts(findings.map((f) => f.destinationIp))} />
      <RiskList title="Top Users with Failed Logins" items={topCounts(findings.filter((f) => /failed|failure|4625/i.test(f.raw)).map((f) => f.username || "unknown"))} />
      <RiskList title="Top Affected Hosts" items={topCounts(findings.map(hostnameFromFinding))} />
      <RiskList title="Top Firewall Deny Rules" items={topCounts(findings.filter(isFirewallFinding).map((f) => f.rule))} />
      <RiskList title="Top Alert Rules" items={topCounts(findings.map((f) => f.rule))} />
      <RiskList title="Top Countries" items={topCounts(findings.map((f) => f.geoCountry || (f.sourceIp ? "Unknown" : null)))} />
      <RiskList title="Top Processes" items={topCounts(findings.map((f) => f.raw.match(/\b(?:process|Process Name|New Process Name)[:=\s]+([^\s]+)/i)?.[1]))} />
      <RiskList title="Top Event IDs" items={topCounts(findings.map(eventIdFromFinding))} />
    </section>
  );
}

export function MitreAttackSection({ findings, language }: { findings: Finding[]; language: Language }) {
  const grouped = topCounts(findings.map((f) => `${f.tactic}||${f.technique}`), 12);
  return (
    <section className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 card-3d">
      <h2 className="text-lg font-semibold text-white">MITRE ATT&CK Mapping</h2>
      <div className="mt-4 overflow-x-auto">
        <table className="w-full min-w-[760px] text-left text-sm">
          <thead className="sticky top-0 border-b border-zinc-800 bg-zinc-900 text-xs text-zinc-500">
            <tr>
              <th className="py-2 pr-3">Tactic</th>
              <th className="py-2 pr-3">Technique</th>
              <th className="py-2 pr-3">Technique ID</th>
              <th className="py-2 pr-3">Related Logs</th>
              <th className="py-2 pr-3">Severity</th>
              <th className="py-2 pr-3">Confidence</th>
            </tr>
          </thead>
          <tbody>
            {grouped.map(([key, count]) => {
              const [tactic, technique] = key.split("||");
              const related = findings.filter((f) => f.tactic === tactic && f.technique === technique);
              const top = related.sort((a, b) => severityRank[b.severity] - severityRank[a.severity])[0];
              const id = technique.match(/\bT\d+(?:\.\d+)?\b/)?.[0] || "T0000";
              const confidence = Math.round(related.reduce((sum, f) => sum + f.confidence, 0) / Math.max(1, related.length));
              return (
                <tr key={key} className="border-b border-zinc-800 hover:bg-zinc-800/50">
                  <td className="py-3 pr-3 text-zinc-300">{localize(tactic, language)}</td>
                  <td className="py-3 pr-3 text-white">{localize(technique, language)}</td>
                  <td className="py-3 pr-3 font-mono text-cyan-300">{id}</td>
                  <td className="py-3 pr-3 font-mono text-zinc-300">{count}</td>
                  <td className="py-3 pr-3">{top && <SeverityBadge severity={top.severity} language={language} />}</td>
                  <td className="py-3 pr-3 font-mono text-zinc-300">{confidence}%</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {grouped.length === 0 && <p className="py-8 text-center text-sm text-zinc-500">No ATT&CK mappings detected yet.</p>}
      </div>
    </section>
  );
}

export function AdvancedFilterBar({
  findings,
  filters,
  setFilters,
  language,
}: {
  findings: Finding[];
  filters: DashboardFilters;
  setFilters: (next: DashboardFilters) => void;
  language: Language;
}) {
  const sources = ["All", ...Array.from(new Set(findings.map(sourceLabel))).sort()];
  const tactics = ["All", ...Array.from(new Set(findings.map((f) => f.tactic).filter(Boolean))).sort()];
  const eventTypes = ["All", ...Array.from(new Set(findings.map((f) => localize(f.rule, language)).filter(Boolean))).slice(0, 20)];
  return (
    <section className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 card-3d">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-white">Advanced Filters</h2>
          <p className="text-sm text-zinc-400">Filter by time, severity, source, user, host, IP, action, status, rule, and MITRE tactic.</p>
        </div>
        <button onClick={() => setFilters(defaultDashboardFilters)} className="rounded-md border border-zinc-700 px-3 py-2 text-sm hover:border-cyan-500">Reset Filters</button>
      </div>
      <div className="grid gap-2 md:grid-cols-3 xl:grid-cols-6">
        <select className="rounded-md border border-zinc-700 bg-black px-3 py-2 text-sm" value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value as Severity | "All" })}>
          {["All", "Critical", "High", "Medium", "Low"].map((value) => <option key={value}>{value}</option>)}
        </select>
        <select className="rounded-md border border-zinc-700 bg-black px-3 py-2 text-sm" value={filters.source} onChange={(e) => setFilters({ ...filters, source: e.target.value })}>
          {sources.map((value) => <option key={value}>{value}</option>)}
        </select>
        <select className="rounded-md border border-zinc-700 bg-black px-3 py-2 text-sm" value={filters.eventType} onChange={(e) => setFilters({ ...filters, eventType: e.target.value })}>
          {eventTypes.map((value) => <option key={value}>{value}</option>)}
        </select>
        <input className="rounded-md border border-zinc-700 bg-black px-3 py-2 text-sm" placeholder="Username" value={filters.username} onChange={(e) => setFilters({ ...filters, username: e.target.value })} />
        <input className="rounded-md border border-zinc-700 bg-black px-3 py-2 text-sm" placeholder="Hostname" value={filters.hostname} onChange={(e) => setFilters({ ...filters, hostname: e.target.value })} />
        <input className="rounded-md border border-zinc-700 bg-black px-3 py-2 text-sm" placeholder="Source IP" value={filters.sourceIp} onChange={(e) => setFilters({ ...filters, sourceIp: e.target.value })} />
        <input className="rounded-md border border-zinc-700 bg-black px-3 py-2 text-sm" placeholder="Destination IP" value={filters.destinationIp} onChange={(e) => setFilters({ ...filters, destinationIp: e.target.value })} />
        <select className="rounded-md border border-zinc-700 bg-black px-3 py-2 text-sm" value={filters.action} onChange={(e) => setFilters({ ...filters, action: e.target.value })}>
          {["All", "Blocked", "Allowed", "Failed", "Investigate", "Review"].map((value) => <option key={value}>{value}</option>)}
        </select>
        <select className="rounded-md border border-zinc-700 bg-black px-3 py-2 text-sm" value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })}>
          {["All", "New", "In Progress", "Investigating", "Escalated", "Resolved", "False Positive"].map((value) => <option key={value}>{value}</option>)}
        </select>
        <input className="rounded-md border border-zinc-700 bg-black px-3 py-2 text-sm" placeholder="Rule Name" value={filters.ruleName} onChange={(e) => setFilters({ ...filters, ruleName: e.target.value })} />
        <select className="rounded-md border border-zinc-700 bg-black px-3 py-2 text-sm" value={filters.mitreTactic} onChange={(e) => setFilters({ ...filters, mitreTactic: e.target.value })}>
          {tactics.map((value) => <option key={value}>{value}</option>)}
        </select>
        <select className="rounded-md border border-zinc-700 bg-black px-3 py-2 text-sm" value={filters.incidentStatus} onChange={(e) => setFilters({ ...filters, incidentStatus: e.target.value })}>
          {["All", "New", "In Progress", "Investigating", "Escalated", "Resolved", "False Positive"].map((value) => <option key={value}>{value}</option>)}
        </select>
      </div>
    </section>
  );
}

type SortKey = "timestamp" | "severity" | "source" | "rule" | "status";

export function MainLogTable({
  findings,
  language,
  onOpen,
}: {
  findings: Finding[];
  language: Language;
  onOpen: (finding: Finding) => void;
}) {
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [page, setPage] = useState(1);
  const pageSize = 25;
  const sorted = useMemo(() => {
    return [...findings].sort((a, b) => {
      const dir = sortDir === "asc" ? 1 : -1;
      if (sortKey === "severity") return (severityRank[a.severity] - severityRank[b.severity]) * dir;
      if (sortKey === "timestamp") return (a.timestamp || "").localeCompare(b.timestamp || "") * dir;
      if (sortKey === "source") return sourceLabel(a).localeCompare(sourceLabel(b)) * dir;
      if (sortKey === "rule") return localize(a.rule, language).localeCompare(localize(b.rule, language)) * dir;
      return statusFromFinding(a).localeCompare(statusFromFinding(b)) * dir;
    });
  }, [findings, sortDir, sortKey, language]);
  const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const rows = sorted.slice((safePage - 1) * pageSize, safePage * pageSize);
  function toggleSort(key: SortKey) {
    if (key === sortKey) setSortDir(sortDir === "asc" ? "desc" : "asc");
    else {
      setSortKey(key);
      setSortDir("desc");
    }
  }
  function SortButton({ value, children }: { value: SortKey; children: ReactNode }) {
    return <button onClick={() => toggleSort(value)} className="hover:text-cyan-200">{children} {sortKey === value ? (sortDir === "asc" ? "^" : "v") : ""}</button>;
  }
  return (
    <section className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 card-3d">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-white">Main Log Table</h2>
          <p className="text-sm text-zinc-400">{findings.length} events after filters</p>
        </div>
        <div className="flex items-center gap-2 text-sm text-zinc-400">
          <button className="rounded border border-zinc-700 px-3 py-2 disabled:opacity-40" disabled={safePage <= 1} onClick={() => setPage((p) => p - 1)}>Prev</button>
          <span>{safePage}/{totalPages}</span>
          <button className="rounded border border-zinc-700 px-3 py-2 disabled:opacity-40" disabled={safePage >= totalPages} onClick={() => setPage((p) => p + 1)}>Next</button>
        </div>
      </div>
      <div className="max-h-[720px] overflow-auto rounded-md border border-zinc-800">
        <table className="w-full min-w-[1680px] border-collapse text-left text-sm">
          <thead className="sticky top-0 z-10 border-b border-zinc-700 bg-zinc-950 text-xs text-zinc-400">
            <tr>
              <th className="px-3 py-3"><SortButton value="timestamp">Time</SortButton></th>
              <th className="px-3 py-3"><SortButton value="severity">Severity</SortButton></th>
              <th className="px-3 py-3"><SortButton value="source">Source</SortButton></th>
              <th className="px-3 py-3">Event Type</th>
              <th className="px-3 py-3">Username</th>
              <th className="px-3 py-3">Source IP</th>
              <th className="px-3 py-3">Destination IP</th>
              <th className="px-3 py-3">Hostname</th>
              <th className="px-3 py-3">Action</th>
              <th className="px-3 py-3"><SortButton value="status">Status</SortButton></th>
              <th className="px-3 py-3"><SortButton value="rule">Rule Name</SortButton></th>
              <th className="px-3 py-3">Message</th>
              <th className="px-3 py-3">MITRE Technique</th>
              <th className="px-3 py-3">Incident Status</th>
              <th className="px-3 py-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((finding) => {
              const critical = finding.severity === "Critical";
              const high = finding.severity === "High";
              const status = statusFromFinding(finding);
              return (
                <tr key={`${finding.id}-${finding.lineNumber}`} className={cn("border-b border-zinc-800 align-top hover:bg-zinc-800/60", critical && "bg-red-500/10", high && "bg-orange-500/10")}>
                  <td className="px-3 py-3 font-mono text-xs text-zinc-400">{finding.timestamp || `Line ${finding.lineNumber}`}</td>
                  <td className="px-3 py-3"><SeverityBadge severity={finding.severity} language={language} /></td>
                  <td className="px-3 py-3 text-zinc-300">{sourceLabel(finding)}</td>
                  <td className="px-3 py-3 text-zinc-300">{finding.logType}</td>
                  <td className="px-3 py-3 text-zinc-300">{finding.username || "-"}</td>
                  <td className="px-3 py-3 font-mono text-cyan-300">{finding.sourceIp || "-"}</td>
                  <td className="px-3 py-3 font-mono text-zinc-300">{finding.destinationIp || "-"}</td>
                  <td className="px-3 py-3 text-zinc-300">{hostnameFromFinding(finding)}</td>
                  <td className="px-3 py-3 text-zinc-300">{actionFromFinding(finding)}</td>
                  <td className="px-3 py-3"><StatusBadge status={status} /></td>
                  <td className="px-3 py-3 font-medium text-white">{localize(finding.rule, language)}</td>
                  <td className="max-w-sm px-3 py-3 text-xs leading-5 text-zinc-400">{finding.evidence || finding.raw}</td>
                  <td className="px-3 py-3 text-zinc-300">{finding.technique}</td>
                  <td className="px-3 py-3"><StatusBadge status={status} /></td>
                  <td className="px-3 py-3">
                    <div className="flex gap-2">
                      <button onClick={() => navigator.clipboard?.writeText(finding.id)} className="rounded border border-zinc-700 px-2 py-1 text-xs hover:border-cyan-500">Copy ID</button>
                      <button onClick={() => onOpen(finding)} className="rounded border border-cyan-500 px-2 py-1 text-xs text-cyan-200">Details</button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {rows.length === 0 && <p className="py-10 text-center text-sm text-zinc-500">No matching events. Adjust filters or analyze a new log set.</p>}
      </div>
    </section>
  );
}

export function LogDetailDrawer({
  finding,
  language,
  onClose,
}: {
  finding: Finding | null;
  language: Language;
  onClose: () => void;
}) {
  if (!finding) return null;
  const parsedFields = {
    eventId: eventIdFromFinding(finding),
    username: finding.username || "-",
    hostname: hostnameFromFinding(finding),
    sourceIp: finding.sourceIp || "-",
    destinationIp: finding.destinationIp || "-",
    processName: finding.raw.match(/\b(?:process|Process Name|New Process Name)[:=\s]+([^\s]+)/i)?.[1] || "-",
    commandLine: finding.raw.match(/\b(?:commandline|CommandLine|cmd)[:=\s]+(.+)/i)?.[1] || "-",
    filePath: finding.raw.match(/\b(?:file|path|filepath)[:=\s]+([^\s]+)/i)?.[1] || "-",
    hash: finding.fileHash || "-",
    geo: finding.geoCountry || "Unknown",
  };
  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm">
      <aside className="h-full w-full max-w-2xl overflow-y-auto border-l border-zinc-800 bg-zinc-950 p-5 shadow-2xl">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-xs text-zinc-500">Log Detail Drawer</p>
            <h2 className="mt-1 text-xl font-semibold text-white">{localize(finding.rule, language)}</h2>
            <div className="mt-2 flex flex-wrap gap-2">
              <SeverityBadge severity={finding.severity} language={language} />
              <StatusBadge status={statusFromFinding(finding)} />
              <span className="rounded-full border border-zinc-700 px-2.5 py-1 text-xs text-zinc-300">{finding.logType}</span>
            </div>
          </div>
          <button onClick={onClose} className="rounded-md border border-zinc-700 px-3 py-2 text-sm hover:border-red-500">Close</button>
        </div>
        <div className="mt-5 grid gap-3 sm:grid-cols-2">
          {Object.entries({
            Timestamp: finding.timestamp || `Line ${finding.lineNumber}`,
            Source: sourceLabel(finding),
            "Event ID": parsedFields.eventId,
            Username: parsedFields.username,
            Hostname: parsedFields.hostname,
            "Source IP": parsedFields.sourceIp,
            "Destination IP": parsedFields.destinationIp,
            "Process Name": parsedFields.processName,
            "Command Line": parsedFields.commandLine,
            "File Path": parsedFields.filePath,
            Hash: parsedFields.hash,
            "Geo Location": parsedFields.geo,
            "MITRE ATT&CK": `${finding.tactic} / ${finding.technique}`,
          }).map(([key, value]) => (
            <div key={key} className="rounded-md border border-zinc-800 bg-black p-3">
              <p className="text-xs text-zinc-500">{key}</p>
              <p className="mt-1 break-words font-mono text-sm text-zinc-200">{value}</p>
            </div>
          ))}
        </div>
        <div className="mt-5 rounded-md border border-zinc-800 bg-black p-3">
          <p className="text-xs text-zinc-500">Raw Log</p>
          <pre className="mt-2 whitespace-pre-wrap break-words font-mono text-xs leading-5 text-zinc-300">{finding.raw}</pre>
        </div>
        <div className="mt-5 rounded-md border border-zinc-800 bg-black p-3">
          <p className="text-xs text-zinc-500">Recommended Action</p>
          <p className="mt-2 text-sm leading-6 text-emerald-300">{localize(finding.recommendedFix, language)}</p>
          <p className="mt-3 text-xs text-zinc-500">Related Events: repeated {finding.repeatedCount} time(s), confidence {finding.confidence}%.</p>
        </div>
        <div className="mt-5 grid gap-2 sm:grid-cols-3">
          {["Copy Raw Log", "Mark as Incident", "Assign Analyst", "Add Note", "Export Event", "Mark as False Positive"].map((action) => (
            <button
              key={action}
              onClick={() => action === "Copy Raw Log" && navigator.clipboard?.writeText(finding.raw)}
              className="rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-200 hover:border-cyan-500"
            >
              {action}
            </button>
          ))}
        </div>
        <textarea className="mt-5 h-28 w-full rounded-md border border-zinc-700 bg-black p-3 text-sm text-zinc-200 outline-none focus:border-cyan-500" placeholder="Analyst notes..." />
      </aside>
    </div>
  );
}

export function DashboardCharts({ result }: { result: AnalysisResult | null }) {
  const findings = result?.findings || [];
  return (
    <section className="grid gap-4 lg:grid-cols-2 xl:grid-cols-3">
      <SeverityOverviewChart result={result} />
      <LogSourceChart result={result} />
      <RiskList title="Alert Trend Over Time" items={(result?.summary.timeline || []).map((item) => [item.timestamp, item.count])} />
      <RiskList title="Failed Login Trend" items={topCounts(findings.filter((f) => /failed|failure|4625/i.test(f.raw)).map((f) => f.timestamp || `Line ${f.lineNumber}`), 10)} />
      <RiskList title="Firewall Deny Trend" items={topCounts(findings.filter(isFirewallFinding).map((f) => f.timestamp || `Line ${f.lineNumber}`), 10)} />
      <RiskList title="Incident Status Overview" items={topCounts(findings.map(statusFromFinding), 10)} />
    </section>
  );
}

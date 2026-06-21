"use client";

import { useState } from "react";
import Link from "next/link";
import type { DetectionRule } from "@/types/log-analysis";

const DETECTION_RULES: DetectionRule[] = [
  // SSH
  { ruleId: "SSH-001", name: "SSH Brute Force",          description: "Multiple failed SSH login attempts from the same IP within a short window",          severity: "Critical", sourceType: "SSH Auth",      mitreTactic: "Credential Access",    mitreTechnique: "Brute Force",              mitreTechniqueId: "T1110",     enabled: true,  tags: ["ssh","brute-force","credential"],       recommendation: "Block source IP, enforce SSH key auth, enable fail2ban" },
  { ruleId: "SSH-002", name: "Password Spray",           description: "Failed logins across multiple accounts from a single IP — low per-account rate",      severity: "High",     sourceType: "SSH Auth",      mitreTactic: "Credential Access",    mitreTechnique: "Password Spraying",        mitreTechniqueId: "T1110.003", enabled: true,  tags: ["ssh","password-spray","credential"],    recommendation: "Alert on cross-account failures, enforce MFA" },
  { ruleId: "SSH-003", name: "Root Login Attempt",       description: "SSH login attempt for the root account",                                              severity: "High",     sourceType: "SSH Auth",      mitreTactic: "Privilege Escalation", mitreTechnique: "Valid Accounts",           mitreTechniqueId: "T1078",     enabled: true,  tags: ["ssh","root","privilege"],               recommendation: "Disable root SSH login, enforce sudo" },
  { ruleId: "SSH-004", name: "Invalid User Login",       description: "SSH login attempt for a non-existent system user",                                    severity: "Medium",   sourceType: "SSH Auth",      mitreTactic: "Credential Access",    mitreTechnique: "Brute Force",              mitreTechniqueId: "T1110",     enabled: true,  tags: ["ssh","invalid-user"],                   recommendation: "Monitor for credential enumeration patterns" },
  // Web
  { ruleId: "WEB-001", name: "SQL Injection",            description: "SQL injection pattern detected in HTTP request parameters",                           severity: "Critical", sourceType: "Apache/Nginx",  mitreTactic: "Initial Access",       mitreTechnique: "Exploit Public-Facing App", mitreTechniqueId: "T1190",     enabled: true,  tags: ["web","sqli","injection"],               recommendation: "Enable WAF, use parameterized queries, review DB logs" },
  { ruleId: "WEB-002", name: "Path Traversal",           description: "Directory traversal attempt to access files outside web root",                        severity: "High",     sourceType: "Apache/Nginx",  mitreTactic: "Discovery",            mitreTechnique: "File and Directory Discovery", mitreTechniqueId: "T1083",  enabled: true,  tags: ["web","path-traversal","lfi"],           recommendation: "Block ../ patterns, restrict web root access" },
  { ruleId: "WEB-003", name: "XSS Attempt",              description: "Cross-site scripting payload detected in request",                                    severity: "High",     sourceType: "Apache/Nginx",  mitreTactic: "Initial Access",       mitreTechnique: "Exploit Public-Facing App", mitreTechniqueId: "T1190",     enabled: true,  tags: ["web","xss","injection"],                recommendation: "Enable CSP, encode output, use XSS WAF rule" },
  { ruleId: "WEB-004", name: "Admin Path Scan",          description: "Scanning for admin panels and sensitive files (wp-admin, .env, config.php)",          severity: "Medium",   sourceType: "Apache/Nginx",  mitreTactic: "Reconnaissance",       mitreTechnique: "Active Scanning",          mitreTechniqueId: "T1595",     enabled: true,  tags: ["web","recon","admin-scan"],             recommendation: "Return 404 for all admin paths, restrict by IP" },
  { ruleId: "WEB-005", name: "Sensitive File Access",    description: "Access to sensitive configuration files (.env, .git, backup files)",                  severity: "Critical", sourceType: "Apache/Nginx",  mitreTactic: "Discovery",            mitreTechnique: "File and Directory Discovery", mitreTechniqueId: "T1083",  enabled: true,  tags: ["web","sensitive-file","recon"],         recommendation: "Block access to sensitive files via web server config" },
  // Firewall
  { ruleId: "FW-001",  name: "Firewall Port Scan",       description: "Multiple ports targeted from single source IP in rapid succession",                   severity: "High",     sourceType: "Firewall",      mitreTactic: "Discovery",            mitreTechnique: "Network Service Discovery", mitreTechniqueId: "T1046",    enabled: true,  tags: ["firewall","port-scan","recon"],         recommendation: "Block IP, enable IDS, review exposed ports" },
  { ruleId: "FW-002",  name: "Repeated Firewall DROP",   description: "Same source IP repeatedly hitting firewall DROP rules",                               severity: "Medium",   sourceType: "Firewall",      mitreTactic: "Reconnaissance",       mitreTechnique: "Active Scanning",          mitreTechniqueId: "T1595",     enabled: true,  tags: ["firewall","repeated-drop","recon"],     recommendation: "Auto-block after threshold, tune firewall rules" },
  { ruleId: "FW-003",  name: "Multi-Target Scan",        description: "Single IP attempting connections to multiple destination hosts",                       severity: "High",     sourceType: "Firewall",      mitreTactic: "Discovery",            mitreTechnique: "Network Service Discovery", mitreTechniqueId: "T1046",    enabled: true,  tags: ["firewall","lateral-scan","recon"],      recommendation: "Investigate for lateral movement attempt" },
  // Windows
  { ruleId: "WIN-001", name: "Windows Failed Logon",     description: "Windows Event ID 4625 — account logon failure",                                      severity: "Medium",   sourceType: "Windows Event", mitreTactic: "Credential Access",    mitreTechnique: "Brute Force",              mitreTechniqueId: "T1110",     enabled: true,  tags: ["windows","logon","credential"],         recommendation: "Enable lockout policy, investigate source address" },
  { ruleId: "WIN-002", name: "Privilege Assigned",       description: "Windows Event ID 4672 — special privileges assigned to new logon",                    severity: "High",     sourceType: "Windows Event", mitreTactic: "Privilege Escalation", mitreTechnique: "Valid Accounts",           mitreTechniqueId: "T1078",     enabled: true,  tags: ["windows","privilege","escalation"],     recommendation: "Verify if expected, review privileged account activity" },
  { ruleId: "WIN-003", name: "Account Created",          description: "Windows Event ID 4720 — a new user account was created",                              severity: "High",     sourceType: "Windows Event", mitreTactic: "Persistence",          mitreTechnique: "Create Account",           mitreTechniqueId: "T1136",     enabled: true,  tags: ["windows","account-creation","persistence"], recommendation: "Verify account creation was authorized, check group membership" },
  { ruleId: "WIN-004", name: "Account Locked Out",       description: "Windows Event ID 4740 — account lockout triggered",                                   severity: "Medium",   sourceType: "Windows Event", mitreTactic: "Credential Access",    mitreTechnique: "Password Spraying",        mitreTechniqueId: "T1110.003", enabled: true,  tags: ["windows","lockout","credential"],       recommendation: "Investigate source, reset and monitor account" },
  { ruleId: "WIN-005", name: "Suspicious Process",       description: "Windows Event ID 4688 — suspicious process (PowerShell encoded command, cmd)",        severity: "Critical", sourceType: "Windows Event", mitreTactic: "Execution",            mitreTechnique: "Command and Scripting Interpreter", mitreTechniqueId: "T1059", enabled: true, tags: ["windows","process","execution"],        recommendation: "Analyze command line, check for C2 connections, scan for malware" },
  { ruleId: "WIN-006", name: "Group Membership Change",  description: "Windows Event ID 4732 — user added to security group (e.g., Administrators)",        severity: "High",     sourceType: "Windows Event", mitreTactic: "Privilege Escalation", mitreTechnique: "Account Manipulation",     mitreTechniqueId: "T1098",     enabled: true,  tags: ["windows","group","privilege"],          recommendation: "Verify authorization, review group policy" },
  // Network
  { ruleId: "NET-001", name: "MAC Flapping",             description: "Layer 2 MAC address flapping — potential ARP spoofing or switch loop",                severity: "Medium",   sourceType: "Cisco IOS",     mitreTactic: "Lateral Movement",     mitreTechnique: "Adversary-in-the-Middle",  mitreTechniqueId: "T1557",     enabled: true,  tags: ["network","arp","layer2"],               recommendation: "Enable Dynamic ARP Inspection, check for rogue devices" },
  { ruleId: "NET-002", name: "DHCP Snooping Deny",       description: "Rogue DHCP server or ARP attack detected on network",                                 severity: "High",     sourceType: "Cisco IOS",     mitreTactic: "Lateral Movement",     mitreTechnique: "Adversary-in-the-Middle",  mitreTechniqueId: "T1557",     enabled: true,  tags: ["network","dhcp","layer2"],              recommendation: "Enable DHCP Snooping, check for rogue DHCP servers" },
  // Threat Intel
  { ruleId: "IOC-001", name: "IOC Match",                description: "Log entry matches a known IOC (IP, domain, hash) from threat intelligence",           severity: "Critical", sourceType: "Any",           mitreTactic: "Initial Access",       mitreTechnique: "External Remote Services", mitreTechniqueId: "T1133",     enabled: true,  tags: ["ioc","threat-intel","indicator"],       recommendation: "Block IOC, investigate affected systems, escalate to IR" },
];

const SEV_COLORS: Record<string, string> = {
  Critical: "text-red-400 border-red-900 bg-red-950/30",
  High:     "text-orange-400 border-orange-900 bg-orange-950/30",
  Medium:   "text-yellow-400 border-yellow-900 bg-yellow-950/30",
  Low:      "text-green-400 border-green-900 bg-green-950/30",
};

const SOURCE_COLORS: Record<string, string> = {
  "SSH Auth":      "text-cyan-400 bg-cyan-950/30 border-cyan-900",
  "Apache/Nginx":  "text-purple-400 bg-purple-950/30 border-purple-900",
  "Firewall":      "text-orange-400 bg-orange-950/30 border-orange-900",
  "Windows Event": "text-blue-400 bg-blue-950/30 border-blue-900",
  "Cisco IOS":     "text-emerald-400 bg-emerald-950/30 border-emerald-900",
  "Any":           "text-zinc-400 bg-zinc-800 border-zinc-700",
};

type Filter = "All" | "Critical" | "High" | "Medium" | "Low" | "SSH" | "Web" | "Firewall" | "Windows" | "Network";
const FILTERS: Filter[] = ["All", "Critical", "High", "Medium", "Low", "SSH", "Web", "Firewall", "Windows", "Network"];

function filterRules(rules: DetectionRule[], filter: Filter, search: string): DetectionRule[] {
  let filtered = rules;
  if (filter === "SSH")     filtered = filtered.filter((r) => r.ruleId.startsWith("SSH"));
  else if (filter === "Web")      filtered = filtered.filter((r) => r.ruleId.startsWith("WEB"));
  else if (filter === "Firewall") filtered = filtered.filter((r) => r.ruleId.startsWith("FW"));
  else if (filter === "Windows")  filtered = filtered.filter((r) => r.ruleId.startsWith("WIN"));
  else if (filter === "Network")  filtered = filtered.filter((r) => r.ruleId.startsWith("NET"));
  else if (["Critical","High","Medium","Low"].includes(filter)) {
    filtered = filtered.filter((r) => r.severity === filter);
  }
  if (search.trim()) {
    const q = search.toLowerCase();
    filtered = filtered.filter((r) =>
      r.name.toLowerCase().includes(q) ||
      r.description.toLowerCase().includes(q) ||
      r.mitreTechnique.toLowerCase().includes(q) ||
      r.mitreTechniqueId.toLowerCase().includes(q) ||
      r.tags.some((t) => t.includes(q))
    );
  }
  return filtered;
}

export default function RulesPage() {
  const [filter, setFilter] = useState<Filter>("All");
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);

  const rules = filterRules(DETECTION_RULES, filter, search);
  const enabledCount = DETECTION_RULES.filter((r) => r.enabled).length;

  return (
    <main className="min-h-screen bg-zinc-950 text-zinc-100" style={{ backgroundColor: "var(--bg-primary)", color: "var(--text-primary)" }}>
      <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6">

        {/* Header */}
        <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.2em] text-cyan-300">Detection Engine</p>
            <h1 className="mt-1 text-3xl font-semibold text-white">Detection Rules</h1>
            <p className="mt-1 text-sm text-zinc-400">
              {enabledCount} of {DETECTION_RULES.length} rules enabled · Sigma-compatible structure
            </p>
          </div>
          <Link
            href="/"
            className="self-start rounded-md border border-zinc-700 px-4 py-2 text-sm text-zinc-300 hover:border-cyan-500 hover:text-white"
          >
            ← Back to Dashboard
          </Link>
        </div>

        {/* Stats */}
        <div className="mb-6 grid grid-cols-4 gap-3">
          {(["Critical","High","Medium","Low"] as const).map((sev) => {
            const count = DETECTION_RULES.filter((r) => r.severity === sev).length;
            return (
              <button
                key={sev}
                onClick={() => setFilter(sev)}
                className={`rounded-lg border p-3 text-center card-3d-sm ${filter === sev ? SEV_COLORS[sev] : "border-zinc-800 bg-zinc-900 hover:border-zinc-600"}`}
              >
                <p className="text-xl font-bold text-white">{count}</p>
                <p className="text-xs text-zinc-500">{sev}</p>
              </button>
            );
          })}
        </div>

        {/* Filters + Search */}
        <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="flex flex-wrap gap-1.5">
            {FILTERS.map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`rounded-full border px-3 py-1 text-xs font-medium ${
                  filter === f
                    ? "border-cyan-500 bg-cyan-500/15 text-cyan-300"
                    : "border-zinc-700 text-zinc-400 hover:border-zinc-500"
                }`}
              >
                {f}
              </button>
            ))}
          </div>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search rules, MITRE ID, tags..."
            className="ml-auto w-full max-w-64 rounded-md border border-zinc-700 bg-black px-3 py-2 text-sm text-zinc-200 outline-none ring-cyan-500 focus:ring-2 placeholder:text-zinc-600"
          />
        </div>

        {/* Rules list */}
        <div className="space-y-2">
          <p className="text-xs text-zinc-600">{rules.length} rule{rules.length !== 1 ? "s" : ""} shown</p>
          {rules.map((rule) => (
            <div
              key={rule.ruleId}
              className="rounded-xl border border-zinc-800 bg-zinc-900 overflow-hidden card-3d"
            >
              <button
                className="w-full px-4 py-3 text-left flex items-start gap-3 hover:bg-zinc-800/50"
                onClick={() => setExpanded(expanded === rule.ruleId ? null : rule.ruleId)}
              >
                {/* Severity */}
                <span className={`mt-0.5 shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-bold ${SEV_COLORS[rule.severity]}`}>
                  {rule.severity}
                </span>
                {/* Main info */}
                <div className="flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-semibold text-white">{rule.name}</span>
                    <span className="font-mono text-xs text-zinc-600">{rule.ruleId}</span>
                    <span className={`rounded border px-1.5 py-0.5 text-[10px] ${SOURCE_COLORS[rule.sourceType] ?? SOURCE_COLORS["Any"]}`}>
                      {rule.sourceType}
                    </span>
                    <span className="rounded border border-violet-900 bg-violet-950/20 px-1.5 py-0.5 text-[10px] text-violet-400">
                      {rule.mitreTechniqueId} · {rule.mitreTechnique}
                    </span>
                  </div>
                  <p className="mt-1 text-xs text-zinc-500 leading-4">{rule.description}</p>
                </div>
                {/* Enabled badge */}
                <span className={`shrink-0 rounded-full px-2 py-0.5 text-[10px] font-medium ${rule.enabled ? "bg-green-950 text-green-400" : "bg-zinc-800 text-zinc-500"}`}>
                  {rule.enabled ? "● Active" : "○ Off"}
                </span>
                {/* Expand chevron */}
                <span className="shrink-0 text-zinc-600 text-sm">{expanded === rule.ruleId ? "▲" : "▼"}</span>
              </button>

              {expanded === rule.ruleId && (
                <div className="border-t border-zinc-800 p-4 space-y-4">
                  {/* MITRE */}
                  <div className="rounded-lg border border-violet-900/50 bg-violet-950/20 p-3">
                    <p className="text-xs text-violet-400 uppercase tracking-wider mb-2">MITRE ATT&CK</p>
                    <div className="flex flex-wrap gap-2">
                      <span className="rounded border border-violet-800 bg-violet-900/30 px-2 py-1 text-xs text-violet-200">
                        Tactic: {rule.mitreTactic}
                      </span>
                      <span className="rounded border border-violet-800 bg-violet-900/30 px-2 py-1 text-xs text-violet-200">
                        {rule.mitreTechniqueId}: {rule.mitreTechnique}
                      </span>
                    </div>
                    <a
                      href={`https://attack.mitre.org/techniques/${rule.mitreTechniqueId.replace(".", "/")}/`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="mt-2 inline-flex items-center gap-1 text-xs text-violet-400 hover:text-violet-300"
                    >
                      View on ATT&CK ↗
                    </a>
                  </div>

                  {/* Tags */}
                  <div className="flex flex-wrap gap-1.5">
                    {rule.tags.map((tag) => (
                      <span key={tag} className="rounded-full border border-zinc-700 bg-zinc-800 px-2 py-0.5 text-xs text-zinc-400">
                        #{tag}
                      </span>
                    ))}
                  </div>

                  {/* Recommendation */}
                  <div className="rounded-lg border border-cyan-900/50 bg-cyan-950/20 p-3">
                    <p className="text-xs text-cyan-400 uppercase tracking-wider mb-1">Recommendation</p>
                    <p className="text-sm text-zinc-300">{rule.recommendation}</p>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </main>
  );
}

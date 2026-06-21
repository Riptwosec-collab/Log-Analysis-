"use client";

import { useEffect } from "react";
import type { Finding } from "@/lib/logAnalyzer";
import type { Language } from "@/lib/i18n";
import { localize, severityLabel, severityClass } from "@/lib/i18n";

interface Props {
  finding: Finding | null;
  onClose: () => void;
  language: Language;
}

const PLAYBOOKS: Record<string, string[]> = {
  "SSH Brute Force":        ["Block source IP at firewall", "Review successful logins after the attack window", "Disable password auth — enforce SSH key only", "Enable fail2ban or rate limiting", "Check /var/log/auth.log for post-breach activity"],
  "Password Spray":         ["Alert on >5 failed logins across different accounts from same IP", "Enforce MFA on all accounts", "Review accounts with successful logins post-event", "Check for lateral movement (RDP, SMB)"],
  "Root Login Attempt":     ["Disable root SSH login (PermitRootLogin no)", "Verify no successful root login occurred", "Review /etc/sudoers and sudo logs", "Audit privileged accounts"],
  "SQL Injection":          ["Inspect endpoint and sanitize input with parameterized queries", "Review database error logs for exfiltration", "Enable WAF rule for SQLi patterns", "Check for data exfiltration in outbound traffic"],
  "Path Traversal":         ["Patch or restrict file download endpoints", "Enable WAF path traversal detection", "Check if /etc/passwd or shadow was accessed", "Review web server access logs for successful reads"],
  "XSS Attempt":            ["Implement Content Security Policy (CSP)", "Validate and encode all user inputs", "Inspect user sessions for cookie theft", "Add XSS filter to WAF"],
  "Firewall Port Scan":     ["Block scanning IP at perimeter", "Review what services are exposed on detected ports", "Enable IDS/IPS signatures for port scan detection", "Assess network segmentation"],
  "Repeated Firewall DROP": ["Block source IP if pattern is persistent", "Enable IDS alerting on repeated DROPs", "Review firewall rule effectiveness", "Consider geo-blocking for attacker country"],
  "Windows Event 4625":     ["Identify accounts involved — check for lockout", "Correlate with Event ID 4624 for successful logins", "Look for Event 4672 (privilege assignment) after failures", "Enable Account Lockout Policy"],
  "Privilege Escalation":   ["Investigate how elevated access was obtained", "Review Event ID 4672, 4728, 4732", "Disable or remove suspicious privileged accounts", "Enforce least privilege and PAM"],
  "Suspicious Process":     ["Examine CommandLine arguments for malicious patterns", "Check if process spawned any children", "Look for network connections from the process", "Submit binary hash to VirusTotal"],
};

function getPlaybook(rule: string): string[] {
  for (const [key, steps] of Object.entries(PLAYBOOKS)) {
    if (rule.toLowerCase().includes(key.toLowerCase())) return steps;
  }
  return ["Investigate the finding and gather more context", "Correlate with other alerts from same source", "Escalate if behaviour continues", "Document in incident management system"];
}

const FIELD_LABELS: Record<string, string> = {
  sourceIp:        "Source IP",
  destinationIp:   "Destination IP",
  destinationPort: "Dest Port",
  username:        "Username",
  asset:           "Asset / Host",
  tactic:          "MITRE Tactic",
  technique:       "MITRE Technique",
  logType:         "Log Type",
  confidence:      "Confidence",
  repeatedCount:   "Repeat Count",
  geoCountry:      "Country",
  asn:             "ASN",
  abuseScore:      "Abuse Score",
  domain:          "Domain",
  fileHash:        "File Hash",
};

export default function EvidenceDrawer({ finding, onClose, language }: Props) {
  // Close on Escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  if (!finding) return null;

  const playbook = getPlaybook(finding.rule);
  const severityColors: Record<string, string> = {
    Critical: "bg-red-950 border-red-800 text-red-300",
    High:     "bg-orange-950 border-orange-800 text-orange-300",
    Medium:   "bg-yellow-950 border-yellow-800 text-yellow-300",
    Low:      "bg-green-950 border-green-800 text-green-300",
  };

  const metaFields = [
    { key: "sourceIp",        val: finding.sourceIp },
    { key: "destinationIp",   val: finding.destinationIp },
    { key: "destinationPort", val: finding.destinationPort },
    { key: "username",        val: finding.username },
    { key: "asset",           val: finding.asset },
    { key: "logType",         val: finding.logType },
    { key: "tactic",          val: finding.tactic },
    { key: "technique",       val: finding.technique },
    { key: "confidence",      val: finding.confidence != null ? `${finding.confidence}%` : null },
    { key: "repeatedCount",   val: finding.repeatedCount > 1 ? String(finding.repeatedCount) : null },
    { key: "geoCountry",      val: finding.geoCountry },
    { key: "asn",             val: finding.asn },
    { key: "abuseScore",      val: finding.abuseScore != null ? `${finding.abuseScore}/100` : null },
    { key: "domain",          val: finding.domain },
    { key: "fileHash",        val: finding.fileHash },
  ].filter((f) => f.val);

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40 bg-black/70 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Drawer */}
      <aside className="fixed right-0 top-0 z-50 flex h-full w-full max-w-xl flex-col overflow-y-auto border-l border-zinc-800 bg-zinc-950 shadow-2xl">

        {/* Header */}
        <div className="sticky top-0 z-10 border-b border-zinc-800 bg-zinc-950 p-5">
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1 min-w-0">
              <div className="flex flex-wrap items-center gap-2 mb-1">
                <span className={`rounded-full border px-2.5 py-0.5 text-xs font-bold ${severityColors[finding.severity]}`}>
                  {finding.severity}
                </span>
                <span className="text-xs text-zinc-500 font-mono">#{finding.id.slice(0, 8)}</span>
                {finding.timestamp && (
                  <span className="text-xs text-zinc-500">{finding.timestamp}</span>
                )}
              </div>
              <h2 className="text-lg font-semibold text-white leading-tight">
                {localize(finding.rule, language)}
              </h2>
            </div>
            <button
              onClick={onClose}
              className="shrink-0 rounded-lg border border-zinc-700 p-2 text-zinc-400 hover:border-zinc-500 hover:text-white"
            >
              ✕
            </button>
          </div>
        </div>

        <div className="flex-1 space-y-5 p-5">

          {/* Root Cause + Impact */}
          <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 space-y-3">
            <div>
              <p className="text-xs uppercase tracking-wider text-zinc-500 mb-1">Root Cause</p>
              <p className="text-sm text-zinc-300 leading-5">{localize(finding.possibleRootCause, language)}</p>
            </div>
            <div>
              <p className="text-xs uppercase tracking-wider text-zinc-500 mb-1">Impact</p>
              <p className="text-sm text-zinc-300 leading-5">{localize(finding.impact, language)}</p>
            </div>
          </div>

          {/* Parsed Fields */}
          {metaFields.length > 0 && (
            <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
              <p className="text-xs uppercase tracking-wider text-zinc-500 mb-3">Parsed Fields</p>
              <div className="grid grid-cols-2 gap-2">
                {metaFields.map(({ key, val }) => (
                  <div key={key} className="rounded-md border border-zinc-800 bg-black p-2">
                    <p className="text-[10px] uppercase tracking-wider text-zinc-600">{FIELD_LABELS[key] ?? key}</p>
                    <p className="mt-0.5 font-mono text-xs text-zinc-200 break-all">{val}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* MITRE ATT&CK */}
          {(finding.tactic || finding.technique) && (
            <div className="rounded-lg border border-violet-900/50 bg-violet-950/20 p-4">
              <p className="text-xs uppercase tracking-wider text-violet-400 mb-3">🛡️ MITRE ATT&CK</p>
              <div className="flex flex-wrap gap-2">
                {finding.tactic && (
                  <div className="rounded-md border border-violet-800 bg-violet-900/30 px-3 py-1.5">
                    <p className="text-[10px] text-violet-500 uppercase">Tactic</p>
                    <p className="text-sm text-violet-200">{finding.tactic}</p>
                  </div>
                )}
                {finding.technique && (
                  <div className="rounded-md border border-violet-800 bg-violet-900/30 px-3 py-1.5">
                    <p className="text-[10px] text-violet-500 uppercase">Technique</p>
                    <p className="text-sm text-violet-200">{finding.technique}</p>
                  </div>
                )}
              </div>
              {finding.technique && (
                <a
                  href={`https://attack.mitre.org/search/?query=${encodeURIComponent(finding.technique)}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="mt-3 inline-flex items-center gap-1.5 text-xs text-violet-400 hover:text-violet-300"
                >
                  View on ATT&CK Navigator ↗
                </a>
              )}
            </div>
          )}

          {/* Keywords */}
          {finding.detectedKeywords.length > 0 && (
            <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
              <p className="text-xs uppercase tracking-wider text-zinc-500 mb-2">Detected Keywords</p>
              <div className="flex flex-wrap gap-1.5">
                {finding.detectedKeywords.map((kw) => (
                  <span key={kw} className="rounded border border-zinc-700 bg-zinc-800 px-2 py-0.5 font-mono text-xs text-zinc-300">
                    {kw}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Raw Evidence */}
          {finding.evidence && (
            <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
              <p className="text-xs uppercase tracking-wider text-zinc-500 mb-2">Raw Evidence Log</p>
              <pre className="max-h-48 overflow-auto rounded-md border border-zinc-800 bg-black p-3 text-xs leading-5 text-zinc-300 whitespace-pre-wrap break-all font-mono">
                {finding.evidence}
              </pre>
            </div>
          )}

          {/* Raw line */}
          {finding.raw && finding.raw !== finding.evidence && (
            <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
              <p className="text-xs uppercase tracking-wider text-zinc-500 mb-2">Triggering Log Line</p>
              <pre className="max-h-32 overflow-auto rounded-md border border-zinc-800 bg-black p-3 text-xs leading-5 text-amber-300 whitespace-pre-wrap break-all font-mono">
                {finding.raw}
              </pre>
            </div>
          )}

          {/* Playbook */}
          <div className="rounded-lg border border-cyan-900/50 bg-cyan-950/20 p-4">
            <p className="text-xs uppercase tracking-wider text-cyan-500 mb-3">🔧 Response Playbook</p>
            <ol className="space-y-2">
              {playbook.map((step, i) => (
                <li key={i} className="flex items-start gap-2.5 text-sm text-zinc-300">
                  <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-cyan-500/20 text-[10px] font-bold text-cyan-400">
                    {i + 1}
                  </span>
                  <span className="leading-5">{step}</span>
                </li>
              ))}
            </ol>
          </div>

          {/* Recommended Fix */}
          {finding.recommendedFix && (
            <div className="rounded-lg border border-green-900/50 bg-green-950/20 p-4">
              <p className="text-xs uppercase tracking-wider text-green-500 mb-2">✅ Recommended Fix</p>
              <p className="text-sm text-zinc-300 leading-5">{localize(finding.recommendedFix, language)}</p>
            </div>
          )}
        </div>
      </aside>
    </>
  );
}

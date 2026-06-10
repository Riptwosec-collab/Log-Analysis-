export type Severity = "Low" | "Medium" | "High" | "Critical";

export type LogType =
  | "Apache/Nginx"
  | "SSH Auth"
  | "Firewall"
  | "Windows Event"
  | "Linux Syslog"
  | "Generic";

export type Finding = {
  id: string;
  lineNumber: number;
  timestamp: string | null;
  severity: Severity;
  logType: LogType;
  rule: string;
  detectedKeywords: string[];
  possibleRootCause: string;
  impact: string;
  recommendedFix: string;
  sourceIp: string | null;
  raw: string;
  repeatedCount: number;
};

export type AnalysisSummary = {
  totalEvents: number;
  suspiciousEvents: number;
  criticalAlerts: number;
  failedLogins: number;
  topSourceIp: string | null;
  logTypes: Record<string, number>;
  severityCounts: Record<Severity, number>;
  timeline: Array<{ timestamp: string; count: number; severity: Severity }>;
};

export type AnalysisResult = {
  generatedAt: string;
  summary: AnalysisSummary;
  findings: Finding[];
};

type Rule = {
  name: string;
  severity: Severity;
  keywords: string[];
  patterns: RegExp[];
  logType?: LogType;
  rootCause: string;
  impact: string;
  fix: string;
};

const severityRank: Record<Severity, number> = {
  Low: 1,
  Medium: 2,
  High: 3,
  Critical: 4,
};

const rules: Rule[] = [
  {
    name: "Brute force login",
    severity: "Critical",
    keywords: ["failed password", "authentication failure", "invalid user"],
    patterns: [/failed password/i, /authentication failure/i, /invalid user/i],
    logType: "SSH Auth",
    rootCause: "Repeated authentication failures suggest password guessing or credential stuffing.",
    impact: "Unauthorized access may occur if a weak or reused credential succeeds.",
    fix: "Block abusive source IPs, enforce MFA, disable password login where possible, and review exposed SSH services.",
  },
  {
    name: "SQL injection pattern",
    severity: "Critical",
    keywords: ["union select", "or 1=1", "sqlmap", "information_schema"],
    patterns: [/union\s+select/i, /or\s+1=1/i, /sqlmap/i, /information_schema/i],
    logType: "Apache/Nginx",
    rootCause: "Request parameters contain SQL injection payloads.",
    impact: "Attackers may read, modify, or delete application data if input handling is vulnerable.",
    fix: "Use parameterized queries, validate input, add WAF rules, and inspect application/database logs for successful exploitation.",
  },
  {
    name: "Path traversal attempt",
    severity: "High",
    keywords: ["../", "..\\", "/etc/passwd", "boot.ini"],
    patterns: [/\.\.\//, /\.\.\\/, /\/etc\/passwd/i, /boot\.ini/i],
    logType: "Apache/Nginx",
    rootCause: "A request attempted to access files outside the intended web directory.",
    impact: "Sensitive files or configuration may be exposed if path handling is unsafe.",
    fix: "Normalize paths, restrict file access to allow-listed directories, and block traversal payloads at the edge.",
  },
  {
    name: "Port scan or blocked probe",
    severity: "High",
    keywords: ["deny", "drop", "blocked", "scan", "syn"],
    patterns: [/\bdeny\b/i, /\bdrop\b/i, /\bblocked\b/i, /\bscan\b/i, /\bsyn\b/i],
    logType: "Firewall",
    rootCause: "Firewall events indicate probing or blocked connection attempts.",
    impact: "Reconnaissance may precede exploitation attempts against exposed services.",
    fix: "Review exposed ports, rate-limit noisy sources, and confirm firewall policy matches the expected attack surface.",
  },
  {
    name: "Repeated denied access",
    severity: "Medium",
    keywords: ["403", "forbidden", "access denied", "permission denied"],
    patterns: [/\b403\b/i, /forbidden/i, /access denied/i, /permission denied/i],
    rootCause: "A user, service, or source repeatedly attempted an unauthorized action.",
    impact: "This may indicate misconfiguration, privilege abuse, or active reconnaissance.",
    fix: "Validate access control rules, review account permissions, and investigate repeated source identities.",
  },
  {
    name: "Service down or timeout",
    severity: "High",
    keywords: ["timeout", "service down", "connection refused", "unavailable", "503"],
    patterns: [/timeout/i, /service down/i, /connection refused/i, /unavailable/i, /\b503\b/i],
    rootCause: "A service dependency appears unavailable, overloaded, or misconfigured.",
    impact: "Users or dependent systems may experience failed requests and degraded availability.",
    fix: "Check service health, capacity, upstream connectivity, and recent deployment/configuration changes.",
  },
  {
    name: "Windows security event",
    severity: "Medium",
    keywords: ["event id 4625", "event id 4624", "audit failure"],
    patterns: [/event id\s*4625/i, /event id\s*4624/i, /audit failure/i],
    logType: "Windows Event",
    rootCause: "Windows audit logs show authentication or security activity that needs review.",
    impact: "Failed logons can indicate account misuse, lockout risk, or lateral movement attempts.",
    fix: "Correlate username, workstation, and source IP with expected user behavior and domain policy.",
  },
  {
    name: "System error",
    severity: "Low",
    keywords: ["error", "warn", "failed"],
    patterns: [/\berror\b/i, /\bwarn(ing)?\b/i, /\bfailed\b/i],
    rootCause: "The log line contains a generic error or warning condition.",
    impact: "The affected service may be degraded depending on frequency and context.",
    fix: "Inspect neighboring log lines, confirm whether the error is recurring, and check recent changes.",
  },
];

export function analyzeLog(content: string): AnalysisResult {
  const lines = content.split(/\r?\n/).filter((line) => line.trim().length > 0);
  const findings: Finding[] = [];
  const repetitionMap = new Map<string, number>();

  lines.forEach((line, index) => {
    const logType = detectLogType(line);
    const matchedRules = rules.filter((rule) =>
      rule.patterns.some((pattern) => pattern.test(line))
    );

    if (matchedRules.length === 0) {
      return;
    }

    const bestRule = matchedRules.sort(
      (a, b) => severityRank[b.severity] - severityRank[a.severity]
    )[0];
    const timestamp = extractTimestamp(line);
    const sourceIp = extractIp(line);
    const normalized = normalizeLine(line);
    const repeatedCount = (repetitionMap.get(normalized) || 0) + 1;
    repetitionMap.set(normalized, repeatedCount);

    findings.push({
      id: `EVT-${String(findings.length + 1).padStart(4, "0")}`,
      lineNumber: index + 1,
      timestamp,
      severity: bestRule.severity,
      logType: bestRule.logType || logType,
      rule: bestRule.name,
      detectedKeywords: bestRule.keywords.filter((keyword) =>
        line.toLowerCase().includes(keyword.toLowerCase())
      ),
      possibleRootCause: bestRule.rootCause,
      impact: bestRule.impact,
      recommendedFix: bestRule.fix,
      sourceIp,
      raw: line,
      repeatedCount,
    });
  });

  const updatedFindings = applyAggregateSeverity(findings);

  return {
    generatedAt: new Date().toISOString(),
    summary: buildSummary(lines.length, updatedFindings),
    findings: updatedFindings,
  };
}

function detectLogType(line: string): LogType {
  if (/\b(sshd|pam_unix|failed password|accepted password)\b/i.test(line)) return "SSH Auth";
  if (/\b(ufw|iptables|firewall|deny|drop|src=|dst=)\b/i.test(line)) return "Firewall";
  if (/\b(event id|audit failure|microsoft-windows)\b/i.test(line)) return "Windows Event";
  if (/\b(kernel|systemd|cron|sudo)\b/i.test(line)) return "Linux Syslog";
  if (/\b(GET|POST|PUT|DELETE|HEAD)\b.*\b(HTTP\/| 200 | 403 | 404 | 500 | 503 )/i.test(line)) {
    return "Apache/Nginx";
  }
  return "Generic";
}

function extractTimestamp(line: string): string | null {
  const iso = line.match(/\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:?\d{2})?/);
  if (iso) return iso[0].replace(" ", "T");

  const syslog = line.match(/\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b/);
  if (syslog) return syslog[0];

  const windows = line.match(/\d{1,2}\/\d{1,2}\/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?/i);
  return windows ? windows[0] : null;
}

function extractIp(line: string): string | null {
  const ip = line.match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/);
  return ip ? ip[0] : null;
}

function normalizeLine(line: string): string {
  return line
    .toLowerCase()
    .replace(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g, "<ip>")
    .replace(/\d{4}-\d{2}-\d{2}[ t]\d{2}:\d{2}:\d{2}/g, "<time>")
    .replace(/\b\d+\b/g, "<num>")
    .trim();
}

function applyAggregateSeverity(findings: Finding[]): Finding[] {
  const bySourceAndRule = new Map<string, number>();

  findings.forEach((finding) => {
    const key = `${finding.sourceIp || "unknown"}:${finding.rule}`;
    bySourceAndRule.set(key, (bySourceAndRule.get(key) || 0) + 1);
  });

  return findings.map((finding) => {
    const key = `${finding.sourceIp || "unknown"}:${finding.rule}`;
    const count = bySourceAndRule.get(key) || finding.repeatedCount;

    if (count >= 5 && severityRank[finding.severity] < severityRank.Critical) {
      return {
        ...finding,
        severity: "Critical",
        repeatedCount: count,
        impact: `${finding.impact} Repeated activity raises the incident priority.`,
      };
    }

    return { ...finding, repeatedCount: Math.max(finding.repeatedCount, count) };
  });
}

function buildSummary(totalEvents: number, findings: Finding[]): AnalysisSummary {
  const severityCounts: Record<Severity, number> = {
    Low: 0,
    Medium: 0,
    High: 0,
    Critical: 0,
  };
  const logTypes: Record<string, number> = {};
  const ipCounts = new Map<string, number>();
  const timelineMap = new Map<string, { count: number; severity: Severity }>();

  findings.forEach((finding) => {
    severityCounts[finding.severity] += 1;
    logTypes[finding.logType] = (logTypes[finding.logType] || 0) + 1;

    if (finding.sourceIp) {
      ipCounts.set(finding.sourceIp, (ipCounts.get(finding.sourceIp) || 0) + 1);
    }

    if (finding.timestamp) {
      const bucket = finding.timestamp.slice(0, 16);
      const current = timelineMap.get(bucket);
      if (!current) {
        timelineMap.set(bucket, { count: 1, severity: finding.severity });
      } else {
        timelineMap.set(bucket, {
          count: current.count + 1,
          severity:
            severityRank[finding.severity] > severityRank[current.severity]
              ? finding.severity
              : current.severity,
        });
      }
    }
  });

  const topSourceIp = Array.from(ipCounts.entries()).sort((a, b) => b[1] - a[1])[0]?.[0] || null;

  return {
    totalEvents,
    suspiciousEvents: findings.length,
    criticalAlerts: severityCounts.Critical,
    failedLogins: findings.filter((finding) => finding.rule === "Brute force login").length,
    topSourceIp,
    logTypes,
    severityCounts,
    timeline: Array.from(timelineMap.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([timestamp, value]) => ({ timestamp, ...value })),
  };
}

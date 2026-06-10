export type Severity = "Low" | "Medium" | "High" | "Critical";

export type LogType =
  | "Apache/Nginx"
  | "SSH Auth"
  | "Firewall"
  | "Windows Event"
  | "Linux Syslog"
  | "Generic";

export type Correlation = {
  title: string;
  severity: Severity;
  sourceIp: string | null;
  eventCount: number;
  description: string;
  recommendedAction: string;
};

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

export type AnalysisSummary = {
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
  tactic: string;
  technique: string;
  confidence: number;
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
    patterns: [/failed password/i, /authentication failure/i, /invalid user/i, /event id\s*4625/i],
    logType: "SSH Auth",
    rootCause: "Repeated authentication failures suggest password guessing or credential stuffing.",
    impact: "Unauthorized access may occur if a weak or reused credential succeeds.",
    fix: "Block abusive source IPs, enforce MFA, disable password login where possible, and review exposed SSH/RDP services.",
    tactic: "Credential Access",
    technique: "T1110 Brute Force",
    confidence: 92,
  },
  {
    name: "SQL injection pattern",
    severity: "Critical",
    keywords: ["union select", "or 1=1", "sqlmap", "information_schema", "sleep("],
    patterns: [/union\s+select/i, /or\s+1=1/i, /sqlmap/i, /information_schema/i, /sleep\s*\(/i, /benchmark\s*\(/i],
    logType: "Apache/Nginx",
    rootCause: "Request parameters contain SQL injection payloads.",
    impact: "Attackers may read, modify, or delete application data if input handling is vulnerable.",
    fix: "Use parameterized queries, validate input, add WAF rules, and inspect application/database logs for successful exploitation.",
    tactic: "Initial Access",
    technique: "T1190 Exploit Public-Facing Application",
    confidence: 95,
  },
  {
    name: "Path traversal attempt",
    severity: "High",
    keywords: ["../", "..\\", "/etc/passwd", "boot.ini", "win.ini"],
    patterns: [/\.\.\//, /\.\.\\/, /\/etc\/passwd/i, /boot\.ini/i, /win\.ini/i],
    logType: "Apache/Nginx",
    rootCause: "A request attempted to access files outside the intended web directory.",
    impact: "Sensitive files or configuration may be exposed if path handling is unsafe.",
    fix: "Normalize paths, restrict file access to allow-listed directories, and block traversal payloads at the edge.",
    tactic: "Discovery",
    technique: "T1083 File and Directory Discovery",
    confidence: 90,
  },
  {
    name: "XSS payload",
    severity: "High",
    keywords: ["<script", "javascript:", "onerror=", "document.cookie"],
    patterns: [/<script/i, /javascript:/i, /onerror\s*=/i, /document\.cookie/i],
    logType: "Apache/Nginx",
    rootCause: "Request data contains browser-executable script payloads.",
    impact: "A successful exploit may steal sessions, deface content, or perform actions as another user.",
    fix: "Encode output, sanitize rich text, set a strict Content Security Policy, and review affected endpoints.",
    tactic: "Initial Access",
    technique: "T1189 Drive-by Compromise",
    confidence: 86,
  },
  {
    name: "Command injection pattern",
    severity: "Critical",
    keywords: [";cat", "|whoami", "cmd.exe", "/bin/sh", "powershell"],
    patterns: [/;\s*(cat|id|whoami|curl|wget)\b/i, /\|\s*(whoami|id|curl|wget)\b/i, /cmd\.exe/i, /\/bin\/sh/i, /powershell/i],
    logType: "Apache/Nginx",
    rootCause: "Request parameters look like operating-system command execution attempts.",
    impact: "If vulnerable, the application host may execute attacker-controlled commands.",
    fix: "Remove shell execution from request paths, use strict allow-lists, and inspect host telemetry for spawned processes.",
    tactic: "Execution",
    technique: "T1059 Command and Scripting Interpreter",
    confidence: 93,
  },
  {
    name: "Web shell upload attempt",
    severity: "Critical",
    keywords: [".php", "multipart", "cmd=", "shell"],
    patterns: [/multipart\/form-data/i, /\.(php|jsp|aspx)\b/i, /\bcmd=/i, /\bshell\b/i],
    logType: "Apache/Nginx",
    rootCause: "Upload or request pattern resembles web shell staging.",
    impact: "A successful upload can provide persistent remote command execution.",
    fix: "Restrict executable uploads, store uploads outside the web root, scan uploaded files, and review recent file writes.",
    tactic: "Persistence",
    technique: "T1505.003 Web Shell",
    confidence: 82,
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
    tactic: "Reconnaissance",
    technique: "T1046 Network Service Discovery",
    confidence: 80,
  },
  {
    name: "Repeated denied access",
    severity: "Medium",
    keywords: ["403", "forbidden", "access denied", "permission denied"],
    patterns: [/\b403\b/i, /forbidden/i, /access denied/i, /permission denied/i],
    rootCause: "A user, service, or source repeatedly attempted an unauthorized action.",
    impact: "This may indicate misconfiguration, privilege abuse, or active reconnaissance.",
    fix: "Validate access control rules, review account permissions, and investigate repeated source identities.",
    tactic: "Defense Evasion",
    technique: "T1078 Valid Accounts",
    confidence: 70,
  },
  {
    name: "Service down or timeout",
    severity: "High",
    keywords: ["timeout", "service down", "connection refused", "unavailable", "503"],
    patterns: [/timeout/i, /service down/i, /connection refused/i, /unavailable/i, /\b503\b/i],
    rootCause: "A service dependency appears unavailable, overloaded, or misconfigured.",
    impact: "Users or dependent systems may experience failed requests and degraded availability.",
    fix: "Check service health, capacity, upstream connectivity, and recent deployment/configuration changes.",
    tactic: "Impact",
    technique: "T1499 Endpoint Denial of Service",
    confidence: 74,
  },
  {
    name: "Privilege escalation signal",
    severity: "High",
    keywords: ["sudo", "root", "privilege", "administrator"],
    patterns: [/sudo:.*COMMAND=/i, /privilege escalation/i, /administrator/i, /root\s+COMMAND=/i],
    logType: "Linux Syslog",
    rootCause: "Administrative command or privileged account activity appears in the logs.",
    impact: "If unexpected, privileged activity can indicate lateral movement or account misuse.",
    fix: "Validate the command owner, compare with change tickets, and rotate credentials if activity is unauthorized.",
    tactic: "Privilege Escalation",
    technique: "T1548 Abuse Elevation Control Mechanism",
    confidence: 76,
  },
  {
    name: "Suspicious outbound transfer",
    severity: "High",
    keywords: ["curl", "wget", "base64", "upload", "exfil"],
    patterns: [/\b(curl|wget)\b.*https?:\/\//i, /\bbase64\b/i, /\bexfil/i, /\bupload(ed)?\b.*\b(bytes|mb|gb)\b/i],
    rootCause: "Log line indicates a possible outbound transfer or encoded payload handling.",
    impact: "This may be benign automation, but it can also indicate data staging or exfiltration.",
    fix: "Review destination domain/IP, user context, transferred volume, and proxy/firewall logs around the same time.",
    tactic: "Exfiltration",
    technique: "T1041 Exfiltration Over C2 Channel",
    confidence: 72,
  },
  {
    name: "System error",
    severity: "Low",
    keywords: ["error", "warn", "failed"],
    patterns: [/\berror\b/i, /\bwarn(ing)?\b/i, /\bfailed\b/i],
    rootCause: "The log line contains a generic error or warning condition.",
    impact: "The affected service may be degraded depending on frequency and context.",
    fix: "Inspect neighboring log lines, confirm whether the error is recurring, and check recent changes.",
    tactic: "Operations",
    technique: "Reliability Signal",
    confidence: 55,
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

    if (matchedRules.length === 0) return;

    const bestRule = matchedRules.sort(
      (a, b) => severityRank[b.severity] - severityRank[a.severity] || b.confidence - a.confidence
    )[0];
    const normalized = normalizeLine(line);
    const repeatedCount = (repetitionMap.get(normalized) || 0) + 1;
    repetitionMap.set(normalized, repeatedCount);

    findings.push({
      id: `EVT-${String(findings.length + 1).padStart(4, "0")}`,
      lineNumber: index + 1,
      timestamp: extractTimestamp(line),
      severity: bestRule.severity,
      logType: bestRule.logType || logType,
      rule: bestRule.name,
      detectedKeywords: bestRule.keywords.filter((keyword) =>
        line.toLowerCase().includes(keyword.toLowerCase())
      ),
      possibleRootCause: bestRule.rootCause,
      impact: bestRule.impact,
      recommendedFix: bestRule.fix,
      sourceIp: extractSourceIp(line),
      destinationIp: extractDestinationIp(line),
      destinationPort: extractDestinationPort(line),
      username: extractUsername(line),
      asset: extractAsset(line),
      tactic: bestRule.tactic,
      technique: bestRule.technique,
      confidence: bestRule.confidence,
      evidence: buildEvidence(line, bestRule),
      raw: line,
      repeatedCount,
    });
  });

  const correlatedFindings = applyAggregateSeverity(findings);
  const correlations = correlateFindings(correlatedFindings);

  return {
    generatedAt: new Date().toISOString(),
    summary: buildSummary(lines.length, correlatedFindings, correlations),
    findings: correlatedFindings,
  };
}

function detectLogType(line: string): LogType {
  if (/\b(sshd|pam_unix|failed password|accepted password)\b/i.test(line)) return "SSH Auth";
  if (/\b(ufw|iptables|firewall|deny|drop|src=|dst=)\b/i.test(line)) return "Firewall";
  if (/\b(event id|audit failure|microsoft-windows)\b/i.test(line)) return "Windows Event";
  if (/\b(kernel|systemd|cron|sudo|systemctl)\b/i.test(line)) return "Linux Syslog";
  if (/\b(GET|POST|PUT|DELETE|HEAD|PATCH)\b.*\b(HTTP\/| 200 | 301 | 302 | 400 | 401 | 403 | 404 | 500 | 503 )/i.test(line)) {
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

function extractSourceIp(line: string): string | null {
  const explicit = line.match(/\b(?:SRC|src|from|client|Source Network Address)[:=\s]+((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))/);
  if (explicit) return explicit[1];
  return extractIps(line)[0] || null;
}

function extractDestinationIp(line: string): string | null {
  const explicit = line.match(/\b(?:DST|dst|to)[:=\s]+((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))/);
  if (explicit) return explicit[1];
  return extractIps(line)[1] || null;
}

function extractDestinationPort(line: string): string | null {
  const match = line.match(/\b(?:DPT|dpt|dst_port|destination port)[:=\s]+(\d{1,5})\b/i);
  return match ? match[1] : null;
}

function extractUsername(line: string): string | null {
  const patterns = [
    /invalid user\s+([a-z0-9._-]+)/i,
    /for\s+([a-z0-9._-]+)\s+from/i,
    /user(?:name)?[=:\s]+([a-z0-9._-]+)/i,
    /Account Name:\s*([a-z0-9._$-]+)/i,
  ];
  for (const pattern of patterns) {
    const match = line.match(pattern);
    if (match && !["from", "invalid", "user"].includes(match[1].toLowerCase())) return match[1];
  }
  return null;
}

function extractAsset(line: string): string | null {
  const syslogHost = line.match(/^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+([a-z0-9._-]+)/i);
  if (syslogHost) return syslogHost[1];
  const host = line.match(/\bhost(?:name)?[=:\s]+([a-z0-9._-]+)/i);
  return host ? host[1] : null;
}

function extractIps(line: string): string[] {
  return Array.from(line.matchAll(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g)).map((match) => match[0]);
}

function buildEvidence(line: string, rule: Rule): string {
  const pattern = rule.patterns.find((item) => item.test(line));
  if (!pattern) return rule.keywords[0] || rule.name;
  const match = line.match(pattern);
  return match?.[0]?.slice(0, 80) || rule.keywords[0] || rule.name;
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
    const repeatBoost = count >= 5 ? 8 : count >= 3 ? 4 : 0;

    if (count >= 5 && severityRank[finding.severity] < severityRank.Critical) {
      return {
        ...finding,
        severity: "Critical",
        confidence: Math.min(99, finding.confidence + repeatBoost),
        repeatedCount: count,
        impact: `${finding.impact} Repeated activity raises the incident priority.`,
      };
    }

    return {
      ...finding,
      confidence: Math.min(99, finding.confidence + repeatBoost),
      repeatedCount: Math.max(finding.repeatedCount, count),
    };
  });
}

function correlateFindings(findings: Finding[]): Correlation[] {
  const correlations: Correlation[] = [];
  const bySource = groupBy(findings.filter((finding) => finding.sourceIp), (finding) => finding.sourceIp || "unknown");

  bySource.forEach((items, sourceIp) => {
    const bruteForce = items.filter((finding) => finding.rule === "Brute force login");
    const uniqueUsers = new Set(bruteForce.map((finding) => finding.username).filter(Boolean));
    if (bruteForce.length >= 4 || uniqueUsers.size >= 3) {
      correlations.push({
        title: "Credential attack burst",
        severity: "Critical",
        sourceIp,
        eventCount: bruteForce.length,
        description: `${sourceIp} generated ${bruteForce.length} authentication failures across ${uniqueUsers.size || 1} account(s).`,
        recommendedAction: "Block the source, review successful logons from the same IP, and force reset for targeted accounts.",
      });
    }

    const ports = new Set(items.map((finding) => finding.destinationPort).filter(Boolean));
    const scanEvents = items.filter((finding) => finding.rule === "Port scan or blocked probe");
    if (scanEvents.length >= 3 || ports.size >= 4) {
      correlations.push({
        title: "Multi-port reconnaissance",
        severity: "High",
        sourceIp,
        eventCount: scanEvents.length || items.length,
        description: `${sourceIp} touched ${ports.size} destination port(s), suggesting service discovery or scanning.`,
        recommendedAction: "Confirm exposed services, add rate limits, and search for follow-on exploit attempts from the same source.",
      });
    }

    const webAttackRules = new Set(
      items
        .filter((finding) => ["SQL injection pattern", "Path traversal attempt", "XSS payload", "Command injection pattern"].includes(finding.rule))
        .map((finding) => finding.rule)
    );
    if (webAttackRules.size >= 2) {
      correlations.push({
        title: "Web exploitation chain",
        severity: "Critical",
        sourceIp,
        eventCount: items.length,
        description: `${sourceIp} attempted multiple web attack classes: ${Array.from(webAttackRules).join(", ")}.`,
        recommendedAction: "Prioritize WAF blocking, endpoint patch review, and application logs for successful 2xx/5xx responses.",
      });
    }
  });

  const serviceIssues = findings.filter((finding) => finding.rule === "Service down or timeout");
  if (serviceIssues.length >= 5) {
    correlations.push({
      title: "Availability degradation spike",
      severity: "High",
      sourceIp: null,
      eventCount: serviceIssues.length,
      description: `${serviceIssues.length} service availability signals were detected in the submitted log window.`,
      recommendedAction: "Check recent deployments, upstream health, saturation metrics, and error-rate dashboards.",
    });
  }

  return correlations.sort((a, b) => severityRank[b.severity] - severityRank[a.severity] || b.eventCount - a.eventCount);
}

function buildSummary(totalEvents: number, findings: Finding[], correlations: Correlation[]): AnalysisSummary {
  const severityCounts: Record<Severity, number> = {
    Low: 0,
    Medium: 0,
    High: 0,
    Critical: 0,
  };
  const logTypes: Record<string, number> = {};
  const ipCounts = new Map<string, number>();
  const ruleCounts = new Map<string, { count: number; severity: Severity }>();
  const timelineMap = new Map<string, { count: number; severity: Severity }>();

  findings.forEach((finding) => {
    severityCounts[finding.severity] += 1;
    logTypes[finding.logType] = (logTypes[finding.logType] || 0) + 1;
    if (finding.sourceIp) ipCounts.set(finding.sourceIp, (ipCounts.get(finding.sourceIp) || 0) + 1);

    const rule = ruleCounts.get(finding.rule);
    ruleCounts.set(finding.rule, {
      count: (rule?.count || 0) + 1,
      severity: !rule || severityRank[finding.severity] > severityRank[rule.severity] ? finding.severity : rule.severity,
    });

    if (finding.timestamp) {
      const bucket = finding.timestamp.slice(0, 16);
      const current = timelineMap.get(bucket);
      timelineMap.set(bucket, {
        count: (current?.count || 0) + 1,
        severity:
          !current || severityRank[finding.severity] > severityRank[current.severity]
            ? finding.severity
            : current.severity,
      });
    }
  });

  const topSourceIp = Array.from(ipCounts.entries()).sort((a, b) => b[1] - a[1])[0]?.[0] || null;
  const riskScore = calculateRiskScore(findings, correlations, totalEvents);
  const riskLevel = scoreToSeverity(riskScore);
  const topRules = Array.from(ruleCounts.entries())
    .map(([rule, value]) => ({ rule, ...value }))
    .sort((a, b) => b.count - a.count || severityRank[b.severity] - severityRank[a.severity])
    .slice(0, 5);
  const affectedUsers = uniqueSorted(findings.map((finding) => finding.username).filter(Boolean) as string[]).slice(0, 8);
  const targetPorts = uniqueSorted(findings.map((finding) => finding.destinationPort).filter(Boolean) as string[]).slice(0, 10);
  const mitreTechniques = uniqueSorted(findings.map((finding) => finding.technique)).slice(0, 8);

  return {
    totalEvents,
    suspiciousEvents: findings.length,
    criticalAlerts: severityCounts.Critical,
    failedLogins: findings.filter((finding) => finding.rule === "Brute force login").length,
    topSourceIp,
    riskScore,
    riskLevel,
    incidentNarrative: buildNarrative(riskScore, findings, correlations, topSourceIp),
    logTypes,
    severityCounts,
    timeline: Array.from(timelineMap.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([timestamp, value]) => ({ timestamp, ...value })),
    topRules,
    affectedUsers,
    targetPorts,
    mitreTechniques,
    recommendedActions: buildRecommendedActions(findings, correlations),
    correlations,
  };
}

function calculateRiskScore(findings: Finding[], correlations: Correlation[], totalEvents: number): number {
  if (findings.length === 0) return 0;
  const severityPoints = findings.reduce((sum, finding) => sum + severityRank[finding.severity] * 9, 0);
  const confidencePoints = findings.reduce((sum, finding) => sum + finding.confidence / 10, 0);
  const correlationPoints = correlations.reduce((sum, item) => sum + severityRank[item.severity] * 8, 0);
  const densityBonus = totalEvents > 0 ? (findings.length / totalEvents) * 18 : 0;
  return Math.min(100, Math.round(severityPoints + confidencePoints + correlationPoints + densityBonus));
}

function scoreToSeverity(score: number): Severity {
  if (score >= 80) return "Critical";
  if (score >= 55) return "High";
  if (score >= 25) return "Medium";
  return "Low";
}

function buildNarrative(
  riskScore: number,
  findings: Finding[],
  correlations: Correlation[],
  topSourceIp: string | null
): string {
  if (findings.length === 0) {
    return "No suspicious patterns were detected in the submitted log window.";
  }

  const leading = correlations[0]?.title || findings[0].rule;
  const source = topSourceIp ? ` Top source: ${topSourceIp}.` : "";
  const techniques = uniqueSorted(findings.map((finding) => finding.technique)).slice(0, 3).join(", ");
  return `Risk score ${riskScore}/100. Primary concern: ${leading}.${source} Observed techniques: ${techniques}.`;
}

function buildRecommendedActions(findings: Finding[], correlations: Correlation[]): string[] {
  const actions = [
    ...correlations.map((item) => item.recommendedAction),
    ...findings
      .filter((finding) => finding.severity === "Critical" || finding.severity === "High")
      .map((finding) => finding.recommendedFix),
  ];

  if (findings.some((finding) => finding.sourceIp)) {
    actions.push("Pivot on top source IPs across firewall, proxy, authentication, and endpoint telemetry.");
  }

  return uniqueSorted(actions).slice(0, 6);
}

function groupBy<T>(items: T[], getKey: (item: T) => string): Map<string, T[]> {
  const grouped = new Map<string, T[]>();
  items.forEach((item) => {
    const key = getKey(item);
    grouped.set(key, [...(grouped.get(key) || []), item]);
  });
  return grouped;
}

function uniqueSorted(values: string[]): string[] {
  return Array.from(new Set(values.filter(Boolean))).sort((a, b) => a.localeCompare(b));
}

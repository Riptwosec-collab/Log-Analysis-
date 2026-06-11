from pathlib import Path

content = r'''export type Severity = "Low" | "Medium" | "High" | "Critical";

export type LogType =
  | "Apache/Nginx"
  | "SSH Auth"
  | "Firewall"
  | "Windows Event"
  | "Linux Syslog"
  | "Cisco IOS"
  | "Meraki"
  | "Network Device"
  | "Application"
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

export type Correlation = {
  title: string;
  severity: Severity;
  sourceIp: string | null;
  eventCount: number;
  description: string;
  recommendedAction: string;
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
  logTypes?: LogType[];
  patterns: RegExp[];
  keywords: string[];
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

const severityPoints: Record<Severity, number> = {
  Low: 8,
  Medium: 18,
  High: 32,
  Critical: 48,
};

const privateIpPatterns = [
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[0-1])\./,
  /^127\./,
  /^169\.254\./,
];

const iocList: Record<string, { type: string; risk: Severity; description: string }> = {
  "185.220.101.21": {
    type: "Tor / suspicious source",
    risk: "High",
    description: "Known suspicious example IP frequently used in security demos.",
  },
  "45.77.10.2": {
    type: "Scanner",
    risk: "High",
    description: "Example scanning source used for firewall and port-scan demos.",
  },
  "198.51.100.44": {
    type: "Web attack source",
    risk: "High",
    description: "Example source for web exploitation demos.",
  },
};

const windowsEventMap: Record<
  string,
  {
    rule: string;
    severity: Severity;
    tactic: string;
    technique: string;
    rootCause: string;
    impact: string;
    fix: string;
    confidence: number;
  }
> = {
  "4624": {
    rule: "Windows successful logon",
    severity: "Low",
    tactic: "Initial Access",
    technique: "T1078 Valid Accounts",
    rootCause: "A Windows account logged on successfully.",
    impact: "Usually normal, but suspicious if it follows many failed logons or comes from an unusual source.",
    fix: "Review the source IP, account name, logon type, and nearby failed logon events.",
    confidence: 62,
  },
  "4625": {
    rule: "Windows failed logon",
    severity: "Medium",
    tactic: "Credential Access",
    technique: "T1110 Brute Force",
    rootCause: "A Windows account authentication attempt failed.",
    impact: "Repeated failures may indicate brute force, password spray, service password mismatch, or locked credentials.",
    fix: "Check the account, source address, logon type, lockout status, and successful logons after the failures.",
    confidence: 82,
  },
  "4672": {
    rule: "Windows special privileges assigned",
    severity: "High",
    tactic: "Privilege Escalation",
    technique: "T1078 Valid Accounts",
    rootCause: "A privileged account logged on and received special privileges.",
    impact: "If unexpected, this may indicate administrator account misuse or privilege escalation.",
    fix: "Validate the admin user, source host, approval record, and activity performed after logon.",
    confidence: 84,
  },
  "4688": {
    rule: "Windows process creation",
    severity: "Medium",
    tactic: "Execution",
    technique: "T1059 Command and Scripting Interpreter",
    rootCause: "A new process was created on a Windows endpoint.",
    impact: "May indicate suspicious execution when paired with PowerShell, encoded commands, or unusual parent process.",
    fix: "Check process command line, parent process, user, hash, and endpoint telemetry.",
    confidence: 70,
  },
  "4720": {
    rule: "Windows account created",
    severity: "High",
    tactic: "Persistence",
    technique: "T1136 Create Account",
    rootCause: "A new Windows account was created.",
    impact: "Could be normal administration or attacker persistence.",
    fix: "Confirm change request, creator account, group membership, and whether the account was used.",
    confidence: 86,
  },
  "4728": {
    rule: "Windows user added to privileged group",
    severity: "Critical",
    tactic: "Privilege Escalation",
    technique: "T1098 Account Manipulation",
    rootCause: "A user was added to a security-enabled global group.",
    impact: "Could grant elevated access or enable persistence.",
    fix: "Verify the requester, group, target user, and remove unauthorized membership immediately.",
    confidence: 90,
  },
  "4732": {
    rule: "Windows user added to local group",
    severity: "High",
    tactic: "Privilege Escalation",
    technique: "T1098 Account Manipulation",
    rootCause: "A user was added to a local group.",
    impact: "If the group is privileged, the user may gain local admin capability.",
    fix: "Review local group name, target user, admin approver, and endpoint activity.",
    confidence: 86,
  },
  "4740": {
    rule: "Windows account locked out",
    severity: "Medium",
    tactic: "Credential Access",
    technique: "T1110 Brute Force",
    rootCause: "A Windows account was locked out after authentication failures.",
    impact: "May indicate brute force, password spray, stale service password, or user error.",
    fix: "Identify the lockout source, check scheduled tasks/services, and reset credentials if needed.",
    confidence: 82,
  },
  "4768": {
    rule: "Kerberos authentication ticket requested",
    severity: "Low",
    tactic: "Credential Access",
    technique: "T1558 Steal or Forge Kerberos Tickets",
    rootCause: "A Kerberos TGT request occurred.",
    impact: "Often normal, but suspicious in bulk or with unusual encryption/pre-auth errors.",
    fix: "Review account, source host, failure codes, and abnormal volume.",
    confidence: 58,
  },
  "4769": {
    rule: "Kerberos service ticket requested",
    severity: "Medium",
    tactic: "Credential Access",
    technique: "T1558 Steal or Forge Kerberos Tickets",
    rootCause: "A Kerberos service ticket request occurred.",
    impact: "Could be normal or indicate Kerberoasting when many service tickets are requested.",
    fix: "Check service accounts, encryption type, volume, and suspicious requesting hosts.",
    confidence: 72,
  },
};

const rules: Rule[] = [
  {
    name: "SSH brute force login",
    severity: "High",
    logTypes: ["SSH Auth", "Linux Syslog"],
    patterns: [
      /failed password/i,
      /authentication failure/i,
      /invalid user/i,
      /maximum authentication attempts exceeded/i,
      /failed publickey/i,
    ],
    keywords: ["failed password", "authentication failure", "invalid user", "sshd"],
    rootCause: "Repeated SSH authentication failures were detected.",
    impact: "The targeted account or server may be under brute force or password spraying attack.",
    fix: "Block or rate-limit the source IP, review successful logons from the same IP, enforce MFA, disable password login, and restrict SSH to VPN or management IPs.",
    tactic: "Credential Access",
    technique: "T1110 Brute Force",
    confidence: 84,
  },
  {
    name: "SSH successful login",
    severity: "Medium",
    logTypes: ["SSH Auth", "Linux Syslog"],
    patterns: [/accepted password/i, /accepted publickey/i, /session opened for user/i],
    keywords: ["accepted password", "accepted publickey", "session opened"],
    rootCause: "An SSH login succeeded.",
    impact: "May be normal, but suspicious if it follows many failed attempts or uses an unusual account/source.",
    fix: "Validate the user, source IP, geolocation, and commands executed after login.",
    tactic: "Initial Access",
    technique: "T1078 Valid Accounts",
    confidence: 72,
  },
  {
    name: "SQL injection pattern",
    severity: "Critical",
    logTypes: ["Apache/Nginx", "Application", "Generic"],
    patterns: [
      /union\s+select/i,
      /or\s+1\s*=\s*1/i,
      /'\s*or\s*'1'\s*=\s*'1/i,
      /sleep\s*\(/i,
      /benchmark\s*\(/i,
      /information_schema/i,
      /sqlmap/i,
      /select.+from.+where/i,
    ],
    keywords: ["union select", "or 1=1", "sleep(", "information_schema", "sqlmap"],
    rootCause: "A request contained payloads commonly used for SQL injection.",
    impact: "The application may be exposed to database extraction, login bypass, or data modification.",
    fix: "Use prepared statements, validate input, review vulnerable endpoint code, add WAF rules, and inspect database logs for successful queries.",
    tactic: "Initial Access",
    technique: "T1190 Exploit Public-Facing Application",
    confidence: 93,
  },
  {
    name: "Path traversal attempt",
    severity: "High",
    logTypes: ["Apache/Nginx", "Application", "Generic"],
    patterns: [
      /\.\.\//,
      /\.\.\\/,
      /%2e%2e%2f/i,
      /%252e%252e%252f/i,
      /\/etc\/passwd/i,
      /boot\.ini/i,
      /win\.ini/i,
      /windows\/system32/i,
    ],
    keywords: ["../", "..\\", "/etc/passwd", "win.ini"],
    rootCause: "A request attempted to access files outside the intended web directory.",
    impact: "Attackers may read sensitive files, configuration secrets, or system files.",
    fix: "Normalize paths, block traversal patterns at WAF, enforce allowlisted file paths, and review file download endpoints.",
    tactic: "Initial Access",
    technique: "T1190 Exploit Public-Facing Application",
    confidence: 90,
  },
  {
    name: "XSS payload",
    severity: "Medium",
    logTypes: ["Apache/Nginx", "Application", "Generic"],
    patterns: [/<script/i, /javascript:/i, /onerror\s*=/i, /onload\s*=/i, /document\.cookie/i],
    keywords: ["<script", "javascript:", "onerror=", "document.cookie"],
    rootCause: "A request contained a cross-site scripting payload.",
    impact: "Users may be exposed to session theft, malicious redirects, or browser-side execution.",
    fix: "Escape output, apply Content Security Policy, validate input, and review affected parameters.",
    tactic: "Initial Access",
    technique: "T1189 Drive-by Compromise",
    confidence: 82,
  },
  {
    name: "Command injection pattern",
    severity: "Critical",
    logTypes: ["Apache/Nginx", "Application", "Generic", "Linux Syslog"],
    patterns: [
      /;\s*(cat|curl|wget|bash|sh|nc|python|perl)\b/i,
      /\|\s*(cat|curl|wget|bash|sh|nc|python|perl)\b/i,
      /`[^`]*(cat|curl|wget|bash|sh|nc|python|perl)/i,
      /\$\([^)]*(cat|curl|wget|bash|sh|nc|python|perl)/i,
      /cmd\.exe/i,
      /powershell/i,
    ],
    keywords: [";cat", "|bash", "wget", "curl", "cmd.exe", "powershell"],
    rootCause: "A request or process contained shell metacharacters and command execution indicators.",
    impact: "Attackers may execute commands on the server and gain remote code execution.",
    fix: "Remove shell execution, use safe APIs, validate input, block payloads at WAF, and check host telemetry for spawned processes.",
    tactic: "Execution",
    technique: "T1059 Command and Scripting Interpreter",
    confidence: 90,
  },
  {
    name: "Firewall drop or deny",
    severity: "Medium",
    logTypes: ["Firewall", "Cisco IOS", "Network Device", "Meraki"],
    patterns: [
      /\b(drop|deny|denied|blocked|reject)\b/i,
      /\baction=(drop|deny|blocked)\b/i,
      /\bDeny\s+tcp\b/i,
      /\bDeny\s+udp\b/i,
    ],
    keywords: ["drop", "deny", "blocked", "reject"],
    rootCause: "Traffic was blocked by a firewall or network security rule.",
    impact: "May indicate scanning, denied application traffic, or a policy misconfiguration.",
    fix: "Review source/destination, port, policy ID, NAT, recent changes, and whether this is expected traffic.",
    tactic: "Reconnaissance",
    technique: "T1595 Active Scanning",
    confidence: 74,
  },
  {
    name: "Port scan or blocked probe",
    severity: "High",
    logTypes: ["Firewall", "Cisco IOS", "Network Device", "Meraki"],
    patterns: [
      /\bSYN\b.*\bDPT=\d+/i,
      /\bDPT=\d+\b/i,
      /\bdst_port[=:\s]+\d+/i,
      /\bport scan\b/i,
      /\bscanning\b/i,
    ],
    keywords: ["DPT=", "SYN", "port scan", "scanning"],
    rootCause: "A source appears to probe one or more destination services.",
    impact: "Could be reconnaissance before exploitation or unauthorized vulnerability scanning.",
    fix: "Rate-limit or block the source, verify exposed services, and search for follow-on exploit attempts.",
    tactic: "Reconnaissance",
    technique: "T1595 Active Scanning",
    confidence: 78,
  },
  {
    name: "Windows suspicious PowerShell",
    severity: "High",
    logTypes: ["Windows Event", "Application", "Generic"],
    patterns: [
      /powershell/i,
      /encodedcommand/i,
      /-enc\s+/i,
      /frombase64string/i,
      /downloadstring/i,
      /iex\s*\(/i,
      /invoke-expression/i,
      /bypass\s+-?executionpolicy/i,
    ],
    keywords: ["powershell", "encodedcommand", "downloadstring", "iex", "bypass"],
    rootCause: "PowerShell activity contains suspicious execution or obfuscation indicators.",
    impact: "May indicate malware execution, script-based intrusion, or lateral movement.",
    fix: "Collect command line, parent process, user, script block logs, endpoint alerts, and isolate the host if malicious.",
    tactic: "Execution",
    technique: "T1059.001 PowerShell",
    confidence: 88,
  },
  {
    name: "Linux privilege or sudo failure",
    severity: "Medium",
    logTypes: ["Linux Syslog", "Generic"],
    patterns: [/sudo:.*authentication failure/i, /sudo:.*incorrect password/i, /user NOT in sudoers/i, /su:.*failure/i],
    keywords: ["sudo", "authentication failure", "NOT in sudoers", "su:"],
    rootCause: "A Linux user attempted privileged access and failed.",
    impact: "Could be user error or an attacker attempting privilege escalation.",
    fix: "Validate the user, source session, sudo policy, and nearby successful privileged commands.",
    tactic: "Privilege Escalation",
    technique: "T1548 Abuse Elevation Control Mechanism",
    confidence: 76,
  },
  {
    name: "Service down or timeout",
    severity: "Medium",
    logTypes: ["Application", "Linux Syslog", "Generic", "Network Device", "Cisco IOS"],
    patterns: [/service.*down/i, /timeout/i, /timed out/i, /connection refused/i, /unreachable/i, /health check failed/i],
    keywords: ["down", "timeout", "connection refused", "unreachable", "health check failed"],
    rootCause: "A service, host, or dependency reported availability problems.",
    impact: "Users may experience application slowness, failed connections, or outage symptoms.",
    fix: "Check recent changes, CPU/memory/interface utilization, dependency health, routing, DNS, and application error rate.",
    tactic: "Impact",
    technique: "Service Disruption",
    confidence: 70,
  },
  {
    name: "Cisco MAC flapping",
    severity: "High",
    logTypes: ["Cisco IOS", "Network Device"],
    patterns: [
      /MACFLAP/i,
      /host\s+[0-9a-f.:-]+\s+in\s+vlan/i,
      /flapping\s+between/i,
      /moved\s+from\s+.*\s+to\s+/i,
    ],
    keywords: ["MACFLAP", "flapping", "moved from", "host"],
    rootCause: "The same MAC address is moving between switch ports.",
    impact: "May indicate a Layer 2 loop, unmanaged switch loop, wrong cabling, AP bridge loop, or STP instability.",
    fix: "Trace the MAC address, check both ports, inspect cabling, verify STP root/blocked ports, and remove unmanaged switch loops.",
    tactic: "Impact",
    technique: "Layer 2 Loop / MAC Instability",
    confidence: 92,
  },
  {
    name: "Cisco DHCP Snooping or DAI violation",
    severity: "High",
    logTypes: ["Cisco IOS", "Network Device"],
    patterns: [
      /DHCP_SNOOPING/i,
      /SW_DAI/i,
      /DYNAMIC ARP INSPECTION/i,
      /ARP.*(deny|drop|inspection)/i,
      /snooping.*(deny|drop|untrusted)/i,
    ],
    keywords: ["DHCP_SNOOPING", "SW_DAI", "DAI", "ARP inspection", "untrusted"],
    rootCause: "The switch detected DHCP Snooping or Dynamic ARP Inspection activity.",
    impact: "Possible rogue DHCP, ARP spoofing, wrong trusted uplink, missing binding, or endpoint misconfiguration.",
    fix: "Check trusted uplinks, DHCP Snooping binding table, VLAN configuration, ARP inspection logs, and recent switch changes.",
    tactic: "Credential Access",
    technique: "T1557 Adversary-in-the-Middle",
    confidence: 88,
  },
  {
    name: "Cisco STP topology change",
    severity: "High",
    logTypes: ["Cisco IOS", "Network Device"],
    patterns: [
      /SPANTREE/i,
      /topology change/i,
      /STP.*(block|forward|root)/i,
      /BPDU/i,
      /root guard/i,
      /loop guard/i,
    ],
    keywords: ["SPANTREE", "topology change", "BPDU", "root guard", "loop guard"],
    rootCause: "Spanning Tree detected a topology change, BPDU event, or port state transition.",
    impact: "Network may experience temporary packet loss, loop prevention events, blocked ports, or unstable Layer 2 paths.",
    fix: "Check root bridge, PortFast, BPDU Guard, Loop Guard, uplink topology, and the port that changed state.",
    tactic: "Impact",
    technique: "Layer 2 Topology Change",
    confidence: 84,
  },
  {
    name: "Cisco interface down",
    severity: "Medium",
    logTypes: ["Cisco IOS", "Network Device"],
    patterns: [
      /LINK-\d+-CHANGED/i,
      /LINEPROTO-\d+-UPDOWN/i,
      /changed state to down/i,
      /interface.*down/i,
      /err-?disabled/i,
    ],
    keywords: ["LINK", "LINEPROTO", "changed state to down", "err-disabled"],
    rootCause: "A network interface changed state or was disabled.",
    impact: "Connected users, APs, uplinks, downstream switches, or servers may lose connectivity.",
    fix: "Check cable, SFP, port errors, remote device power, interface counters, err-disable reason, and recent maintenance.",
    tactic: "Impact",
    technique: "Network Service Disruption",
    confidence: 78,
  },
  {
    name: "Cisco port security violation",
    severity: "High",
    logTypes: ["Cisco IOS", "Network Device"],
    patterns: [
      /PORT_SECURITY/i,
      /PSECURE/i,
      /security violation/i,
      /violation.*(shutdown|restrict|protect)/i,
    ],
    keywords: ["PORT_SECURITY", "PSECURE", "security violation"],
    rootCause: "Port security detected an unauthorized MAC address or violation.",
    impact: "The switch port may be restricted or shut down, causing user/device outage or indicating unauthorized device connection.",
    fix: "Verify the connected device, learned MAC address, port-security settings, violation mode, and clear err-disable only after confirming legitimacy.",
    tactic: "Defense Evasion",
    technique: "Network Access Control Bypass",
    confidence: 86,
  },
  {
    name: "Routing adjacency down",
    severity: "High",
    logTypes: ["Cisco IOS", "Network Device"],
    patterns: [
      /OSPF.*(DOWN|Down|FULL to DOWN|neighbor)/i,
      /BGP.*(Down|Idle|Cease|Notification)/i,
      /EIGRP.*neighbor.*down/i,
      /HSRP.*state.*(Speak|Standby|Active)/i,
    ],
    keywords: ["OSPF", "BGP", "EIGRP", "HSRP", "neighbor down"],
    rootCause: "A routing or gateway redundancy adjacency changed state.",
    impact: "Traffic may reroute, fail over, flap, or lose reachability depending on topology.",
    fix: "Check physical link, peer reachability, timers, authentication, routing policy, CPU, interface errors, and recent changes.",
    tactic: "Impact",
    technique: "Network Route Disruption",
    confidence: 82,
  },
];

export function analyzeLog(logContent: string): AnalysisResult {
  const lines = logContent
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const findings: Finding[] = [];

  lines.forEach((line, index) => {
    const logType = detectLogType(line);
    const eventIdFinding = analyzeWindowsEventId(line, index + 1, logType);
    if (eventIdFinding) {
      findings.push(eventIdFinding);
    }

    for (const rule of rules) {
      if (rule.logTypes && !rule.logTypes.includes(logType) && !rule.logTypes.includes("Generic")) {
        continue;
      }

      const matchedPattern = rule.patterns.find((pattern) => pattern.test(line));
      const matchedKeywords = rule.keywords.filter((keyword) => line.toLowerCase().includes(keyword.toLowerCase()));

      if (!matchedPattern && matchedKeywords.length === 0) continue;

      const duplicateWindowsEvent =
        eventIdFinding &&
        logType === "Windows Event" &&
        eventIdFinding.rule === rule.name;

      if (duplicateWindowsEvent) continue;

      const parsed = parseFields(line);
      const ioc = parsed.sourceIp ? iocList[parsed.sourceIp] : null;
      const severity = escalateSeverity(rule.severity, ioc?.risk || null);

      findings.push({
        id: `EVT-${String(findings.length + 1).padStart(4, "0")}`,
        lineNumber: index + 1,
        timestamp: parsed.timestamp,
        severity,
        logType,
        rule: rule.name,
        detectedKeywords: uniqueSorted([...matchedKeywords, matchedPattern ? matchedPattern.source.slice(0, 40) : ""]),
        possibleRootCause: ioc ? `${rule.rootCause} IOC matched: ${ioc.type}.` : rule.rootCause,
        impact: ioc ? `${rule.impact} IOC context: ${ioc.description}` : rule.impact,
        recommendedFix: rule.fix,
        sourceIp: parsed.sourceIp,
        destinationIp: parsed.destinationIp,
        destinationPort: parsed.destinationPort,
        username: parsed.username,
        asset: parsed.asset,
        tactic: rule.tactic,
        technique: rule.technique,
        confidence: calculateFindingConfidence(rule.confidence, line, ioc?.risk || null),
        evidence: buildEvidence(line, rule),
        raw: line,
        repeatedCount: 1,
      });
    }
  });

  const normalizedFindings = applyAggregateSeverity(findings);
  const correlations = correlateFindings(normalizedFindings);
  const summary = buildSummary(lines.length, normalizedFindings, correlations);

  return {
    generatedAt: new Date().toISOString(),
    summary,
    findings: normalizedFindings,
  };
}

function analyzeWindowsEventId(line: string, lineNumber: number, logType: LogType): Finding | null {
  const eventId = extractWindowsEventId(line);
  if (!eventId) return null;

  const mapped = windowsEventMap[eventId];
  if (!mapped) return null;

  const parsed = parseFields(line);
  const ioc = parsed.sourceIp ? iocList[parsed.sourceIp] : null;
  const severity = escalateSeverity(mapped.severity, ioc?.risk || null);

  return {
    id: `EVT-WIN-${lineNumber}`,
    lineNumber,
    timestamp: parsed.timestamp,
    severity,
    logType: logType === "Generic" ? "Windows Event" : logType,
    rule: mapped.rule,
    detectedKeywords: [`Event ID ${eventId}`],
    possibleRootCause: ioc ? `${mapped.rootCause} IOC matched: ${ioc.type}.` : mapped.rootCause,
    impact: ioc ? `${mapped.impact} IOC context: ${ioc.description}` : mapped.impact,
    recommendedFix: mapped.fix,
    sourceIp: parsed.sourceIp,
    destinationIp: parsed.destinationIp,
    destinationPort: parsed.destinationPort,
    username: parsed.username,
    asset: parsed.asset,
    tactic: mapped.tactic,
    technique: mapped.technique,
    confidence: calculateFindingConfidence(mapped.confidence, line, ioc?.risk || null),
    evidence: `Event ID ${eventId}`,
    raw: line,
    repeatedCount: 1,
  };
}

function parseFields(line: string) {
  return {
    timestamp: extractTimestamp(line),
    sourceIp: extractSourceIp(line),
    destinationIp: extractDestinationIp(line),
    destinationPort: extractDestinationPort(line),
    username: extractUsername(line),
    asset: extractAsset(line),
    interfaceName: extractInterface(line),
    vlan: extractVlan(line),
    macAddress: extractMac(line),
  };
}

function detectLogType(line: string): LogType {
  if (/%[A-Z0-9_-]+-\d+-[A-Z0-9_-]+/i.test(line)) return "Cisco IOS";
  if (/\b(MACFLAP|SPANTREE|LINK|LINEPROTO|DHCP_SNOOPING|SW_DAI|PORT_SECURITY|PSECURE|OSPF|BGP|EIGRP|HSRP)\b/i.test(line)) {
    return "Cisco IOS";
  }
  if (/\bmeraki\b|\bclient vpn\b|\bevent type\b|\bssid\b/i.test(line)) return "Meraki";
  if (/\b(sshd|pam_unix|failed password|accepted password|invalid user)\b/i.test(line)) return "SSH Auth";
  if (/\b(event id|audit failure|microsoft-windows|security-auditing|logon type)\b/i.test(line)) return "Windows Event";
  if (/\b(ufw|iptables|firewall|deny|drop|src=|dst=|dpt=|spt=|action=blocked)\b/i.test(line)) return "Firewall";
  if (/\b(kernel|systemd|cron|sudo|systemctl|journal)\b/i.test(line)) return "Linux Syslog";
  if (/\b(GET|POST|PUT|DELETE|HEAD|PATCH)\b.*\b(HTTP\/| 200 | 301 | 302 | 400 | 401 | 403 | 404 | 500 | 503 )/i.test(line)) {
    return "Apache/Nginx";
  }
  if (/\b(error|exception|stack trace|traceback|fatal|warn|info)\b/i.test(line)) return "Application";
  return "Generic";
}

function extractTimestamp(line: string): string | null {
  const iso = line.match(/\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?/);
  if (iso) return iso[0].replace(" ", "T");

  const syslog = line.match(/\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b/);
  if (syslog) return syslog[0];

  const windows = line.match(/\d{1,2}\/\d{1,2}\/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?/i);
  if (windows) return windows[0];

  const cisco = line.match(/\b\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+\w+)?\b/);
  return cisco ? cisco[0] : null;
}

function extractSourceIp(line: string): string | null {
  const explicit = line.match(
    /\b(?:SRC|src|source|from|client|Source Network Address|srcip|sourceip|source_ip|remote_addr)[:=\s]+((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))/i
  );
  if (explicit) return explicit[1];

  const ips = extractIps(line);
  const publicIp = ips.find((ip) => !isPrivateIp(ip));
  return publicIp || ips[0] || null;
}

function extractDestinationIp(line: string): string | null {
  const explicit = line.match(
    /\b(?:DST|dst|destination|to|dstip|destinationip|destination_ip)[:=\s]+((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))/i
  );
  if (explicit) return explicit[1];

  const ips = extractIps(line);
  if (ips.length < 2) return null;
  return ips[1];
}

function extractDestinationPort(line: string): string | null {
  const patterns = [
    /\b(?:DPT|dpt|dst_port|destination port|destination_port|dstport)[:=\s]+(\d{1,5})\b/i,
    /\bto\s+(?:port\s+)?(\d{1,5})\b/i,
    /\bport\s+(\d{1,5})\b/i,
  ];

  for (const pattern of patterns) {
    const match = line.match(pattern);
    if (match) return match[1];
  }

  return null;
}

function extractUsername(line: string): string | null {
  const patterns = [
    /invalid user\s+([a-z0-9._$-]+)/i,
    /for\s+invalid user\s+([a-z0-9._$-]+)/i,
    /for\s+([a-z0-9._$-]+)\s+from/i,
    /user(?:name)?[=:\s]+([a-z0-9._$-]+)/i,
    /Account Name:\s*([a-z0-9._$-]+)/i,
    /acct(?:ount)?[=:\s]+([a-z0-9._$-]+)/i,
    /User:\s*([a-z0-9._$-]+)/i,
  ];

  for (const pattern of patterns) {
    const match = line.match(pattern);
    if (match && !["from", "invalid", "user", "-", "anonymous"].includes(match[1].toLowerCase())) return match[1];
  }

  return null;
}

function extractAsset(line: string): string | null {
  const syslogHost = line.match(
    /^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+([a-z0-9._-]+)/i
  );
  if (syslogHost) return syslogHost[1];

  const host = line.match(/\b(?:host|hostname|device|devname|computer)[:=\s]+([a-z0-9._-]+)/i);
  if (host) return host[1];

  const ciscoHost = line.match(/^([a-z0-9._-]+)\s+%[A-Z0-9_-]+-\d+-/i);
  return ciscoHost ? ciscoHost[1] : null;
}

function extractInterface(line: string): string | null {
  const match = line.match(
    /\b(?:Gi|GigabitEthernet|Fa|FastEthernet|Te|TenGigabitEthernet|Twe|TwentyFiveGigE|Fo|FortyGigabitEthernet|Hu|HundredGigE|Eth|Ethernet|Po|Port-channel|Vl|Vlan)\d+(?:\/\d+){0,3}\b/i
  );
  return match ? match[0] : null;
}

function extractVlan(line: string): string | null {
  const match = line.match(/\bVLAN(?:\s|=|-)?(\d+)\b/i) || line.match(/\bvlan\s+(\d+)\b/i);
  return match ? match[1] : null;
}

function extractMac(line: string): string | null {
  const patterns = [
    /\b[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\b/i,
    /\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b/i,
    /\b[0-9a-f]{2}(?:-[0-9a-f]{2}){5}\b/i,
  ];

  for (const pattern of patterns) {
    const match = line.match(pattern);
    if (match) return match[0];
  }

  return null;
}

function extractWindowsEventId(line: string): string | null {
  const match = line.match(/\bEvent\s*ID[:\s]+(\d{4})\b/i) || line.match(/\bEventCode[=:\s]+(\d{4})\b/i) || line.match(/\bID[:\s]+(\d{4})\b/i);
  return match ? match[1] : null;
}

function extractIps(line: string): string[] {
  return Array.from(
    line.matchAll(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g)
  ).map((match) => match[0]);
}

function isPrivateIp(ip: string): boolean {
  return privateIpPatterns.some((pattern) => pattern.test(ip));
}

function escalateSeverity(base: Severity, iocRisk: Severity | null): Severity {
  if (!iocRisk) return base;
  return severityRank[iocRisk] > severityRank[base] ? iocRisk : base;
}

function calculateFindingConfidence(base: number, line: string, iocRisk: Severity | null): number {
  const parsed = parseFields(line);
  let score = base;

  if (parsed.timestamp) score += 2;
  if (parsed.sourceIp) score += 4;
  if (parsed.username) score += 2;
  if (parsed.destinationPort) score += 2;
  if (iocRisk) score += severityRank[iocRisk] * 3;

  return Math.min(99, score);
}

function buildEvidence(line: string, rule: Rule): string {
  const pattern = rule.patterns.find((item) => item.test(line));
  if (!pattern) return rule.keywords[0] || rule.name;
  const match = line.match(pattern);
  return match?.[0]?.slice(0, 100) || rule.keywords[0] || rule.name;
}

function applyAggregateSeverity(findings: Finding[]): Finding[] {
  const bySourceAndRule = new Map<string, number>();

  findings.forEach((finding) => {
    const key = `${finding.sourceIp || finding.asset || "unknown"}:${finding.rule}`;
    bySourceAndRule.set(key, (bySourceAndRule.get(key) || 0) + 1);
  });

  return findings.map((finding) => {
    const key = `${finding.sourceIp || finding.asset || "unknown"}:${finding.rule}`;
    const count = bySourceAndRule.get(key) || finding.repeatedCount;
    const repeatBoost = count >= 10 ? 14 : count >= 5 ? 8 : count >= 3 ? 4 : 0;
    let severity = finding.severity;

    if (count >= 10 && severityRank[severity] < severityRank.Critical) severity = "Critical";
    else if (count >= 5 && severityRank[severity] < severityRank.High) severity = "High";

    return {
      ...finding,
      severity,
      confidence: Math.min(99, finding.confidence + repeatBoost),
      repeatedCount: Math.max(finding.repeatedCount, count),
      impact:
        count >= 5 && !finding.impact.includes("Repeated activity")
          ? `${finding.impact} Repeated activity raises the incident priority.`
          : finding.impact,
    };
  });
}

function correlateFindings(findings: Finding[]): Correlation[] {
  const correlations: Correlation[] = [];
  const bySource = groupBy(findings.filter((finding) => finding.sourceIp), (finding) => finding.sourceIp || "unknown");

  bySource.forEach((items, sourceIp) => {
    const bruteForce = items.filter((finding) => finding.rule.includes("brute force") || finding.rule.includes("failed logon"));
    const uniqueUsers = new Set(bruteForce.map((finding) => finding.username).filter(Boolean));

    if (bruteForce.length >= 4 || uniqueUsers.size >= 3) {
      correlations.push({
        title: "Credential attack burst",
        severity: "Critical",
        sourceIp,
        eventCount: bruteForce.length,
        description: `${sourceIp} generated ${bruteForce.length} authentication failure signal(s) across ${uniqueUsers.size || 1} account(s).`,
        recommendedAction: "Block or rate-limit the source, review successful logons from the same IP, and force reset for targeted accounts if compromise is suspected.",
      });
    }

    const ports = new Set(items.map((finding) => finding.destinationPort).filter(Boolean));
    const scanEvents = items.filter((finding) => finding.rule === "Port scan or blocked probe" || finding.rule === "Firewall drop or deny");

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
        .filter((finding) =>
          ["SQL injection pattern", "Path traversal attempt", "XSS payload", "Command injection pattern"].includes(finding.rule)
        )
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

    const iocHits = items.filter((finding) => finding.sourceIp && iocList[finding.sourceIp]);
    if (iocHits.length >= 1) {
      correlations.push({
        title: "IOC source activity",
        severity: "High",
        sourceIp,
        eventCount: iocHits.length,
        description: `${sourceIp} matched local IOC context and generated ${iocHits.length} suspicious event(s).`,
        recommendedAction: "Block the IOC if business impact is acceptable, hunt for the same IP across firewall/proxy/auth logs, and document the IOC in the incident ticket.",
      });
    }
  });

  const byAsset = groupBy(findings.filter((finding) => finding.asset), (finding) => finding.asset || "unknown");
  byAsset.forEach((items, asset) => {
    const layer2 = items.filter((finding) =>
      ["Cisco MAC flapping", "Cisco STP topology change", "Cisco DHCP Snooping or DAI violation", "Cisco interface down"].includes(finding.rule)
    );

    if (layer2.length >= 3) {
      correlations.push({
        title: "Layer 2 instability cluster",
        severity: "High",
        sourceIp: null,
        eventCount: layer2.length,
        description: `${asset} generated ${layer2.length} Layer 2 or interface stability signal(s).`,
        recommendedAction: "Check STP state, recent cabling changes, unmanaged switches, uplinks, AP bridge links, and interface counters.",
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
      recommendedAction: "Check recent deployments, upstream health, saturation metrics, DNS, routing, and error-rate dashboards.",
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
  const mitreTechniques = uniqueSorted(findings.map((finding) => finding.technique)).slice(0, 10);

  return {
    totalEvents,
    suspiciousEvents: findings.length,
    criticalAlerts: severityCounts.Critical,
    failedLogins: findings.filter((finding) => finding.rule.includes("brute force") || finding.rule.includes("failed logon")).length,
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

  const eventPoints = findings.reduce((sum, finding) => {
    const repeatBonus = finding.repeatedCount >= 10 ? 10 : finding.repeatedCount >= 5 ? 6 : finding.repeatedCount >= 3 ? 3 : 0;
    const confidenceBonus = finding.confidence >= 90 ? 5 : finding.confidence >= 80 ? 3 : finding.confidence >= 70 ? 1 : 0;
    const iocBonus = finding.sourceIp && iocList[finding.sourceIp] ? 8 : 0;
    return sum + severityPoints[finding.severity] + repeatBonus + confidenceBonus + iocBonus;
  }, 0);

  const correlationPoints = correlations.reduce((sum, item) => sum + severityRank[item.severity] * 9, 0);
  const densityBonus = totalEvents > 0 ? Math.min(18, (findings.length / totalEvents) * 18) : 0;

  return Math.min(100, Math.round(eventPoints / 2.5 + correlationPoints + densityBonus));
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
    actions.push("Pivot on top source IPs across firewall, proxy, authentication, endpoint, and DNS telemetry.");
  }

  if (findings.some((finding) => finding.logType === "Cisco IOS" || finding.logType === "Network Device")) {
    actions.push("For network-device incidents, collect show log, show interface status, show spanning-tree, show mac address-table, and recent change records.");
  }

  return uniqueSorted(actions).slice(0, 8);
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
'''

path = Path("/mnt/data/logAnalyzer.ts")
path.write_text(content, encoding="utf-8")
print(f"Created {path} ({len(content)} characters)")

export type Severity = "Low" | "Medium" | "High" | "Critical";

export type LogType =
  | "Apache/Nginx"
  | "Apache"
  | "Nginx"
  | "SSH Auth"
  | "Firewall"
  | "FortiGate"
  | "Palo Alto"
  | "Sophos"
  | "Cloudflare"
  | "Microsoft 365"
  | "Windows Event"
  | "Linux Syslog"
  | "Cisco IOS"
  | "Meraki"
  | "Network Device"
  | "Application"
  | "Generic";

export type ThreatIntel = {
  indicator: string;
  indicatorType: "ip" | "domain" | "hash";
  type: string;
  risk: Severity;
  description: string;
  country?: string;
  asn?: string;
  abuseScore?: number;
  reputation?: string;
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

export type Correlation = {
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
  iocHits: number;
  publicIpCount: number;
  privateIpCount: number;
  reservedIpCount: number;
  vendorCounts: Record<string, number>;
  analystReport: AnalystReport;
};

export type AnalystReport = {
  socAnalyst: string;
  rca: string;
  managerSummary: string;
  fixCommand: string;
  ticket: string;
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
  timeWindowMinutes?: number;
  aggregateThreshold?: number;
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

const reservedIpPatterns = [
  /^0\./,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,
  /^192\.0\.2\./,
  /^198\.51\.100\./,
  /^203\.0\.113\./,
  /^224\./,
  /^240\./,
  /^255\.255\.255\.255$/,
];

const iocList: Record<string, ThreatIntel> = {
  "185.220.101.21": {
    indicator: "185.220.101.21",
    indicatorType: "ip",
    type: "Known Tor Exit Node / Suspicious Source",
    risk: "High",
    description: "IP นี้อยู่ในรายการ IOC ภายใน เป็นแหล่งที่ควรตรวจสอบเพิ่มเติม",
    country: "Unknown",
    asn: "AS-TOR",
    abuseScore: 88,
    reputation: "suspicious",
  },
  "45.77.10.2": {
    indicator: "45.77.10.2",
    indicatorType: "ip",
    type: "Scanner / Recon Source",
    risk: "High",
    description: "IP นี้มีพฤติกรรมสแกนพอร์ตหรือ Probe Service",
    country: "Unknown",
    asn: "AS-SCANNER",
    abuseScore: 82,
    reputation: "scanner",
  },
  "198.51.100.44": {
    indicator: "198.51.100.44",
    indicatorType: "ip",
    type: "Web Attack Source",
    risk: "High",
    description: "IP นี้ถูกใช้เป็นตัวอย่าง IOC สำหรับ Web Attack",
    country: "Reserved/Test",
    asn: "TEST-NET-2",
    abuseScore: 72,
    reputation: "test-ioc",
  },
  "203.0.113.9": {
    indicator: "203.0.113.9",
    indicatorType: "ip",
    type: "Path Traversal Source",
    risk: "Medium",
    description: "IP ตัวอย่างสำหรับ Path Traversal / Web Recon",
    country: "Reserved/Test",
    asn: "TEST-NET-3",
    abuseScore: 60,
    reputation: "test-ioc",
  },
};

const domainIocList: Record<string, ThreatIntel> = {
  "evil.example.com": {
    indicator: "evil.example.com",
    indicatorType: "domain",
    type: "Malicious Domain",
    risk: "Critical",
    description: "Domain นี้อยู่ในรายการ IOC ภายใน อาจเกี่ยวข้องกับ Malware C2 หรือ Phishing",
    country: "Unknown",
    asn: "Unknown",
    abuseScore: 95,
    reputation: "malicious",
  },
  "c2.bad-domain.test": {
    indicator: "c2.bad-domain.test",
    indicatorType: "domain",
    type: "Command and Control Domain",
    risk: "Critical",
    description: "Domain นี้ถูกจัดเป็น C2 Indicator สำหรับทดสอบ Threat Intelligence",
    country: "Unknown",
    asn: "Unknown",
    abuseScore: 98,
    reputation: "c2",
  },
};

const hashIocList: Record<string, ThreatIntel> = {
  "44d88612fea8a8f36de82e1278abb02f": {
    indicator: "44d88612fea8a8f36de82e1278abb02f",
    indicatorType: "hash",
    type: "Malware Hash",
    risk: "Critical",
    description: "Hash นี้อยู่ใน IOC ภายใน อาจเป็นไฟล์ Malware หรือ Tool ที่ไม่ควรพบในระบบ",
    abuseScore: 99,
    reputation: "malware",
  },
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
    indicator: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    indicatorType: "hash",
    type: "Suspicious Hash",
    risk: "High",
    description: "Hash ตัวอย่างสำหรับทดสอบ Hash Reputation",
    abuseScore: 80,
    reputation: "suspicious",
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
    rule: "Windows: เข้าสู่ระบบสำเร็จ",
    severity: "Low",
    tactic: "Initial Access",
    technique: "T1078 - Valid Accounts",
    rootCause: "พบบัญชี Windows เข้าสู่ระบบสำเร็จ",
    impact: "โดยทั่วไปอาจเป็นเหตุการณ์ปกติ แต่ควรตรวจสอบถ้าเกิดหลังจาก login fail หลายครั้ง หรือมาจากแหล่งที่ผิดปกติ",
    fix: "ตรวจสอบ Source IP, Account Name, Logon Type และเหตุการณ์ login fail ในช่วงเวลาใกล้เคียง",
    confidence: 62,
  },
  "4625": {
    rule: "Windows: เข้าสู่ระบบไม่สำเร็จ",
    severity: "Medium",
    tactic: "Credential Access",
    technique: "T1110 - Brute Force",
    rootCause: "พบบัญชี Windows พยายามยืนยันตัวตนไม่สำเร็จ",
    impact: "ถ้าเกิดซ้ำหลายครั้ง อาจเป็น Brute Force, Password Spray, รหัสผ่าน Service ผิด หรือ Credential ถูกล็อก",
    fix: "ตรวจสอบบัญชี, Source IP, Logon Type, สถานะ Lockout และ login สำเร็จหลังจากเหตุการณ์ล้มเหลว",
    confidence: 82,
  },
  "4672": {
    rule: "Windows: มีการใช้สิทธิ์พิเศษ",
    severity: "High",
    tactic: "Privilege Escalation",
    technique: "T1078 - Valid Accounts",
    rootCause: "พบบัญชีสิทธิ์สูงเข้าสู่ระบบและได้รับสิทธิ์พิเศษ",
    impact: "ถ้าไม่ได้คาดหมาย อาจเป็นการใช้งานบัญชีผู้ดูแลระบบผิดปกติ หรือการยกระดับสิทธิ์",
    fix: "ตรวจสอบผู้ใช้ admin, เครื่องต้นทาง, เอกสารอนุมัติ และกิจกรรมหลังจาก login",
    confidence: 84,
  },
  "4688": {
    rule: "Windows: มีการสร้าง Process",
    severity: "Medium",
    tactic: "Execution",
    technique: "T1059 - Command and Scripting Interpreter",
    rootCause: "พบการสร้าง Process ใหม่บนเครื่อง Windows",
    impact: "อาจน่าสงสัยถ้าเกี่ยวข้องกับ PowerShell, encoded command หรือ parent process ที่ผิดปกติ",
    fix: "ตรวจสอบ command line, parent process, user, hash และข้อมูลจาก Endpoint Security",
    confidence: 70,
  },
  "4720": {
    rule: "Windows: มีการสร้างบัญชีใหม่",
    severity: "High",
    tactic: "Persistence",
    technique: "T1136 - Create Account",
    rootCause: "พบการสร้างบัญชี Windows ใหม่",
    impact: "อาจเป็นงานดูแลระบบปกติ หรือเป็นการสร้างบัญชีเพื่อฝังตัวของผู้โจมตี",
    fix: "ตรวจสอบ Change Request, ผู้สร้างบัญชี, Group Membership และการใช้งานบัญชีนั้น",
    confidence: 86,
  },
  "4728": {
    rule: "Windows: เพิ่มผู้ใช้เข้ากลุ่มสิทธิ์สูง",
    severity: "Critical",
    tactic: "Privilege Escalation",
    technique: "T1098 - Account Manipulation",
    rootCause: "พบการเพิ่มผู้ใช้เข้ากลุ่มที่มีผลต่อสิทธิ์ความปลอดภัย",
    impact: "อาจทำให้ผู้ใช้ได้รับสิทธิ์สูงขึ้น หรือใช้เป็นช่องทางคงสิทธิ์ในระบบ",
    fix: "ตรวจสอบผู้ร้องขอ, กลุ่ม, ผู้ใช้เป้าหมาย และลบสิทธิ์ทันทีถ้าไม่ได้รับอนุญาต",
    confidence: 90,
  },
  "4732": {
    rule: "Windows: เพิ่มผู้ใช้เข้ากลุ่ม Local",
    severity: "High",
    tactic: "Privilege Escalation",
    technique: "T1098 - Account Manipulation",
    rootCause: "พบการเพิ่มผู้ใช้เข้ากลุ่มภายในเครื่อง",
    impact: "ถ้ากลุ่มนั้นมีสิทธิ์สูง ผู้ใช้อาจได้รับสิทธิ์ Local Admin",
    fix: "ตรวจสอบชื่อกลุ่ม, ผู้ใช้เป้าหมาย, ผู้อนุมัติ และกิจกรรมบนเครื่อง",
    confidence: 86,
  },
  "4740": {
    rule: "Windows: บัญชีถูกล็อก",
    severity: "Medium",
    tactic: "Credential Access",
    technique: "T1110 - Brute Force",
    rootCause: "พบบัญชี Windows ถูกล็อกจากการยืนยันตัวตนผิดพลาด",
    impact: "อาจเกิดจาก Brute Force, Password Spray, Service ใช้รหัสผ่านเก่า หรือผู้ใช้กรอกรหัสผิด",
    fix: "หาแหล่งที่ทำให้บัญชีล็อก ตรวจสอบ Scheduled Task/Service และรีเซ็ตรหัสผ่านถ้าจำเป็น",
    confidence: 82,
  },
  "4768": {
    rule: "Kerberos: มีการขอ Authentication Ticket",
    severity: "Low",
    tactic: "Credential Access",
    technique: "T1558 - Steal or Forge Kerberos Tickets",
    rootCause: "พบการขอ Kerberos TGT",
    impact: "มักเป็นเหตุการณ์ปกติ แต่ควรตรวจสอบถ้าเกิดจำนวนมาก หรือมี pre-auth/encryption ผิดปกติ",
    fix: "ตรวจสอบบัญชี, เครื่องต้นทาง, Failure Code และปริมาณที่ผิดปกติ",
    confidence: 58,
  },
  "4769": {
    rule: "Kerberos: มีการขอ Service Ticket",
    severity: "Medium",
    tactic: "Credential Access",
    technique: "T1558 - Steal or Forge Kerberos Tickets",
    rootCause: "พบการขอ Kerberos Service Ticket",
    impact: "อาจเป็นเหตุการณ์ปกติ หรือเป็นสัญญาณ Kerberoasting ถ้ามีการขอ ticket จำนวนมาก",
    fix: "ตรวจสอบ Service Account, Encryption Type, ปริมาณ และเครื่องที่ร้องขอผิดปกติ",
    confidence: 72,
  },
};

const rules: Rule[] = [
  {
    name: "SSH: พยายามเดารหัสผ่าน",
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
    rootCause: "พบการยืนยันตัวตน SSH ล้มเหลวซ้ำหลายครั้ง",
    impact: "บัญชีหรือ Server เป้าหมายอาจกำลังถูก Brute Force หรือ Password Spray",
    fix: "Block หรือจำกัดความถี่ Source IP, ตรวจสอบ login สำเร็จจาก IP เดียวกัน, เปิดใช้ MFA, ปิด password login และจำกัด SSH ให้เข้าได้เฉพาะ VPN/Management IP",
    tactic: "Credential Access",
    technique: "T1110 - Brute Force",
    confidence: 84,
    timeWindowMinutes: 5,
    aggregateThreshold: 5,
  },
  {
    name: "SSH: เข้าสู่ระบบสำเร็จ",
    severity: "Medium",
    logTypes: ["SSH Auth", "Linux Syslog"],
    patterns: [/accepted password/i, /accepted publickey/i, /session opened for user/i],
    keywords: ["accepted password", "accepted publickey", "session opened"],
    rootCause: "พบการเข้าสู่ระบบผ่าน SSH สำเร็จ",
    impact: "อาจเป็นเหตุการณ์ปกติ แต่ควรตรวจสอบถ้าเกิดหลังจากพยายาม login fail หลายครั้ง หรือมาจากบัญชี/IP ที่ผิดปกติ",
    fix: "ตรวจสอบผู้ใช้, Source IP, ตำแหน่งที่มา และคำสั่งที่รันหลังจาก login",
    tactic: "Initial Access",
    technique: "T1078 - Valid Accounts",
    confidence: 72,
  },
  {
    name: "SQL Injection",
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
    rootCause: "พบ Request ที่มีรูปแบบ Payload ที่ใช้โจมตี SQL Injection",
    impact: "ระบบอาจเสี่ยงต่อการถูกอ่านข้อมูลจาก Database, Bypass Login หรือแก้ไขข้อมูล",
    fix: "ใช้ Prepared Statement, ตรวจสอบ Input, Review Code ของ Endpoint ที่เกี่ยวข้อง, เพิ่ม WAF Rule และตรวจสอบ Database Log ว่ามี Query สำเร็จหรือไม่",
    tactic: "Initial Access",
    technique: "T1190 - Exploit Public-Facing Application",
    confidence: 93,
  },
  {
    name: "Path Traversal",
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
    rootCause: "พบ Request ที่พยายามเข้าถึงไฟล์นอก Directory ที่เว็บอนุญาต",
    impact: "ผู้โจมตีอาจอ่านไฟล์สำคัญ เช่น Config, Secret หรือไฟล์ระบบ",
    fix: "Normalize Path, Block Pattern ที่ WAF, ใช้ Allowlist สำหรับ Path และตรวจสอบ Endpoint ดาวน์โหลดไฟล์",
    tactic: "Initial Access",
    technique: "T1190 - Exploit Public-Facing Application",
    confidence: 90,
  },
  {
    name: "XSS Payload",
    severity: "Medium",
    logTypes: ["Apache/Nginx", "Application", "Generic"],
    patterns: [/<script/i, /javascript:/i, /onerror\s*=/i, /onload\s*=/i, /document\.cookie/i],
    keywords: ["<script", "javascript:", "onerror=", "document.cookie"],
    rootCause: "พบ Request ที่มี Payload สำหรับ Cross-site Scripting",
    impact: "ผู้ใช้อาจเสี่ยงถูกขโมย Session, Redirect ไปเว็บอันตราย หรือรัน Script ฝั่ง Browser",
    fix: "Escape Output, ใช้ Content Security Policy, Validate Input และตรวจสอบ Parameter ที่เกี่ยวข้อง",
    tactic: "Initial Access",
    technique: "T1189 - Drive-by Compromise",
    confidence: 82,
  },
  {
    name: "Command Injection",
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
    rootCause: "พบ Request หรือ Process ที่มีตัวบ่งชี้การสั่งรันคำสั่งระบบ",
    impact: "ผู้โจมตีอาจรันคำสั่งบน Server และยกระดับเป็น Remote Code Execution",
    fix: "หลีกเลี่ยงการเรียก Shell, ใช้ API ที่ปลอดภัย, Validate Input, Block Payload ที่ WAF และตรวจสอบ Process ที่ถูก Spawn บนเครื่อง",
    tactic: "Execution",
    technique: "T1059 - Command and Scripting Interpreter",
    confidence: 90,
  },
  {
    name: "Firewall: Drop/Deny Traffic",
    severity: "Medium",
    logTypes: ["Firewall", "Cisco IOS", "Network Device", "Meraki"],
    patterns: [
      /\b(drop|deny|denied|blocked|reject)\b/i,
      /\baction=(drop|deny|blocked)\b/i,
      /\bDeny\s+tcp\b/i,
      /\bDeny\s+udp\b/i,
    ],
    keywords: ["drop", "deny", "blocked", "reject"],
    rootCause: "พบ Traffic ถูก Firewall หรือ Security Policy ปฏิเสธ",
    impact: "อาจเป็นการสแกนระบบ, Traffic ของแอปที่ถูกปฏิเสธ หรือ Policy ตั้งค่าผิด",
    fix: "ตรวจสอบ Source/Destination, Port, Policy ID, NAT, Change ล่าสุด และยืนยันว่า Traffic นี้ควรถูก Block หรือไม่",
    tactic: "Reconnaissance",
    technique: "T1595 - Active Scanning",
    confidence: 74,
  },
  {
    name: "Port Scan / Probe",
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
    rootCause: "พบ Source พยายาม Probe หรือสแกน Service ปลายทาง",
    impact: "อาจเป็นขั้นตอน Recon ก่อนโจมตีจริง หรือเป็นการสแกนช่องโหว่โดยไม่ได้รับอนุญาต",
    fix: "Rate-limit หรือ Block Source, ตรวจสอบ Service ที่เปิดเผย และค้นหาเหตุการณ์โจมตีต่อเนื่องจาก IP เดียวกัน",
    tactic: "Reconnaissance",
    technique: "T1595 - Active Scanning",
    confidence: 78,
  },
  {
    name: "Windows: PowerShell น่าสงสัย",
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
    rootCause: "พบกิจกรรม PowerShell ที่มีรูปแบบน่าสงสัยหรือมีการ Obfuscation",
    impact: "อาจเป็นการรัน Malware, Script-based Intrusion หรือ Lateral Movement",
    fix: "เก็บ Command Line, Parent Process, User, Script Block Log, Endpoint Alert และแยกเครื่องออกจากเครือข่ายถ้ายืนยันว่าเป็นอันตราย",
    tactic: "Execution",
    technique: "T1059.001 - PowerShell",
    confidence: 88,
  },
  {
    name: "Linux: พยายามใช้สิทธิ์สูงไม่สำเร็จ",
    severity: "Medium",
    logTypes: ["Linux Syslog", "Generic"],
    patterns: [/sudo:.*authentication failure/i, /sudo:.*incorrect password/i, /user NOT in sudoers/i, /su:.*failure/i],
    keywords: ["sudo", "authentication failure", "NOT in sudoers", "su:"],
    rootCause: "พบผู้ใช้ Linux พยายามใช้สิทธิ์สูงแต่ไม่สำเร็จ",
    impact: "อาจเป็นผู้ใช้กรอกรหัสผิด หรือผู้โจมตีพยายามยกระดับสิทธิ์",
    fix: "ตรวจสอบผู้ใช้, Session ต้นทาง, Sudo Policy และคำสั่งสิทธิ์สูงที่สำเร็จในช่วงเวลาใกล้เคียง",
    tactic: "Privilege Escalation",
    technique: "T1548 - Abuse Elevation Control Mechanism",
    confidence: 76,
  },
  {
    name: "Service Down / Timeout",
    severity: "Medium",
    logTypes: ["Application", "Linux Syslog", "Generic", "Network Device", "Cisco IOS"],
    patterns: [/service.*down/i, /timeout/i, /timed out/i, /connection refused/i, /unreachable/i, /health check failed/i],
    keywords: ["down", "timeout", "connection refused", "unreachable", "health check failed"],
    rootCause: "พบ Service, Host หรือ Dependency มีปัญหาด้าน Availability",
    impact: "ผู้ใช้อาจเจอระบบช้า, เชื่อมต่อไม่ได้ หรือมีอาการระบบล่ม",
    fix: "ตรวจสอบ Change ล่าสุด, CPU/Memory/Interface Utilization, Dependency, Routing, DNS และ Error Rate ของแอป",
    tactic: "Impact",
    technique: "Impact - Service Disruption",
    confidence: 70,
  },
  {
    name: "Cisco: MAC Flapping",
    severity: "High",
    logTypes: ["Cisco IOS", "Network Device"],
    patterns: [
      /MACFLAP/i,
      /host\s+[0-9a-f.:-]+\s+in\s+vlan/i,
      /flapping\s+between/i,
      /moved\s+from\s+.*\s+to\s+/i,
    ],
    keywords: ["MACFLAP", "flapping", "moved from", "host"],
    rootCause: "พบ MAC Address เดียวกันย้ายไปมาระหว่าง Port บน Switch",
    impact: "อาจเกิดจาก Layer 2 Loop, Unmanaged Switch วนลูป, เสียบสายผิด, AP Bridge Loop หรือ STP ไม่เสถียร",
    fix: "ไล่ MAC Address, ตรวจสอบ Port ทั้งสองฝั่ง, ตรวจสาย, ตรวจ STP Root/Blocked Port และตัด Loop จาก Unmanaged Switch",
    tactic: "Impact",
    technique: "L2 - MAC Instability / Loop",
    confidence: 92,
  },
  {
    name: "Cisco: DHCP Snooping / DAI Violation",
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
    rootCause: "Switch ตรวจพบเหตุการณ์ DHCP Snooping หรือ Dynamic ARP Inspection",
    impact: "อาจเกิดจาก Rogue DHCP, ARP Spoofing, ตั้ง Trusted Uplink ผิด, Binding หาย หรือ Endpoint ตั้งค่าผิด",
    fix: "ตรวจสอบ Trusted Uplink, DHCP Snooping Binding Table, VLAN, ARP Inspection Log และ Change ล่าสุดบน Switch",
    tactic: "Credential Access",
    technique: "T1557 - Adversary-in-the-Middle",
    confidence: 88,
  },
  {
    name: "Cisco: STP Topology Change",
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
    rootCause: "Spanning Tree ตรวจพบ Topology Change, BPDU Event หรือ Port State เปลี่ยน",
    impact: "Network อาจมี Packet Loss ชั่วคราว, Port ถูก Block หรือเส้นทาง Layer 2 ไม่เสถียร",
    fix: "ตรวจสอบ Root Bridge, PortFast, BPDU Guard, Loop Guard, Uplink Topology และ Port ที่เปลี่ยนสถานะ",
    tactic: "Impact",
    technique: "L2 - STP Topology Change",
    confidence: 84,
  },
  {
    name: "Cisco: Interface Down",
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
    rootCause: "พบ Interface เปลี่ยนสถานะหรือถูก Disable",
    impact: "ผู้ใช้, AP, Uplink, Switch ปลายทาง หรือ Server ที่เชื่อมต่อกับ Port นี้อาจหลุดจากระบบ",
    fix: "ตรวจสอบสาย, SFP, Port Error, ไฟเลี้ยงอุปกรณ์ปลายทาง, Interface Counter, สาเหตุ Err-disable และ Maintenance ล่าสุด",
    tactic: "Impact",
    technique: "Impact - Network Service Disruption",
    confidence: 78,
  },
  {
    name: "Cisco: Port Security Violation",
    severity: "High",
    logTypes: ["Cisco IOS", "Network Device"],
    patterns: [
      /PORT_SECURITY/i,
      /PSECURE/i,
      /security violation/i,
      /violation.*(shutdown|restrict|protect)/i,
    ],
    keywords: ["PORT_SECURITY", "PSECURE", "security violation"],
    rootCause: "Port Security ตรวจพบ MAC Address ที่ไม่ได้รับอนุญาตหรือเกิด Violation",
    impact: "Port อาจถูก Restrict หรือ Shutdown ทำให้อุปกรณ์ใช้งานไม่ได้ หรืออาจมีอุปกรณ์ไม่ได้รับอนุญาตมาต่อเข้าระบบ",
    fix: "ตรวจสอบอุปกรณ์ที่ต่ออยู่, MAC Address ที่เรียนรู้, ค่า Port-Security, Violation Mode และ Clear Err-disable หลังยืนยันว่าอุปกรณ์ถูกต้องเท่านั้น",
    tactic: "Defense Evasion",
    technique: "Defense Evasion - Network Access Control Bypass",
    confidence: 86,
  },
  {
    name: "Routing: Adjacency Down",
    severity: "High",
    logTypes: ["Cisco IOS", "Network Device"],
    patterns: [
      /OSPF.*(DOWN|Down|FULL to DOWN|neighbor)/i,
      /BGP.*(Down|Idle|Cease|Notification)/i,
      /EIGRP.*neighbor.*down/i,
      /HSRP.*state.*(Speak|Standby|Active)/i,
    ],
    keywords: ["OSPF", "BGP", "EIGRP", "HSRP", "neighbor down"],
    rootCause: "พบ Routing Neighbor หรือ Gateway Redundancy เปลี่ยนสถานะ",
    impact: "Traffic อาจเปลี่ยนเส้นทาง, Failover, Flap หรือขาดการเชื่อมต่อ ขึ้นอยู่กับ Topology",
    fix: "ตรวจสอบ Physical Link, Peer Reachability, Timer, Authentication, Routing Policy, CPU, Interface Error และ Change ล่าสุด",
    tactic: "Impact",
    technique: "Impact - Network Route Disruption",
    confidence: 82,
  },
  {
    name: "Credential Dumping Indicator",
    severity: "Critical",
    logTypes: ["Windows Event", "Application", "Generic"],
    patterns: [
      /mimikatz/i,
      /sekurlsa/i,
      /lsass/i,
      /procdump.*lsass/i,
      /comsvcs\.dll/i,
      /ntds\.dit/i,
      /vssadmin.*shadow/i,
      /sam\s+dump/i,
    ],
    keywords: ["mimikatz", "sekurlsa", "lsass", "ntds.dit", "vssadmin"],
    rootCause: "พบตัวบ่งชี้การพยายามดึง Credential หรือ Dump ข้อมูลยืนยันตัวตน",
    impact: "อาจทำให้รหัสผ่าน Hash, Token หรือ Credential ถูกนำไปใช้โจมตีต่อ",
    fix: "Isolate เครื่องที่เกี่ยวข้อง, เก็บ Memory/Process Evidence, ตรวจสอบบัญชีที่ใช้งานบนเครื่อง และบังคับเปลี่ยนรหัสผ่านบัญชีที่เสี่ยง",
    tactic: "Credential Access",
    technique: "T1003 - OS Credential Dumping",
    confidence: 92,
  },
  {
    name: "Lateral Movement Indicator",
    severity: "High",
    logTypes: ["Windows Event", "Application", "Firewall", "Generic", "Microsoft 365"],
    patterns: [
      /psexec/i,
      /wmic/i,
      /winrm/i,
      /evil-winrm/i,
      /ADMIN\$/i,
      /remote service/i,
      /rdp/i,
      /mstsc/i,
      /smb/i,
    ],
    keywords: ["psexec", "wmic", "winrm", "ADMIN$", "remote service", "rdp", "smb"],
    rootCause: "พบตัวบ่งชี้การเคลื่อนที่ภายในเครือข่ายหรือ Remote Execution",
    impact: "ผู้โจมตีอาจใช้บัญชีที่ได้มาเพื่อเข้าถึงเครื่องอื่นในระบบ",
    fix: "ตรวจสอบ Source/Destination Host, Account ที่ใช้, SMB/RDP/WinRM Log, Endpoint Alert และจำกัดการเชื่อมต่อ East-West ที่ไม่จำเป็น",
    tactic: "Lateral Movement",
    technique: "T1021 - Remote Services",
    confidence: 86,
  },
  {
    name: "Malware Indicator / IOC Match",
    severity: "Critical",
    logTypes: ["Windows Event", "Linux Syslog", "Application", "Firewall", "Generic", "Microsoft 365"],
    patterns: [
      /\b[a-f0-9]{32}\b/i,
      /\b[a-f0-9]{40}\b/i,
      /\b[a-f0-9]{64}\b/i,
      /\bevil\.example\.com\b/i,
      /\bc2\.bad-domain\.test\b/i,
    ],
    keywords: ["evil.example.com", "c2.bad-domain.test"],
    rootCause: "พบ Hash, Domain หรือ Indicator ที่ตรงกับ IOC ภายในระบบ",
    impact: "อาจเกี่ยวข้องกับ Malware, C2, Phishing หรือไฟล์ต้องสงสัย",
    fix: "กักกันไฟล์หรือเครื่องที่เกี่ยวข้อง, ตรวจสอบ Hash/Domain Reputation, ค้นหา Indicator เดียวกันทั้งองค์กร และบันทึก IOC ลง Incident Ticket",
    tactic: "Command and Control",
    technique: "T1105 - Ingress Tool Transfer",
    confidence: 90,
  },
  {
    name: "Microsoft 365 suspicious sign-in",
    severity: "High",
    logTypes: ["Microsoft 365", "Generic"],
    patterns: [
      /riskLevel[:=\s]+(high|medium)/i,
      /risky user/i,
      /impossible travel/i,
      /conditional access.*failure/i,
      /mfa.*denied/i,
      /legacy authentication/i,
    ],
    keywords: ["risky user", "impossible travel", "conditional access", "legacy authentication", "mfa denied"],
    rootCause: "พบ Sign-in หรือ Identity Event ที่มีความเสี่ยงบน Microsoft 365 / Entra ID",
    impact: "บัญชีอาจถูกโจมตีด้วย Credential Stuffing, MFA Fatigue หรือ Login จากตำแหน่งผิดปกติ",
    fix: "ตรวจสอบ Sign-in Log, Conditional Access, MFA Method, Risky Users และบังคับ Reset Password/Revoke Session หากจำเป็น",
    tactic: "Initial Access",
    technique: "T1078 - Valid Accounts",
    confidence: 84,
  },
];

function matchesRuleLogType(rule: Rule, logType: LogType): boolean {
  if (!rule.logTypes || rule.logTypes.includes(logType)) return true;
  if (rule.logTypes.includes("Generic")) return true;

  const firewallLike: LogType[] = ["Firewall", "FortiGate", "Palo Alto", "Sophos", "Cloudflare"];
  const webLike: LogType[] = ["Apache/Nginx", "Apache", "Nginx", "Cloudflare", "Application"];
  const linuxLike: LogType[] = ["Linux Syslog", "SSH Auth"];
  const networkLike: LogType[] = ["Cisco IOS", "Meraki", "Network Device"];

  if (rule.logTypes.includes("Firewall") && firewallLike.includes(logType)) return true;
  if (rule.logTypes.includes("Apache/Nginx") && webLike.includes(logType)) return true;
  if (rule.logTypes.includes("Linux Syslog") && linuxLike.includes(logType)) return true;
  if (rule.logTypes.includes("Network Device") && networkLike.includes(logType)) return true;

  return false;
}

export function analyzeLog(logContent: string): AnalysisResult {
  const lines = logContent
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const findings: Finding[] = [];

  lines.forEach((line, index) => {
    const lineNumber = index + 1;
    const logType = detectLogType(line);
    const eventIdFinding = analyzeWindowsEventId(line, lineNumber, logType);

    if (eventIdFinding) {
      findings.push(eventIdFinding);
    }

    const threatFindings = analyzeThreatIntel(line, lineNumber, logType);
    findings.push(...threatFindings);

    for (const rule of rules) {
      if (!matchesRuleLogType(rule, logType)) continue;

      const matchedPattern = rule.patterns.find((pattern) => pattern.test(line));
      const matchedKeywords = rule.keywords.filter((keyword) => line.toLowerCase().includes(keyword.toLowerCase()));

      if (!matchedPattern && matchedKeywords.length === 0) continue;

      const duplicateWindowsEvent =
        eventIdFinding &&
        logType === "Windows Event" &&
        eventIdFinding.rule === rule.name;

      const duplicateThreatIntel =
        threatFindings.length > 0 &&
        rule.name === "Malware Indicator / IOC Match";

      if (duplicateWindowsEvent || duplicateThreatIntel) continue;

      const parsed = parseFields(line);
      const threat = getThreatIntel(parsed.sourceIp, parsed.domain, parsed.fileHash);
      const severity = escalateSeverity(rule.severity, threat?.risk || null);

      findings.push({
        id: `EVT-${String(findings.length + 1).padStart(4, "0")}`,
        lineNumber,
        timestamp: parsed.timestamp,
        severity,
        logType,
        rule: rule.name,
        detectedKeywords: uniqueSorted([...matchedKeywords, matchedPattern ? matchedPattern.source.slice(0, 40) : ""]),
        possibleRootCause: threat ? `${rule.rootCause} พบ IOC ตรงกับรายการ: ${threat.type}.` : rule.rootCause,
        impact: threat ? `${rule.impact} ข้อมูล IOC: ${threat.description}` : rule.impact,
        recommendedFix: rule.fix,
        sourceIp: parsed.sourceIp,
        destinationIp: parsed.destinationIp,
        destinationPort: parsed.destinationPort,
        username: parsed.username,
        asset: parsed.asset,
        tactic: rule.tactic,
        technique: rule.technique,
        confidence: calculateFindingConfidence(rule.confidence, line, threat?.risk || null),
        evidence: buildEvidence(line, rule),
        raw: line,
        repeatedCount: 1,
        interfaceName: parsed.interfaceName,
        vlan: parsed.vlan,
        macAddress: parsed.macAddress,
        domain: parsed.domain,
        fileHash: parsed.fileHash,
        iocType: threat?.type || null,
        iocRisk: threat?.risk || null,
        iocDescription: threat?.description || null,
        geoCountry: threat?.country || null,
        asn: threat?.asn || null,
        abuseScore: threat?.abuseScore || null,
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
  const threat = getThreatIntel(parsed.sourceIp, parsed.domain, parsed.fileHash);
  const severity = escalateSeverity(mapped.severity, threat?.risk || null);

  return {
    id: `EVT-WIN-${lineNumber}`,
    lineNumber,
    timestamp: parsed.timestamp,
    severity,
    logType: logType === "Generic" ? "Windows Event" : logType,
    rule: mapped.rule,
    detectedKeywords: [`Event ID ${eventId}`],
    possibleRootCause: threat ? `${mapped.rootCause} พบ IOC ตรงกับรายการ: ${threat.type}.` : mapped.rootCause,
    impact: threat ? `${mapped.impact} ข้อมูล IOC: ${threat.description}` : mapped.impact,
    recommendedFix: mapped.fix,
    sourceIp: parsed.sourceIp,
    destinationIp: parsed.destinationIp,
    destinationPort: parsed.destinationPort,
    username: parsed.username,
    asset: parsed.asset,
    tactic: mapped.tactic,
    technique: mapped.technique,
    confidence: calculateFindingConfidence(mapped.confidence, line, threat?.risk || null),
    evidence: `Event ID ${eventId}`,
    raw: line,
    repeatedCount: 1,
    interfaceName: parsed.interfaceName,
    vlan: parsed.vlan,
    macAddress: parsed.macAddress,
    domain: parsed.domain,
    fileHash: parsed.fileHash,
    iocType: threat?.type || null,
    iocRisk: threat?.risk || null,
    iocDescription: threat?.description || null,
    geoCountry: threat?.country || null,
    asn: threat?.asn || null,
    abuseScore: threat?.abuseScore || null,
  };
}

function analyzeThreatIntel(line: string, lineNumber: number, logType: LogType): Finding[] {
  const parsed = parseFields(line);
  const matches = getAllThreatIntelMatches(parsed.sourceIp, parsed.domain, parsed.fileHash, line);

  return matches.map((threat, offset) => ({
    id: `EVT-IOC-${lineNumber}-${offset + 1}`,
    lineNumber,
    timestamp: parsed.timestamp,
    severity: threat.risk,
    logType,
    rule: "Malware Indicator / IOC Match",
    detectedKeywords: [threat.indicator],
    possibleRootCause: `พบ Indicator ที่ตรงกับ IOC ภายใน: ${threat.type}`,
    impact: threat.description,
    recommendedFix: "กักกันเครื่องหรือไฟล์ที่เกี่ยวข้อง, ตรวจสอบ IOC ใน Firewall/Proxy/DNS/Endpoint Log, Block Indicator หากไม่กระทบงาน และสร้าง Incident Ticket",
    sourceIp: parsed.sourceIp,
    destinationIp: parsed.destinationIp,
    destinationPort: parsed.destinationPort,
    username: parsed.username,
    asset: parsed.asset,
    tactic: threat.indicatorType === "domain" ? "Command and Control" : "Threat Intelligence",
    technique: threat.indicatorType === "hash" ? "T1204 - User Execution" : "T1105 - Ingress Tool Transfer",
    confidence: Math.min(99, 88 + severityRank[threat.risk] * 2),
    evidence: threat.indicator,
    raw: line,
    repeatedCount: 1,
    interfaceName: parsed.interfaceName,
    vlan: parsed.vlan,
    macAddress: parsed.macAddress,
    domain: parsed.domain,
    fileHash: parsed.fileHash,
    iocType: threat.type,
    iocRisk: threat.risk,
    iocDescription: threat.description,
    geoCountry: threat.country || null,
    asn: threat.asn || null,
    abuseScore: threat.abuseScore || null,
  }));
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
    domain: extractDomain(line),
    fileHash: extractHash(line),
  };
}

function detectLogType(line: string): LogType {
  if (/%[A-Z0-9_-]+-\d+-[A-Z0-9_-]+/i.test(line)) return "Cisco IOS";
  if (/\b(MACFLAP|SPANTREE|LINK|LINEPROTO|DHCP_SNOOPING|SW_DAI|PORT_SECURITY|PSECURE|OSPF|BGP|EIGRP|HSRP)\b/i.test(line)) {
    return "Cisco IOS";
  }
  if (/\bmeraki\b|\bclient vpn\b|\bevent type\b|\bssid\b/i.test(line)) return "Meraki";
  if (/\bfortigate\b|\bfortios\b|\bdevname=|\btype=traffic\b|\bsubtype=forward\b|\baction=(deny|blocked|accept)\b/i.test(line)) return "FortiGate";
  if (/\bpalo alto\b|\bPAN-OS\b|\bTRAFFIC\b|\bTHREAT\b|\burl-category\b|\baction eq deny\b/i.test(line)) return "Palo Alto";
  if (/\bsophos\b|\bXG Firewall\b|\bSFOS\b|\blog_subtype=Firewall\b/i.test(line)) return "Sophos";
  if (/\bcloudflare\b|\bcf-ray\b|\bWAFAction\b|\bEdgeStartTimestamp\b/i.test(line)) return "Cloudflare";
  if (/\bOffice 365\b|\bMicrosoft 365\b|\bEntra ID\b|\bAzureAD\b|\bUserLoggedIn\b|\bRiskyUser\b|\bConditionalAccess\b/i.test(line)) return "Microsoft 365";
  if (/\b(sshd|pam_unix|failed password|accepted password|invalid user)\b/i.test(line)) return "SSH Auth";
  if (/\b(event id|audit failure|microsoft-windows|security-auditing|logon type|eventcode)\b/i.test(line)) return "Windows Event";
  if (/\b(ufw|iptables|firewall|deny|drop|src=|dst=|dpt=|spt=|action=blocked)\b/i.test(line)) return "Firewall";
  if (/\b(kernel|systemd|cron|sudo|systemctl|journal)\b/i.test(line)) return "Linux Syslog";
  if (/\bnginx\b/i.test(line)) return "Nginx";
  if (/\bapache\b/i.test(line)) return "Apache";
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
  const match =
    line.match(/\bEvent\s*ID[:\s]+(\d{4})\b/i) ||
    line.match(/\bEventCode[=:\s]+(\d{4})\b/i) ||
    line.match(/\bID[:\s]+(\d{4})\b/i) ||
    line.match(/\bAudit\s+(?:Success|Failure)\s*,\s*(\d{4})\b/i);
  return match ? match[1] : null;
}

function extractDomain(line: string): string | null {
  const urlDomain = line.match(/https?:\/\/([a-z0-9.-]+\.[a-z]{2,})/i);
  if (urlDomain) return urlDomain[1].toLowerCase();

  const explicit = line.match(/\b(?:domain|host|fqdn|url|requestHost|cs-host)[:=\s]+([a-z0-9.-]+\.[a-z]{2,})\b/i);
  if (explicit) return explicit[1].toLowerCase();

  const candidates = Array.from(line.matchAll(/\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b/gi)).map((match) => match[1].toLowerCase());
  const domain = candidates.find((item) => !/\d+\.\d+\.\d+\.\d+/.test(item) && !item.endsWith(".local"));
  return domain || null;
}

function extractHash(line: string): string | null {
  const match = line.match(/\b[a-f0-9]{64}\b/i) || line.match(/\b[a-f0-9]{40}\b/i) || line.match(/\b[a-f0-9]{32}\b/i);
  return match ? match[0].toLowerCase() : null;
}

function getThreatIntel(sourceIp: string | null, domain: string | null, fileHash: string | null): ThreatIntel | null {
  if (sourceIp && iocList[sourceIp]) return iocList[sourceIp];
  if (domain && domainIocList[domain.toLowerCase()]) return domainIocList[domain.toLowerCase()];
  if (fileHash && hashIocList[fileHash.toLowerCase()]) return hashIocList[fileHash.toLowerCase()];
  return null;
}

function getAllThreatIntelMatches(
  sourceIp: string | null,
  domain: string | null,
  fileHash: string | null,
  line: string
): ThreatIntel[] {
  const matches: ThreatIntel[] = [];

  extractIps(line).forEach((ip) => {
    if (iocList[ip]) matches.push(iocList[ip]);
  });

  const detectedDomain = domain?.toLowerCase();
  if (detectedDomain && domainIocList[detectedDomain]) matches.push(domainIocList[detectedDomain]);

  Object.keys(domainIocList).forEach((iocDomain) => {
    if (line.toLowerCase().includes(iocDomain) && !matches.some((item) => item.indicator === iocDomain)) {
      matches.push(domainIocList[iocDomain]);
    }
  });

  const detectedHash = fileHash?.toLowerCase();
  if (detectedHash && hashIocList[detectedHash]) matches.push(hashIocList[detectedHash]);

  return matches.filter((item, index, array) => array.findIndex((candidate) => candidate.indicator === item.indicator) === index);
}

function extractIps(line: string): string[] {
  return Array.from(
    line.matchAll(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g)
  ).map((match) => match[0]);
}

function isPrivateIp(ip: string): boolean {
  return privateIpPatterns.some((pattern) => pattern.test(ip));
}

function isReservedIp(ip: string): boolean {
  return reservedIpPatterns.some((pattern) => pattern.test(ip));
}

function isPublicIp(ip: string): boolean {
  return !isPrivateIp(ip) && !isReservedIp(ip);
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
          ? `${finding.impact} เหตุการณ์เกิดซ้ำหลายครั้ง ทำให้ความสำคัญของ Incident สูงขึ้น`
          : finding.impact,
    };
  });
}

function correlateFindings(findings: Finding[]): Correlation[] {
  const correlations: Correlation[] = [];
  const bySource = groupBy(findings.filter((finding) => finding.sourceIp), (finding) => finding.sourceIp || "unknown");

  bySource.forEach((items, sourceIp) => {
    const authFailures = items.filter(isAuthFailureFinding);
    const sshFailures = items.filter((finding) => finding.rule.includes("SSH") && isAuthFailureFinding(finding));
    const windowsFailures = items.filter((finding) => finding.rule === "Windows: เข้าสู่ระบบไม่สำเร็จ");
    const firewallDrops = items.filter((finding) => finding.rule === "Firewall: Drop/Deny Traffic" || finding.rule === "Port Scan / Probe");
    const webAttacks = items.filter(isWebAttackFinding);
    const iocHits = items.filter((finding) => finding.iocType || (finding.sourceIp && iocList[finding.sourceIp]));
    const ports = new Set(items.map((finding) => finding.destinationPort).filter(Boolean));
    const users = new Set(authFailures.map((finding) => finding.username).filter(Boolean));

    if (maxWindowCount(sshFailures, 5) >= 5) {
      correlations.push({
        title: "SSH Brute Force",
        severity: "Critical",
        sourceIp,
        eventCount: sshFailures.length,
        confidence: 92,
        mitreTechniques: ["T1110 - Brute Force"],
        incidentType: "Authentication Attack",
        description: `${sourceIp} มี SSH login fail อย่างน้อย 5 ครั้งภายใน 5 นาที รวมทั้งหมด ${sshFailures.length} ครั้ง`,
        recommendedAction: "Block Source IP, ตรวจสอบ successful login หลังจาก failed attempts, เปิด MFA/Disable password login และจำกัด SSH ผ่าน VPN/Management IP เท่านั้น",
      });
    }

    if (maxWindowCount(windowsFailures, 5) >= 5) {
      correlations.push({
        title: "Windows Brute Force",
        severity: "Critical",
        sourceIp,
        eventCount: windowsFailures.length,
        confidence: 90,
        mitreTechniques: ["T1110 - Brute Force"],
        incidentType: "Windows Authentication Attack",
        description: `${sourceIp} สร้าง Event ID 4625 ซ้ำอย่างน้อย 5 ครั้งภายใน 5 นาที`,
        recommendedAction: "ตรวจสอบ Account ที่ถูกยิง, Logon Type, Source Workstation และหา Event 4624 หลังจากช่วงโจมตี",
      });
    }

    if (authFailures.length >= 5 && users.size >= 5) {
      correlations.push({
        title: "Password Spray",
        severity: "Critical",
        sourceIp,
        eventCount: authFailures.length,
        confidence: 91,
        mitreTechniques: ["T1110.003 - Password Spraying"],
        incidentType: "Credential Attack",
        description: `${sourceIp} พยายาม Login กับหลายบัญชี (${users.size} users) ซึ่งเข้าข่าย Password Spray`,
        recommendedAction: "Block/Rate-limit Source, ตรวจสอบบัญชีที่ถูกยิง, บังคับ Reset Password เฉพาะบัญชีเสี่ยง และเพิ่ม Conditional Access/MFA",
      });
    }

    if (firewallDrops.length >= 5) {
      correlations.push({
        title: "Firewall Attack Burst",
        severity: "High",
        sourceIp,
        eventCount: firewallDrops.length,
        confidence: 84,
        mitreTechniques: ["T1595 - Active Scanning"],
        incidentType: "Network Recon",
        description: `${sourceIp} ถูก Firewall Drop/Deny ซ้ำ ${firewallDrops.length} ครั้ง`,
        recommendedAction: "ตรวจ Policy, Destination, Port ที่ถูกยิงซ้ำ และเพิ่ม Block/Rate-limit ถ้าเป็นแหล่งภายนอกที่ไม่จำเป็น",
      });
    }

    if (ports.size >= 4 || maxUniquePortsInWindow(firewallDrops, 5) >= 4) {
      correlations.push({
        title: "Port Scan",
        severity: "High",
        sourceIp,
        eventCount: firewallDrops.length || items.length,
        confidence: 87,
        mitreTechniques: ["T1595 - Active Scanning"],
        incidentType: "Reconnaissance",
        description: `${sourceIp} พยายามเข้าถึงหลายพอร์ต (${ports.size} ports) บ่งชี้การสแกน Service`,
        recommendedAction: "ตรวจสอบ Service ที่เปิดอยู่, จำกัด Exposure, เปิด Rate Limit และค้นหา Web/Exploit Activity ต่อจาก IP เดียวกัน",
      });
    }

    if (webAttacks.length >= 1 && (authFailures.length >= 3 || firewallDrops.length >= 3)) {
      correlations.push({
        title: "Brute Force + Web Recon",
        severity: "Critical",
        sourceIp,
        eventCount: authFailures.length + firewallDrops.length + webAttacks.length,
        confidence: 89,
        mitreTechniques: uniqueSorted(["T1110 - Brute Force", "T1595 - Active Scanning", ...webAttacks.map((finding) => finding.technique)]),
        incidentType: "Coordinated Attack",
        description: `${sourceIp} มีทั้ง Authentication Failure, Firewall/Port Probe และ Web Attack ในชุด Log เดียวกัน เข้าข่าย Possible Coordinated Attack`,
        recommendedAction: "Block Source IP, ตรวจสอบบัญชีที่อาจถูก Compromise, ตรวจ successful login หลัง failed attempts และ Review Web Access/Application Log รอบเวลาเดียวกัน",
      });
    }

    const webAttackRules = new Set(webAttacks.map((finding) => finding.rule));
    if (webAttackRules.size >= 2) {
      correlations.push({
        title: "Web Exploitation Chain",
        severity: "Critical",
        sourceIp,
        eventCount: webAttacks.length,
        confidence: 90,
        mitreTechniques: uniqueSorted(webAttacks.map((finding) => finding.technique)),
        incidentType: "Web Attack",
        description: `${sourceIp} พยายามโจมตีเว็บหลายประเภท: ${Array.from(webAttackRules).join(", ")}`,
        recommendedAction: "Block ที่ WAF, ตรวจ Endpoint/Route ที่ถูกเรียก, Review Response Code 2xx/5xx และตรวจ Database/App Log ว่ามีผลสำเร็จหรือไม่",
      });
    }

    if (iocHits.length >= 1) {
      correlations.push({
        title: "IOC / Threat Intel Match",
        severity: "High",
        sourceIp,
        eventCount: iocHits.length,
        confidence: 93,
        mitreTechniques: uniqueSorted(iocHits.map((finding) => finding.technique)),
        incidentType: "Threat Intelligence",
        description: `${sourceIp} ตรงกับ IOC หรือเกี่ยวข้องกับ Indicator ภายในจำนวน ${iocHits.length} รายการ`,
        recommendedAction: "Block IOC ถ้าไม่กระทบงาน, Hunt Indicator เดียวกันใน Firewall/Proxy/DNS/Endpoint และบันทึกลง Incident Ticket",
      });
    }
  });

  const byAsset = groupBy(findings.filter((finding) => finding.asset), (finding) => finding.asset || "unknown");
  byAsset.forEach((items, asset) => {
    const layer2 = items.filter((finding) =>
      ["Cisco: MAC Flapping", "Cisco: STP Topology Change", "Cisco: DHCP Snooping / DAI Violation", "Cisco: Interface Down"].includes(finding.rule)
    );

    if (layer2.length >= 3) {
      correlations.push({
        title: "Layer 2 Instability Cluster",
        severity: "High",
        sourceIp: null,
        eventCount: layer2.length,
        confidence: 85,
        mitreTechniques: uniqueSorted(layer2.map((finding) => finding.technique)),
        incidentType: "Network Operations",
        description: `${asset} มีสัญญาณ Layer 2 หรือ Interface ไม่เสถียร ${layer2.length} รายการ`,
        recommendedAction: "ตรวจสอบ STP State, Recent Cabling Change, Unmanaged Switch, Uplink, AP Bridge Link และ Interface Counter",
      });
    }
  });

  const privilege = findings.filter((finding) => finding.technique.includes("Privilege") || finding.rule.includes("สิทธิ์"));
  if (privilege.length >= 2) {
    correlations.push({
      title: "Privilege Escalation Cluster",
      severity: "Critical",
      sourceIp: null,
      eventCount: privilege.length,
      confidence: 88,
      mitreTechniques: uniqueSorted(privilege.map((finding) => finding.technique)),
      incidentType: "Privilege Escalation",
      description: `พบเหตุการณ์เกี่ยวกับสิทธิ์สูง ${privilege.length} รายการ เช่น Event ID 4672 หรือการเพิ่มผู้ใช้เข้ากลุ่ม`,
      recommendedAction: "ตรวจสอบ Change Request, Admin Account, Group Membership และกิจกรรมหลังจากได้รับสิทธิ์",
    });
  }

  const serviceIssues = findings.filter((finding) => finding.rule === "Service Down / Timeout");
  if (serviceIssues.length >= 5) {
    correlations.push({
      title: "Availability Degradation Spike",
      severity: "High",
      sourceIp: null,
      eventCount: serviceIssues.length,
      confidence: 80,
      mitreTechniques: ["Impact - Service Disruption"],
      incidentType: "Availability",
      description: `พบเหตุการณ์ที่เกี่ยวข้องกับ Availability จำนวน ${serviceIssues.length} รายการ`,
      recommendedAction: "ตรวจสอบ Deployment ล่าสุด, Upstream Health, Saturation Metrics, DNS, Routing และ Dashboard Error Rate",
    });
  }

  return dedupeCorrelations(correlations).sort((a, b) => severityRank[b.severity] - severityRank[a.severity] || b.eventCount - a.eventCount);
}

function buildSummary(totalEvents: number, findings: Finding[], correlations: Correlation[]): AnalysisSummary {
  const severityCounts: Record<Severity, number> = {
    Low: 0,
    Medium: 0,
    High: 0,
    Critical: 0,
  };

  const logTypes: Record<string, number> = {};
  const vendorCounts: Record<string, number> = {};
  const ipCounts = new Map<string, number>();
  const ruleCounts = new Map<string, { count: number; severity: Severity }>();
  const timelineMap = new Map<string, { count: number; severity: Severity }>();

  let iocHits = 0;
  let publicIpCount = 0;
  let privateIpCount = 0;
  let reservedIpCount = 0;

  findings.forEach((finding) => {
    severityCounts[finding.severity] += 1;
    logTypes[finding.logType] = (logTypes[finding.logType] || 0) + 1;
    vendorCounts[finding.logType] = (vendorCounts[finding.logType] || 0) + 1;

    if (finding.iocType) iocHits += 1;

    if (finding.sourceIp) {
      ipCounts.set(finding.sourceIp, (ipCounts.get(finding.sourceIp) || 0) + 1);
      if (isPrivateIp(finding.sourceIp)) privateIpCount += 1;
      else if (isReservedIp(finding.sourceIp)) reservedIpCount += 1;
      else if (isPublicIp(finding.sourceIp)) publicIpCount += 1;
    }

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
    .slice(0, 8);

  const affectedUsers = uniqueSorted(findings.map((finding) => finding.username).filter(Boolean) as string[]).slice(0, 12);
  const targetPorts = uniqueSorted(findings.map((finding) => finding.destinationPort).filter(Boolean) as string[]).slice(0, 16);
  const mitreTechniques = uniqueSorted(findings.map((finding) => finding.technique)).slice(0, 16);
  const recommendedActions = buildRecommendedActions(findings, correlations);
  const analystReport = buildAnalystReport(findings, correlations, riskScore, riskLevel, topSourceIp, recommendedActions);

  return {
    totalEvents,
    suspiciousEvents: findings.length,
    criticalAlerts: severityCounts.Critical,
    failedLogins: findings.filter(isAuthFailureFinding).length,
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
    recommendedActions,
    correlations,
    iocHits,
    publicIpCount,
    privateIpCount,
    reservedIpCount,
    vendorCounts,
    analystReport,
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
    return "ไม่พบรูปแบบที่น่าสงสัยใน Log ที่ส่งเข้ามาวิเคราะห์";
  }

  const leading = correlations[0]?.title || findings[0].rule;
  const source = topSourceIp ? ` แหล่งที่พบมากที่สุด: ${topSourceIp}.` : "";
  const techniques = uniqueSorted(findings.map((finding) => finding.technique)).slice(0, 3).join(", ");
  return `คะแนนความเสี่ยง ${riskScore}/100 ประเด็นหลักที่ควรสนใจ: ${leading}.${source} เทคนิคที่พบ: ${techniques}.`;
}

function buildRecommendedActions(findings: Finding[], correlations: Correlation[]): string[] {
  const actions = [
    ...correlations.map((item) => item.recommendedAction),
    ...findings
      .filter((finding) => finding.severity === "Critical" || finding.severity === "High")
      .map((finding) => finding.recommendedFix),
  ];

  if (findings.some((finding) => finding.sourceIp)) {
    actions.push("นำ Top Source IP ไปค้นต่อใน Firewall, Proxy, Authentication, Endpoint และ DNS Log");
  }

  if (findings.some((finding) => finding.logType === "Cisco IOS" || finding.logType === "Network Device")) {
    actions.push("สำหรับ Incident ฝั่ง Network Device ให้เก็บ show log, show interface status, show spanning-tree, show mac address-table และบันทึก Change ล่าสุด");
  }

  return uniqueSorted(actions).slice(0, 8);
}

function isAuthFailureFinding(finding: Finding): boolean {
  return (
    finding.rule.includes("พยายามเดารหัสผ่าน") ||
    finding.rule.includes("เข้าสู่ระบบไม่สำเร็จ") ||
    finding.rule.toLowerCase().includes("brute force") ||
    finding.raw.toLowerCase().includes("failed password") ||
    finding.raw.toLowerCase().includes("event id 4625") ||
    (finding.logType === "Windows Event" && /\b4625\b/.test(finding.raw))
  );
}

function isWebAttackFinding(finding: Finding): boolean {
  return ["SQL Injection", "Path Traversal", "XSS Payload", "Command Injection"].includes(finding.rule);
}

function parseFindingDate(finding: Finding): Date | null {
  if (!finding.timestamp) return null;

  const direct = new Date(finding.timestamp);
  if (!Number.isNaN(direct.getTime())) return direct;

  const syslog = new Date(`${new Date().getFullYear()} ${finding.timestamp}`);
  if (!Number.isNaN(syslog.getTime())) return syslog;

  return null;
}

function timeWindowKey(finding: Finding, minutes: number): string {
  const parsed = parseFindingDate(finding);
  if (!parsed) return "unknown";
  const bucket = Math.floor(parsed.getTime() / (minutes * 60 * 1000));
  return String(bucket);
}

function maxWindowCount(findings: Finding[], minutes: number): number {
  const counts = new Map<string, number>();
  findings.forEach((finding) => {
    const key = timeWindowKey(finding, minutes);
    counts.set(key, (counts.get(key) || 0) + 1);
  });
  return Math.max(0, ...Array.from(counts.values()));
}

function maxUniquePortsInWindow(findings: Finding[], minutes: number): number {
  const windows = new Map<string, Set<string>>();
  findings.forEach((finding) => {
    if (!finding.destinationPort) return;
    const key = timeWindowKey(finding, minutes);
    const ports = windows.get(key) || new Set<string>();
    ports.add(finding.destinationPort);
    windows.set(key, ports);
  });
  return Math.max(0, ...Array.from(windows.values()).map((ports) => ports.size));
}

function dedupeCorrelations(correlations: Correlation[]): Correlation[] {
  const seen = new Set<string>();
  return correlations.filter((item) => {
    const key = `${item.title}:${item.sourceIp || "global"}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function buildAnalystReport(
  findings: Finding[],
  correlations: Correlation[],
  riskScore: number,
  riskLevel: Severity,
  topSourceIp: string | null,
  actions: string[]
): AnalystReport {
  const critical = findings.filter((finding) => finding.severity === "Critical");
  const high = findings.filter((finding) => finding.severity === "High");
  const topCorrelation = correlations[0];
  const topRules = uniqueSorted(findings.map((finding) => finding.rule)).slice(0, 5).join(", ") || "ไม่พบ";
  const mitre = uniqueSorted(findings.map((finding) => finding.technique)).slice(0, 6).join(", ") || "ไม่พบ";
  const firstCritical = critical[0] || high[0] || findings[0];

  const socAnalyst =
    findings.length === 0
      ? "ไม่พบเหตุการณ์น่าสงสัยจาก Log ที่นำมาวิเคราะห์ แนะนำให้เพิ่มช่วงเวลา Log หรือเพิ่ม Source อื่นเพื่อยืนยัน"
      : `สรุปแบบ SOC Analyst: พบ ${findings.length} เหตุการณ์น่าสงสัย ระดับความเสี่ยง ${riskLevel} (${riskScore}/100). ประเด็นหลักคือ ${topCorrelation?.title || firstCritical?.rule}. Top Source IP: ${topSourceIp || "ไม่พบ"}. MITRE ที่เกี่ยวข้อง: ${mitre}.`;

  const rca =
    findings.length === 0
      ? "RCA: ยังไม่พบหลักฐานเพียงพอในการระบุสาเหตุ"
      : `RCA: ${firstCritical?.possibleRootCause || "พบพฤติกรรมผิดปกติจาก Log"}. หลักฐานสำคัญคือ ${firstCritical?.evidence || "ไม่มี"} จากบรรทัด ${firstCritical?.lineNumber || "-"}.`;

  const managerSummary =
    findings.length === 0
      ? "สรุปสำหรับหัวหน้า: ไม่พบเหตุการณ์น่าสงสัยใน Log ชุดนี้"
      : `สรุปสำหรับหัวหน้า: ระบบพบความเสี่ยงระดับ ${riskLevel} คะแนน ${riskScore}/100 มี Critical ${critical.length} รายการ และ High ${high.length} รายการ ประเด็นหลักคือ ${topCorrelation?.title || topRules}. แนะนำให้ดำเนินการ: ${actions[0] || "ตรวจสอบ Log เพิ่มเติม"}`;

  const fixCommand =
    `Fix Command / Checklist:\n` +
    [
      topSourceIp ? `- Firewall/WAF: block หรือ rate-limit source ${topSourceIp} หากไม่ใช่ traffic ที่จำเป็น` : "- ตรวจสอบ Top Source IP จาก Event Table",
      "- Authentication: ตรวจ successful login หลังจาก failed attempts และ reset password บัญชีเสี่ยง",
      "- Windows: ตรวจ Event ID 4624/4625/4672/4720/4740 ในช่วงเวลาเดียวกัน",
      "- Network: ตรวจ Firewall deny/drop, port scan และ interface/STP log ที่เกี่ยวข้อง",
      "- Web: ตรวจ access log, application log, database log และ WAF event รอบเวลาเดียวกัน",
    ].join("\n");

  const ticket =
    `Incident Ticket:\n` +
    `Title: ${topCorrelation?.title || firstCritical?.rule || "SOC Log Analysis Finding"}\n` +
    `Severity: ${riskLevel}\n` +
    `Risk Score: ${riskScore}/100\n` +
    `Top Source IP: ${topSourceIp || "N/A"}\n` +
    `Event Count: ${findings.length}\n` +
    `MITRE: ${mitre}\n` +
    `Root Cause: ${firstCritical?.possibleRootCause || "N/A"}\n` +
    `Impact: ${firstCritical?.impact || "N/A"}\n` +
    `Recommended Action: ${actions.join(" | ") || "Review logs and validate activity"}\n` +
    `Evidence: ${firstCritical?.raw || "N/A"}`;

  return {
    socAnalyst,
    rca,
    managerSummary,
    fixCommand,
    ticket,
  };
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

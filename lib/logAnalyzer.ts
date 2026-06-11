export type Severity = "Low" | "Medium" | "High" | "Critical";

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
    type: "Tor / แหล่งที่น่าสงสัย",
    risk: "High",
    description: "IP ตัวอย่างที่ถูกจัดเป็นแหล่งที่น่าสงสัย ใช้สำหรับทดสอบเหตุการณ์ด้านความปลอดภัย",
  },
  "45.77.10.2": {
    type: "แหล่งสแกนระบบ",
    risk: "High",
    description: "IP ตัวอย่างที่มีพฤติกรรมสแกนพอร์ต ใช้สำหรับทดสอบ Firewall / Port Scan",
  },
  "198.51.100.44": {
    type: "แหล่งโจมตีเว็บ",
    risk: "High",
    description: "IP ตัวอย่างที่ใช้จำลองการโจมตีเว็บแอปพลิเคชัน",
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
    technique: "T1078 Valid Accounts",
    rootCause: "พบบัญชี Windows เข้าสู่ระบบสำเร็จ",
    impact: "โดยทั่วไปอาจเป็นเหตุการณ์ปกติ แต่ควรตรวจสอบถ้าเกิดหลังจาก login fail หลายครั้ง หรือมาจากแหล่งที่ผิดปกติ",
    fix: "ตรวจสอบ Source IP, Account Name, Logon Type และเหตุการณ์ login fail ในช่วงเวลาใกล้เคียง",
    confidence: 62,
  },
  "4625": {
    rule: "Windows: เข้าสู่ระบบไม่สำเร็จ",
    severity: "Medium",
    tactic: "Credential Access",
    technique: "T1110 Brute Force",
    rootCause: "พบบัญชี Windows พยายามยืนยันตัวตนไม่สำเร็จ",
    impact: "ถ้าเกิดซ้ำหลายครั้ง อาจเป็น Brute Force, Password Spray, รหัสผ่าน Service ผิด หรือ Credential ถูกล็อก",
    fix: "ตรวจสอบบัญชี, Source IP, Logon Type, สถานะ Lockout และ login สำเร็จหลังจากเหตุการณ์ล้มเหลว",
    confidence: 82,
  },
  "4672": {
    rule: "Windows: มีการใช้สิทธิ์พิเศษ",
    severity: "High",
    tactic: "Privilege Escalation",
    technique: "T1078 Valid Accounts",
    rootCause: "พบบัญชีสิทธิ์สูงเข้าสู่ระบบและได้รับสิทธิ์พิเศษ",
    impact: "ถ้าไม่ได้คาดหมาย อาจเป็นการใช้งานบัญชีผู้ดูแลระบบผิดปกติ หรือการยกระดับสิทธิ์",
    fix: "ตรวจสอบผู้ใช้ admin, เครื่องต้นทาง, เอกสารอนุมัติ และกิจกรรมหลังจาก login",
    confidence: 84,
  },
  "4688": {
    rule: "Windows: มีการสร้าง Process",
    severity: "Medium",
    tactic: "Execution",
    technique: "T1059 Command and Scripting Interpreter",
    rootCause: "พบการสร้าง Process ใหม่บนเครื่อง Windows",
    impact: "อาจน่าสงสัยถ้าเกี่ยวข้องกับ PowerShell, encoded command หรือ parent process ที่ผิดปกติ",
    fix: "ตรวจสอบ command line, parent process, user, hash และข้อมูลจาก Endpoint Security",
    confidence: 70,
  },
  "4720": {
    rule: "Windows: มีการสร้างบัญชีใหม่",
    severity: "High",
    tactic: "Persistence",
    technique: "T1136 Create Account",
    rootCause: "พบการสร้างบัญชี Windows ใหม่",
    impact: "อาจเป็นงานดูแลระบบปกติ หรือเป็นการสร้างบัญชีเพื่อฝังตัวของผู้โจมตี",
    fix: "ตรวจสอบ Change Request, ผู้สร้างบัญชี, Group Membership และการใช้งานบัญชีนั้น",
    confidence: 86,
  },
  "4728": {
    rule: "Windows: เพิ่มผู้ใช้เข้ากลุ่มสิทธิ์สูง",
    severity: "Critical",
    tactic: "Privilege Escalation",
    technique: "T1098 Account Manipulation",
    rootCause: "พบการเพิ่มผู้ใช้เข้ากลุ่มที่มีผลต่อสิทธิ์ความปลอดภัย",
    impact: "อาจทำให้ผู้ใช้ได้รับสิทธิ์สูงขึ้น หรือใช้เป็นช่องทางคงสิทธิ์ในระบบ",
    fix: "ตรวจสอบผู้ร้องขอ, กลุ่ม, ผู้ใช้เป้าหมาย และลบสิทธิ์ทันทีถ้าไม่ได้รับอนุญาต",
    confidence: 90,
  },
  "4732": {
    rule: "Windows: เพิ่มผู้ใช้เข้ากลุ่ม Local",
    severity: "High",
    tactic: "Privilege Escalation",
    technique: "T1098 Account Manipulation",
    rootCause: "พบการเพิ่มผู้ใช้เข้ากลุ่มภายในเครื่อง",
    impact: "ถ้ากลุ่มนั้นมีสิทธิ์สูง ผู้ใช้อาจได้รับสิทธิ์ Local Admin",
    fix: "ตรวจสอบชื่อกลุ่ม, ผู้ใช้เป้าหมาย, ผู้อนุมัติ และกิจกรรมบนเครื่อง",
    confidence: 86,
  },
  "4740": {
    rule: "Windows: บัญชีถูกล็อก",
    severity: "Medium",
    tactic: "Credential Access",
    technique: "T1110 Brute Force",
    rootCause: "พบบัญชี Windows ถูกล็อกจากการยืนยันตัวตนผิดพลาด",
    impact: "อาจเกิดจาก Brute Force, Password Spray, Service ใช้รหัสผ่านเก่า หรือผู้ใช้กรอกรหัสผิด",
    fix: "หาแหล่งที่ทำให้บัญชีล็อก ตรวจสอบ Scheduled Task/Service และรีเซ็ตรหัสผ่านถ้าจำเป็น",
    confidence: 82,
  },
  "4768": {
    rule: "Kerberos: มีการขอ Authentication Ticket",
    severity: "Low",
    tactic: "Credential Access",
    technique: "T1558 Steal or Forge Kerberos Tickets",
    rootCause: "พบการขอ Kerberos TGT",
    impact: "มักเป็นเหตุการณ์ปกติ แต่ควรตรวจสอบถ้าเกิดจำนวนมาก หรือมี pre-auth/encryption ผิดปกติ",
    fix: "ตรวจสอบบัญชี, เครื่องต้นทาง, Failure Code และปริมาณที่ผิดปกติ",
    confidence: 58,
  },
  "4769": {
    rule: "Kerberos: มีการขอ Service Ticket",
    severity: "Medium",
    tactic: "Credential Access",
    technique: "T1558 Steal or Forge Kerberos Tickets",
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
    technique: "T1110 Brute Force",
    confidence: 84,
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
    technique: "T1078 Valid Accounts",
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
    technique: "T1190 Exploit Public-Facing Application",
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
    technique: "T1190 Exploit Public-Facing Application",
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
    technique: "T1189 Drive-by Compromise",
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
    technique: "T1059 Command and Scripting Interpreter",
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
    technique: "T1595 Active Scanning",
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
    technique: "T1595 Active Scanning",
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
    technique: "T1059.001 PowerShell",
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
    technique: "T1548 Abuse Elevation Control Mechanism",
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
    technique: "Service Disruption",
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
    technique: "Layer 2 Loop / MAC Instability",
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
    technique: "T1557 Adversary-in-the-Middle",
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
    technique: "Layer 2 Topology Change",
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
    technique: "Network Service Disruption",
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
    technique: "Network Access Control Bypass",
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
        possibleRootCause: ioc ? `${rule.rootCause} พบ IOC ตรงกับรายการ: ${ioc.type}.` : rule.rootCause,
        impact: ioc ? `${rule.impact} ข้อมูล IOC: ${ioc.description}` : rule.impact,
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
    possibleRootCause: ioc ? `${mapped.rootCause} พบ IOC ตรงกับรายการ: ${ioc.type}.` : mapped.rootCause,
    impact: ioc ? `${mapped.impact} ข้อมูล IOC: ${ioc.description}` : mapped.impact,
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
          ? `${finding.impact} เหตุการณ์เกิดซ้ำหลายครั้ง ทำให้ความสำคัญของ Incident สูงขึ้น`
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
        title: "พบพฤติกรรมโจมตี Credential แบบถี่ผิดปกติ",
        severity: "Critical",
        sourceIp,
        eventCount: bruteForce.length,
        description: `${sourceIp} สร้าง ${bruteForce.length} เหตุการณ์ยืนยันตัวตนล้มเหลว ครอบคลุม ${uniqueUsers.size || 1} บัญชี`,
        recommendedAction: "Block หรือ Rate-limit Source, ตรวจสอบ Login สำเร็จจาก IP เดียวกัน และบังคับ Reset รหัสผ่านบัญชีเป้าหมายหากสงสัยว่าถูกยึดบัญชี",
      });
    }

    const ports = new Set(items.map((finding) => finding.destinationPort).filter(Boolean));
    const scanEvents = items.filter((finding) => finding.rule === "Port Scan / Probe" || finding.rule === "Firewall: Drop/Deny Traffic");

    if (scanEvents.length >= 3 || ports.size >= 4) {
      correlations.push({
        title: "พบพฤติกรรม Recon / สแกนหลายพอร์ต",
        severity: "High",
        sourceIp,
        eventCount: scanEvents.length || items.length,
        description: `${sourceIp} เข้าถึง ${ports.size} พอร์ตปลายทาง บ่งชี้การค้นหา Service หรือการสแกน`,
        recommendedAction: "ยืนยัน Service ที่เปิดอยู่, เพิ่ม Rate Limit และค้นหาเหตุการณ์โจมตีต่อเนื่องจาก Source เดียวกัน",
      });
    }

    const webAttackRules = new Set(
      items
        .filter((finding) =>
          ["SQL Injection", "Path Traversal", "XSS Payload", "Command Injection"].includes(finding.rule)
        )
        .map((finding) => finding.rule)
    );

    if (webAttackRules.size >= 2) {
      correlations.push({
        title: "พบลำดับการโจมตีเว็บหลายรูปแบบ",
        severity: "Critical",
        sourceIp,
        eventCount: items.length,
        description: `${sourceIp} พยายามโจมตีเว็บหลายประเภท: ${Array.from(webAttackRules).join(", ")}.`,
        recommendedAction: "ให้ความสำคัญกับการ Block ที่ WAF, ตรวจ Patch ของ Endpoint และดู Application Log ว่ามี Response 2xx/5xx ที่บ่งชี้ว่าสำเร็จหรือไม่",
      });
    }

    const iocHits = items.filter((finding) => finding.sourceIp && iocList[finding.sourceIp]);
    if (iocHits.length >= 1) {
      correlations.push({
        title: "พบกิจกรรมจาก Source ที่อยู่ใน IOC",
        severity: "High",
        sourceIp,
        eventCount: iocHits.length,
        description: `${sourceIp} ตรงกับ IOC ภายในระบบ และสร้าง ${iocHits.length} เหตุการณ์น่าสงสัย`,
        recommendedAction: "Block IOC ถ้าไม่กระทบงาน, Hunt หา IP เดียวกันใน Firewall/Proxy/Auth Log และบันทึก IOC ลง Incident Ticket",
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
        title: "พบกลุ่มเหตุการณ์ Layer 2 ไม่เสถียร",
        severity: "High",
        sourceIp: null,
        eventCount: layer2.length,
        description: `${asset} สร้าง ${layer2.length} สัญญาณปัญหา Layer 2 หรือ Interface`,
        recommendedAction: "ตรวจสอบ STP State, การเปลี่ยนสายล่าสุด, Unmanaged Switch, Uplink, AP Bridge Link และ Interface Counter",
      });
    }
  });

  const serviceIssues = findings.filter((finding) => finding.rule === "Service Down / Timeout");
  if (serviceIssues.length >= 5) {
    correlations.push({
      title: "พบสัญญาณ Availability แย่ลงผิดปกติ",
      severity: "High",
      sourceIp: null,
      eventCount: serviceIssues.length,
      description: `${serviceIssues.length} เหตุการณ์ที่เกี่ยวข้องกับ Availability ใน Log ช่วงนี้`,
      recommendedAction: "ตรวจสอบ Deployment ล่าสุด, Upstream Health, Saturation Metrics, DNS, Routing และ Dashboard Error Rate",
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

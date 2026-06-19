export type Language = "th" | "en";

export const UI: Record<Language, Record<string, string>> = {
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
    clearSession: "ล้างข้อมูล Session",
    cancel: "ยกเลิก",
    results: "ผลการวิเคราะห์",
    showing: "แสดง",
    of: "จาก",
    events: "เหตุการณ์",
    prev: "ก่อนหน้า",
    next: "ถัดไป",
    page: "หน้า",
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
    clearSession: "Clear Session",
    cancel: "Cancel",
    results: "Analysis Results",
    showing: "Showing",
    of: "of",
    events: "events",
    prev: "Prev",
    next: "Next",
    page: "Page",
  },
};

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

export function toEnglish(value: string): string {
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

export function localize(value: string | null | undefined, language: Language): string {
  if (!value) return "";
  if (language === "th") return value;
  return toEnglish(value);
}

export function severityLabel(severity: string, language: Language): string {
  if (language === "en") return severity;
  if (severity === "Critical") return "วิกฤต";
  if (severity === "High") return "สูง";
  if (severity === "Medium") return "ปานกลาง";
  return "ต่ำ";
}

export function severityClass(severity: string): string {
  if (severity === "Critical") return "bg-red-500/20 text-red-200";
  if (severity === "High") return "bg-orange-500/20 text-orange-200";
  if (severity === "Medium") return "bg-amber-500/20 text-amber-200";
  return "bg-emerald-500/20 text-emerald-200";
}

export function barClass(severity: string): string {
  if (severity === "Critical") return "bg-red-500";
  if (severity === "High") return "bg-orange-500";
  if (severity === "Medium") return "bg-amber-500";
  return "bg-emerald-500";
}

export function severityOptionLabel(option: string, language: Language): string {
  if (option === "All") return language === "th" ? "ทุกระดับความรุนแรง" : "All Severities";
  return severityLabel(option, language);
}

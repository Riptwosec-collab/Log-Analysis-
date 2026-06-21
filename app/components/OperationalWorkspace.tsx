"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";

type Language = "th" | "en";
type UXTheme = "sentinel" | "aurora" | "daylight";
type Severity = "Critical" | "High" | "Medium" | "Low";
type WorkStatus = "New" | "Acknowledged" | "Investigating" | "Contained" | "Resolved" | "Closed" | "Active" | "Review" | "Healthy" | "Watch";
type ModuleKey = "logs" | "alerts" | "incidents" | "threat-intelligence" | "mitre" | "reports" | "rules" | "assets" | "users" | "settings";
type L10n = Record<Language, string>;

type NavItem = { key: "dashboard" | ModuleKey; href: string; code: string };
type LogRow = { id: string; timestamp: string; vendor: string; source: string; host: string; user: string; sourceIp: string; severity: Severity; parser: WorkStatus; raw: string };
type AlertRow = { id: string; time: string; rule: L10n; severity: Severity; sourceIp: string; asset: string; mitre: string; status: WorkStatus; confidence: number; evidence: L10n };
type IncidentRow = { id: string; title: L10n; severity: Severity; status: WorkStatus; owner: string; created: string; alerts: number; assets: string; rca: L10n; impact: L10n; fix: L10n; timeline: L10n[] };
type IocRow = { indicator: string; type: string; confidence: number; source: string; lastSeen: string; status: WorkStatus; note: L10n };
type TechniqueRow = { tactic: L10n; technique: string; name: L10n; severity: Severity; evidence: number; action: L10n };
type ReportRow = { id: string; caseId: string; title: L10n; type: string; owner: string; updated: string; status: WorkStatus };
type RuleRow = { id: string; name: L10n; pattern: string; severity: Severity; source: string; mitre: string; enabled: boolean; recommendation: L10n };
type AssetRow = { id: string; name: string; type: string; owner: string; location: string; criticality: Severity; status: WorkStatus; lastSeen: string; notes: L10n };
type UserRow = { id: string; name: string; email: string; role: string; permission: string; status: WorkStatus; lastActive: string; notes: L10n };

type Copy = {
  nav: Record<NavItem["key"], string>;
  modules: Record<ModuleKey, { eyebrow: string; title: string; description: string }>;
  common: Record<string, string>;
  fields: Record<string, string>;
  status: Record<WorkStatus, string>;
  severity: Record<Severity, string>;
  themes: Record<UXTheme, { label: string; note: string }>;
};

const navItems: NavItem[] = [
  { key: "dashboard", href: "/", code: "01" },
  { key: "logs", href: "/logs", code: "02" },
  { key: "alerts", href: "/alerts", code: "03" },
  { key: "incidents", href: "/incidents", code: "04" },
  { key: "threat-intelligence", href: "/threat-intelligence", code: "05" },
  { key: "mitre", href: "/mitre", code: "06" },
  { key: "reports", href: "/reports", code: "07" },
  { key: "rules", href: "/rules", code: "08" },
  { key: "assets", href: "/assets", code: "09" },
  { key: "users", href: "/users", code: "10" },
  { key: "settings", href: "/settings", code: "11" },
];

const copy: Record<Language, Copy> = {
  en: {
    nav: {
      dashboard: "Dashboard",
      logs: "Logs",
      alerts: "Alerts",
      incidents: "Incidents",
      "threat-intelligence": "Threat Intelligence",
      mitre: "MITRE ATT&CK",
      reports: "Reports",
      rules: "Rules",
      assets: "Assets",
      users: "Users",
      settings: "Settings",
    },
    modules: {
      logs: { eyebrow: "LOG WORKSPACE", title: "Logs", description: "Raw log ingestion, parser health, source status, and searchable evidence lines." },
      alerts: { eyebrow: "ALERT QUEUE", title: "Alerts", description: "Prioritized SOC alerts with severity, MITRE mapping, source IP, confidence, and triage status." },
      incidents: { eyebrow: "CASE BOARD", title: "Incidents", description: "Incident cases with RCA, impact, timeline, owner, and recommended fix actions." },
      "threat-intelligence": { eyebrow: "INTEL WATCH", title: "Threat Intelligence", description: "IOC watchlist, confidence scoring, related cases, and enrichment notes." },
      mitre: { eyebrow: "ATT&CK COVERAGE", title: "MITRE ATT&CK", description: "Tactic and technique matrix mapped to evidence and response actions." },
      reports: { eyebrow: "EXPORT CENTER", title: "Reports", description: "Generate JSON, CSV, and Markdown evidence packages for tickets, RCA, and manager review." },
      rules: { eyebrow: "DETECTION ENGINE", title: "Rules", description: "Create, edit, enable, disable, and tune detection rules in browser local storage." },
      assets: { eyebrow: "ASSET INVENTORY", title: "Assets", description: "Track hosts, network devices, cloud resources, owners, criticality, and last-seen status." },
      users: { eyebrow: "ACCESS REVIEW", title: "Users", description: "Review SOC users, roles, permissions, activity context, and notes." },
      settings: { eyebrow: "CONTROL CENTER", title: "Settings", description: "Privacy, webhook, language, theme, retention, masking, and operational preferences." },
    },
    common: {
      appName: "SOC Console",
      globalSearch: "Search current page...",
      search: "Search",
      filter: "Filter",
      all: "All",
      clear: "Clear",
      add: "Add",
      save: "Save",
      delete: "Delete",
      edit: "Edit",
      cancel: "Cancel",
      exportJson: "Export JSON",
      exportCsv: "Export CSV",
      exportMarkdown: "Export Markdown",
      uploadHint: "Drop .log, .txt, .csv, or paste raw evidence here",
      chooseFiles: "Choose files",
      selectedFiles: "Selected files",
      noData: "No matching records. Try clearing search or filters.",
      summary: "Summary",
      table: "Table",
      details: "Details",
      workflow: "Workflow",
      language: "Language",
      theme: "Theme",
      thai: "Thai",
      english: "English",
      localOnly: "Saved in this browser only",
      privacyNotice: "Mask secrets, tokens, emails, customer names, and private hostnames before sharing logs publicly.",
      refresh: "Refresh",
    },
    fields: {
      time: "Time",
      vendor: "Vendor",
      source: "Source",
      host: "Host",
      user: "User",
      sourceIp: "Source IP",
      severity: "Severity",
      parser: "Parser",
      rawLog: "Raw log line",
      rule: "Rule",
      asset: "Asset",
      mitre: "MITRE",
      status: "Status",
      confidence: "Confidence",
      evidence: "Evidence",
      caseId: "Case ID",
      owner: "Owner",
      created: "Created",
      alerts: "Alerts",
      rca: "Root cause",
      impact: "Impact",
      fix: "Fix action",
      timeline: "Timeline",
      indicator: "Indicator",
      type: "Type",
      lastSeen: "Last seen",
      tactic: "Tactic",
      technique: "Technique",
      action: "Action",
      reportType: "Report type",
      updated: "Updated",
      pattern: "Pattern",
      enabled: "Enabled",
      recommendation: "Recommendation",
      location: "Location",
      criticality: "Criticality",
      notes: "Notes",
      email: "Email",
      role: "Role",
      permission: "Permission",
      lastActive: "Last active",
      webhookUrl: "Webhook URL",
      retention: "Retention days",
      masking: "Sensitive data masking",
    },
    status: { New: "New", Acknowledged: "Acknowledged", Investigating: "Investigating", Contained: "Contained", Resolved: "Resolved", Closed: "Closed", Active: "Active", Review: "Review", Healthy: "Healthy", Watch: "Watch" },
    severity: { Critical: "Critical", High: "High", Medium: "Medium", Low: "Low" },
    themes: {
      sentinel: { label: "Midnight SOC", note: "Dark professional" },
      aurora: { label: "Aurora Cyber", note: "Modern neon" },
      daylight: { label: "Daylight Clean", note: "Bright and clear" },
    },
  },
  th: {
    nav: {
      dashboard: "แดชบอร์ด",
      logs: "บันทึก Log",
      alerts: "การแจ้งเตือน",
      incidents: "เหตุการณ์",
      "threat-intelligence": "ข่าวกรองภัยคุกคาม",
      mitre: "MITRE ATT&CK",
      reports: "รายงาน",
      rules: "กฎตรวจจับ",
      assets: "สินทรัพย์",
      users: "ผู้ใช้",
      settings: "ตั้งค่า",
    },
    modules: {
      logs: { eyebrow: "พื้นที่ LOG", title: "บันทึก Log", description: "นำเข้า Log ดิบ ตรวจสถานะ parser แหล่งข้อมูล และค้นหาหลักฐานที่ใช้วิเคราะห์ได้" },
      alerts: { eyebrow: "คิวแจ้งเตือน", title: "การแจ้งเตือน", description: "จัดลำดับ Alert ตามความรุนแรง MITRE, Source IP, ความมั่นใจ และสถานะ triage" },
      incidents: { eyebrow: "กระดานเคส", title: "เหตุการณ์", description: "จัดการเคส Incident พร้อม RCA ผลกระทบ ไทม์ไลน์ เจ้าของงาน และแนวทางแก้ไข" },
      "threat-intelligence": { eyebrow: "เฝ้าระวัง IOC", title: "ข่าวกรองภัยคุกคาม", description: "รายการ IOC คะแนนความมั่นใจ เคสที่เกี่ยวข้อง และบันทึก enrichment" },
      mitre: { eyebrow: "ความครอบคลุม ATT&CK", title: "MITRE ATT&CK", description: "เมทริกซ์ tactic และ technique ที่เชื่อมกับหลักฐานและแนวทางตอบสนอง" },
      reports: { eyebrow: "ศูนย์ส่งออก", title: "รายงาน", description: "สร้างชุดหลักฐาน JSON, CSV และ Markdown สำหรับ Ticket, RCA และรายงานผู้บริหาร" },
      rules: { eyebrow: "เครื่องมือตรวจจับ", title: "กฎตรวจจับ", description: "เพิ่ม แก้ไข เปิด ปิด และปรับแต่งกฎตรวจจับด้วย localStorage ในเบราว์เซอร์" },
      assets: { eyebrow: "ทะเบียนสินทรัพย์", title: "สินทรัพย์", description: "ติดตาม host, อุปกรณ์เครือข่าย, cloud resource, เจ้าของ, criticality และสถานะล่าสุด" },
      users: { eyebrow: "ตรวจสิทธิ์ผู้ใช้", title: "ผู้ใช้", description: "ตรวจผู้ใช้ SOC บทบาท สิทธิ์การใช้งาน บริบทกิจกรรม และบันทึกเพิ่มเติม" },
      settings: { eyebrow: "ศูนย์ควบคุม", title: "ตั้งค่า", description: "ตั้งค่าความเป็นส่วนตัว webhook ภาษา ธีม retention masking และการใช้งานระบบ" },
    },
    common: {
      appName: "SOC Console",
      globalSearch: "ค้นหาในหน้านี้...",
      search: "ค้นหา",
      filter: "ตัวกรอง",
      all: "ทั้งหมด",
      clear: "ล้าง",
      add: "เพิ่ม",
      save: "บันทึก",
      delete: "ลบ",
      edit: "แก้ไข",
      cancel: "ยกเลิก",
      exportJson: "ส่งออก JSON",
      exportCsv: "ส่งออก CSV",
      exportMarkdown: "ส่งออก Markdown",
      uploadHint: "วางไฟล์ .log, .txt, .csv หรือวางหลักฐานดิบที่นี่",
      chooseFiles: "เลือกไฟล์",
      selectedFiles: "ไฟล์ที่เลือก",
      noData: "ไม่พบข้อมูลที่ตรงกัน ลองล้างคำค้นหาหรือตัวกรอง",
      summary: "สรุป",
      table: "ตาราง",
      details: "รายละเอียด",
      workflow: "ขั้นตอนงาน",
      language: "ภาษา",
      theme: "ธีม",
      thai: "ไทย",
      english: "อังกฤษ",
      localOnly: "บันทึกเฉพาะในเบราว์เซอร์นี้",
      privacyNotice: "ปิดบัง secret, token, email, ชื่อลูกค้า และ hostname ภายใน ก่อนแชร์ Log แบบสาธารณะ",
      refresh: "รีเฟรช",
    },
    fields: {
      time: "เวลา",
      vendor: "ผู้ผลิต/ระบบ",
      source: "แหล่งข้อมูล",
      host: "โฮสต์",
      user: "ผู้ใช้",
      sourceIp: "Source IP",
      severity: "ความรุนแรง",
      parser: "Parser",
      rawLog: "บรรทัด Log ดิบ",
      rule: "กฎ",
      asset: "สินทรัพย์",
      mitre: "MITRE",
      status: "สถานะ",
      confidence: "ความมั่นใจ",
      evidence: "หลักฐาน",
      caseId: "รหัสเคส",
      owner: "เจ้าของงาน",
      created: "สร้างเมื่อ",
      alerts: "จำนวน Alert",
      rca: "สาเหตุหลัก",
      impact: "ผลกระทบ",
      fix: "แนวทางแก้ไข",
      timeline: "ไทม์ไลน์",
      indicator: "Indicator",
      type: "ประเภท",
      lastSeen: "พบล่าสุด",
      tactic: "Tactic",
      technique: "Technique",
      action: "การตอบสนอง",
      reportType: "ประเภทรายงาน",
      updated: "อัปเดต",
      pattern: "Pattern",
      enabled: "เปิดใช้งาน",
      recommendation: "คำแนะนำ",
      location: "สถานที่",
      criticality: "ความสำคัญ",
      notes: "บันทึก",
      email: "อีเมล",
      role: "บทบาท",
      permission: "สิทธิ์",
      lastActive: "ใช้งานล่าสุด",
      webhookUrl: "Webhook URL",
      retention: "จำนวนวันเก็บข้อมูล",
      masking: "ปิดบังข้อมูลสำคัญ",
    },
    status: { New: "ใหม่", Acknowledged: "รับทราบแล้ว", Investigating: "กำลังตรวจสอบ", Contained: "ควบคุมแล้ว", Resolved: "แก้ไขแล้ว", Closed: "ปิดแล้ว", Active: "ใช้งาน", Review: "รอตรวจ", Healthy: "ปกติ", Watch: "เฝ้าระวัง" },
    severity: { Critical: "วิกฤต", High: "สูง", Medium: "กลาง", Low: "ต่ำ" },
    themes: {
      sentinel: { label: "Midnight SOC", note: "เข้ม คม มืออาชีพ" },
      aurora: { label: "Aurora Cyber", note: "นีออน ทันสมัย" },
      daylight: { label: "Daylight Clean", note: "สว่าง อ่านง่าย" },
    },
  },
};

const themeClassMap: Record<UXTheme, string> = {
  sentinel: "theme-soc-sentinel",
  aurora: "theme-soc-aurora",
  daylight: "theme-soc-daylight",
};

const severityClass: Record<Severity, string> = {
  Critical: "border-red-500/50 bg-red-500/10 text-red-200",
  High: "border-orange-500/50 bg-orange-500/10 text-orange-200",
  Medium: "border-amber-500/50 bg-amber-500/10 text-amber-200",
  Low: "border-emerald-500/50 bg-emerald-500/10 text-emerald-200",
};

const statusClass: Record<WorkStatus, string> = {
  New: "border-cyan-500/50 bg-cyan-500/10 text-cyan-100",
  Acknowledged: "border-blue-500/50 bg-blue-500/10 text-blue-100",
  Investigating: "border-violet-500/50 bg-violet-500/10 text-violet-100",
  Contained: "border-amber-500/50 bg-amber-500/10 text-amber-100",
  Resolved: "border-emerald-500/50 bg-emerald-500/10 text-emerald-100",
  Closed: "border-zinc-500/50 bg-zinc-500/10 text-zinc-100",
  Active: "border-emerald-500/50 bg-emerald-500/10 text-emerald-100",
  Review: "border-amber-500/50 bg-amber-500/10 text-amber-100",
  Healthy: "border-emerald-500/50 bg-emerald-500/10 text-emerald-100",
  Watch: "border-orange-500/50 bg-orange-500/10 text-orange-100",
};

const seedLogs: LogRow[] = [
  { id: "LOG-1001", timestamp: "2026-06-21 22:14:02", vendor: "Linux Auth", source: "sshd", host: "web-01", user: "admin", sourceIp: "185.220.101.21", severity: "High", parser: "Healthy", raw: "Failed password for invalid user admin from 185.220.101.21 port 55110 ssh2" },
  { id: "LOG-1002", timestamp: "2026-06-21 22:16:40", vendor: "Cloudflare", source: "WAF", host: "app.example.com", user: "-", sourceIp: "198.51.100.44", severity: "Critical", parser: "Healthy", raw: "WAFAction=block URI=/login.php?id=1 UNION SELECT password FROM users" },
  { id: "LOG-1003", timestamp: "2026-06-21 22:18:27", vendor: "FortiGate", source: "traffic", host: "FGT-EDGE", user: "-", sourceIp: "45.77.10.2", severity: "High", parser: "Healthy", raw: "action=deny srcip=45.77.10.2 dstip=10.0.0.12 dstport=22 proto=6" },
  { id: "LOG-1004", timestamp: "2026-06-21 22:19:44", vendor: "Windows Event", source: "Security", host: "DC-01", user: "svc-backup", sourceIp: "192.0.2.71", severity: "Medium", parser: "Review", raw: "Event ID 4625 Audit Failure Account Name: svc-backup Source Network Address: 192.0.2.71" },
  { id: "LOG-1005", timestamp: "2026-06-21 22:25:01", vendor: "Cisco IOS", source: "Switch", host: "SW-CORE-01", user: "-", sourceIp: "10.10.2.12", severity: "Medium", parser: "Healthy", raw: "%SW_MATM-4-MACFLAP_NOTIF: Host 6c3b.e51f.fd9f in vlan 2 is flapping" },
];

const seedAlerts: AlertRow[] = [
  { id: "ALT-9001", time: "22:16", rule: { en: "SQL Injection blocked by WAF", th: "WAF บล็อก SQL Injection" }, severity: "Critical", sourceIp: "198.51.100.44", asset: "app.example.com", mitre: "T1190", status: "New", confidence: 96, evidence: { en: "UNION SELECT pattern detected in login parameter.", th: "พบ pattern UNION SELECT ในพารามิเตอร์ login" } },
  { id: "ALT-9002", time: "22:18", rule: { en: "Firewall port scan", th: "พบการสแกนพอร์ตที่ Firewall" }, severity: "High", sourceIp: "45.77.10.2", asset: "FGT-EDGE", mitre: "T1046", status: "Acknowledged", confidence: 88, evidence: { en: "Single IP touched 22, 80, 443, 445, 3389 in short window.", th: "IP เดียวแตะ port 22, 80, 443, 445, 3389 ในช่วงเวลาสั้น" } },
  { id: "ALT-9003", time: "22:19", rule: { en: "Windows failed logon burst", th: "Windows login ล้มเหลวหลายครั้ง" }, severity: "Medium", sourceIp: "192.0.2.71", asset: "DC-01", mitre: "T1110", status: "Investigating", confidence: 74, evidence: { en: "Event ID 4625 repeated for service and admin accounts.", th: "Event ID 4625 เกิดซ้ำกับบัญชี service และ admin" } },
  { id: "ALT-9004", time: "22:25", rule: { en: "MAC flapping detected", th: "ตรวจพบ MAC flapping" }, severity: "Medium", sourceIp: "10.10.2.12", asset: "SW-CORE-01", mitre: "T1557", status: "Review", confidence: 69, evidence: { en: "Host moved between Gi1/0/12 and Gi1/0/20.", th: "Host สลับระหว่าง Gi1/0/12 และ Gi1/0/20" } },
];

const seedIncidents: IncidentRow[] = [
  { id: "CASE-2406-001", title: { en: "Web attack blocked at edge", th: "การโจมตีเว็บถูกบล็อกที่ Edge" }, severity: "Critical", status: "Investigating", owner: "Nicha / SOC L2", created: "2026-06-21 22:20", alerts: 3, assets: "app.example.com, WAF", rca: { en: "External source attempted SQL injection and path traversal against public login endpoints.", th: "แหล่งภายนอกพยายาม SQL Injection และ Path Traversal กับ endpoint login สาธารณะ" }, impact: { en: "Traffic was blocked by WAF; no confirmed data exposure in current evidence.", th: "WAF บล็อก traffic แล้ว ยังไม่มีหลักฐานยืนยันว่าข้อมูลรั่วไหล" }, fix: { en: "Keep WAF block, review application logs, add source IP to temporary deny list.", th: "คง WAF block ตรวจ application log และเพิ่ม source IP เข้า deny list ชั่วคราว" }, timeline: [{ en: "22:16 WAF blocked SQL injection", th: "22:16 WAF บล็อก SQL Injection" }, { en: "22:17 Path traversal blocked", th: "22:17 บล็อก Path Traversal" }, { en: "22:21 Case assigned to SOC L2", th: "22:21 มอบหมายเคสให้ SOC L2" }] },
  { id: "CASE-2406-002", title: { en: "Credential attack against DC", th: "Credential attack ต่อ DC" }, severity: "High", status: "Contained", owner: "Mek / SOC L1", created: "2026-06-21 22:24", alerts: 2, assets: "DC-01", rca: { en: "Repeated failed logons from one source suggest password guessing or misconfigured service.", th: "Login ล้มเหลวซ้ำจาก source เดียว อาจเป็น password guessing หรือ service ตั้งค่าผิด" }, impact: { en: "Account lockout observed; no privilege escalation confirmed.", th: "พบ account lockout แต่ยังไม่ยืนยัน privilege escalation" }, fix: { en: "Block source, reset affected account, review MFA and lockout policy.", th: "บล็อก source รีเซ็ตบัญชีที่เกี่ยวข้อง และตรวจ MFA/lockout policy" }, timeline: [{ en: "22:19 Failed logons begin", th: "22:19 เริ่มพบ failed logon" }, { en: "22:22 Account locked", th: "22:22 บัญชีถูก lock" }, { en: "22:30 Source blocked", th: "22:30 บล็อก source แล้ว" }] },
];

const seedIocs: IocRow[] = [
  { indicator: "185.220.101.21", type: "IP", confidence: 92, source: "Tor exit / OSINT", lastSeen: "2026-06-21", status: "Watch", note: { en: "Seen in SSH brute-force attempts.", th: "พบในความพยายาม brute-force SSH" } },
  { indicator: "evil.example.com", type: "Domain", confidence: 89, source: "Internal EDR", lastSeen: "2026-06-20", status: "Active", note: { en: "Endpoint alert linked a file hash to this domain.", th: "EDR เชื่อม file hash กับ domain นี้" } },
  { indicator: "44d88612fea8a8f36de82e1278abb02f", type: "Hash", confidence: 78, source: "Malware sandbox", lastSeen: "2026-06-18", status: "Review", note: { en: "Known test hash used for validation workflows.", th: "Hash สำหรับทดสอบ ใช้ตรวจ workflow" } },
];

const seedTechniques: TechniqueRow[] = [
  { tactic: { en: "Initial Access", th: "Initial Access" }, technique: "T1190", name: { en: "Exploit Public-Facing Application", th: "โจมตีแอปพลิเคชันที่เปิดสาธารณะ" }, severity: "Critical", evidence: 3, action: { en: "Keep WAF rule active and review application logs.", th: "เปิด WAF rule ต่อ และตรวจ application log" } },
  { tactic: { en: "Credential Access", th: "Credential Access" }, technique: "T1110", name: { en: "Brute Force", th: "เดารหัสผ่านซ้ำ" }, severity: "High", evidence: 6, action: { en: "Enforce MFA and tune failed-login alerts.", th: "บังคับ MFA และปรับ alert failed-login" } },
  { tactic: { en: "Discovery", th: "Discovery" }, technique: "T1046", name: { en: "Network Service Discovery", th: "สแกนบริการเครือข่าย" }, severity: "High", evidence: 5, action: { en: "Block scanner and review exposed ports.", th: "บล็อกตัวสแกนและตรวจ port ที่เปิด" } },
  { tactic: { en: "Lateral Movement", th: "Lateral Movement" }, technique: "T1557", name: { en: "Adversary-in-the-Middle", th: "โจมตีแบบแทรกกลาง" }, severity: "Medium", evidence: 2, action: { en: "Check switch loop, DHCP snooping, and DAI status.", th: "ตรวจ loop switch, DHCP snooping และ DAI" } },
];

const seedReports: ReportRow[] = [
  { id: "RPT-001", caseId: "CASE-2406-001", title: { en: "Web attack executive summary", th: "สรุปผู้บริหารเหตุโจมตีเว็บ" }, type: "Manager Markdown", owner: "Nicha", updated: "2026-06-21 23:00", status: "Review" },
  { id: "RPT-002", caseId: "CASE-2406-002", title: { en: "Credential attack evidence package", th: "ชุดหลักฐาน Credential attack" }, type: "JSON + CSV", owner: "Mek", updated: "2026-06-21 23:10", status: "Active" },
  { id: "RPT-003", caseId: "CASE-2406-003", title: { en: "Network anomaly RCA draft", th: "ร่าง RCA เหตุผิดปกติในเครือข่าย" }, type: "RCA Markdown", owner: "SOC L2", updated: "2026-06-22 00:15", status: "New" },
];

const seedRules: RuleRow[] = [
  { id: "RULE-SSH-001", name: { en: "SSH brute force", th: "SSH brute force" }, pattern: "Failed password", severity: "High", source: "Linux Auth", mitre: "T1110", enabled: true, recommendation: { en: "Block source IP and enforce key-based authentication.", th: "บล็อก source IP และบังคับใช้ SSH key" } },
  { id: "RULE-WEB-001", name: { en: "SQL injection", th: "SQL injection" }, pattern: "UNION SELECT", severity: "Critical", source: "WAF / Web", mitre: "T1190", enabled: true, recommendation: { en: "Enable WAF block and review query handling.", th: "เปิด WAF block และตรวจ query handling" } },
  { id: "RULE-NET-001", name: { en: "MAC flapping", th: "MAC flapping" }, pattern: "MACFLAP", severity: "Medium", source: "Cisco IOS", mitre: "T1557", enabled: true, recommendation: { en: "Check loop, rogue device, and DAI status.", th: "ตรวจ loop, rogue device และ DAI" } },
  { id: "RULE-FW-001", name: { en: "Firewall port scan", th: "Firewall port scan" }, pattern: "multiple dstport", severity: "High", source: "Firewall", mitre: "T1046", enabled: true, recommendation: { en: "Block scanner and review exposed services.", th: "บล็อก scanner และตรวจบริการที่เปิด" } },
];

const seedAssets: AssetRow[] = [
  { id: "AST-001", name: "app.example.com", type: "Web App", owner: "App Team", location: "Bangkok / Vercel", criticality: "Critical", status: "Active", lastSeen: "2026-06-21 22:17", notes: { en: "Public login endpoint protected by WAF.", th: "Endpoint login สาธารณะมี WAF ป้องกัน" } },
  { id: "AST-002", name: "DC-01", type: "Domain Controller", owner: "Infrastructure", location: "HQ", criticality: "Critical", status: "Watch", lastSeen: "2026-06-21 22:22", notes: { en: "Failed logon burst observed.", th: "พบ failed logon หลายครั้ง" } },
  { id: "AST-003", name: "SW-CORE-01", type: "Core Switch", owner: "Network", location: "MDF", criticality: "High", status: "Review", lastSeen: "2026-06-21 22:25", notes: { en: "MAC flapping on VLAN 2 requires review.", th: "MAC flapping บน VLAN 2 ต้องตรวจสอบ" } },
];

const seedUsers: UserRow[] = [
  { id: "USR-001", name: "Mek SOC", email: "mek.soc@example.com", role: "SOC Analyst", permission: "Triage, Export", status: "Active", lastActive: "2026-06-22 00:20", notes: { en: "Handles L1 triage and report handoff.", th: "ดูแล triage L1 และส่งต่อรายงาน" } },
  { id: "USR-002", name: "Nicha IR", email: "nicha.ir@example.com", role: "Incident Responder", permission: "Cases, Rules, Reports", status: "Active", lastActive: "2026-06-22 00:05", notes: { en: "Owns high severity case review.", th: "รับผิดชอบเคสความรุนแรงสูง" } },
  { id: "USR-003", name: "Audit Viewer", email: "audit.viewer@example.com", role: "Viewer", permission: "Read-only", status: "Review", lastActive: "2026-06-20 16:44", notes: { en: "Quarterly access review pending.", th: "รอตรวจสิทธิ์รายไตรมาส" } },
];

function text(value: L10n, language: Language): string {
  return value[language];
}

function loadLocal<T>(key: string, fallback: T): T {
  if (typeof window === "undefined") return fallback;
  try {
    const raw = window.localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function useWorkspacePreferences() {
  const [language, setLanguageState] = useState<Language>("th");
  const [theme, setThemeState] = useState<UXTheme>("sentinel");

  useEffect(() => {
    const sync = () => {
      const savedLanguage = window.localStorage.getItem("soc_language");
      const savedTheme = window.localStorage.getItem("soc_ux_theme");
      if (savedLanguage === "th" || savedLanguage === "en") setLanguageState(savedLanguage);
      if (savedTheme === "sentinel" || savedTheme === "aurora" || savedTheme === "daylight") setThemeState(savedTheme);
    };
    sync();
    const interval = window.setInterval(sync, 300);
    return () => window.clearInterval(interval);
  }, []);

  const setLanguage = (next: Language) => {
    setLanguageState(next);
    window.localStorage.setItem("soc_language", next);
  };

  const setTheme = (next: UXTheme) => {
    setThemeState(next);
    window.localStorage.setItem("soc_ux_theme", next);
    const html = document.documentElement;
    Object.values(themeClassMap).forEach((className) => html.classList.remove(className));
    html.classList.add(themeClassMap[next]);
  };

  return { language, theme, setLanguage, setTheme };
}

function Pill({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <span className={`inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-medium ${className}`}>{children}</span>;
}

function MetricCard({ label, value, note }: { label: string; value: string | number; note?: string }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-4 shadow-xl shadow-black/10 backdrop-blur">
      <p className="text-xs uppercase tracking-[0.18em] text-cyan-200/80">{label}</p>
      <p className="mt-2 text-2xl font-semibold text-white">{value}</p>
      {note && <p className="mt-1 text-xs text-slate-400">{note}</p>}
    </div>
  );
}

function SearchFilterBar({ search, setSearch, filter, setFilter, options, labels }: { search: string; setSearch: (value: string) => void; filter: string; setFilter: (value: string) => void; options: string[]; labels: Copy }) {
  return (
    <div className="flex flex-col gap-3 rounded-2xl border border-white/10 bg-white/[0.04] p-4 backdrop-blur md:flex-row md:items-center">
      <label className="flex-1">
        <span className="sr-only">{labels.common.search}</span>
        <input
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder={labels.common.globalSearch}
          className="w-full rounded-xl border border-white/10 bg-black/30 px-4 py-3 text-sm text-white outline-none transition placeholder:text-slate-500 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/20"
        />
      </label>
      <select
        value={filter}
        onChange={(event) => setFilter(event.target.value)}
        className="rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white outline-none focus:border-cyan-400"
      >
        {options.map((option) => <option key={option} value={option}>{option === "All" ? labels.common.all : option}</option>)}
      </select>
      <button type="button" onClick={() => { setSearch(""); setFilter("All"); }} className="rounded-xl border border-white/10 px-4 py-3 text-sm text-slate-200 transition hover:border-cyan-400 hover:text-white">
        {labels.common.clear}
      </button>
    </div>
  );
}

function EmptyState({ message }: { message: string }) {
  return <div className="rounded-2xl border border-dashed border-white/15 bg-white/[0.03] p-8 text-center text-sm text-slate-400">{message}</div>;
}

function downloadFile(filename: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function matchesQuery(values: string[], query: string): boolean {
  if (!query.trim()) return true;
  const q = query.toLowerCase();
  return values.some((value) => value.toLowerCase().includes(q));
}

function WorkspaceLayout({ moduleKey, children }: { moduleKey: ModuleKey; children: React.ReactNode }) {
  const { language, theme, setLanguage, setTheme } = useWorkspacePreferences();
  const labels = copy[language];
  const module = labels.modules[moduleKey];

  return (
    <main data-i18n-ignore className="flex min-h-screen text-slate-100" style={{ backgroundColor: "var(--bg-primary)", color: "var(--text-primary)" }}>
      <aside className="sticky top-0 hidden h-screen w-72 shrink-0 border-r border-white/10 bg-black/35 p-4 backdrop-blur-xl lg:flex lg:flex-col">
        <Link href="/" className="mb-4 rounded-2xl border border-white/10 bg-white/[0.04] px-4 py-3 text-sm font-semibold text-white transition hover:border-cyan-400">
          {labels.common.appName}
        </Link>
        <nav className="space-y-1 overflow-y-auto pr-1">
          {navItems.map((item) => {
            const active = item.key === moduleKey;
            return (
              <Link key={item.href} href={item.href} className={`group flex items-center gap-3 rounded-2xl border px-3 py-3 text-sm transition ${active ? "border-cyan-400/70 bg-cyan-400/12 text-cyan-50 shadow-lg shadow-cyan-950/30" : "border-transparent text-slate-400 hover:border-white/10 hover:bg-white/[0.04] hover:text-white"}`}>
                <span className="font-mono text-xs text-cyan-300">{item.code}</span>
                <span className="truncate">{labels.nav[item.key]}</span>
              </Link>
            );
          })}
        </nav>
      </aside>

      <section className="min-w-0 flex-1 px-4 py-6 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-7xl space-y-6">
          <header className="rounded-[2rem] border border-white/10 bg-white/[0.05] p-5 shadow-2xl shadow-black/20 backdrop-blur-xl">
            <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
              <div>
                <p className="text-xs font-bold uppercase tracking-[0.24em] text-cyan-300">{module.eyebrow}</p>
                <h1 className="mt-2 text-3xl font-semibold text-white sm:text-4xl">{module.title}</h1>
                <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-300">{module.description}</p>
              </div>
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
                <div className="flex rounded-2xl border border-white/10 bg-black/30 p-1">
                  {(["th", "en"] as Language[]).map((item) => (
                    <button key={item} type="button" onClick={() => setLanguage(item)} className={`rounded-xl px-4 py-2 text-sm font-semibold transition ${language === item ? "bg-cyan-400 text-slate-950" : "text-slate-300 hover:text-white"}`}>
                      {item === "th" ? labels.common.thai : labels.common.english}
                    </button>
                  ))}
                </div>
                <select value={theme} onChange={(event) => setTheme(event.target.value as UXTheme)} className="rounded-2xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white outline-none focus:border-cyan-400">
                  {(["sentinel", "aurora", "daylight"] as UXTheme[]).map((item) => <option key={item} value={item}>{labels.themes[item].label}</option>)}
                </select>
              </div>
            </div>
          </header>
          {children}
        </div>
      </section>
    </main>
  );
}

function LogsModule({ labels, language }: { labels: Copy; language: Language }) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("All");
  const [files, setFiles] = useState<string[]>([]);
  const rows = seedLogs.filter((row) => (filter === "All" || row.severity === filter || row.vendor === filter) && matchesQuery([row.raw, row.vendor, row.host, row.user, row.sourceIp], search));
  const parserHealthy = seedLogs.filter((row) => row.parser === "Healthy").length;
  return <div className="space-y-5">
    <div className="grid gap-4 md:grid-cols-4"><MetricCard label={labels.fields.rawLog} value={seedLogs.length} /><MetricCard label={labels.fields.parser} value={`${parserHealthy}/${seedLogs.length}`} /><MetricCard label={labels.fields.sourceIp} value="4" /><MetricCard label={labels.fields.severity} value="1 Critical" /></div>
    <section className="rounded-2xl border border-cyan-400/25 bg-cyan-400/8 p-5">
      <p className="text-sm font-semibold text-cyan-100">{labels.common.uploadHint}</p>
      <div className="mt-3 flex flex-wrap items-center gap-3">
        <label className="cursor-pointer rounded-xl border border-cyan-400/40 px-4 py-2 text-sm text-cyan-100 hover:bg-cyan-400/10">
          {labels.common.chooseFiles}
          <input className="hidden" type="file" multiple accept=".log,.txt,.csv,.json,.jsonl" onChange={(event) => setFiles(Array.from(event.target.files ?? []).map((file) => file.name))} />
        </label>
        <span className="text-sm text-slate-400">{files.length ? `${labels.common.selectedFiles}: ${files.join(", ")}` : labels.common.localOnly}</span>
      </div>
    </section>
    <SearchFilterBar search={search} setSearch={setSearch} filter={filter} setFilter={setFilter} options={["All", "Critical", "High", "Medium", "Linux Auth", "Cloudflare", "FortiGate", "Windows Event", "Cisco IOS"]} labels={labels} />
    {rows.length ? <div className="overflow-hidden rounded-2xl border border-white/10"><table className="w-full min-w-[900px] text-left text-sm"><thead className="bg-white/[0.05] text-xs uppercase tracking-[0.16em] text-slate-400"><tr><th className="p-3">{labels.fields.time}</th><th>{labels.fields.vendor}</th><th>{labels.fields.host}</th><th>{labels.fields.user}</th><th>{labels.fields.sourceIp}</th><th>{labels.fields.severity}</th><th>{labels.fields.rawLog}</th></tr></thead><tbody>{rows.map((row) => <tr key={row.id} className="border-t border-white/10"><td className="p-3 font-mono text-xs text-slate-300">{row.timestamp}</td><td>{row.vendor}</td><td>{row.host}</td><td>{row.user}</td><td className="font-mono text-cyan-200">{row.sourceIp}</td><td><Pill className={severityClass[row.severity]}>{labels.severity[row.severity]}</Pill></td><td className="max-w-xl truncate text-slate-300">{row.raw}</td></tr>)}</tbody></table></div> : <EmptyState message={labels.common.noData} />}
  </div>;
}

function AlertsModule({ labels, language }: { labels: Copy; language: Language }) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("All");
  const rows = seedAlerts.filter((row) => (filter === "All" || row.severity === filter || row.status === filter) && matchesQuery([text(row.rule, language), row.sourceIp, row.asset, row.mitre, text(row.evidence, language)], search));
  return <div className="space-y-5">
    <div className="grid gap-4 md:grid-cols-4"><MetricCard label={labels.severity.Critical} value={seedAlerts.filter((a) => a.severity === "Critical").length} /><MetricCard label={labels.severity.High} value={seedAlerts.filter((a) => a.severity === "High").length} /><MetricCard label={labels.fields.confidence} value="82%" /><MetricCard label={labels.status.Investigating} value={seedAlerts.filter((a) => a.status === "Investigating").length} /></div>
    <SearchFilterBar search={search} setSearch={setSearch} filter={filter} setFilter={setFilter} options={["All", "Critical", "High", "Medium", "New", "Acknowledged", "Investigating", "Review"]} labels={labels} />
    {rows.length ? <div className="grid gap-4">{rows.map((row) => <article key={row.id} className="rounded-2xl border border-white/10 bg-white/[0.04] p-4"><div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between"><div><div className="flex flex-wrap items-center gap-2"><Pill className={severityClass[row.severity]}>{labels.severity[row.severity]}</Pill><Pill className={statusClass[row.status]}>{labels.status[row.status]}</Pill><span className="font-mono text-xs text-cyan-200">{row.id}</span></div><h2 className="mt-3 text-lg font-semibold text-white">{text(row.rule, language)}</h2><p className="mt-1 text-sm text-slate-300">{text(row.evidence, language)}</p></div><div className="grid gap-2 text-sm text-slate-300 sm:grid-cols-2 lg:min-w-96"><span>{labels.fields.sourceIp}: <b className="font-mono text-cyan-100">{row.sourceIp}</b></span><span>{labels.fields.asset}: {row.asset}</span><span>{labels.fields.mitre}: {row.mitre}</span><span>{labels.fields.confidence}: {row.confidence}%</span></div></div></article>)}</div> : <EmptyState message={labels.common.noData} />}
  </div>;
}

function IncidentsModule({ labels, language }: { labels: Copy; language: Language }) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("All");
  const [selectedId, setSelectedId] = useState(seedIncidents[0]?.id ?? "");
  const rows = seedIncidents.filter((row) => (filter === "All" || row.severity === filter || row.status === filter) && matchesQuery([row.id, text(row.title, language), row.owner, row.assets, text(row.rca, language)], search));
  const selected = rows.find((row) => row.id === selectedId) ?? rows[0];
  return <div className="space-y-5">
    <SearchFilterBar search={search} setSearch={setSearch} filter={filter} setFilter={setFilter} options={["All", "Critical", "High", "Investigating", "Contained", "Resolved"]} labels={labels} />
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_420px]">
      <div className="space-y-3">{rows.length ? rows.map((row) => <button key={row.id} type="button" onClick={() => setSelectedId(row.id)} className={`w-full rounded-2xl border p-4 text-left transition ${selected?.id === row.id ? "border-cyan-400 bg-cyan-400/10" : "border-white/10 bg-white/[0.04] hover:border-cyan-400/50"}`}><div className="flex flex-wrap items-center justify-between gap-2"><span className="font-mono text-xs text-cyan-200">{row.id}</span><Pill className={severityClass[row.severity]}>{labels.severity[row.severity]}</Pill></div><h2 className="mt-2 font-semibold text-white">{text(row.title, language)}</h2><p className="mt-1 text-sm text-slate-400">{labels.fields.owner}: {row.owner} · {labels.fields.alerts}: {row.alerts}</p></button>) : <EmptyState message={labels.common.noData} />}</div>
      {selected && <aside className="rounded-2xl border border-white/10 bg-white/[0.04] p-5"><div className="flex items-center justify-between gap-3"><h2 className="text-lg font-semibold text-white">{labels.common.details}</h2><Pill className={statusClass[selected.status]}>{labels.status[selected.status]}</Pill></div><dl className="mt-4 space-y-3 text-sm"><div><dt className="text-cyan-200">{labels.fields.rca}</dt><dd className="text-slate-300">{text(selected.rca, language)}</dd></div><div><dt className="text-cyan-200">{labels.fields.impact}</dt><dd className="text-slate-300">{text(selected.impact, language)}</dd></div><div><dt className="text-cyan-200">{labels.fields.fix}</dt><dd className="text-slate-300">{text(selected.fix, language)}</dd></div></dl><div className="mt-5"><p className="text-sm font-semibold text-white">{labels.fields.timeline}</p><ol className="mt-2 space-y-2">{selected.timeline.map((item, index) => <li key={index} className="rounded-xl border border-white/10 bg-black/20 p-3 text-sm text-slate-300">{text(item, language)}</li>)}</ol></div></aside>}
    </div>
  </div>;
}

function ThreatIntelModule({ labels, language }: { labels: Copy; language: Language }) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("All");
  const rows = seedIocs.filter((row) => (filter === "All" || row.type === filter || row.status === filter) && matchesQuery([row.indicator, row.type, row.source, text(row.note, language)], search));
  return <TableCard labels={labels} rows={rows} empty={labels.common.noData} columns={[labels.fields.indicator, labels.fields.type, labels.fields.confidence, labels.fields.source, labels.fields.lastSeen, labels.fields.status, labels.fields.notes]} render={(row: IocRow) => [row.indicator, row.type, `${row.confidence}%`, row.source, row.lastSeen, <Pill key="s" className={statusClass[row.status]}>{labels.status[row.status]}</Pill>, text(row.note, language)]} before={<SearchFilterBar search={search} setSearch={setSearch} filter={filter} setFilter={setFilter} options={["All", "IP", "Domain", "Hash", "Active", "Review", "Watch"]} labels={labels} />} />;
}

function MitreModule({ labels, language }: { labels: Copy; language: Language }) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("All");
  const rows = seedTechniques.filter((row) => (filter === "All" || row.severity === filter || text(row.tactic, language) === filter) && matchesQuery([row.technique, text(row.name, language), text(row.tactic, language), text(row.action, language)], search));
  return <div className="space-y-5"><SearchFilterBar search={search} setSearch={setSearch} filter={filter} setFilter={setFilter} options={["All", "Critical", "High", "Medium", "Initial Access", "Credential Access", "Discovery", "Lateral Movement"]} labels={labels} /><div className="grid gap-4 md:grid-cols-2">{rows.length ? rows.map((row) => <article key={row.technique} className="rounded-2xl border border-white/10 bg-white/[0.04] p-4"><div className="flex items-center justify-between"><span className="font-mono text-cyan-200">{row.technique}</span><Pill className={severityClass[row.severity]}>{labels.severity[row.severity]}</Pill></div><h2 className="mt-3 text-lg font-semibold text-white">{text(row.name, language)}</h2><p className="mt-1 text-sm text-slate-400">{labels.fields.tactic}: {text(row.tactic, language)} · {labels.fields.evidence}: {row.evidence}</p><p className="mt-3 text-sm text-slate-300">{text(row.action, language)}</p></article>) : <EmptyState message={labels.common.noData} />}</div></div>;
}

function ReportsModule({ labels, language }: { labels: Copy; language: Language }) {
  const [search, setSearch] = useState("");
  const rows = seedReports.filter((row) => matchesQuery([row.id, row.caseId, text(row.title, language), row.type, row.owner], search));
  const payload = { generatedAt: new Date().toISOString(), reports: seedReports, incidents: seedIncidents, alerts: seedAlerts };
  const csv = ["id,caseId,title,type,owner,updated,status", ...seedReports.map((r) => [r.id, r.caseId, text(r.title, language), r.type, r.owner, r.updated, r.status].map((v) => `"${v}"`).join(","))].join("\n");
  const markdown = seedReports.map((r) => `## ${r.id} - ${text(r.title, language)}\n- Case: ${r.caseId}\n- Type: ${r.type}\n- Owner: ${r.owner}\n- Status: ${labels.status[r.status]}\n`).join("\n");
  return <div className="space-y-5"><div className="flex flex-wrap gap-3 rounded-2xl border border-white/10 bg-white/[0.04] p-4"><button className="rounded-xl bg-cyan-400 px-4 py-2 text-sm font-semibold text-slate-950" onClick={() => downloadFile("soc-report.json", JSON.stringify(payload, null, 2), "application/json")}>{labels.common.exportJson}</button><button className="rounded-xl border border-white/10 px-4 py-2 text-sm text-white" onClick={() => downloadFile("soc-report.csv", csv, "text/csv")}>{labels.common.exportCsv}</button><button className="rounded-xl border border-white/10 px-4 py-2 text-sm text-white" onClick={() => downloadFile("soc-report.md", markdown, "text/markdown")}>{labels.common.exportMarkdown}</button></div><SearchFilterBar search={search} setSearch={setSearch} filter="All" setFilter={() => undefined} options={["All"]} labels={labels} />{rows.length ? <div className="grid gap-4">{rows.map((row) => <article key={row.id} className="rounded-2xl border border-white/10 bg-white/[0.04] p-4"><div className="flex flex-wrap items-center justify-between gap-3"><div><span className="font-mono text-xs text-cyan-200">{row.id}</span><h2 className="mt-1 font-semibold text-white">{text(row.title, language)}</h2><p className="text-sm text-slate-400">{row.caseId} · {row.type}</p></div><Pill className={statusClass[row.status]}>{labels.status[row.status]}</Pill></div></article>)}</div> : <EmptyState message={labels.common.noData} />}</div>;
}

function RulesModule({ labels, language }: { labels: Copy; language: Language }) {
  const [rules, setRules] = useState<RuleRow[]>(() => loadLocal("soc_workspace_rules", seedRules));
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("All");
  const [name, setName] = useState("");
  const [pattern, setPattern] = useState("");
  useEffect(() => { window.localStorage.setItem("soc_workspace_rules", JSON.stringify(rules)); }, [rules]);
  const rows = rules.filter((row) => (filter === "All" || row.severity === filter || row.source === filter) && matchesQuery([row.id, text(row.name, language), row.pattern, row.source, row.mitre], search));
  const addRule = () => { if (!name.trim() || !pattern.trim()) return; setRules((prev) => [{ id: `RULE-CUSTOM-${Date.now().toString().slice(-5)}`, name: { en: name, th: name }, pattern, severity: "Medium", source: "Custom", mitre: "T0000", enabled: true, recommendation: { en: "Review custom match and tune threshold.", th: "ตรวจ match ที่กำหนดเองและปรับ threshold" } }, ...prev]); setName(""); setPattern(""); };
  return <div className="space-y-5"><div className="grid gap-3 rounded-2xl border border-white/10 bg-white/[0.04] p-4 md:grid-cols-[1fr_1fr_auto]"><input value={name} onChange={(e) => setName(e.target.value)} placeholder={labels.fields.rule} className="rounded-xl border border-white/10 bg-black/30 px-4 py-3 text-sm text-white outline-none" /><input value={pattern} onChange={(e) => setPattern(e.target.value)} placeholder={labels.fields.pattern} className="rounded-xl border border-white/10 bg-black/30 px-4 py-3 text-sm text-white outline-none" /><button onClick={addRule} className="rounded-xl bg-cyan-400 px-4 py-3 text-sm font-semibold text-slate-950">{labels.common.add}</button></div><SearchFilterBar search={search} setSearch={setSearch} filter={filter} setFilter={setFilter} options={["All", "Critical", "High", "Medium", "Low", "Linux Auth", "WAF / Web", "Cisco IOS", "Firewall", "Custom"]} labels={labels} />{rows.length ? <div className="grid gap-3">{rows.map((row) => <article key={row.id} className="rounded-2xl border border-white/10 bg-white/[0.04] p-4"><div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between"><div><div className="flex flex-wrap items-center gap-2"><Pill className={severityClass[row.severity]}>{labels.severity[row.severity]}</Pill><span className="font-mono text-xs text-cyan-200">{row.id}</span></div><h2 className="mt-2 font-semibold text-white">{text(row.name, language)}</h2><p className="text-sm text-slate-400">{labels.fields.pattern}: <code>{row.pattern}</code> · {labels.fields.mitre}: {row.mitre}</p></div><div className="flex gap-2"><button className="rounded-xl border border-white/10 px-3 py-2 text-sm" onClick={() => setRules((prev) => prev.map((item) => item.id === row.id ? { ...item, enabled: !item.enabled } : item))}>{row.enabled ? labels.fields.enabled : labels.status.Closed}</button><button className="rounded-xl border border-red-500/30 px-3 py-2 text-sm text-red-200" onClick={() => setRules((prev) => prev.filter((item) => item.id !== row.id))}>{labels.common.delete}</button></div></div></article>)}</div> : <EmptyState message={labels.common.noData} />}</div>;
}

function AssetsModule({ labels, language }: { labels: Copy; language: Language }) {
  const [assets, setAssets] = useState<AssetRow[]>(() => loadLocal("soc_workspace_assets", seedAssets));
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("All");
  const [assetName, setAssetName] = useState("");
  useEffect(() => { window.localStorage.setItem("soc_workspace_assets", JSON.stringify(assets)); }, [assets]);
  const rows = assets.filter((row) => (filter === "All" || row.criticality === filter || row.status === filter || row.type === filter) && matchesQuery([row.name, row.type, row.owner, row.location, text(row.notes, language)], search));
  const addAsset = () => { if (!assetName.trim()) return; setAssets((prev) => [{ id: `AST-${Date.now().toString().slice(-4)}`, name: assetName, type: "Custom", owner: "Unassigned", location: "Unknown", criticality: "Medium", status: "Review", lastSeen: new Date().toISOString().slice(0, 16).replace("T", " "), notes: { en: "New asset added from workspace.", th: "เพิ่มสินทรัพย์ใหม่จาก workspace" } }, ...prev]); setAssetName(""); };
  return <div className="space-y-5"><div className="flex gap-3 rounded-2xl border border-white/10 bg-white/[0.04] p-4"><input value={assetName} onChange={(e) => setAssetName(e.target.value)} placeholder={labels.fields.asset} className="flex-1 rounded-xl border border-white/10 bg-black/30 px-4 py-3 text-sm text-white outline-none" /><button onClick={addAsset} className="rounded-xl bg-cyan-400 px-4 py-3 text-sm font-semibold text-slate-950">{labels.common.add}</button></div><SearchFilterBar search={search} setSearch={setSearch} filter={filter} setFilter={setFilter} options={["All", "Critical", "High", "Medium", "Active", "Watch", "Review", "Web App", "Domain Controller", "Core Switch"]} labels={labels} />{rows.length ? <div className="grid gap-4 md:grid-cols-2">{rows.map((row) => <article key={row.id} className="rounded-2xl border border-white/10 bg-white/[0.04] p-4"><div className="flex items-center justify-between"><span className="font-mono text-xs text-cyan-200">{row.id}</span><Pill className={severityClass[row.criticality]}>{labels.severity[row.criticality]}</Pill></div><h2 className="mt-2 font-semibold text-white">{row.name}</h2><p className="text-sm text-slate-400">{row.type} · {row.owner} · {row.location}</p><p className="mt-3 text-sm text-slate-300">{text(row.notes, language)}</p><div className="mt-3 flex items-center justify-between"><Pill className={statusClass[row.status]}>{labels.status[row.status]}</Pill><button className="text-sm text-red-200" onClick={() => setAssets((prev) => prev.filter((item) => item.id !== row.id))}>{labels.common.delete}</button></div></article>)}</div> : <EmptyState message={labels.common.noData} />}</div>;
}

function UsersModule({ labels, language }: { labels: Copy; language: Language }) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("All");
  const rows = seedUsers.filter((row) => (filter === "All" || row.role === filter || row.status === filter) && matchesQuery([row.name, row.email, row.role, row.permission, text(row.notes, language)], search));
  return <TableCard labels={labels} rows={rows} empty={labels.common.noData} columns={[labels.fields.user, labels.fields.email, labels.fields.role, labels.fields.permission, labels.fields.status, labels.fields.lastActive, labels.fields.notes]} render={(row: UserRow) => [row.name, row.email, row.role, row.permission, <Pill key="s" className={statusClass[row.status]}>{labels.status[row.status]}</Pill>, row.lastActive, text(row.notes, language)]} before={<SearchFilterBar search={search} setSearch={setSearch} filter={filter} setFilter={setFilter} options={["All", "SOC Analyst", "Incident Responder", "Viewer", "Active", "Review"]} labels={labels} />} />;
}

function SettingsModule({ labels, language, theme, setLanguage, setTheme }: { labels: Copy; language: Language; theme: UXTheme; setLanguage: (value: Language) => void; setTheme: (value: UXTheme) => void }) {
  const [webhook, setWebhook] = useState(() => typeof window === "undefined" ? "" : window.localStorage.getItem("soc_webhook_url") ?? "");
  const [retention, setRetention] = useState(() => typeof window === "undefined" ? "30" : window.localStorage.getItem("soc_retention_days") ?? "30");
  const [masking, setMasking] = useState(() => typeof window === "undefined" ? true : window.localStorage.getItem("soc_masking") !== "0");
  useEffect(() => { window.localStorage.setItem("soc_webhook_url", webhook); }, [webhook]);
  useEffect(() => { window.localStorage.setItem("soc_retention_days", retention); }, [retention]);
  useEffect(() => { window.localStorage.setItem("soc_masking", masking ? "1" : "0"); }, [masking]);
  return <div className="grid gap-5 lg:grid-cols-2"><section className="rounded-2xl border border-white/10 bg-white/[0.04] p-5"><h2 className="font-semibold text-white">{labels.common.language}</h2><div className="mt-3 flex gap-2"><button onClick={() => setLanguage("th")} className={`rounded-xl px-4 py-2 text-sm ${language === "th" ? "bg-cyan-400 text-slate-950" : "border border-white/10"}`}>{labels.common.thai}</button><button onClick={() => setLanguage("en")} className={`rounded-xl px-4 py-2 text-sm ${language === "en" ? "bg-cyan-400 text-slate-950" : "border border-white/10"}`}>{labels.common.english}</button></div><h2 className="mt-6 font-semibold text-white">{labels.common.theme}</h2><div className="mt-3 grid gap-2">{(["sentinel", "aurora", "daylight"] as UXTheme[]).map((item) => <button key={item} onClick={() => setTheme(item)} className={`rounded-xl border px-4 py-3 text-left ${theme === item ? "border-cyan-400 bg-cyan-400/10" : "border-white/10"}`}><b>{labels.themes[item].label}</b><p className="text-sm text-slate-400">{labels.themes[item].note}</p></button>)}</div></section><section className="rounded-2xl border border-white/10 bg-white/[0.04] p-5"><h2 className="font-semibold text-white">{labels.common.privacyNotice}</h2><label className="mt-4 block text-sm text-slate-300">{labels.fields.webhookUrl}<input value={webhook} onChange={(e) => setWebhook(e.target.value)} className="mt-2 w-full rounded-xl border border-white/10 bg-black/30 px-4 py-3 text-white outline-none" placeholder="https://hooks.example.com/soc" /></label><label className="mt-4 block text-sm text-slate-300">{labels.fields.retention}<input value={retention} onChange={(e) => setRetention(e.target.value)} className="mt-2 w-full rounded-xl border border-white/10 bg-black/30 px-4 py-3 text-white outline-none" /></label><label className="mt-4 flex items-center gap-3 text-sm text-slate-300"><input type="checkbox" checked={masking} onChange={(e) => setMasking(e.target.checked)} />{labels.fields.masking}</label></section></div>;
}

function TableCard<T>({ labels, before, rows, columns, render, empty }: { labels: Copy; before?: React.ReactNode; rows: T[]; columns: string[]; render: (row: T) => React.ReactNode[]; empty: string }) {
  return <div className="space-y-5">{before}{rows.length ? <div className="overflow-hidden rounded-2xl border border-white/10"><table className="w-full min-w-[820px] text-left text-sm"><thead className="bg-white/[0.05] text-xs uppercase tracking-[0.16em] text-slate-400"><tr>{columns.map((column) => <th key={column} className="p-3">{column}</th>)}</tr></thead><tbody>{rows.map((row, index) => <tr key={index} className="border-t border-white/10">{render(row).map((cell, cellIndex) => <td key={cellIndex} className="p-3 text-slate-300">{cell}</td>)}</tr>)}</tbody></table></div> : <EmptyState message={empty} />}</div>;
}

export default function OperationalWorkspace({ module }: { module: ModuleKey }) {
  const prefs = useWorkspacePreferences();
  const labels = copy[prefs.language];
  const content = useMemo(() => {
    switch (module) {
      case "logs": return <LogsModule labels={labels} language={prefs.language} />;
      case "alerts": return <AlertsModule labels={labels} language={prefs.language} />;
      case "incidents": return <IncidentsModule labels={labels} language={prefs.language} />;
      case "threat-intelligence": return <ThreatIntelModule labels={labels} language={prefs.language} />;
      case "mitre": return <MitreModule labels={labels} language={prefs.language} />;
      case "reports": return <ReportsModule labels={labels} language={prefs.language} />;
      case "rules": return <RulesModule labels={labels} language={prefs.language} />;
      case "assets": return <AssetsModule labels={labels} language={prefs.language} />;
      case "users": return <UsersModule labels={labels} language={prefs.language} />;
      case "settings": return <SettingsModule labels={labels} language={prefs.language} theme={prefs.theme} setLanguage={prefs.setLanguage} setTheme={prefs.setTheme} />;
      default: return null;
    }
  }, [module, labels, prefs.language, prefs.theme]);

  return (
    <WorkspaceLayout moduleKey={module}>
      {content}
    </WorkspaceLayout>
  );
}

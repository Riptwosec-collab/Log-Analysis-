"use client";

import { useEffect, useState } from "react";

type Language = "th" | "en";
type SeverityTone = "critical" | "high" | "medium" | "low" | "info";

type GuideCopy = {
  eyebrow: string;
  title: string;
  subtitle: string;
  workflowTitle: string;
  fieldsTitle: string;
  patternsTitle: string;
  vendorTitle: string;
  checklistTitle: string;
  cheatTitle: string;
  workflow: { title: string; body: string }[];
  fields: { key: string; meaning: string; example: string }[];
  patterns: { tone: SeverityTone; title: string; signal: string; action: string }[];
  vendors: { name: string; focus: string; fields: string }[];
  checklist: string[];
  cheat: { label: string; value: string }[];
  footer: string;
};

const copy: Record<Language, GuideCopy> = {
  th: {
    eyebrow: "คู่มือท้ายหน้า",
    title: "คู่มืออ่าน Log แบบ SOC Analyst",
    subtitle: "ใช้เป็นเช็กลิสต์อ่าน Log ตั้งแต่รับข้อมูลดิบ → แยกเหตุการณ์ → ประเมินความเสี่ยง → เขียน RCA / Report ให้หัวหน้าหรือทีม IT Security",
    workflowTitle: "ลำดับอ่าน Log ที่แนะนำ",
    fieldsTitle: "ฟิลด์สำคัญที่ต้องมองหา",
    patternsTitle: "สัญญาณผิดปกติที่พบบ่อย",
    vendorTitle: "อ่าน Log แยกตามแหล่งข้อมูล",
    checklistTitle: "Checklist ก่อนสรุป Incident",
    cheatTitle: "Cheat Sheet คำที่เจอบ่อย",
    workflow: [
      { title: "1. ระบุช่วงเวลา", body: "ดู timestamp ก่อนเสมอ แล้วจัดเรียงเหตุการณ์จากเก่าไปใหม่ เพื่อหาว่าอะไรเกิดก่อน อะไรเป็นผลตามมา" },
      { title: "2. หา Source และ Destination", body: "แยก source IP, destination IP, hostname, username, service และ port เพื่อรู้ว่าใครคุยกับใคร" },
      { title: "3. แยกประเภท Event", body: "จัดกลุ่มเป็น authentication, network, firewall, web, endpoint, cloud, DNS หรือ email เพื่อเลือกวิธีวิเคราะห์ที่ถูกต้อง" },
      { title: "4. ดูความถี่และ pattern", body: "เหตุการณ์เดียวอาจไม่ร้ายแรง แต่ถ้าเกิดซ้ำเร็ว ๆ เช่น login fail จำนวนมาก หรือ deny หลาย port อาจเป็น brute force / scanning" },
      { title: "5. ประเมิน severity", body: "ดูจาก asset สำคัญไหม, user เป็น admin ไหม, มี successful login หลัง failed login หรือไม่, และมี lateral movement หรือ privilege change หรือไม่" },
      { title: "6. จับคู่ MITRE ATT&CK", body: "Map พฤติกรรมกับ tactic/technique เช่น Credential Access, Initial Access, Discovery, Lateral Movement เพื่อสื่อสารกับทีมได้มาตรฐาน" },
      { title: "7. เก็บ Evidence", body: "บันทึก raw log line, timestamp, IP, user, host, rule matched และ screenshot/report export เพื่อใช้ทำ ticket หรือ RCA" },
      { title: "8. สรุป Action", body: "ระบุสิ่งที่ต้องทำทันที เช่น block IP, disable user, reset password, isolate endpoint, tune rule หรือ escalate ไปทีมที่เกี่ยวข้อง" },
    ],
    fields: [
      { key: "timestamp", meaning: "เวลาที่เกิดเหตุการณ์ ใช้สร้าง timeline", example: "2026-06-10T21:18:27Z" },
      { key: "src / source_ip", meaning: "ต้นทางของกิจกรรม ใช้ดูผู้โจมตีหรือเครื่องที่ผิดปกติ", example: "185.220.101.21" },
      { key: "dst / destination", meaning: "ปลายทางหรือ asset ที่ถูกเข้าถึง", example: "10.0.0.12:443" },
      { key: "user / account", meaning: "บัญชีที่เกี่ยวข้อง สำคัญมากถ้าเป็น admin หรือ service account", example: "admin, svc-backup" },
      { key: "action", meaning: "ผลลัพธ์ของ event เช่น allow, deny, block, success, failure", example: "deny / failed / allowed" },
      { key: "event_id / rule", meaning: "รหัสเหตุการณ์หรือกฎที่ match ใช้ค้นหา context เพิ่ม", example: "4625, SQLi, MACFLAP" },
      { key: "severity", meaning: "ระดับความสำคัญ ใช้จัดลำดับการตอบสนอง", example: "Critical / High / Medium / Low" },
      { key: "message / raw", meaning: "ข้อความดิบที่ต้องอ่านประกอบ ไม่ควรดูแค่ summary", example: "Failed password for root from ..." },
    ],
    patterns: [
      { tone: "critical", title: "Login fail หลายครั้งแล้ว success", signal: "Failed password ซ้ำ ๆ ตามด้วย Accepted password หรือ privileged event", action: "ตรวจว่า account ถูกยึดหรือไม่ รีเซ็ตรหัสผ่าน เปิด MFA และตรวจ session ย้อนหลัง" },
      { tone: "high", title: "Port scanning / probing", signal: "IP เดียวถูก deny หลาย port เช่น 22, 80, 443, 445, 3389 ในเวลาสั้น", action: "Block source IP, ตรวจ firewall rule, เช็กว่ามี service เปิดผิดหรือไม่" },
      { tone: "high", title: "Web attack pattern", signal: "URL มี UNION SELECT, ../, <script>, cmd=, shell, wp-admin brute force", action: "ตรวจ WAF, web access log, response code และไฟล์ที่ถูกเข้าถึง" },
      { tone: "medium", title: "Network loop / MAC flapping", signal: "%SW_MATM-4-MACFLAP_NOTIF หรือ MAC เดิมย้าย port เร็วผิดปกติ", action: "ตรวจ loop, trunk, unmanaged switch, EtherChannel, STP และ port ที่เกี่ยวข้อง" },
      { tone: "medium", title: "DAI / DHCP Snooping deny", signal: "Invalid ARP, DHCP snooping deny, IP/MAC mismatch", action: "ตรวจ ARP spoofing, static binding, DHCP binding และเครื่องปลายทาง" },
      { tone: "info", title: "Noise / false positive", signal: "Event เกิดน้อย ไม่กระทบ asset สำคัญ และไม่มี correlation", action: "บันทึกไว้ ปรับ threshold หรือ suppress เฉพาะ source ที่เชื่อถือได้" },
    ],
    vendors: [
      { name: "Linux Auth / SSH", focus: "ดู Failed/Accepted password, invalid user, sudo, session opened", fields: "user, source IP, port, sshd PID, hostname" },
      { name: "Windows Event", focus: "ดู 4625 failed logon, 4624 success, 4672 privilege, 4720 user created", fields: "Event ID, Account Name, Logon Type, Source Network Address" },
      { name: "Firewall / FortiGate / Palo Alto", focus: "ดู action allow/deny, policy, src/dst, port, application, threat name", fields: "srcip, dstip, dstport, action, policyid, app" },
      { name: "Web / Nginx / Apache / Cloudflare", focus: "ดู request path, method, status code, user-agent, WAF action", fields: "client IP, URI, status, host, referrer, WAFAction" },
      { name: "Cisco / Switch / Meraki", focus: "ดู interface up/down, MAC flap, STP block, DAI deny, 802.1X fail", fields: "interface, VLAN, MAC, event code, device name" },
      { name: "Cloud / AWS / M365 / Entra ID", focus: "ดู sign-in risk, impossible travel, API calls, IAM changes, MFA failure", fields: "user, source IP, app, riskLevel, operation, resource" },
    ],
    checklist: [
      "มี timestamp ครบและ timezone ถูกต้องหรือไม่",
      "Source IP / user / host / asset ถูกระบุครบหรือไม่",
      "มีเหตุการณ์ก่อนหน้าและหลังหน้าที่เกี่ยวข้องหรือไม่",
      "มี successful action หลังจาก failed/rejected action หรือไม่",
      "asset ที่กระทบเป็น critical system หรือไม่",
      "มี user admin, service account หรือ privileged event เกี่ยวข้องหรือไม่",
      "มี evidence ดิบพอสำหรับแนบ ticket หรือ report หรือไม่",
      "มี action ที่ทำแล้ว / ต้องทำต่อ / owner ชัดเจนหรือไม่",
    ],
    cheat: [
      { label: "Brute force", value: "พยายาม login จำนวนมากในเวลาสั้น" },
      { label: "Reconnaissance", value: "การสแกนหรือสำรวจระบบก่อนโจมตี" },
      { label: "Lateral movement", value: "ขยับจากเครื่องหนึ่งไปอีกเครื่องในเครือข่าย" },
      { label: "Privilege escalation", value: "ยกระดับสิทธิ์จาก user ปกติเป็นสิทธิ์สูง" },
      { label: "IOC", value: "ตัวบ่งชี้ภัย เช่น IP, domain, hash, URL" },
      { label: "False positive", value: "แจ้งเตือนที่ดูผิดปกติแต่ไม่ใช่ภัยจริง" },
    ],
    footer: "คำแนะนำ: ก่อนนำ Log จริงไปแชร์หรือส่งให้ AI ควร mask token, password, email, customer name, public IP ภายในองค์กร และ hostname ที่เป็นข้อมูลลับเสมอ",
  },
  en: {
    eyebrow: "Bottom guide",
    title: "SOC Analyst Log Reading Guide",
    subtitle: "Use this checklist to move from raw evidence → event grouping → risk assessment → RCA/report writing for IT or security teams.",
    workflowTitle: "Recommended log review workflow",
    fieldsTitle: "Key fields to inspect",
    patternsTitle: "Common suspicious signals",
    vendorTitle: "How to read logs by source",
    checklistTitle: "Incident summary checklist",
    cheatTitle: "Common terms cheat sheet",
    workflow: [
      { title: "1. Confirm the time window", body: "Start with timestamps and sort events from oldest to newest so you can see cause, sequence, and follow-up activity." },
      { title: "2. Identify source and destination", body: "Separate source IP, destination IP, host, user, service, and port to understand who connected to what." },
      { title: "3. Classify the event type", body: "Group logs into authentication, network, firewall, web, endpoint, cloud, DNS, or email so you can analyze them correctly." },
      { title: "4. Look for frequency and patterns", body: "A single event may be harmless, but repeated failed logins or denies across many ports can indicate brute force or scanning." },
      { title: "5. Assess severity", body: "Check asset criticality, admin users, successful actions after failures, lateral movement, and privilege changes." },
      { title: "6. Map to MITRE ATT&CK", body: "Map behavior to tactics and techniques such as Credential Access, Initial Access, Discovery, or Lateral Movement." },
      { title: "7. Preserve evidence", body: "Keep raw log lines, timestamps, IPs, users, hosts, matched rules, screenshots, and exported reports for tickets or RCA." },
      { title: "8. Define response actions", body: "Write immediate actions such as block IP, disable user, reset password, isolate endpoint, tune rule, or escalate to the right team." },
    ],
    fields: [
      { key: "timestamp", meaning: "When the event happened; used to build the timeline", example: "2026-06-10T21:18:27Z" },
      { key: "src / source_ip", meaning: "Origin of the activity; potential attacker or suspicious endpoint", example: "185.220.101.21" },
      { key: "dst / destination", meaning: "Target asset or service being accessed", example: "10.0.0.12:443" },
      { key: "user / account", meaning: "Account involved; high priority if admin or service account", example: "admin, svc-backup" },
      { key: "action", meaning: "Outcome of the event such as allow, deny, block, success, or failure", example: "deny / failed / allowed" },
      { key: "event_id / rule", meaning: "Event identifier or matched detection rule", example: "4625, SQLi, MACFLAP" },
      { key: "severity", meaning: "Priority level used to decide response order", example: "Critical / High / Medium / Low" },
      { key: "message / raw", meaning: "Original message; always read it, not only the summary", example: "Failed password for root from ..." },
    ],
    patterns: [
      { tone: "critical", title: "Repeated login failures followed by success", signal: "Many failed password events followed by accepted password or privilege events", action: "Check account compromise, reset credentials, enforce MFA, and review sessions." },
      { tone: "high", title: "Port scanning / probing", signal: "One source IP denied across ports like 22, 80, 443, 445, 3389 in a short window", action: "Block the source, review firewall exposure, and check unexpected open services." },
      { tone: "high", title: "Web attack pattern", signal: "URL includes UNION SELECT, ../, <script>, cmd=, shell, or wp-admin brute force", action: "Review WAF, access logs, response codes, and touched files." },
      { tone: "medium", title: "Network loop / MAC flapping", signal: "%SW_MATM-4-MACFLAP_NOTIF or one MAC moving rapidly between ports", action: "Check loops, trunks, unmanaged switches, EtherChannel, STP, and affected ports." },
      { tone: "medium", title: "DAI / DHCP Snooping deny", signal: "Invalid ARP, DHCP snooping deny, or IP/MAC mismatch", action: "Review ARP spoofing risk, static bindings, DHCP bindings, and endpoint state." },
      { tone: "info", title: "Noise / false positive", signal: "Low-frequency event with no critical asset impact and no correlation", action: "Document, tune threshold, or suppress only trusted sources." },
    ],
    vendors: [
      { name: "Linux Auth / SSH", focus: "Check Failed/Accepted password, invalid user, sudo, session opened", fields: "user, source IP, port, sshd PID, hostname" },
      { name: "Windows Event", focus: "Check 4625 failed logon, 4624 success, 4672 privilege, 4720 user created", fields: "Event ID, Account Name, Logon Type, Source Network Address" },
      { name: "Firewall / FortiGate / Palo Alto", focus: "Check allow/deny action, policy, src/dst, port, application, threat name", fields: "srcip, dstip, dstport, action, policyid, app" },
      { name: "Web / Nginx / Apache / Cloudflare", focus: "Check request path, method, status code, user-agent, and WAF action", fields: "client IP, URI, status, host, referrer, WAFAction" },
      { name: "Cisco / Switch / Meraki", focus: "Check interface up/down, MAC flap, STP block, DAI deny, 802.1X fail", fields: "interface, VLAN, MAC, event code, device name" },
      { name: "Cloud / AWS / M365 / Entra ID", focus: "Check sign-in risk, impossible travel, API calls, IAM changes, MFA failure", fields: "user, source IP, app, riskLevel, operation, resource" },
    ],
    checklist: [
      "Are timestamps complete and is the timezone correct?",
      "Are source IP, user, host, and asset identified?",
      "Are there relevant before/after events around the finding?",
      "Is there a successful action after repeated failed or rejected actions?",
      "Is the impacted asset a critical system?",
      "Are admin users, service accounts, or privileged events involved?",
      "Is there enough raw evidence for a ticket or report?",
      "Are completed actions, next actions, and owners clear?",
    ],
    cheat: [
      { label: "Brute force", value: "Many login attempts in a short time window" },
      { label: "Reconnaissance", value: "Scanning or discovery before an attack" },
      { label: "Lateral movement", value: "Moving from one host to another inside the network" },
      { label: "Privilege escalation", value: "Gaining higher permissions from a lower-privileged account" },
      { label: "IOC", value: "Indicator such as IP, domain, hash, or URL" },
      { label: "False positive", value: "Suspicious-looking alert that is not a real threat" },
    ],
    footer: "Tip: Before sharing real logs or sending them to AI, mask tokens, passwords, emails, customer names, internal public IP context, and confidential hostnames.",
  },
};

const toneClass: Record<SeverityTone, string> = {
  critical: "border-red-400/40 bg-red-500/10 text-red-100",
  high: "border-orange-400/40 bg-orange-500/10 text-orange-100",
  medium: "border-amber-400/40 bg-amber-500/10 text-amber-100",
  low: "border-emerald-400/40 bg-emerald-500/10 text-emerald-100",
  info: "border-cyan-400/40 bg-cyan-500/10 text-cyan-100",
};

function getSavedLanguage(): Language {
  if (typeof window === "undefined") return "th";
  const saved = window.localStorage.getItem("soc_language");
  return saved === "en" ? "en" : "th";
}

export default function LogReadingGuide() {
  const [language, setLanguage] = useState<Language>("th");

  useEffect(() => {
    const sync = () => setLanguage(getSavedLanguage());
    sync();
    const interval = window.setInterval(sync, 400);
    window.addEventListener("storage", sync);
    return () => {
      window.clearInterval(interval);
      window.removeEventListener("storage", sync);
    };
  }, []);

  const labels = copy[language];

  return (
    <section id="log-reading-guide" data-i18n-ignore className="border-t border-white/10 bg-[var(--bg-primary)] px-4 py-10 text-[var(--text-primary)] sm:px-6 lg:px-8">
      <div className="mx-auto max-w-7xl space-y-6 rounded-[2rem] border border-white/10 bg-white/[0.05] p-5 shadow-2xl shadow-black/20 backdrop-blur-xl sm:p-7">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <p className="text-xs font-bold uppercase tracking-[0.24em] text-cyan-300">{labels.eyebrow}</p>
            <h2 className="mt-2 text-3xl font-semibold text-white">{labels.title}</h2>
            <p className="mt-3 max-w-4xl text-sm leading-6 text-slate-300">{labels.subtitle}</p>
          </div>
          <a href="#top" className="w-fit rounded-2xl border border-cyan-400/30 px-4 py-2 text-sm font-semibold text-cyan-100 transition hover:bg-cyan-400/10">
            {language === "th" ? "กลับขึ้นด้านบน" : "Back to top"}
          </a>
        </div>

        <div className="grid gap-4 lg:grid-cols-4">
          {labels.workflow.map((item) => (
            <article key={item.title} className="rounded-2xl border border-white/10 bg-black/20 p-4">
              <h3 className="text-sm font-semibold text-cyan-100">{item.title}</h3>
              <p className="mt-2 text-sm leading-6 text-slate-300">{item.body}</p>
            </article>
          ))}
        </div>

        <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_420px]">
          <section className="rounded-2xl border border-white/10 bg-black/20 p-5">
            <h3 className="text-xl font-semibold text-white">{labels.fieldsTitle}</h3>
            <div className="mt-4 overflow-hidden rounded-2xl border border-white/10">
              <table className="w-full min-w-[760px] text-left text-sm">
                <thead className="bg-white/[0.05] text-xs uppercase tracking-[0.16em] text-slate-400">
                  <tr>
                    <th className="p-3">Field</th>
                    <th>{language === "th" ? "ความหมาย" : "Meaning"}</th>
                    <th>{language === "th" ? "ตัวอย่าง" : "Example"}</th>
                  </tr>
                </thead>
                <tbody>
                  {labels.fields.map((field) => (
                    <tr key={field.key} className="border-t border-white/10">
                      <td className="p-3 font-mono text-cyan-200">{field.key}</td>
                      <td className="text-slate-300">{field.meaning}</td>
                      <td className="font-mono text-xs text-slate-400">{field.example}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="rounded-2xl border border-white/10 bg-black/20 p-5">
            <h3 className="text-xl font-semibold text-white">{labels.checklistTitle}</h3>
            <ol className="mt-4 space-y-3">
              {labels.checklist.map((item, index) => (
                <li key={item} className="flex gap-3 rounded-xl border border-white/10 bg-white/[0.04] p-3 text-sm leading-6 text-slate-300">
                  <span className="font-mono text-cyan-300">{String(index + 1).padStart(2, "0")}</span>
                  <span>{item}</span>
                </li>
              ))}
            </ol>
          </section>
        </div>

        <section className="rounded-2xl border border-white/10 bg-black/20 p-5">
          <h3 className="text-xl font-semibold text-white">{labels.patternsTitle}</h3>
          <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {labels.patterns.map((pattern) => (
              <article key={pattern.title} className={`rounded-2xl border p-4 ${toneClass[pattern.tone]}`}>
                <h4 className="font-semibold">{pattern.title}</h4>
                <p className="mt-3 text-sm leading-6"><b>{language === "th" ? "สัญญาณ:" : "Signal:"}</b> {pattern.signal}</p>
                <p className="mt-2 text-sm leading-6"><b>{language === "th" ? "ควรทำ:" : "Action:"}</b> {pattern.action}</p>
              </article>
            ))}
          </div>
        </section>

        <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_420px]">
          <section className="rounded-2xl border border-white/10 bg-black/20 p-5">
            <h3 className="text-xl font-semibold text-white">{labels.vendorTitle}</h3>
            <div className="mt-4 grid gap-3">
              {labels.vendors.map((vendor) => (
                <article key={vendor.name} className="rounded-2xl border border-white/10 bg-white/[0.04] p-4">
                  <div className="flex flex-col gap-2 lg:flex-row lg:items-start lg:justify-between">
                    <div>
                      <h4 className="font-semibold text-cyan-100">{vendor.name}</h4>
                      <p className="mt-1 text-sm leading-6 text-slate-300">{vendor.focus}</p>
                    </div>
                    <p className="rounded-xl border border-white/10 bg-black/25 p-3 font-mono text-xs leading-5 text-slate-400 lg:max-w-sm">{vendor.fields}</p>
                  </div>
                </article>
              ))}
            </div>
          </section>

          <section className="rounded-2xl border border-white/10 bg-black/20 p-5">
            <h3 className="text-xl font-semibold text-white">{labels.cheatTitle}</h3>
            <div className="mt-4 space-y-3">
              {labels.cheat.map((item) => (
                <div key={item.label} className="rounded-xl border border-white/10 bg-white/[0.04] p-3">
                  <p className="font-mono text-sm text-cyan-200">{item.label}</p>
                  <p className="mt-1 text-sm leading-6 text-slate-300">{item.value}</p>
                </div>
              ))}
            </div>
          </section>
        </div>

        <p className="rounded-2xl border border-cyan-400/25 bg-cyan-400/10 p-4 text-sm leading-6 text-cyan-50">{labels.footer}</p>
      </div>
    </section>
  );
}

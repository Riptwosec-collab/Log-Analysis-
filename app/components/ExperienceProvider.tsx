"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

type Language = "th" | "en";
type UXTheme = "sentinel" | "aurora" | "daylight";

const THEME_CLASSES = ["theme-soc-sentinel", "theme-soc-aurora", "theme-soc-daylight"];
const UX_PANEL_STORAGE_KEY = "soc_ux_panel_open";

const navSectionIds = [
  "dashboard",
  "logs",
  "alerts",
  "incidents",
  "threat-intelligence",
  "mitre",
  "reports",
  "rules",
  "assets",
  "users",
  "settings",
] as const;

const navRoutes = [
  "/",
  "/logs",
  "/alerts",
  "/incidents",
  "/threat-intelligence",
  "/mitre",
  "/reports",
  "/rules",
  "/assets",
  "/users",
  "/settings",
] as const;

const themeOptions: Record<UXTheme, { label: Record<Language, string>; note: Record<Language, string>; dot: string }> = {
  sentinel: {
    label: { th: "Midnight SOC", en: "Midnight SOC" },
    note: { th: "เข้ม คม มืออาชีพ", en: "Dark professional" },
    dot: "#22d3ee",
  },
  aurora: {
    label: { th: "Aurora Cyber", en: "Aurora Cyber" },
    note: { th: "นีออน ทันสมัย", en: "Modern neon" },
    dot: "#a78bfa",
  },
  daylight: {
    label: { th: "Daylight Clean", en: "Daylight Clean" },
    note: { th: "สว่าง อ่านง่าย", en: "Bright and clear" },
    dot: "#2563eb",
  },
};

const EN_TO_TH: Record<string, string> = {
  "Log Analysis": "วิเคราะห์ Log",
  "SOC Log Analysis Dashboard": "แดชบอร์ดวิเคราะห์ Log สำหรับ SOC",
  "Language": "ภาษา",
  "English": "อังกฤษ",
  "Dashboard": "แดชบอร์ด",
  "Logs": "บันทึก Log",
  "Log": "บันทึก Log",
  "Alerts": "การแจ้งเตือน",
  "Incidents": "เหตุการณ์",
  "Incident": "เหตุการณ์",
  "Threat Intelligence": "ข่าวกรองภัยคุกคาม",
  "Intelligence": "ข่าวกรองภัยคุกคาม",
  "MITRE ATT&CK": "MITRE ATT&CK",
  "Reports": "รายงาน",
  "Rules": "กฎตรวจจับ",
  "Assets": "สินทรัพย์",
  "Users": "ผู้ใช้",
  "Settings": "ตั้งค่า",
  "History": "ประวัติ",
  "Tools": "เครื่องมือ",
  "Sources": "แหล่งข้อมูล",
  "Mapped": "จับคู่แล้ว",
  "Session History": "ประวัติการวิเคราะห์",
  "Clear All": "ล้างทั้งหมด",
  "No sessions yet.": "ยังไม่มีประวัติการวิเคราะห์",
  "Custom Rules": "กฎที่กำหนดเอง",
  "IOC Watchlist": "รายการ IOC ที่เฝ้าระวัง",
  "Audit Log": "บันทึก Audit",
  "Geo Map": "แผนที่ภูมิศาสตร์",
  "MITRE Matrix": "เมทริกซ์ MITRE",
  "ATT&CK Coverage": "ความครอบคลุม ATT&CK",
  "Back to dashboard": "กลับไปหน้าแดชบอร์ด",
  "Return to Dashboard": "กลับไปแดชบอร์ด",
  "Saved Cases": "เคสที่บันทึกไว้",
  "Case fields": "ข้อมูลในเคส",
  "Case ID": "รหัสเคส",
  "Created time": "เวลาที่สร้าง",
  "Risk score": "คะแนนความเสี่ยง",
  "Risk level": "ระดับความเสี่ยง",
  "Finding count": "จำนวน Finding",
  "Top source IP": "Source IP ที่พบมากสุด",
  "Analyst note": "บันทึกนักวิเคราะห์",
  "Status": "สถานะ",
  "New": "ใหม่",
  "Investigating": "กำลังตรวจสอบ",
  "Resolved": "แก้ไขแล้ว",
  "Newly analyzed case waiting for review.": "เคสที่เพิ่งวิเคราะห์และรอการตรวจสอบ",
  "Analyst is checking evidence and timeline.": "นักวิเคราะห์กำลังตรวจหลักฐานและไทม์ไลน์",
  "Case has an outcome and export is ready.": "เคสมีผลสรุปแล้วและพร้อมส่งออก",
  "Export Report Center": "ศูนย์ส่งออกรายงาน",
  "Machine-readable full result for automation.": "ผลลัพธ์เต็มแบบเครื่องอ่านได้สำหรับ Automation",
  "Spreadsheet-friendly finding table.": "ตาราง Finding ที่เหมาะกับ Spreadsheet",
  "Readable incident summary for tickets.": "สรุป Incident สำหรับใส่ Ticket",
  "Manager-friendly report file.": "ไฟล์รายงานสำหรับผู้บริหาร",
  "Common Event Format export.": "ส่งออกเป็น Common Event Format",
  "Log Event Extended Format export.": "ส่งออกเป็น Log Event Extended Format",
  "Recommended report flow": "ขั้นตอนรายงานที่แนะนำ",
  "Analyze the logs and review the highest severity findings first.": "วิเคราะห์ Log และตรวจ Finding ที่รุนแรงที่สุดก่อน",
  "Open the detail drawer and confirm evidence, source, user, asset, and mapped technique.": "เปิดรายละเอียดและตรวจหลักฐาน Source, User, Asset และ Technique ที่จับคู่ไว้",
  "Copy RCA or manager summary for the ticket.": "คัดลอก RCA หรือสรุปผู้บริหารไปใส่ Ticket",
  "Export JSON or CSV for evidence archive, then PDF for presentation.": "ส่งออก JSON หรือ CSV เพื่อเก็บหลักฐาน แล้วค่อยส่งออก PDF สำหรับนำเสนอ",
  "Settings & Privacy": "ตั้งค่าและความเป็นส่วนตัว",
  "Review theme, language, local settings, and privacy notes before using real operational data.": "ตรวจธีม ภาษา การตั้งค่าในเครื่อง และหมายเหตุความเป็นส่วนตัวก่อนใช้ข้อมูลปฏิบัติการจริง",
  "Theme": "ธีม",
  "Three polished themes: Midnight SOC, Aurora Cyber, and Daylight Clean.": "มี 3 ธีมสวยงาม: Midnight SOC, Aurora Cyber และ Daylight Clean",
  "Thai and English labels across dashboard, reports, history, settings, and analyst outputs.": "รองรับป้ายข้อความภาษาไทยและอังกฤษทั้งแดชบอร์ด รายงาน ประวัติ ตั้งค่า และผลลัพธ์นักวิเคราะห์",
  "Auto refresh": "รีเฟรชอัตโนมัติ",
  "Optional browser-side refresh while reviewing active data.": "รีเฟรชฝั่งเบราว์เซอร์ได้เมื่อกำลังตรวจข้อมูลที่เปลี่ยนแปลง",
  "Custom rules": "กฎที่กำหนดเอง",
  "Browser-local rule tuning for your environment.": "ปรับแต่งกฎในเบราว์เซอร์ให้เหมาะกับสภาพแวดล้อมของคุณ",
  "IOC list": "รายการ IOC",
  "Browser-local indicator watchlist.": "รายการ Indicator ที่เฝ้าระวังในเบราว์เซอร์",
  "Webhook": "เว็บฮุก",
  "Optional outbound alert delivery configuration.": "ตั้งค่าการส่งแจ้งเตือนออกภายนอกแบบเลือกใช้ได้",
  "Privacy checklist": "เช็กลิสต์ความเป็นส่วนตัว",
  "Remove private values before sharing examples publicly.": "ลบข้อมูลส่วนตัวก่อนแชร์ตัวอย่างแบบสาธารณะ",
  "Mask customer names, emails, and private hostnames in screenshots.": "ปิดบังชื่อลูกค้า อีเมล และ hostname ภายในในภาพหน้าจอ",
  "Use sample fixtures when opening public issues.": "ใช้ sample fixture เมื่อต้องเปิด issue สาธารณะ",
  "Clear browser storage when working on a shared computer.": "ล้างข้อมูล browser storage เมื่อใช้คอมพิวเตอร์ร่วมกัน",
  "Risk Score": "คะแนนเสี่ยง",
  "Total Events": "Event ทั้งหมด",
  "Suspicious": "น่าสงสัย",
  "Critical": "วิกฤต",
  "Failed Login": "เข้าสู่ระบบล้มเหลว",
  "Correlation": "ความสัมพันธ์ของเหตุการณ์",
  "Top Source IP": "Source IP ที่พบมากที่สุด",
  "Overview": "สรุปภาพรวม",
  "Paste or upload logs": "ใส่หรืออัปโหลด Log",
  "Analyze Log": "วิเคราะห์ Log",
  "Analyzing...": "กำลังวิเคราะห์...",
  "Cancel": "ยกเลิก",
  "Analysis Results": "ผลการวิเคราะห์",
  "Incident Intelligence Summary": "สรุปข่าวกรองเหตุการณ์",
  "Top Rules": "กฎที่พบมากสุด",
  "Affected Users": "ผู้ใช้ที่ได้รับผลกระทบ",
  "Priority Actions": "สิ่งที่ควรทำก่อน",
  "Copy Output": "คัดลอกผลลัพธ์",
  "Copied": "คัดลอกแล้ว",
  "Copy failed": "คัดลอกไม่สำเร็จ",
  "Suspicious Event Table": "ตารางเหตุการณ์ที่น่าสงสัย",
  "Evidence": "หลักฐาน",
  "Root Cause": "สาเหตุหลัก",
  "Impact": "ผลกระทบ",
  "Fix": "วิธีแก้",
  "Recommendations": "คำแนะนำ",
  "Timeline": "ไทม์ไลน์",
  "Manager Summary": "สรุปสำหรับหัวหน้า",
  "Recommended Action": "แนวทางที่แนะนำ",
  "Clear Session": "ล้าง Session",
  "Showing": "แสดง",
  "of": "จาก",
  "events": "เหตุการณ์",
  "Prev": "ก่อนหน้า",
  "Next": "ถัดไป",
  "Page": "หน้า",
  "Search keyword, IP, or rule": "ค้นหา keyword, IP หรือ rule",
  "All Severities": "ทุกระดับความรุนแรง",
  "All Log Types": "ทุกประเภท Log",
  "Timestamp contains": "ค้นหาจากเวลา",
  "Severity": "ความรุนแรง",
  "Confidence": "ความมั่นใจ",
  "Type": "ประเภท",
  "Time": "เวลา",
  "Repeat": "ซ้ำ",
  "Unknown": "ไม่พบเวลา",
  "None": "ไม่มี",
  "UX Mode": "โหมด UX",
  "Theme mode": "โหมดธีม",
  "Modern UI": "UI ทันสมัย",
  "Workspace module": "โมดูล Workspace",
  "Operational view for SOC workflow. Use the dashboard analyzer output as the source of truth while this module is expanded into a full data view.": "มุมมองสำหรับงาน SOC ใช้ผลวิเคราะห์จากแดชบอร์ดเป็นข้อมูลหลักระหว่างขยายโมดูลนี้เป็นหน้าจริง",
  "What this page will include": "หน้านี้จะมีอะไรบ้าง",
  "Live table and saved filters": "ตารางสดและ filter ที่บันทึกไว้",
  "Export-ready workflow": "Workflow พร้อมส่งออก",
  "Role-based SOC actions": "Action ตามบทบาท SOC",
  "Central view for raw log ingestion, saved filters, and source parsing status.": "ศูนย์กลางสำหรับนำเข้า Log ดิบ filter ที่บันทึกไว้ และสถานะการแยกข้อมูลจากแหล่ง Log",
  "Review raw events, search by keyword, IP, host, user, and save common triage views.": "ตรวจ Event ดิบ ค้นหาด้วย keyword, IP, host, user และบันทึกมุมมองที่ใช้ triage บ่อย",
  "Source health": "สถานะแหล่งข้อมูล",
  "Track parser coverage for firewall, Windows, Linux, cloud, and application logs.": "ติดตามความครอบคลุมของ parser สำหรับ firewall, Windows, Linux, cloud และ application log",
  "Move clean evidence into reports, tickets, or RCA output after analysis.": "ย้ายหลักฐานที่จัดระเบียบแล้วไปยังรายงาน ticket หรือ RCA หลังวิเคราะห์",
  "SOC alert queue for severity, confidence, correlation, and escalation workflow.": "คิวแจ้งเตือน SOC สำหรับความรุนแรง ความมั่นใจ ความสัมพันธ์ และขั้นตอน escalation",
  "Severity queue": "คิวตามความรุนแรง",
  "Prioritize Critical and High alerts before Medium and Low signals.": "จัดลำดับ Critical และ High ก่อน Medium และ Low",
  "Correlation context": "บริบทความสัมพันธ์",
  "Group repeated indicators, users, assets, and techniques into incident candidates.": "รวม indicator, user, asset และ technique ที่ซ้ำกันให้เป็น candidate ของ incident",
  "Assign triage, acknowledge alerts, and prepare next-step fix commands.": "มอบหมาย triage รับทราบ alert และเตรียมคำสั่งแก้ไขขั้นต่อไป",
  "Incident case board for RCA, evidence, timeline, business impact, and response status.": "กระดาน incident สำหรับ RCA หลักฐาน ไทม์ไลน์ ผลกระทบธุรกิจ และสถานะการตอบสนอง",
  "Case lifecycle": "วงจรชีวิตเคส",
  "Move cases from New to Investigating, Contained, Resolved, or False Positive.": "ย้ายเคสจากใหม่ ไปเป็นกำลังตรวจสอบ ควบคุมแล้ว แก้ไขแล้ว หรือ false positive",
  "Evidence timeline": "ไทม์ไลน์หลักฐาน",
  "Combine raw log lines, source IPs, users, assets, and MITRE mapping into one story.": "รวม log ดิบ source IP user asset และ MITRE mapping ให้เป็นเรื่องเดียว",
  "RCA handoff": "ส่งต่อ RCA",
  "Prepare manager summary, root cause, impact, and recommended remediation.": "เตรียมสรุปผู้บริหาร สาเหตุ ผลกระทบ และแนวทางแก้ไขที่แนะนำ",
  "Workspace for reviewing context, confidence, notes, and follow-up details.": "พื้นที่สำหรับตรวจบริบท ความมั่นใจ บันทึก และรายละเอียดติดตามผล",
  "Context view": "มุมมองบริบท",
  "Review signals found in analyzed logs and keep notes for follow-up.": "ตรวจสัญญาณที่พบจาก Log ที่วิเคราะห์แล้ว และเก็บบันทึกเพื่อติดตามผล",
  "Confidence flow": "ขั้นตอนความมั่นใจ",
  "Add asset importance, user context, and confidence scoring.": "เพิ่มความสำคัญของ asset บริบทผู้ใช้ และคะแนนความมั่นใจ",
  "Report handoff": "ส่งต่อรายงาน",
  "Copy clean findings into reports, cases, and notes.": "คัดลอก finding ที่จัดระเบียบแล้วไปยังรายงาน เคส และโน้ต",
  "Tactic and technique coverage view for mapping findings to analyst-friendly categories.": "มุมมอง tactic และ technique สำหรับจับคู่ finding ให้เป็นหมวดที่นักวิเคราะห์อ่านง่าย",
  "Coverage matrix": "เมทริกซ์ความครอบคลุม",
  "Show tactics and techniques found in the current analysis result.": "แสดง tactic และ technique ที่พบในผลวิเคราะห์ปัจจุบัน",
  "Technique detail": "รายละเอียด Technique",
  "Explain evidence, confidence, and recommended response for each mapping.": "อธิบายหลักฐาน ความมั่นใจ และการตอบสนองที่แนะนำในแต่ละ mapping",
  "Export a coverage summary for audit, RCA, and manager review.": "ส่งออกสรุปความครอบคลุมสำหรับ audit, RCA และผู้บริหาร",
  "Asset inventory view for hosts, devices, cloud resources, and ownership context.": "มุมมอง inventory สำหรับ host, device, cloud resource และข้อมูลเจ้าของ",
  "Asset inventory": "ทะเบียนสินทรัพย์",
  "Track names, owners, locations, and business criticality.": "ติดตามชื่อ เจ้าของ สถานที่ และความสำคัญทางธุรกิจ",
  "Risk context": "บริบทความเสี่ยง",
  "Connect findings to important assets and prioritize response work.": "เชื่อม finding กับ asset สำคัญและจัดลำดับงานตอบสนอง",
  "Operational notes": "บันทึกปฏิบัติการ",
  "Keep support notes, owner, and last review status in one view.": "เก็บโน้ต support เจ้าของ และสถานะรีวิวล่าสุดไว้ในมุมมองเดียว",
  "User workspace for accounts, activity context, and analyst notes.": "พื้นที่ผู้ใช้สำหรับบัญชี บริบทกิจกรรม และบันทึกนักวิเคราะห์",
  "User timeline": "ไทม์ไลน์ผู้ใช้",
  "Review activity trends and recent notes for each account.": "ตรวจแนวโน้มกิจกรรมและโน้ตล่าสุดของแต่ละบัญชี",
  "Context": "บริบท",
  "Connect events to user behavior, related assets, and review notes.": "เชื่อม event กับพฤติกรรมผู้ใช้ asset ที่เกี่ยวข้อง และโน้ตรีวิว",
  "Case handoff": "ส่งต่อเคส",
  "Prepare a clear user-focused summary for tickets and reports.": "เตรียมสรุปที่เน้นผู้ใช้ให้ชัดเจนสำหรับ ticket และรายงาน",
};

const TH_TO_EN = Object.fromEntries(Object.entries(EN_TO_TH).map(([en, th]) => [th, en])) as Record<string, string>;
const originalTextNodes = new WeakMap<Text, string>();
const attrNames = ["placeholder", "title", "aria-label"] as const;

function translateCore(core: string, language: Language): string {
  const numbered = core.match(/^(\d+)\.\s+(.+)$/);
  if (numbered) {
    return `${numbered[1]}. ${translateCore(numbered[2], language)}`;
  }

  const dictionary = language === "th" ? EN_TO_TH : TH_TO_EN;
  if (dictionary[core]) return dictionary[core];

  const historyMatch = core.match(/^History \((\d+)\)$/);
  if (historyMatch) return language === "th" ? `ประวัติ (${historyMatch[1]})` : `History (${historyMatch[1]})`;

  const toolsMatch = core.match(/^Tools \((\d+) rules \/ (\d+) IOCs\)$/);
  if (toolsMatch) {
    return language === "th"
      ? `เครื่องมือ (${toolsMatch[1]} กฎ / ${toolsMatch[2]} IOC)`
      : `Tools (${toolsMatch[1]} rules / ${toolsMatch[2]} IOCs)`;
  }

  const findingMatch = core.match(/^(\d+) findings$/);
  if (findingMatch) return language === "th" ? `${findingMatch[1]} Findings` : `${findingMatch[1]} findings`;

  return core;
}

function translateTextValue(value: string, language: Language): string {
  const leading = value.match(/^\s*/)?.[0] ?? "";
  const trailing = value.match(/\s*$/)?.[0] ?? "";
  const core = value.trim().replace(/\s+/g, " ");
  if (!core) return value;
  return `${leading}${translateCore(core, language)}${trailing}`;
}

function shouldSkipNode(parent: ParentNode | null): boolean {
  if (!(parent instanceof HTMLElement)) return true;
  return Boolean(parent.closest("[data-i18n-ignore], textarea, input, pre, code, script, style, svg, canvas"));
}

function applyRuntimeLanguage(language: Language): void {
  if (typeof document === "undefined") return;
  document.documentElement.lang = language;

  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
    acceptNode(node: Node): number {
      if (!node.nodeValue?.trim()) return NodeFilter.FILTER_REJECT;
      return shouldSkipNode(node.parentNode) ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT;
    },
  });

  let node = walker.nextNode() as Text | null;
  while (node) {
    const original = originalTextNodes.get(node) ?? node.nodeValue ?? "";
    originalTextNodes.set(node, original);
    const translated = translateTextValue(original, language);
    if (node.nodeValue !== translated) node.nodeValue = translated;
    node = walker.nextNode() as Text | null;
  }

  document.querySelectorAll<HTMLElement>("[placeholder], [title], [aria-label]").forEach((element) => {
    if (element.closest("[data-i18n-ignore]")) return;
    attrNames.forEach((attr) => {
      const current = element.getAttribute(attr);
      if (!current) return;
      const key = `data-i18n-origin-${attr.replace(/[^a-z]/g, "")}`;
      const original = element.getAttribute(key) ?? current;
      element.setAttribute(key, original);
      const translated = translateTextValue(original, language);
      if (current !== translated) element.setAttribute(attr, translated);
    });
  });
}

function clickNativeLanguageButton(language: Language): void {
  const label = language === "th" ? "ไทย" : "English";
  window.setTimeout(() => {
    const button = Array.from(document.querySelectorAll<HTMLButtonElement>("button")).find((item) => {
      if (item.closest("[data-ux-control]")) return false;
      return item.textContent?.trim() === label;
    });
    button?.click();
  }, 0);
}

function getVisibleTargets(): HTMLElement[] {
  const seen = new Set<HTMLElement>();
  const selectors = [
    "main [data-nav-section]",
    "main header",
    "main section",
    "main [class*='card-3d']",
  ];
  return selectors.flatMap((selector) => Array.from(document.querySelectorAll<HTMLElement>(selector)))
    .filter((element) => {
      if (seen.has(element)) return false;
      const rect = element.getBoundingClientRect();
      const isVisible = rect.width > 0 && rect.height > 0;
      if (!isVisible) return false;
      seen.add(element);
      return true;
    });
}

function scrollToSidebarSection(index: number): void {
  const sectionId = navSectionIds[index];
  if (!sectionId) return;

  const explicitTarget = document.querySelector<HTMLElement>(`#${sectionId}, [data-nav-section="${sectionId}"]`);
  const targets = getVisibleTargets();
  const fallbackTarget = targets[Math.min(index, Math.max(targets.length - 1, 0))];
  const target = explicitTarget || fallbackTarget || document.querySelector<HTMLElement>("main");

  if (!target) return;
  target.scrollIntoView({ behavior: "smooth", block: "start" });
}

function setActiveSidebarButton(activeIndex: number): void {
  Array.from(document.querySelectorAll<HTMLButtonElement>("aside nav button")).forEach((button, index) => {
    button.setAttribute("data-active", index === activeIndex ? "true" : "false");
    button.classList.toggle("is-sidebar-active", index === activeIndex);
  });
}

function installSidebarNavigation(): () => void {
  const handleClick = (event: MouseEvent): void => {
    const target = event.target instanceof HTMLElement ? event.target.closest<HTMLButtonElement>("aside nav button") : null;
    if (!target) return;

    const buttons = Array.from(document.querySelectorAll<HTMLButtonElement>("aside nav button"));
    const index = buttons.indexOf(target);
    if (index < 0) return;

    event.preventDefault();
    setActiveSidebarButton(index);

    if (window.location.pathname !== "/") {
      window.location.assign(`${navRoutes[0]}#${navSectionIds[index]}`);
      return;
    }

    scrollToSidebarSection(index);
    window.history.replaceState(null, "", `#${navSectionIds[index]}`);
  };

  const handleHashScroll = (): void => {
    const hash = window.location.hash.replace("#", "");
    const index = navSectionIds.indexOf(hash as (typeof navSectionIds)[number]);
    if (index >= 0) {
      window.setTimeout(() => {
        setActiveSidebarButton(index);
        scrollToSidebarSection(index);
      }, 120);
    }
  };

  document.addEventListener("click", handleClick);
  window.addEventListener("hashchange", handleHashScroll);
  handleHashScroll();

  return () => {
    document.removeEventListener("click", handleClick);
    window.removeEventListener("hashchange", handleHashScroll);
  };
}

export default function ExperienceProvider({ children }: { children: ReactNode }): ReactNode {
  const [language, setLanguageState] = useState<Language>("th");
  const [theme, setThemeState] = useState<UXTheme>("sentinel");
  const [isUxOpen, setIsUxOpen] = useState(false);

  useEffect(() => {
    const savedLanguage = window.localStorage.getItem("soc_language") as Language | null;
    const savedTheme = window.localStorage.getItem("soc_ux_theme") as UXTheme | null;
    const savedPanel = window.localStorage.getItem(UX_PANEL_STORAGE_KEY);
    if (savedLanguage === "th" || savedLanguage === "en") setLanguageState(savedLanguage);
    if (savedTheme === "sentinel" || savedTheme === "aurora" || savedTheme === "daylight") setThemeState(savedTheme);
    if (savedPanel === "1") setIsUxOpen(true);
  }, []);

  useEffect(() => {
    const html = document.documentElement;
    html.classList.remove(...THEME_CLASSES);
    html.classList.add(`theme-soc-${theme}`);
    window.localStorage.setItem("soc_ux_theme", theme);
  }, [theme]);

  useEffect(() => {
    window.localStorage.setItem(UX_PANEL_STORAGE_KEY, isUxOpen ? "1" : "0");
  }, [isUxOpen]);

  useEffect(() => {
    window.localStorage.setItem("soc_language", language);
    applyRuntimeLanguage(language);

    let frame = 0;
    const observer = new MutationObserver(() => {
      window.cancelAnimationFrame(frame);
      frame = window.requestAnimationFrame(() => applyRuntimeLanguage(language));
    });
    observer.observe(document.body, { childList: true, subtree: true });
    return () => {
      window.cancelAnimationFrame(frame);
      observer.disconnect();
    };
  }, [language]);

  useEffect(() => installSidebarNavigation(), []);

  const setLanguage = useCallback((nextLanguage: Language): void => {
    setLanguageState(nextLanguage);
    clickNativeLanguageButton(nextLanguage);
  }, []);

  const activeTheme = themeOptions[theme];
  const themeEntries = useMemo(() => Object.entries(themeOptions) as [UXTheme, typeof themeOptions[UXTheme]][], []);

  return (
    <>
      {children}
      <aside className={`ux-command-center${isUxOpen ? " is-open" : " is-collapsed"}`} data-i18n-ignore data-ux-control>
        <button
          type="button"
          className="ux-panel-toggle"
          onClick={() => setIsUxOpen((value) => !value)}
          aria-expanded={isUxOpen}
          aria-label={isUxOpen ? (language === "th" ? "พับแผง UX" : "Collapse UX panel") : language === "th" ? "เปิดแผง UX" : "Open UX panel"}
        >
          <span className="ux-live-dot" style={{ background: activeTheme.dot }} />
          <span>{isUxOpen ? (language === "th" ? "พับ" : "Hide") : "UX"}</span>
        </button>

        {isUxOpen && (
          <div className="ux-panel-body">
            <div className="ux-control-head">
              <div>
                <p className="ux-eyebrow">{language === "th" ? "ตั้งค่าหน้าเว็บ" : "Interface"}</p>
                <h2>{language === "th" ? "โหมด UX" : "UX Mode"}</h2>
              </div>
            </div>

            <div className="ux-segment" aria-label="Language selector">
              {(["th", "en"] as Language[]).map((item) => (
                <button
                  key={item}
                  type="button"
                  onClick={() => setLanguage(item)}
                  className={language === item ? "is-active" : ""}
                  data-ux-lang={item}
                >
                  {item === "th" ? "ไทย" : "EN"}
                </button>
              ))}
            </div>

            <div className="ux-theme-list" aria-label="Theme selector">
              {themeEntries.map(([key, option]) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => setThemeState(key)}
                  className={theme === key ? "is-active" : ""}
                >
                  <span className="ux-theme-dot" style={{ background: option.dot }} />
                  <span>
                    <strong>{option.label[language]}</strong>
                    <small>{option.note[language]}</small>
                  </span>
                </button>
              ))}
            </div>
          </div>
        )}
      </aside>
    </>
  );
}

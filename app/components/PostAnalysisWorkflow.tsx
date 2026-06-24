"use client";

import { useEffect, useMemo, useState } from "react";
import type { AnalysisResult, Finding, Severity } from "@/lib/logAnalyzer";
import type { Language } from "@/lib/i18n";
import { localize, severityLabel } from "@/lib/i18n";

type WorkflowStatus = "New" | "Investigating" | "Contained" | "Resolved" | "Closed";
type ExportFormat = "json" | "csv" | "markdown";

type IncidentCase = {
  id: string;
  findingId: string;
  title: string;
  severity: Severity;
  status: WorkflowStatus;
  sourceIp: string | null;
  asset: string | null;
  user: string | null;
  mitre: string;
  rca: string;
  impact: string;
  fix: string;
  raw: string;
  createdAt: string;
  updatedAt: string;
};

type CustomIoc = {
  id: string;
  indicator: string;
  type: "ip" | "domain" | "hash";
  risk: Severity;
  description: string;
  source: string;
  addedAt: string;
};

type CustomRule = {
  id: string;
  name: string;
  pattern: string;
  keywords: string;
  severity: Severity;
  tactic: string;
  technique: string;
  rootCause: string;
  impact: string;
  fix: string;
  enabled: boolean;
};

type WorkflowEvent = {
  id: string;
  findingId: string;
  action: string;
  createdAt: string;
  status?: WorkflowStatus;
};

const STORAGE = {
  result: "soc_last_result",
  language: "soc_language",
  statuses: "soc_finding_statuses",
  incidents: "soc_incident_cases",
  legacyCases: "soc_cases",
  iocs: "soc_custom_iocs",
  rules: "soc_custom_rules",
  events: "soc_workflow_events",
};

const statusTone: Record<WorkflowStatus, string> = {
  New: "border-sky-300/40 bg-sky-500/10 text-sky-100",
  Investigating: "border-amber-300/50 bg-amber-500/10 text-amber-100",
  Contained: "border-violet-300/50 bg-violet-500/10 text-violet-100",
  Resolved: "border-emerald-300/50 bg-emerald-500/10 text-emerald-100",
  Closed: "border-slate-300/30 bg-slate-500/10 text-slate-200",
};

const copy: Record<Language, Record<string, string>> = {
  th: {
    eyebrow: "ขั้นตอนหลังวิเคราะห์",
    title: "SOC Response Workflow",
    subtitle: "เมื่อเจอ Finding แล้ว สามารถสร้างเคส ส่งออกรายงาน เพิ่ม IOC เพิ่ม Rule และติดตามสถานะได้ทันที",
    selectFinding: "เลือก Finding",
    statusTracking: "ติดตามสถานะ",
    createIncident: "Create Incident",
    exportJson: "Export JSON",
    exportCsv: "Export CSV",
    exportMarkdown: "Export Markdown",
    addIoc: "Add IOC",
    addRule: "Add Rule",
    currentStatus: "สถานะปัจจุบัน",
    sourceIp: "Source IP",
    asset: "Asset",
    user: "ผู้ใช้",
    mitre: "MITRE",
    evidence: "หลักฐาน",
    fix: "แนวทางแก้",
    raw: "Raw Log",
    noResult: "ยังไม่มีผลวิเคราะห์ ให้ใส่ Log แล้วกด Analyze ก่อน",
    noIoc: "Finding นี้ยังไม่มี IP / Domain / Hash สำหรับเพิ่ม IOC",
    incidentDone: "สร้าง Incident แล้ว",
    reportDone: "ส่งออกรายงานแล้ว",
    iocDone: "เพิ่ม IOC เข้า Watchlist แล้ว",
    ruleDone: "เพิ่ม Rule ใหม่แล้ว",
    statusDone: "อัปเดตสถานะแล้ว",
    alreadyExists: "มีรายการนี้อยู่แล้ว ระบบไม่เพิ่มซ้ำ",
    openIncidents: "ไปหน้า Incidents",
    openRules: "ไปหน้า Rules",
    openIntel: "ไปหน้า Threat Intel",
    new: "New",
    investigating: "Investigating",
    contained: "Contained",
    resolved: "Resolved",
    closed: "Closed",
  },
  en: {
    eyebrow: "Post-analysis workflow",
    title: "SOC Response Workflow",
    subtitle: "After a finding is detected, create an incident, export evidence, add IOC, add a rule, and track response status.",
    selectFinding: "Select finding",
    statusTracking: "Status tracking",
    createIncident: "Create Incident",
    exportJson: "Export JSON",
    exportCsv: "Export CSV",
    exportMarkdown: "Export Markdown",
    addIoc: "Add IOC",
    addRule: "Add Rule",
    currentStatus: "Current status",
    sourceIp: "Source IP",
    asset: "Asset",
    user: "User",
    mitre: "MITRE",
    evidence: "Evidence",
    fix: "Recommended fix",
    raw: "Raw Log",
    noResult: "No analysis result yet. Paste logs and run Analyze first.",
    noIoc: "This finding has no IP / domain / hash to add as an IOC.",
    incidentDone: "Incident created",
    reportDone: "Report exported",
    iocDone: "IOC added to watchlist",
    ruleDone: "Rule added",
    statusDone: "Status updated",
    alreadyExists: "This item already exists, so it was not duplicated.",
    openIncidents: "Open Incidents",
    openRules: "Open Rules",
    openIntel: "Open Threat Intel",
    new: "New",
    investigating: "Investigating",
    contained: "Contained",
    resolved: "Resolved",
    closed: "Closed",
  },
};

const statusLabels: Record<WorkflowStatus, keyof typeof copy.th> = {
  New: "new",
  Investigating: "investigating",
  Contained: "contained",
  Resolved: "resolved",
  Closed: "closed",
};

function getLanguage(): Language {
  if (typeof window === "undefined") return "th";
  const language = window.localStorage.getItem(STORAGE.language);
  return language === "en" || language === "th" ? language : "th";
}

function readJson<T>(key: string, fallback: T): T {
  if (typeof window === "undefined") return fallback;
  try {
    const raw = window.localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function writeJson<T>(key: string, value: T): void {
  window.localStorage.setItem(key, JSON.stringify(value));
  window.dispatchEvent(new Event("storage"));
}

function csvCell(value: unknown): string {
  return `"${String(value ?? "").replace(/"/g, '""')}"`;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function shortId(prefix: string): string {
  const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const random = Math.random().toString(36).slice(2, 6).toUpperCase();
  return `${prefix}-${stamp}-${random}`;
}

function detectIndicatorType(indicator: string): CustomIoc["type"] {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(indicator)) return "ip";
  if (/^[a-f0-9]{32,64}$/i.test(indicator)) return "hash";
  return "domain";
}

function getIndicators(finding: Finding): Array<{ indicator: string; type: CustomIoc["type"] }> {
  const values = [finding.sourceIp, finding.destinationIp, finding.domain, finding.fileHash]
    .filter((value): value is string => Boolean(value && value.trim()))
    .map((indicator) => ({ indicator, type: detectIndicatorType(indicator) }));
  const unique = new Map(values.map((item) => [item.indicator, item]));
  return [...unique.values()];
}

function downloadFile(filename: string, content: string, type: string): void {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function buildFindingReport(result: AnalysisResult, finding: Finding, language: Language, format: ExportFormat): string {
  const title = localize(finding.rule, language);
  const rows = {
    generatedAt: new Date().toISOString(),
    findingId: finding.id,
    severity: finding.severity,
    riskScore: result.summary.riskScore,
    rule: title,
    logType: finding.logType,
    sourceIp: finding.sourceIp ?? "",
    destinationIp: finding.destinationIp ?? "",
    user: finding.username ?? "",
    asset: finding.asset ?? "",
    mitre: `${finding.tactic} / ${finding.technique}`,
    confidence: `${finding.confidence}%`,
    evidence: localize(finding.evidence, language),
    rootCause: localize(finding.possibleRootCause, language),
    impact: localize(finding.impact, language),
    recommendedFix: localize(finding.recommendedFix, language),
    rawLog: finding.raw,
  };

  if (format === "json") return JSON.stringify({ summary: result.summary, finding: rows }, null, 2);
  if (format === "csv") {
    const header = Object.keys(rows).map(csvCell).join(",");
    const values = Object.values(rows).map(csvCell).join(",");
    return `${header}\n${values}\n`;
  }
  return `# ${title}\n\n` +
    `- Finding ID: ${rows.findingId}\n` +
    `- Severity: ${rows.severity}\n` +
    `- Risk Score: ${rows.riskScore}\n` +
    `- Log Type: ${rows.logType}\n` +
    `- Source IP: ${rows.sourceIp || "-"}\n` +
    `- Destination IP: ${rows.destinationIp || "-"}\n` +
    `- User: ${rows.user || "-"}\n` +
    `- Asset: ${rows.asset || "-"}\n` +
    `- MITRE: ${rows.mitre}\n` +
    `- Confidence: ${rows.confidence}\n\n` +
    `## Evidence\n${rows.evidence}\n\n` +
    `## Root Cause\n${rows.rootCause}\n\n` +
    `## Impact\n${rows.impact}\n\n` +
    `## Recommended Fix\n${rows.recommendedFix}\n\n` +
    `## Raw Log\n\`\`\`text\n${rows.rawLog}\n\`\`\`\n`;
}

function Field({ label, value }: { label: string; value: string | number | null | undefined }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-black/20 p-3">
      <p className="text-[10px] uppercase tracking-[0.18em] text-cyan-200/70">{label}</p>
      <p className="mt-1 break-words text-sm text-slate-100">{value || "-"}</p>
    </div>
  );
}

export default function PostAnalysisWorkflow() {
  const [language, setLanguage] = useState<Language>("th");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [selectedId, setSelectedId] = useState<string>("");
  const [statuses, setStatuses] = useState<Record<string, WorkflowStatus>>({});
  const [toast, setToast] = useState("");

  useEffect(() => {
    const sync = () => {
      setLanguage(getLanguage());
      setStatuses(readJson<Record<string, WorkflowStatus>>(STORAGE.statuses, {}));
      const storedResult = readJson<AnalysisResult | null>(STORAGE.result, null);
      setResult(storedResult);
      if (storedResult?.findings.length && !selectedId) setSelectedId(storedResult.findings[0].id);
    };
    sync();
    const interval = window.setInterval(sync, 900);
    window.addEventListener("storage", sync);
    return () => {
      window.clearInterval(interval);
      window.removeEventListener("storage", sync);
    };
  }, [selectedId]);

  const findings = result?.findings ?? [];
  const selectedFinding = useMemo(
    () => findings.find((finding) => finding.id === selectedId) ?? findings[0] ?? null,
    [findings, selectedId]
  );
  const t = copy[language];

  function notify(message: string): void {
    setToast(message);
    window.setTimeout(() => setToast(""), 2400);
  }

  function trackEvent(findingId: string, action: string, status?: WorkflowStatus): void {
    const events = readJson<WorkflowEvent[]>(STORAGE.events, []);
    events.unshift({ id: crypto.randomUUID(), findingId, action, status, createdAt: new Date().toISOString() });
    writeJson(STORAGE.events, events.slice(0, 100));
  }

  function setWorkflowStatus(finding: Finding, status: WorkflowStatus): void {
    const next = { ...statuses, [finding.id]: status };
    setStatuses(next);
    writeJson(STORAGE.statuses, next);
    trackEvent(finding.id, "status", status);
    notify(t.statusDone);
  }

  function createIncident(finding: Finding): void {
    const incidents = readJson<IncidentCase[]>(STORAGE.incidents, []);
    const existing = incidents.find((incident) => incident.findingId === finding.id);
    if (existing) {
      setWorkflowStatus(finding, existing.status);
      notify(t.alreadyExists);
      return;
    }
    const now = new Date().toISOString();
    const incident: IncidentCase = {
      id: shortId("CASE"),
      findingId: finding.id,
      title: localize(finding.rule, language),
      severity: finding.severity,
      status: "Investigating",
      sourceIp: finding.sourceIp,
      asset: finding.asset,
      user: finding.username,
      mitre: `${finding.tactic} / ${finding.technique}`,
      rca: localize(finding.possibleRootCause, language),
      impact: localize(finding.impact, language),
      fix: localize(finding.recommendedFix, language),
      raw: finding.raw,
      createdAt: now,
      updatedAt: now,
    };
    writeJson(STORAGE.incidents, [incident, ...incidents]);
    writeJson(STORAGE.legacyCases, [incident, ...readJson<IncidentCase[]>(STORAGE.legacyCases, [])]);
    setWorkflowStatus(finding, "Investigating");
    trackEvent(finding.id, "create_incident", "Investigating");
    notify(`${t.incidentDone}: ${incident.id}`);
  }

  function exportReport(finding: Finding, format: ExportFormat): void {
    if (!result) return;
    const content = buildFindingReport(result, finding, language, format);
    const ext = format === "markdown" ? "md" : format;
    const type = format === "json" ? "application/json;charset=utf-8" : format === "csv" ? "text/csv;charset=utf-8" : "text/markdown;charset=utf-8";
    downloadFile(`soc-finding-${finding.id}.${ext}`, content, type);
    trackEvent(finding.id, `export_${format}`);
    notify(t.reportDone);
  }

  function addIoc(finding: Finding): void {
    const candidates = getIndicators(finding);
    if (!candidates.length) {
      notify(t.noIoc);
      return;
    }
    const current = readJson<CustomIoc[]>(STORAGE.iocs, []);
    const currentIndicators = new Set(current.map((ioc) => ioc.indicator));
    const additions = candidates
      .filter((candidate) => !currentIndicators.has(candidate.indicator))
      .map<CustomIoc>((candidate) => ({
        id: crypto.randomUUID(),
        indicator: candidate.indicator,
        type: candidate.type,
        risk: finding.severity,
        description: localize(finding.evidence, language),
        source: `Finding ${finding.id}`,
        addedAt: new Date().toISOString().slice(0, 10),
      }));
    if (!additions.length) {
      notify(t.alreadyExists);
      return;
    }
    writeJson(STORAGE.iocs, [...current, ...additions]);
    trackEvent(finding.id, "add_ioc");
    notify(`${t.iocDone}: ${additions.length}`);
  }

  function addRule(finding: Finding): void {
    const rules = readJson<CustomRule[]>(STORAGE.rules, []);
    const existing = rules.some((rule) => rule.name === localize(finding.rule, language));
    if (existing) {
      notify(t.alreadyExists);
      return;
    }
    const keyword = finding.detectedKeywords[0] || finding.sourceIp || finding.technique || finding.rule;
    const rule: CustomRule = {
      id: crypto.randomUUID(),
      name: localize(finding.rule, language),
      pattern: escapeRegex(keyword),
      keywords: finding.detectedKeywords.join(", ") || keyword,
      severity: finding.severity,
      tactic: finding.tactic,
      technique: finding.technique,
      rootCause: localize(finding.possibleRootCause, language),
      impact: localize(finding.impact, language),
      fix: localize(finding.recommendedFix, language),
      enabled: true,
    };
    writeJson(STORAGE.rules, [rule, ...rules]);
    trackEvent(finding.id, "add_rule");
    notify(t.ruleDone);
  }

  if (!result || findings.length === 0 || !selectedFinding) return null;

  const currentStatus = statuses[selectedFinding.id] ?? "New";

  return (
    <section data-i18n-ignore className="mx-auto mt-6 w-full max-w-[1800px] px-4 pb-6 sm:px-6 lg:px-8">
      <div className="overflow-hidden rounded-[2rem] border border-violet-300/20 bg-slate-950/70 shadow-2xl shadow-violet-950/20 backdrop-blur-2xl">
        <div className="border-b border-white/10 bg-gradient-to-r from-violet-500/15 via-cyan-400/10 to-transparent p-5 sm:p-6">
          <p className="text-xs font-semibold uppercase tracking-[0.22em] text-violet-200">{t.eyebrow}</p>
          <div className="mt-2 flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <h2 className="text-2xl font-bold text-white md:text-3xl">{t.title}</h2>
              <p className="mt-2 max-w-4xl text-sm leading-6 text-slate-300">{t.subtitle}</p>
            </div>
            {toast && <div className="rounded-2xl border border-emerald-300/40 bg-emerald-500/10 px-4 py-2 text-sm font-semibold text-emerald-100">{toast}</div>}
          </div>
        </div>

        <div className="grid gap-0 xl:grid-cols-[380px_minmax(0,1fr)]">
          <div className="border-b border-white/10 p-4 xl:border-b-0 xl:border-r">
            <label className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400" htmlFor="workflow-finding-select">{t.selectFinding}</label>
            <select
              id="workflow-finding-select"
              value={selectedFinding.id}
              onChange={(event) => setSelectedId(event.target.value)}
              className="mt-3 w-full rounded-2xl border border-white/10 bg-black/30 px-4 py-3 text-sm text-white outline-none ring-cyan-400/40 focus:ring-2"
            >
              {findings.map((finding) => (
                <option key={finding.id} value={finding.id} className="bg-slate-950 text-white">
                  {finding.id} · {severityLabel(finding.severity, language)} · {localize(finding.rule, language)}
                </option>
              ))}
            </select>

            <div className="mt-4 rounded-2xl border border-white/10 bg-black/20 p-4">
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">{t.currentStatus}</p>
              <div className={`mt-2 w-fit rounded-full border px-3 py-1 text-xs font-semibold ${statusTone[currentStatus]}`}>{t[statusLabels[currentStatus]]}</div>
              <div className="mt-4 grid grid-cols-1 gap-2">
                {(Object.keys(statusTone) as WorkflowStatus[]).map((status) => (
                  <button
                    key={status}
                    type="button"
                    onClick={() => setWorkflowStatus(selectedFinding, status)}
                    className={`rounded-xl border px-3 py-2 text-left text-xs font-semibold transition hover:-translate-y-0.5 ${currentStatus === status ? statusTone[status] : "border-white/10 bg-white/[0.03] text-slate-300 hover:border-cyan-300/40"}`}
                  >
                    {t[statusLabels[status]]}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="p-4 sm:p-5">
            <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_330px]">
              <div className="space-y-4">
                <div className="rounded-3xl border border-cyan-300/20 bg-cyan-400/10 p-5">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                    <div>
                      <p className="text-xs text-cyan-100/70">{selectedFinding.id} · {selectedFinding.logType}</p>
                      <h3 className="mt-1 text-xl font-bold text-white">{localize(selectedFinding.rule, language)}</h3>
                    </div>
                    <span className="w-fit rounded-full border border-white/20 bg-black/25 px-3 py-1 text-xs font-semibold text-white">{severityLabel(selectedFinding.severity, language)}</span>
                  </div>
                  <p className="mt-3 text-sm leading-6 text-slate-300">{localize(selectedFinding.evidence, language)}</p>
                </div>

                <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                  <Field label={t.sourceIp} value={selectedFinding.sourceIp} />
                  <Field label={t.asset} value={selectedFinding.asset} />
                  <Field label={t.user} value={selectedFinding.username} />
                  <Field label={t.mitre} value={`${selectedFinding.tactic} / ${selectedFinding.technique}`} />
                </div>

                <Field label={t.fix} value={localize(selectedFinding.recommendedFix, language)} />
                <div className="rounded-2xl border border-white/10 bg-black/30 p-4">
                  <p className="text-[10px] uppercase tracking-[0.18em] text-cyan-200/70">{t.raw}</p>
                  <pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-words rounded-xl bg-black/35 p-3 font-mono text-xs leading-5 text-slate-200">{selectedFinding.raw}</pre>
                </div>
              </div>

              <div className="space-y-3">
                <button type="button" onClick={() => createIncident(selectedFinding)} className="w-full rounded-2xl border border-cyan-300/40 bg-cyan-400/15 px-4 py-3 text-sm font-bold text-cyan-50 transition hover:-translate-y-0.5 hover:bg-cyan-400/20">
                  {t.createIncident}
                </button>
                <div className="grid grid-cols-1 gap-2 rounded-2xl border border-white/10 bg-black/20 p-3">
                  <button type="button" onClick={() => exportReport(selectedFinding, "json")} className="rounded-xl border border-white/10 bg-white/[0.04] px-3 py-2 text-left text-sm text-slate-100 hover:border-cyan-300/40">{t.exportJson}</button>
                  <button type="button" onClick={() => exportReport(selectedFinding, "csv")} className="rounded-xl border border-white/10 bg-white/[0.04] px-3 py-2 text-left text-sm text-slate-100 hover:border-cyan-300/40">{t.exportCsv}</button>
                  <button type="button" onClick={() => exportReport(selectedFinding, "markdown")} className="rounded-xl border border-white/10 bg-white/[0.04] px-3 py-2 text-left text-sm text-slate-100 hover:border-cyan-300/40">{t.exportMarkdown}</button>
                </div>
                <button type="button" onClick={() => addIoc(selectedFinding)} className="w-full rounded-2xl border border-violet-300/40 bg-violet-500/15 px-4 py-3 text-sm font-bold text-violet-50 transition hover:-translate-y-0.5 hover:bg-violet-500/20">
                  {t.addIoc}
                </button>
                <button type="button" onClick={() => addRule(selectedFinding)} className="w-full rounded-2xl border border-amber-300/40 bg-amber-500/15 px-4 py-3 text-sm font-bold text-amber-50 transition hover:-translate-y-0.5 hover:bg-amber-500/20">
                  {t.addRule}
                </button>
                <div className="grid grid-cols-1 gap-2 pt-2 text-xs">
                  <a href="/incidents" className="rounded-xl border border-white/10 bg-white/[0.03] px-3 py-2 text-slate-300 hover:border-cyan-300/40">{t.openIncidents}</a>
                  <a href="/threat-intelligence" className="rounded-xl border border-white/10 bg-white/[0.03] px-3 py-2 text-slate-300 hover:border-cyan-300/40">{t.openIntel}</a>
                  <a href="/rules" className="rounded-xl border border-white/10 bg-white/[0.03] px-3 py-2 text-slate-300 hover:border-cyan-300/40">{t.openRules}</a>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

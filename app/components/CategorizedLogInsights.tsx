"use client";

import { useEffect, useMemo, useState } from "react";
import type { AnalysisResult, Finding, Severity } from "@/lib/logAnalyzer";
import type { Language } from "@/lib/i18n";
import { localize, severityLabel } from "@/lib/i18n";

type CategoryKey =
  | "authentication"
  | "webAttack"
  | "firewall"
  | "windows"
  | "network"
  | "threatIntel"
  | "cloudIdentity"
  | "other";

type CategoryDefinition = {
  key: CategoryKey;
  icon: string;
  title: Record<Language, string>;
  description: Record<Language, string>;
};

type CategoryGroup = CategoryDefinition & {
  findings: Finding[];
  highestSeverity: Severity;
  riskScore: number;
  topSourceIp: string;
};

const severityRank: Record<Severity, number> = {
  Low: 1,
  Medium: 2,
  High: 3,
  Critical: 4,
};

const severityTone: Record<Severity, string> = {
  Critical: "border-red-400/60 bg-red-500/15 text-red-100 shadow-red-950/30",
  High: "border-orange-400/60 bg-orange-500/15 text-orange-100 shadow-orange-950/30",
  Medium: "border-amber-400/60 bg-amber-500/15 text-amber-100 shadow-amber-950/30",
  Low: "border-emerald-400/60 bg-emerald-500/15 text-emerald-100 shadow-emerald-950/30",
};

const categoryDefinitions: CategoryDefinition[] = [
  {
    key: "authentication",
    icon: "🔐",
    title: { th: "การ Login / Credential", en: "Login / Credential" },
    description: {
      th: "รวม failed login, brute force, account lockout และพฤติกรรมเดารหัสผ่าน",
      en: "Failed logons, brute force, account lockout, and password-guessing behavior.",
    },
  },
  {
    key: "webAttack",
    icon: "🌐",
    title: { th: "โจมตีเว็บ / WAF", en: "Web Attack / WAF" },
    description: {
      th: "รวม SQL Injection, XSS, path traversal, WAF block และ web exploit",
      en: "SQL injection, XSS, path traversal, WAF blocks, and web exploit attempts.",
    },
  },
  {
    key: "firewall",
    icon: "🧱",
    title: { th: "Firewall / Port Scan", en: "Firewall / Port Scan" },
    description: {
      th: "รวม deny/drop, port scan, probe service และ traffic ผิดปกติ",
      en: "Deny/drop events, port scans, service probes, and suspicious traffic.",
    },
  },
  {
    key: "windows",
    icon: "🪟",
    title: { th: "Windows Event", en: "Windows Event" },
    description: {
      th: "รวม Event ID, process execution, privilege assignment และ account activity",
      en: "Event IDs, process execution, privilege assignment, and account activity.",
    },
  },
  {
    key: "network",
    icon: "🧭",
    title: { th: "Network Device", en: "Network Device" },
    description: {
      th: "รวม MAC flapping, DAI deny, interface down, BPDU guard และ switch/router log",
      en: "MAC flapping, DAI deny, interface down, BPDU Guard, and switch/router logs.",
    },
  },
  {
    key: "threatIntel",
    icon: "🎯",
    title: { th: "IOC / Threat Intel", en: "IOC / Threat Intel" },
    description: {
      th: "รวม IP, domain, hash, reputation และ indicator ที่ควรเฝ้าระวัง",
      en: "IP, domain, hash, reputation, and indicators that need monitoring.",
    },
  },
  {
    key: "cloudIdentity",
    icon: "☁️",
    title: { th: "Cloud / Identity", en: "Cloud / Identity" },
    description: {
      th: "รวม Microsoft 365, Entra ID, cloud sign-in, MFA และ risky user",
      en: "Microsoft 365, Entra ID, cloud sign-ins, MFA, and risky-user events.",
    },
  },
  {
    key: "other",
    icon: "📦",
    title: { th: "อื่น ๆ", en: "Other" },
    description: {
      th: "เหตุการณ์ที่ยังไม่เข้า pattern หลัก แต่ควรเก็บไว้ดูต่อ",
      en: "Events that do not fit the main patterns yet but should be reviewed.",
    },
  },
];

const labels: Record<Language, Record<string, string>> = {
  th: {
    eyebrow: "ผลวิเคราะห์แบบแยกเรื่อง",
    title: "จัดกลุ่ม Log ให้อ่านง่าย และกดดูรายตัวได้",
    subtitle: "หลังวิเคราะห์ ระบบจะรวม Finding ที่เกี่ยวข้องกันเป็นหมวด เช่น Login, Web Attack, Firewall, Network และ IOC เพื่อให้ไล่ตรวจทีละเรื่องได้เร็วขึ้น",
    categories: "หมวดที่พบ",
    findings: "รายการในหมวดนี้",
    details: "รายละเอียดรายตัว",
    noSelection: "เลือก finding ด้านซ้ายเพื่อดูรายละเอียดหลักฐาน",
    total: "ทั้งหมด",
    risk: "Risk",
    topSource: "Top Source",
    line: "บรรทัด",
    rule: "กฎที่พบ",
    severity: "ความรุนแรง",
    logType: "ชนิด Log",
    sourceIp: "Source IP",
    destinationIp: "Destination IP",
    user: "ผู้ใช้",
    asset: "Asset",
    mitre: "MITRE",
    confidence: "ความมั่นใจ",
    evidence: "หลักฐาน",
    rootCause: "สาเหตุที่เป็นไปได้",
    impact: "ผลกระทบ",
    fix: "แนวทางแก้",
    raw: "Raw Log",
    repeated: "จำนวนซ้ำ",
    none: "ไม่มีข้อมูล",
  },
  en: {
    eyebrow: "Categorized Analysis",
    title: "Group log findings by topic and drill into each item",
    subtitle: "After analysis, related findings are grouped into Login, Web Attack, Firewall, Network, IOC, and other categories so analysts can review one story at a time.",
    categories: "Detected categories",
    findings: "Findings in this category",
    details: "Item details",
    noSelection: "Select a finding on the left to review the evidence details.",
    total: "Total",
    risk: "Risk",
    topSource: "Top Source",
    line: "Line",
    rule: "Matched rule",
    severity: "Severity",
    logType: "Log type",
    sourceIp: "Source IP",
    destinationIp: "Destination IP",
    user: "User",
    asset: "Asset",
    mitre: "MITRE",
    confidence: "Confidence",
    evidence: "Evidence",
    rootCause: "Possible root cause",
    impact: "Impact",
    fix: "Recommended fix",
    raw: "Raw Log",
    repeated: "Repeated",
    none: "None",
  },
};

function getStoredLanguage(): Language {
  if (typeof window === "undefined") return "th";
  const language = window.localStorage.getItem("soc_language");
  return language === "en" || language === "th" ? language : "th";
}

function normalize(value: string | null | undefined): string {
  return String(value ?? "").toLowerCase();
}

function includesAny(value: string, keywords: string[]): boolean {
  return keywords.some((keyword) => value.includes(keyword));
}

function classifyFinding(finding: Finding): CategoryKey {
  const combined = [
    finding.logType,
    finding.rule,
    finding.tactic,
    finding.technique,
    finding.evidence,
    finding.raw,
    finding.domain,
    finding.fileHash,
    finding.iocType,
    ...finding.detectedKeywords,
  ]
    .map(normalize)
    .join(" ");

  if (finding.iocRisk || finding.domain || finding.fileHash || includesAny(combined, ["ioc", "hash", "domain", "reputation", "malware", "c2"])) return "threatIntel";
  if (includesAny(combined, ["microsoft 365", "entra", "azuread", "conditionalaccess", "mfa", "risky user", "cloudtrail", "aws"])) return "cloudIdentity";
  if (includesAny(combined, ["sql", "union select", "xss", "script", "path traversal", "../", "waf", "cloudflare", "apache", "nginx", "http", "login.php"])) return "webAttack";
  if (includesAny(combined, ["failed password", "failed logon", "4625", "4740", "brute", "credential", "ssh", "sshd", "password", "account locked"])) return "authentication";
  if (includesAny(combined, ["firewall", "fortigate", "palo alto", "sophos", "deny", "drop", "dstport", "dpt=", "port scan", "scan", "proto=tcp"])) return "firewall";
  if (includesAny(combined, ["windows event", "event id", "4672", "4720", "4688", "powershell", "security"])) return "windows";
  if (includesAny(combined, ["cisco", "meraki", "macflap", "flapping", "dhcp_snooping", "dai", "lineproto", "bpdu", "switch", "interface", "vlan"])) return "network";
  return "other";
}

function highestSeverity(findings: Finding[]): Severity {
  return findings.reduce<Severity>((highest, finding) => (severityRank[finding.severity] > severityRank[highest] ? finding.severity : highest), "Low");
}

function categoryRiskScore(findings: Finding[]): number {
  if (!findings.length) return 0;
  const total = findings.reduce((sum, finding) => sum + severityRank[finding.severity] * 20 + Math.round(finding.confidence / 10), 0);
  return Math.min(100, Math.round(total / findings.length));
}

function topSourceIp(findings: Finding[]): string {
  const counts = new Map<string, number>();
  findings.forEach((finding) => {
    const ip = finding.sourceIp || "-";
    counts.set(ip, (counts.get(ip) ?? 0) + 1);
  });
  return [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "-";
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-white/10 bg-black/20 p-3">
      <p className="text-[10px] uppercase tracking-[0.16em] text-cyan-200/70">{label}</p>
      <div className="mt-1 break-words text-sm text-slate-100">{value || "-"}</div>
    </div>
  );
}

export default function CategorizedLogInsights() {
  const [language, setLanguage] = useState<Language>("th");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<CategoryKey | null>(null);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);

  useEffect(() => {
    const sync = () => {
      setLanguage(getStoredLanguage());
      try {
        const raw = window.localStorage.getItem("soc_last_result");
        setResult(raw ? (JSON.parse(raw) as AnalysisResult) : null);
      } catch {
        setResult(null);
      }
    };

    sync();
    const interval = window.setInterval(sync, 800);
    window.addEventListener("storage", sync);
    return () => {
      window.clearInterval(interval);
      window.removeEventListener("storage", sync);
    };
  }, []);

  const groups = useMemo<CategoryGroup[]>(() => {
    if (!result?.findings.length) return [];
    return categoryDefinitions
      .map((definition) => {
        const findings = result.findings.filter((finding) => classifyFinding(finding) === definition.key);
        return {
          ...definition,
          findings,
          highestSeverity: highestSeverity(findings),
          riskScore: categoryRiskScore(findings),
          topSourceIp: topSourceIp(findings),
        };
      })
      .filter((group) => group.findings.length > 0)
      .sort((a, b) => severityRank[b.highestSeverity] - severityRank[a.highestSeverity] || b.findings.length - a.findings.length);
  }, [result]);

  useEffect(() => {
    if (!groups.length) return;
    if (!selectedCategory || !groups.some((group) => group.key === selectedCategory)) {
      setSelectedCategory(groups[0].key);
      setSelectedFindingId(null);
    }
  }, [groups, selectedCategory]);

  if (!result || groups.length === 0) return null;

  const t = labels[language];
  const activeGroup = groups.find((group) => group.key === selectedCategory) ?? groups[0];
  const selectedFinding = activeGroup.findings.find((finding) => finding.id === selectedFindingId) ?? null;

  return (
    <section data-i18n-ignore className="mx-auto mt-8 w-full max-w-[1800px] px-4 pb-6 sm:px-6 lg:px-8">
      <div className="overflow-hidden rounded-[2rem] border border-cyan-300/20 bg-slate-950/70 shadow-2xl shadow-cyan-950/20 backdrop-blur-2xl">
        <div className="border-b border-white/10 bg-gradient-to-r from-cyan-400/10 via-violet-500/10 to-transparent p-5 sm:p-6">
          <p className="text-xs font-semibold uppercase tracking-[0.22em] text-cyan-200">{t.eyebrow}</p>
          <div className="mt-2 flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <h2 className="text-2xl font-bold text-white md:text-3xl">{t.title}</h2>
              <p className="mt-2 max-w-4xl text-sm leading-6 text-slate-300">{t.subtitle}</p>
            </div>
            <div className="grid grid-cols-3 gap-2 text-center text-xs sm:min-w-80">
              <div className="rounded-2xl border border-white/10 bg-black/25 p-3">
                <p className="text-slate-400">{t.total}</p>
                <p className="mt-1 text-xl font-semibold text-white">{result.findings.length}</p>
              </div>
              <div className="rounded-2xl border border-white/10 bg-black/25 p-3">
                <p className="text-slate-400">{t.categories}</p>
                <p className="mt-1 text-xl font-semibold text-white">{groups.length}</p>
              </div>
              <div className="rounded-2xl border border-white/10 bg-black/25 p-3">
                <p className="text-slate-400">{t.risk}</p>
                <p className="mt-1 text-xl font-semibold text-white">{result.summary.riskScore}</p>
              </div>
            </div>
          </div>
        </div>

        <div className="grid gap-0 xl:grid-cols-[420px_minmax(0,1fr)]">
          <div className="border-b border-white/10 p-4 xl:border-b-0 xl:border-r">
            <p className="mb-3 text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">{t.categories}</p>
            <div className="space-y-3">
              {groups.map((group) => {
                const active = group.key === activeGroup.key;
                return (
                  <button
                    key={group.key}
                    type="button"
                    onClick={() => {
                      setSelectedCategory(group.key);
                      setSelectedFindingId(null);
                    }}
                    className={`w-full rounded-2xl border p-4 text-left transition duration-200 ${active ? "border-cyan-300/70 bg-cyan-400/15 shadow-lg shadow-cyan-950/30" : "border-white/10 bg-white/[0.03] hover:-translate-y-0.5 hover:border-cyan-300/40 hover:bg-white/[0.06]"}`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex gap-3">
                        <span className="flex h-10 w-10 items-center justify-center rounded-2xl border border-white/10 bg-black/25 text-xl">{group.icon}</span>
                        <div>
                          <h3 className="font-semibold text-white">{group.title[language]}</h3>
                          <p className="mt-1 line-clamp-2 text-xs leading-5 text-slate-400">{group.description[language]}</p>
                        </div>
                      </div>
                      <span className="rounded-full border border-cyan-300/30 bg-cyan-400/10 px-2.5 py-1 text-xs font-semibold text-cyan-100">{group.findings.length}</span>
                    </div>
                    <div className="mt-4 grid grid-cols-3 gap-2 text-xs">
                      <span className={`rounded-xl border px-2 py-1.5 text-center ${severityTone[group.highestSeverity]}`}>{severityLabel(group.highestSeverity, language)}</span>
                      <span className="rounded-xl border border-white/10 bg-black/20 px-2 py-1.5 text-center text-slate-200">{t.risk} {group.riskScore}</span>
                      <span className="truncate rounded-xl border border-white/10 bg-black/20 px-2 py-1.5 text-center text-slate-200" title={group.topSourceIp}>{group.topSourceIp}</span>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="grid gap-0 lg:grid-cols-[minmax(0,1fr)_430px]">
            <div className="border-b border-white/10 p-4 lg:border-b-0 lg:border-r">
              <div className="mb-3 flex items-center justify-between gap-3">
                <div>
                  <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">{t.findings}</p>
                  <h3 className="mt-1 text-lg font-semibold text-white">{activeGroup.icon} {activeGroup.title[language]}</h3>
                </div>
                <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${severityTone[activeGroup.highestSeverity]}`}>{severityLabel(activeGroup.highestSeverity, language)}</span>
              </div>
              <div className="max-h-[620px] space-y-3 overflow-y-auto pr-1">
                {activeGroup.findings.map((finding) => {
                  const active = finding.id === selectedFinding?.id;
                  return (
                    <button
                      key={finding.id}
                      type="button"
                      onClick={() => setSelectedFindingId(finding.id)}
                      className={`w-full rounded-2xl border p-4 text-left transition ${active ? "border-violet-300/70 bg-violet-500/15" : "border-white/10 bg-black/20 hover:border-cyan-300/40 hover:bg-white/[0.05]"}`}
                    >
                      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                        <div>
                          <p className="text-xs text-slate-500">{finding.id} · {t.line} {finding.lineNumber}</p>
                          <h4 className="mt-1 font-semibold text-white">{localize(finding.rule, language)}</h4>
                        </div>
                        <span className={`w-fit rounded-full border px-2.5 py-1 text-xs font-semibold ${severityTone[finding.severity]}`}>{severityLabel(finding.severity, language)}</span>
                      </div>
                      <p className="mt-2 line-clamp-2 text-sm leading-6 text-slate-300">{localize(finding.evidence, language)}</p>
                      <div className="mt-3 flex flex-wrap gap-2 text-xs text-slate-300">
                        <span className="rounded-full border border-white/10 bg-white/[0.04] px-2.5 py-1">{finding.logType}</span>
                        {finding.sourceIp && <span className="rounded-full border border-white/10 bg-white/[0.04] px-2.5 py-1">SRC {finding.sourceIp}</span>}
                        <span className="rounded-full border border-white/10 bg-white/[0.04] px-2.5 py-1">{finding.technique}</span>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            <aside className="p-4">
              <p className="mb-3 text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">{t.details}</p>
              {selectedFinding ? (
                <div className="space-y-3">
                  <div className="rounded-2xl border border-cyan-300/30 bg-cyan-400/10 p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <p className="text-xs text-cyan-100/70">{selectedFinding.id} · {t.line} {selectedFinding.lineNumber}</p>
                        <h3 className="mt-1 text-lg font-semibold text-white">{localize(selectedFinding.rule, language)}</h3>
                      </div>
                      <span className={`rounded-full border px-2.5 py-1 text-xs font-semibold ${severityTone[selectedFinding.severity]}`}>{severityLabel(selectedFinding.severity, language)}</span>
                    </div>
                  </div>

                  <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-1">
                    <Field label={t.logType} value={selectedFinding.logType} />
                    <Field label={t.sourceIp} value={selectedFinding.sourceIp ?? t.none} />
                    <Field label={t.destinationIp} value={selectedFinding.destinationIp ?? t.none} />
                    <Field label={t.user} value={selectedFinding.username ?? t.none} />
                    <Field label={t.asset} value={selectedFinding.asset ?? t.none} />
                    <Field label={t.mitre} value={`${selectedFinding.tactic} · ${selectedFinding.technique}`} />
                    <Field label={t.confidence} value={`${selectedFinding.confidence}%`} />
                    <Field label={t.repeated} value={selectedFinding.repeatedCount} />
                  </div>

                  <Field label={t.evidence} value={localize(selectedFinding.evidence, language)} />
                  <Field label={t.rootCause} value={localize(selectedFinding.possibleRootCause, language)} />
                  <Field label={t.impact} value={localize(selectedFinding.impact, language)} />
                  <Field label={t.fix} value={localize(selectedFinding.recommendedFix, language)} />

                  <div className="rounded-2xl border border-white/10 bg-black/30 p-4">
                    <p className="text-[10px] uppercase tracking-[0.16em] text-cyan-200/70">{t.raw}</p>
                    <pre className="mt-2 max-h-56 overflow-auto whitespace-pre-wrap break-words rounded-xl bg-black/35 p-3 font-mono text-xs leading-5 text-slate-200">{selectedFinding.raw}</pre>
                  </div>
                </div>
              ) : (
                <div className="rounded-2xl border border-dashed border-white/15 bg-white/[0.03] p-8 text-center text-sm leading-6 text-slate-400">{t.noSelection}</div>
              )}
            </aside>
          </div>
        </div>
      </div>
    </section>
  );
}

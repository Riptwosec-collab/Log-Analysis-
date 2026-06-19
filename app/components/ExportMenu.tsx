"use client";

import type { AnalysisResult, Finding } from "@/lib/logAnalyzer";
import type { Language } from "@/lib/i18n";
import { localize, severityLabel, UI } from "@/lib/i18n";

interface Props {
  result: AnalysisResult;
  findings: Finding[];
  language: Language;
  t: Record<string, string>;
}

function csvCell(value: string): string {
  return `"${value.replace(/"/g, '""')}"`;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function buildExport(
  format: "json" | "csv" | "txt",
  result: AnalysisResult,
  findings: Finding[],
  language: Language
): string {
  if (format === "json") {
    const localized = {
      generatedAt: result.generatedAt,
      language,
      summary: {
        ...result.summary,
        incidentNarrative: localize(result.summary.incidentNarrative, language),
        recommendedActions: result.summary.recommendedActions.map((item) =>
          localize(item, language)
        ),
        correlations: result.summary.correlations.map((item) => ({
          ...item,
          title: localize(item.title, language),
          description: localize(item.description, language),
          recommendedAction: localize(item.recommendedAction, language),
        })),
        analystReport: {
          socAnalyst: localize(result.summary.analystReport.socAnalyst, language),
          rca: localize(result.summary.analystReport.rca, language),
          managerSummary: localize(result.summary.analystReport.managerSummary, language),
          fixCommand: localize(result.summary.analystReport.fixCommand, language),
          ticket: localize(result.summary.analystReport.ticket, language),
        },
      },
      findings: findings.map((f) => ({
        ...f,
        rule: localize(f.rule, language),
        possibleRootCause: localize(f.possibleRootCause, language),
        impact: localize(f.impact, language),
        recommendedFix: localize(f.recommendedFix, language),
        iocDescription: localize(f.iocDescription || "", language),
      })),
    };
    return JSON.stringify(localized, null, 2);
  }

  if (format === "csv") {
    const rows = [
      [
        "id", "line", "severity", "confidence", "type", "timestamp",
        "source_ip", "destination_ip", "destination_port", "username",
        "asset", "interface", "vlan", "mac", "ioc_type", "ioc_risk",
        "ioc_description", "country", "asn", "abuse_score", "rule",
        "tactic", "technique", "repeat", "evidence", "root_cause",
        "impact", "recommendation", "raw",
      ],
      ...findings.map((f) => [
        f.id,
        String(f.lineNumber),
        severityLabel(f.severity, language),
        String(f.confidence),
        f.logType,
        f.timestamp || "",
        f.sourceIp || "",
        f.destinationIp || "",
        f.destinationPort || "",
        f.username || "",
        f.asset || "",
        f.interfaceName || "",
        f.vlan || "",
        f.macAddress || "",
        localize(f.iocType || "", language),
        f.iocRisk || "",
        localize(f.iocDescription || "", language),
        f.geoCountry || "",
        f.asn || "",
        f.abuseScore !== null && f.abuseScore !== undefined
          ? String(f.abuseScore)
          : "",
        localize(f.rule, language),
        f.tactic,
        f.technique,
        String(f.repeatedCount),
        localize(f.evidence, language),
        localize(f.possibleRootCause, language),
        localize(f.impact, language),
        localize(f.recommendedFix, language),
        f.raw,
      ]),
    ];
    return rows.map((row) => row.map(csvCell).join(",")).join("\n");
  }

  // txt
  const u = UI[language];
  const criticalFindings = findings.filter((f) => f.severity === "Critical");
  const iocFindings = findings.filter((f) => f.iocType);

  return [
    u.reportTitle,
    "",
    "Executive Summary",
    `${u.generatedAt}: ${result.generatedAt}`,
    `${u.totalEvents}: ${result.summary.totalEvents}`,
    `${u.suspicious}: ${result.summary.suspiciousEvents}`,
    `${u.critical}: ${result.summary.criticalAlerts}`,
    `IOC Hits: ${result.summary.iocHits}`,
    `${u.riskScore}: ${result.summary.riskScore}/100 (${severityLabel(result.summary.riskLevel, language)})`,
    `${u.topSourceIp}: ${result.summary.topSourceIp || u.none}`,
    `${language === "th" ? "สรุป" : "Summary"}: ${localize(result.summary.incidentNarrative, language)}`,
    "",
    "AI Analyst Summary",
    localize(result.summary.analystReport.socAnalyst, language),
    "",
    u.managerSummary,
    localize(result.summary.analystReport.managerSummary, language),
    "",
    "Timeline",
    ...(result.summary.timeline.length
      ? result.summary.timeline.map(
          (item) =>
            `${item.timestamp} | ${item.count} events | ${severityLabel(item.severity, language)}`
        )
      : [u.noTimestamp]),
    "",
    "Critical Events",
    ...(criticalFindings.length
      ? criticalFindings.map(
          (f) =>
            `${f.id} | ${localize(f.rule, language)} | ${f.sourceIp || "-"} | ${localize(f.evidence, language)}`
        )
      : [u.none]),
    "",
    "MITRE Mapping",
    ...(result.summary.mitreTechniques.length
      ? result.summary.mitreTechniques
      : [u.none]),
    "",
    "IOC / Threat Intelligence",
    ...(iocFindings.length
      ? iocFindings.map(
          (f) =>
            `${f.id} | ${localize(f.iocType || "", language)} | Risk=${f.iocRisk} | Abuse=${f.abuseScore ?? "-"} | ${localize(f.iocDescription || "", language)}`
        )
      : [u.none]),
    "",
    u.correlationTitle,
    ...(result.summary.correlations.length
      ? result.summary.correlations.map(
          (item) =>
            `${severityLabel(item.severity, language)} | ${localize(item.title, language)} | Confidence ${item.confidence ?? "-"}% | MITRE ${(item.mitreTechniques || []).join(", ")} | ${localize(item.description, language)} | ${localize(item.recommendedAction, language)}`
        )
      : [u.none]),
    "",
    "Root Cause / Impact / Recommended Action",
    localize(result.summary.analystReport.rca, language),
    "",
    "Fix Command / Checklist",
    localize(result.summary.analystReport.fixCommand, language),
    "",
    "Incident Ticket",
    localize(result.summary.analystReport.ticket, language),
    "",
    "Raw Evidence / Findings",
    ...findings.flatMap((f) => [
      `${f.id} | ${severityLabel(f.severity, language)} | ${f.confidence}% | ${f.logType} | ${localize(f.rule, language)}`,
      `${u.time}: ${f.timestamp || u.notFoundTime} | Source: ${f.sourceIp || "-"} | User: ${f.username || "-"} | Port: ${f.destinationPort || "-"} | Asset: ${f.asset || "-"}`,
      `MITRE: ${f.technique} | Tactic: ${f.tactic}`,
      `${u.evidence}: ${localize(f.evidence, language)}`,
      `Keyword: ${f.detectedKeywords.join(", ") || u.none}`,
      `IOC: ${localize(f.iocType || u.none, language)} | Country: ${f.geoCountry || "-"} | ASN: ${f.asn || "-"} | Abuse: ${f.abuseScore ?? "-"}`,
      `${u.rootCause}: ${localize(f.possibleRootCause, language)}`,
      `${u.impact}: ${localize(f.impact, language)}`,
      `${u.fix}: ${localize(f.recommendedFix, language)}`,
      `Raw: ${f.raw}`,
      "",
    ]),
  ].join("\n");
}

function buildCEF(findings: Finding[], result: AnalysisResult): string {
  const severityInt: Record<string, number> = { Low: 3, Medium: 5, High: 7, Critical: 9 };
  const header = `# CEF Export — SOC Dashboard | Generated: ${result.generatedAt}\n`;
  const rows = findings
    .map(
      (f) =>
        `CEF:0|SOCDashboard|LogAnalyzer|1.0|${f.rule.replace(/\|/g, "")}|${f.rule.replace(/\|/g, "")}|${severityInt[f.severity] ?? 5}|` +
        `src=${f.sourceIp ?? "-"} dst=${f.destinationIp ?? "-"} dpt=${f.destinationPort ?? "-"} ` +
        `suser=${f.username ?? "-"} msg=${f.evidence.replace(/\n/g, " ")} ` +
        `cs1=${f.technique} cs1Label=MITRETechnique confidence=${f.confidence}`
    )
    .join("\n");
  return header + rows;
}

function buildLEEF(findings: Finding[], result: AnalysisResult): string {
  const header = `# LEEF Export — SOC Dashboard | Generated: ${result.generatedAt}\n`;
  const rows = findings
    .map(
      (f) =>
        `LEEF:2.0|SOCDashboard|LogAnalyzer|1.0|${encodeURIComponent(f.rule)}|` +
        `cat=${f.severity}\tsrc=${f.sourceIp ?? "-"}\tdst=${f.destinationIp ?? "-"}\t` +
        `dstPort=${f.destinationPort ?? "-"}\tusrName=${f.username ?? "-"}\t` +
        `msg=${f.evidence.replace(/\t/g, " ")}\ttechnique=${f.technique}\tconfidence=${f.confidence}`
    )
    .join("\n");
  return header + rows;
}

async function exportPDF(
  result: AnalysisResult,
  findings: Finding[],
  language: Language
) {
  if (!(window as any).jspdf) {
    await new Promise<void>((resolve, reject) => {
      const s = document.createElement("script");
      s.src =
        "https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js";
      s.onload = () => resolve();
      s.onerror = () => reject(new Error("Failed to load jsPDF"));
      document.head.appendChild(s);
    });
  }
  const { jsPDF } = (window as any).jspdf;
  const doc = new jsPDF({ orientation: "landscape", unit: "mm", format: "a4" });

  doc.setFontSize(16);
  doc.text("SOC Analytics — Incident Report", 14, 15);
  doc.setFontSize(9);
  doc.text(
    `Generated: ${result.generatedAt}  |  Risk: ${result.summary.riskLevel}  |  Score: ${result.summary.riskScore}/100`,
    14,
    22
  );

  doc.setFontSize(10);
  const summaryLines = [
    `Total Events: ${result.summary.totalEvents}`,
    `Suspicious: ${result.summary.suspiciousEvents}`,
    `Critical: ${result.summary.criticalAlerts}`,
    `Failed Logins: ${result.summary.failedLogins}`,
    `Top Source IP: ${result.summary.topSourceIp ?? "-"}`,
    `IOC Hits: ${result.summary.iocHits}`,
  ];
  doc.text(summaryLines.join("   |   "), 14, 30);

  let y = 40;
  const cols = [
    "#", "Severity", "Rule", "Source IP", "Username",
    "Port", "Confidence", "Technique", "Timestamp",
  ];
  const colWidths = [10, 22, 60, 32, 28, 18, 22, 40, 36];
  doc.setFillColor(30, 41, 59);
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(8);
  doc.rect(14, y - 5, 268, 7, "F");
  let x = 14;
  cols.forEach((col, i) => {
    doc.text(col, x + 1, y);
    x += colWidths[i];
  });
  doc.setTextColor(0, 0, 0);
  y += 4;

  findings.forEach((f, idx) => {
    if (y > 190) {
      doc.addPage();
      y = 15;
    }
    const rowColor: [number, number, number] =
      f.severity === "Critical"
        ? [254, 202, 202]
        : f.severity === "High"
        ? [254, 215, 170]
        : f.severity === "Medium"
        ? [254, 249, 195]
        : [220, 252, 231];
    doc.setFillColor(...rowColor);
    doc.rect(14, y - 4, 268, 6, "F");
    doc.setFontSize(7);
    const cells = [
      String(idx + 1),
      f.severity,
      localize(f.rule, language).slice(0, 38),
      f.sourceIp ?? "-",
      f.username ?? "-",
      f.destinationPort ?? "-",
      String(f.confidence) + "%",
      f.technique.slice(0, 28),
      f.timestamp ?? "-",
    ];
    x = 14;
    cells.forEach((cell, i) => {
      doc.text(String(cell), x + 1, y);
      x += colWidths[i];
    });
    y += 6;
  });

  doc.save(`soc-report-${new Date().toISOString().slice(0, 10)}.pdf`);
}

export default function ExportMenu({ result, findings, language, t }: Props) {
  function downloadFile(format: "json" | "csv" | "txt") {
    const filenamePrefix = language === "th" ? "รายงาน-soc" : "soc-report";
    const filename = `${filenamePrefix}-${new Date().toISOString().slice(0, 10)}.${format}`;
    const content = buildExport(format, result, findings, language);
    const type =
      format === "json" ? "application/json" : "text/plain;charset=utf-8";
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
  }

  function downloadCEF() {
    const content = buildCEF(findings, result);
    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `soc-report-${new Date().toISOString().slice(0, 10)}.cef`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function downloadLEEF() {
    const content = buildLEEF(findings, result);
    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `soc-report-${new Date().toISOString().slice(0, 10)}.leef`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="flex flex-wrap gap-2">
      <button
        className="rounded-md border border-zinc-700 px-3 py-2 text-sm hover:border-cyan-500"
        onClick={() => downloadFile("txt")}
      >
        TXT
      </button>
      <button
        className="rounded-md border border-zinc-700 px-3 py-2 text-sm hover:border-cyan-500"
        onClick={() => downloadFile("csv")}
      >
        CSV
      </button>
      <button
        className="rounded-md border border-zinc-700 px-3 py-2 text-sm hover:border-cyan-500"
        onClick={() => downloadFile("json")}
      >
        JSON
      </button>
      <button
        className="rounded-md border border-zinc-700 px-3 py-2 text-sm hover:border-cyan-500"
        onClick={() => exportPDF(result, findings, language)}
      >
        PDF
      </button>
      <button
        className="rounded-md border border-zinc-700 px-3 py-2 text-sm hover:border-cyan-500"
        onClick={downloadCEF}
        title="Common Event Format"
      >
        CEF
      </button>
      <button
        className="rounded-md border border-zinc-700 px-3 py-2 text-sm hover:border-cyan-500"
        onClick={downloadLEEF}
        title="Log Event Extended Format"
      >
        LEEF
      </button>
    </div>
  );
}

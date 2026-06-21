"use client";

import { useState, useMemo, useEffect } from "react";
import type { Finding, Severity } from "@/lib/logAnalyzer";
import type { Language } from "@/lib/i18n";
import { localize, severityLabel, severityClass, severityOptionLabel } from "@/lib/i18n";

const PAGE_SIZE = 50;

const SEVERITY_RANK: Record<Severity, number> = {
  Low: 1,
  Medium: 2,
  High: 3,
  Critical: 4,
};

const severityOptions: Array<Severity | "All"> = [
  "All",
  "Critical",
  "High",
  "Medium",
  "Low",
];

type SortKey = "severity" | "confidence" | "timestamp" | "repeatedCount";
type SortDir = "asc" | "desc";

interface Props {
  findings: Finding[];
  language: Language;
  t: Record<string, string>;
  localize: (v: string | null | undefined, lang: Language) => string;
  onViewEvidence?: (finding: Finding) => void;
}

export default function FindingsTable({
  findings,
  language,
  t,
  onViewEvidence,
}: Props) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<Severity | "All">("All");
  const [logType, setLogType] = useState("All");
  const [timestampFilter, setTimestampFilter] = useState("");
  const [page, setPage] = useState(1);
  const [sortKey, setSortKey] = useState<SortKey | null>(null);
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const logTypes = useMemo(() => {
    const types = new Set(findings.map((f) => f.logType));
    return ["All", ...Array.from(types).sort()];
  }, [findings]);

  // Reset to page 1 when filters change
  useEffect(() => {
    setPage(1);
  }, [query, severity, logType, timestampFilter, sortKey, sortDir]);

  const filtered = useMemo(() => {
    const needle = query.toLowerCase().trim();
    return findings.filter((f) => {
      const blob = [
        f.id,
        localize(f.rule, language),
        f.raw,
        f.sourceIp || "",
        f.destinationPort || "",
        f.username || "",
        f.technique,
        f.tactic,
        f.detectedKeywords.join(" "),
        localize(f.possibleRootCause, language),
        localize(f.recommendedFix, language),
      ]
        .join(" ")
        .toLowerCase();
      const matchesQuery = !needle || blob.includes(needle);
      const matchesSeverity = severity === "All" || f.severity === severity;
      const matchesType = logType === "All" || f.logType === logType;
      const matchesTimestamp =
        !timestampFilter || (f.timestamp || "").includes(timestampFilter);
      return matchesQuery && matchesSeverity && matchesType && matchesTimestamp;
    });
  }, [findings, query, severity, logType, timestampFilter, language]);

  const sorted = useMemo(() => {
    if (!sortKey) return filtered;
    return [...filtered].sort((a, b) => {
      let av: number | string;
      let bv: number | string;
      if (sortKey === "severity") {
        av = SEVERITY_RANK[a.severity] ?? 0;
        bv = SEVERITY_RANK[b.severity] ?? 0;
      } else if (sortKey === "confidence") {
        av = a.confidence;
        bv = b.confidence;
      } else if (sortKey === "timestamp") {
        av = a.timestamp || "";
        bv = b.timestamp || "";
      } else {
        av = a.repeatedCount;
        bv = b.repeatedCount;
      }
      if (av < bv) return sortDir === "asc" ? -1 : 1;
      if (av > bv) return sortDir === "asc" ? 1 : -1;
      return 0;
    });
  }, [filtered, sortKey, sortDir]);

  const totalPages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const pageStart = (safePage - 1) * PAGE_SIZE;
  const pageEnd = Math.min(safePage * PAGE_SIZE, sorted.length);
  const paginated = sorted.slice(pageStart, pageEnd);

  function toggleSort(key: SortKey) {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("desc");
    }
  }

  function SortIndicator({ col }: { col: SortKey }) {
    if (sortKey !== col) return <span className="ml-1 text-zinc-600">⇅</span>;
    return (
      <span className="ml-1 text-cyan-400">{sortDir === "asc" ? "▲" : "▼"}</span>
    );
  }

  function SortTh({
    col,
    children,
  }: {
    col: SortKey;
    children: React.ReactNode;
  }) {
    return (
      <th
        className="cursor-pointer select-none py-3 pr-3 hover:text-cyan-300"
        onClick={() => toggleSort(col)}
      >
        {children}
        <SortIndicator col={col} />
      </th>
    );
  }

  return (
    <div>
      {/* Filters */}
      <div className="mt-4 grid gap-2 md:grid-cols-4">
        <input
          className="rounded-md border border-zinc-800 bg-black px-3 py-2 text-sm outline-none focus:border-cyan-500"
          placeholder={t.searchPlaceholder}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <select
          className="rounded-md border border-zinc-800 bg-black px-3 py-2 text-sm outline-none focus:border-cyan-500"
          value={severity}
          onChange={(e) => setSeverity(e.target.value as Severity | "All")}
        >
          {severityOptions.map((opt) => (
            <option key={opt} value={opt}>
              {severityOptionLabel(opt, language)}
            </option>
          ))}
        </select>
        <select
          className="rounded-md border border-zinc-800 bg-black px-3 py-2 text-sm outline-none focus:border-cyan-500"
          value={logType}
          onChange={(e) => setLogType(e.target.value)}
        >
          {logTypes.map((opt) => (
            <option key={opt} value={opt}>
              {opt === "All" ? t.allLogTypes : opt}
            </option>
          ))}
        </select>
        <input
          className="rounded-md border border-zinc-800 bg-black px-3 py-2 text-sm outline-none focus:border-cyan-500"
          placeholder={t.timestampSearch}
          value={timestampFilter}
          onChange={(e) => setTimestampFilter(e.target.value)}
        />
      </div>

      {/* Pagination info */}
      {sorted.length > 0 && (
        <div className="mt-3 flex items-center justify-between text-xs text-zinc-400">
          <span>
            {t.showing} {pageStart + 1}–{pageEnd} {t.of} {sorted.length}{" "}
            {t.events}
          </span>
          <div className="flex items-center gap-2">
            <button
              className="rounded border border-zinc-700 px-3 py-1 hover:border-cyan-500 disabled:opacity-40"
              disabled={safePage <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
            >
              {t.prev}
            </button>
            <span>
              {t.page} {safePage}/{totalPages}
            </span>
            <button
              className="rounded border border-zinc-700 px-3 py-1 hover:border-cyan-500 disabled:opacity-40"
              disabled={safePage >= totalPages}
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            >
              {t.next}
            </button>
          </div>
        </div>
      )}

      {/* Table */}
      <div className="mt-4 overflow-x-auto">
        <table className="w-full min-w-[1280px] border-collapse text-left text-sm">
          <thead className="border-b border-zinc-800 text-xs uppercase tracking-[0.14em] text-zinc-500">
            <tr>
              <th className="py-3 pr-3">ID</th>
              <SortTh col="severity">{t.severity}</SortTh>
              <SortTh col="confidence">{t.confidence}</SortTh>
              <th className="py-3 pr-3">{t.type}</th>
              <SortTh col="timestamp">{t.time}</SortTh>
              <th className="py-3 pr-3">Source</th>
              <th className="py-3 pr-3">{t.userPort}</th>
              <th className="py-3 pr-3">MITRE</th>
              <th className="py-3 pr-3">{t.assetIoc}</th>
              <th className="py-3 pr-3">{t.ruleRcaFix}</th>
              <SortTh col="repeatedCount">{t.repeat}</SortTh>
              {onViewEvidence && <th className="py-3 pr-3">Action</th>}
            </tr>
          </thead>
          <tbody>
            {paginated.map((finding) => (
              <tr
                key={finding.id}
                className="border-b border-zinc-900 align-top hover:bg-zinc-800/50"
              >
                <td className="py-3 pr-3 font-mono text-xs text-zinc-400">
                  {finding.id}
                </td>
                <td className="py-3 pr-3">
                  <span
                    className={`rounded px-2 py-1 text-xs font-semibold ${severityClass(finding.severity)}`}
                  >
                    {severityLabel(finding.severity, language)}
                  </span>
                </td>
                <td className="py-3 pr-3 font-mono text-xs text-zinc-300">
                  {finding.confidence}%
                </td>
                <td className="py-3 pr-3 text-zinc-300">{finding.logType}</td>
                <td className="py-3 pr-3 font-mono text-xs text-zinc-400">
                  {finding.timestamp || t.notFoundTime}
                </td>
                <td className="py-3 pr-3 font-mono text-xs text-cyan-300">
                  {finding.sourceIp || "-"}
                </td>
                <td className="py-3 pr-3 text-xs text-zinc-300">
                  <p>{finding.username || "-"}</p>
                  <p className="mt-1 font-mono text-zinc-500">
                    {finding.destinationPort ? `:${finding.destinationPort}` : ""}
                  </p>
                </td>
                <td className="py-3 pr-3">
                  <p className="text-xs font-medium text-zinc-200">
                    {finding.technique}
                  </p>
                  <p className="mt-1 text-xs text-zinc-500">{finding.tactic}</p>
                </td>
                <td className="py-3 pr-3 text-xs text-zinc-300">
                  <p>{finding.asset || "-"}</p>
                  {finding.interfaceName && (
                    <p className="mt-1 font-mono text-zinc-500">
                      IF: {finding.interfaceName}
                    </p>
                  )}
                  {finding.vlan && (
                    <p className="mt-1 font-mono text-zinc-500">
                      VLAN: {finding.vlan}
                    </p>
                  )}
                  {finding.macAddress && (
                    <p className="mt-1 font-mono text-zinc-500">
                      MAC: {finding.macAddress}
                    </p>
                  )}
                  {finding.iocType && (
                    <p className="mt-2 rounded border border-red-800 bg-red-950/40 px-2 py-1 text-red-200">
                      IOC: {localize(finding.iocType, language)}
                    </p>
                  )}
                  {finding.abuseScore !== null &&
                    finding.abuseScore !== undefined && (
                      <p className="mt-1 text-red-300">
                        Abuse: {finding.abuseScore}
                      </p>
                    )}
                </td>
                <td className="py-3 pr-3">
                  <p className="font-medium text-white">
                    {localize(finding.rule, language)}
                  </p>
                  <p className="mt-1 text-xs text-cyan-300">
                    {t.evidence}: {localize(finding.evidence, language)}
                  </p>
                  <p className="mt-1 max-w-xl text-xs leading-5 text-zinc-400">
                    {t.rootCause}: {localize(finding.possibleRootCause, language)}
                  </p>
                  <p className="mt-1 max-w-xl text-xs leading-5 text-zinc-400">
                    {t.impact}: {localize(finding.impact, language)}
                  </p>
                  <p className="mt-1 max-w-xl text-xs leading-5 text-emerald-300">
                    {t.fix}: {localize(finding.recommendedFix, language)}
                  </p>
                  {finding.iocDescription && (
                    <p className="mt-1 max-w-xl text-xs leading-5 text-red-200">
                      Threat Intel: {localize(finding.iocDescription, language)}
                    </p>
                  )}
                  <p className="mt-2 max-w-xl font-mono text-xs leading-5 text-zinc-500">
                    Raw: {finding.raw}
                  </p>
                </td>
                <td className="py-3 pr-3 font-mono text-zinc-300">
                  {finding.repeatedCount}
                </td>
                {onViewEvidence && (
                  <td className="py-3 pr-3">
                    <button
                      onClick={() => onViewEvidence(finding)}
                      className="rounded border border-cyan-800 bg-cyan-950/30 px-2 py-1 text-xs text-cyan-400 hover:border-cyan-600 hover:text-cyan-300 whitespace-nowrap"
                    >
                      🔍 Evidence
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
        {sorted.length === 0 && (
          <p className="py-8 text-center text-sm text-zinc-500">
            {t.noMatchingEvents}
          </p>
        )}
      </div>

      {/* Bottom pagination */}
      {sorted.length > PAGE_SIZE && (
        <div className="mt-4 flex items-center justify-center gap-3 text-sm">
          <button
            className="rounded border border-zinc-700 px-4 py-2 hover:border-cyan-500 disabled:opacity-40"
            disabled={safePage <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
          >
            {t.prev}
          </button>
          <span className="text-zinc-400">
            {t.page} {safePage} / {totalPages}
          </span>
          <button
            className="rounded border border-zinc-700 px-4 py-2 hover:border-cyan-500 disabled:opacity-40"
            disabled={safePage >= totalPages}
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
          >
            {t.next}
          </button>
        </div>
      )}
    </div>
  );
}

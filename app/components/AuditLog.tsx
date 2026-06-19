"use client";
import { useState, useEffect, useCallback } from "react";
import type { Language } from "@/lib/i18n";

type AuditEntry = {
  ts: string;
  ip: string;
  logSize: number;
  riskScore: number | null;
  riskLevel: string | null;
  findingCount: number | null;
  criticalCount: number | null;
  status: string;
};

type Props = { language: Language; t: Record<string, string> };

const RISK_COLORS: Record<string, string> = {
  Low: "bg-green-900 text-green-300",
  Medium: "bg-yellow-900 text-yellow-300",
  High: "bg-orange-900 text-orange-300",
  Critical: "bg-red-900 text-red-300",
};

export default function AuditLog({ language, t }: Props) {
  const [collapsed, setCollapsed] = useState(false);
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const fetchAudit = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/api/audit");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setEntries(data.entries ?? []);
    } catch (e: any) {
      setError(e.message || "Failed to load audit log");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAudit();
  }, [fetchAudit]);

  function handleExportCSV() {
    const header =
      "timestamp,ip,log_size_bytes,risk_score,risk_level,finding_count,critical_count,status";
    const rows = entries.map(
      (e) =>
        `"${e.ts}","${e.ip}","${e.logSize}","${e.riskScore ?? ""}","${e.riskLevel ?? ""}","${e.findingCount ?? ""}","${e.criticalCount ?? ""}","${e.status}"`
    );
    const blob = new Blob([[header, ...rows].join("\n")], {
      type: "text/csv;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "soc-audit-log.csv";
    a.click();
    URL.revokeObjectURL(url);
  }

  function formatTs(ts: string) {
    try {
      return new Date(ts).toLocaleString();
    } catch {
      return ts;
    }
  }

  function formatKB(bytes: number) {
    if (!bytes) return "0 B";
    if (bytes < 1024) return `${bytes} B`;
    return `${(bytes / 1024).toFixed(1)} KB`;
  }

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900">
      {/* Header */}
      <button
        className="flex w-full items-center justify-between px-4 py-3 text-left"
        onClick={() => setCollapsed((c) => !c)}
      >
        <span className="font-semibold text-white">
          Audit Log{" "}
          <span className="ml-1 rounded-full bg-zinc-700 px-2 py-0.5 text-xs text-zinc-300">
            {entries.length} entries
          </span>
        </span>
        <span className="text-zinc-400">{collapsed ? "▸" : "▾"}</span>
      </button>

      {!collapsed && (
        <div className="border-t border-zinc-800 p-4 space-y-4">
          {/* Toolbar */}
          <div className="flex gap-2">
            <button
              className="rounded-md border border-zinc-700 px-3 py-1.5 text-sm hover:border-cyan-500 disabled:opacity-50"
              onClick={fetchAudit}
              disabled={loading}
            >
              {loading ? "Loading…" : "Refresh"}
            </button>
            <button
              className="rounded-md border border-zinc-700 px-3 py-1.5 text-sm hover:border-cyan-500 disabled:opacity-50"
              onClick={handleExportCSV}
              disabled={entries.length === 0}
            >
              Export CSV
            </button>
          </div>

          {error && (
            <p className="text-sm text-red-400">{error}</p>
          )}

          {/* Table or empty state */}
          {entries.length === 0 && !loading && !error ? (
            <p className="text-sm text-zinc-500">No audit entries yet.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-zinc-700 text-left text-xs text-zinc-400">
                    <th className="pb-2 pr-3 whitespace-nowrap">Timestamp</th>
                    <th className="pb-2 pr-3">IP</th>
                    <th className="pb-2 pr-3 whitespace-nowrap">Log Size</th>
                    <th className="pb-2 pr-3 whitespace-nowrap">Risk Score</th>
                    <th className="pb-2 pr-3 whitespace-nowrap">Risk Level</th>
                    <th className="pb-2 pr-3">Findings</th>
                    <th className="pb-2 pr-3">Criticals</th>
                    <th className="pb-2">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {entries.map((entry, idx) => (
                    <tr
                      key={idx}
                      className="border-b border-zinc-800 hover:bg-zinc-800/50"
                    >
                      <td className="py-2 pr-3 text-xs text-zinc-300 whitespace-nowrap">
                        {formatTs(entry.ts)}
                      </td>
                      <td className="py-2 pr-3 font-mono text-xs text-zinc-300">
                        {entry.ip || "—"}
                      </td>
                      <td className="py-2 pr-3 text-xs text-zinc-400 whitespace-nowrap">
                        {formatKB(entry.logSize)}
                      </td>
                      <td className="py-2 pr-3 text-xs text-zinc-300">
                        {entry.riskScore !== null && entry.riskScore !== undefined
                          ? `${entry.riskScore}/100`
                          : "—"}
                      </td>
                      <td className="py-2 pr-3">
                        {entry.riskLevel ? (
                          <span
                            className={`rounded px-2 py-0.5 text-xs font-medium ${
                              RISK_COLORS[entry.riskLevel] ?? "bg-zinc-700 text-zinc-300"
                            }`}
                          >
                            {entry.riskLevel}
                          </span>
                        ) : (
                          <span className="text-zinc-600 text-xs">—</span>
                        )}
                      </td>
                      <td className="py-2 pr-3 text-xs text-zinc-300">
                        {entry.findingCount ?? "—"}
                      </td>
                      <td className="py-2 pr-3 text-xs text-zinc-300">
                        {entry.criticalCount ?? "—"}
                      </td>
                      <td className="py-2">
                        <span
                          className={`rounded px-2 py-0.5 text-xs font-medium ${
                            entry.status === "success"
                              ? "bg-green-900 text-green-300"
                              : "bg-red-900 text-red-300"
                          }`}
                        >
                          {entry.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

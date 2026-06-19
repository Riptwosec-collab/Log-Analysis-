"use client";
import { useState, useEffect } from "react";
import type { Language } from "@/lib/i18n";

export type CustomIoc = {
  id: string;
  indicator: string;
  type: "ip" | "domain" | "hash";
  risk: "Low" | "Medium" | "High" | "Critical";
  description: string;
  source: string;
  addedAt: string;
};

type Props = { language: Language; t: Record<string, string> };

const STORAGE_KEY = "soc_custom_iocs";

const RISK_COLORS: Record<string, string> = {
  Low: "bg-green-900 text-green-300",
  Medium: "bg-yellow-900 text-yellow-300",
  High: "bg-orange-900 text-orange-300",
  Critical: "bg-red-900 text-red-300",
};

const TYPE_COLORS: Record<string, string> = {
  ip: "bg-blue-900 text-blue-300",
  domain: "bg-purple-900 text-purple-300",
  hash: "bg-zinc-700 text-zinc-300",
};

// ── Type auto-detect ─────────────────────────────────────────────────────────

function detectType(v: string): "ip" | "domain" | "hash" {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v.trim())) return "ip";
  if (/^[a-f0-9]{32,64}$/i.test(v.trim())) return "hash";
  return "domain";
}

// ── Hook ─────────────────────────────────────────────────────────────────────

export function useCustomIocs() {
  const [iocs, setIocs] = useState<CustomIoc[]>([]);
  useEffect(() => {
    try {
      setIocs(JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]"));
    } catch {}
  }, []);
  const save = (i: CustomIoc[]) => {
    setIocs(i);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(i));
  };
  return {
    iocs,
    addIoc: (i: CustomIoc) => save([...iocs, i]),
    deleteIoc: (id: string) => save(iocs.filter((x) => x.id !== id)),
  };
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function IocManager({ language, t }: Props) {
  const { iocs, addIoc, deleteIoc } = useCustomIocs();
  const [collapsed, setCollapsed] = useState(false);
  const [activeTab, setActiveTab] = useState<"all" | "ip" | "domain" | "hash">("all");
  const [showForm, setShowForm] = useState(false);
  const [showBulk, setShowBulk] = useState(false);

  // Single-add form
  const [formIndicator, setFormIndicator] = useState("");
  const [formType, setFormType] = useState<CustomIoc["type"]>("ip");
  const [formRisk, setFormRisk] = useState<CustomIoc["risk"]>("Medium");
  const [formDesc, setFormDesc] = useState("");
  const [formSource, setFormSource] = useState("");

  // Bulk import
  const [bulkText, setBulkText] = useState("");

  const counts = {
    all: iocs.length,
    ip: iocs.filter((i) => i.type === "ip").length,
    domain: iocs.filter((i) => i.type === "domain").length,
    hash: iocs.filter((i) => i.type === "hash").length,
  };

  const filtered =
    activeTab === "all" ? iocs : iocs.filter((i) => i.type === activeTab);

  function handleIndicatorChange(v: string) {
    setFormIndicator(v);
    if (v) setFormType(detectType(v));
  }

  function handleAddSingle() {
    if (!formIndicator.trim()) return;
    addIoc({
      id: crypto.randomUUID(),
      indicator: formIndicator.trim(),
      type: formType,
      risk: formRisk,
      description: formDesc.trim(),
      source: formSource.trim() || "Manual",
      addedAt: new Date().toISOString().slice(0, 10),
    });
    setFormIndicator("");
    setFormRisk("Medium");
    setFormDesc("");
    setFormSource("");
    setShowForm(false);
  }

  function handleBulkImport() {
    const lines = bulkText
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);
    lines.forEach((line) => {
      addIoc({
        id: crypto.randomUUID(),
        indicator: line,
        type: detectType(line),
        risk: "Medium",
        description: "",
        source: "Manual Import",
        addedAt: new Date().toISOString().slice(0, 10),
      });
    });
    setBulkText("");
    setShowBulk(false);
  }

  function handleExportCSV() {
    const header = "indicator,type,risk,description,source,addedAt";
    const rows = iocs.map(
      (i) =>
        `"${i.indicator}","${i.type}","${i.risk}","${i.description.replace(/"/g, '""')}","${i.source}","${i.addedAt}"`
    );
    const blob = new Blob([[header, ...rows].join("\n")], {
      type: "text/csv;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "soc-ioc-watchlist.csv";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900">
      {/* Header */}
      <button
        className="flex w-full items-center justify-between px-4 py-3 text-left"
        onClick={() => setCollapsed((c) => !c)}
      >
        <span className="font-semibold text-white">
          IOC Watchlist{" "}
          <span className="ml-1 rounded-full bg-purple-900 px-2 py-0.5 text-xs text-purple-300">
            {iocs.length} indicators
          </span>
        </span>
        <span className="text-zinc-400">{collapsed ? "▸" : "▾"}</span>
      </button>

      {!collapsed && (
        <div className="border-t border-zinc-800 p-4 space-y-4">
          {/* Summary row */}
          <div className="flex flex-wrap gap-3 text-sm">
            <span className="text-red-400">🔴 IPs: {counts.ip}</span>
            <span className="text-purple-400">🌐 Domains: {counts.domain}</span>
            <span className="text-zinc-300">🔑 Hashes: {counts.hash}</span>
          </div>

          {/* Toolbar */}
          <div className="flex flex-wrap gap-2">
            <button
              className="rounded-md bg-purple-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-purple-600"
              onClick={() => {
                setShowForm((s) => !s);
                setShowBulk(false);
              }}
            >
              + Add IOC
            </button>
            <button
              className="rounded-md border border-zinc-700 px-3 py-1.5 text-sm hover:border-purple-500"
              onClick={() => {
                setShowBulk((s) => !s);
                setShowForm(false);
              }}
            >
              Bulk Import
            </button>
            <button
              className="rounded-md border border-zinc-700 px-3 py-1.5 text-sm hover:border-purple-500"
              onClick={handleExportCSV}
              disabled={iocs.length === 0}
            >
              Export CSV
            </button>
          </div>

          {/* Single-add form */}
          {showForm && (
            <div className="rounded-lg border border-zinc-700 bg-zinc-800 p-4 space-y-3">
              <h3 className="text-sm font-semibold text-white">Add IOC</h3>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div>
                  <label className="block text-xs text-zinc-400 mb-1">
                    Indicator <span className="text-red-400">*</span>
                  </label>
                  <input
                    className="w-full rounded border border-zinc-600 bg-zinc-900 px-2 py-1.5 text-sm font-mono text-white outline-none focus:ring-1 ring-purple-500"
                    value={formIndicator}
                    onChange={(e) => handleIndicatorChange(e.target.value)}
                    placeholder="IP, domain, or hash"
                  />
                </div>
                <div>
                  <label className="block text-xs text-zinc-400 mb-1">Type</label>
                  <select
                    className="w-full rounded border border-zinc-600 bg-zinc-900 px-2 py-1.5 text-sm text-white outline-none focus:ring-1 ring-purple-500"
                    value={formType}
                    onChange={(e) => setFormType(e.target.value as CustomIoc["type"])}
                  >
                    <option value="ip">IP</option>
                    <option value="domain">Domain</option>
                    <option value="hash">Hash</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-zinc-400 mb-1">Risk</label>
                  <select
                    className="w-full rounded border border-zinc-600 bg-zinc-900 px-2 py-1.5 text-sm text-white outline-none focus:ring-1 ring-purple-500"
                    value={formRisk}
                    onChange={(e) => setFormRisk(e.target.value as CustomIoc["risk"])}
                  >
                    <option>Low</option>
                    <option>Medium</option>
                    <option>High</option>
                    <option>Critical</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-zinc-400 mb-1">Source</label>
                  <input
                    className="w-full rounded border border-zinc-600 bg-zinc-900 px-2 py-1.5 text-sm text-white outline-none focus:ring-1 ring-purple-500"
                    value={formSource}
                    onChange={(e) => setFormSource(e.target.value)}
                    placeholder="e.g. VirusTotal, internal"
                  />
                </div>
                <div className="sm:col-span-2">
                  <label className="block text-xs text-zinc-400 mb-1">
                    Description
                  </label>
                  <input
                    className="w-full rounded border border-zinc-600 bg-zinc-900 px-2 py-1.5 text-sm text-white outline-none focus:ring-1 ring-purple-500"
                    value={formDesc}
                    onChange={(e) => setFormDesc(e.target.value)}
                    placeholder="e.g. Known C2 server"
                  />
                </div>
              </div>
              <div className="flex gap-2 pt-1">
                <button
                  className="rounded-md bg-purple-700 px-4 py-1.5 text-sm font-medium text-white hover:bg-purple-600 disabled:opacity-50"
                  onClick={handleAddSingle}
                  disabled={!formIndicator.trim()}
                >
                  Add
                </button>
                <button
                  className="rounded-md border border-zinc-700 px-4 py-1.5 text-sm hover:border-zinc-500"
                  onClick={() => setShowForm(false)}
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {/* Bulk import */}
          {showBulk && (
            <div className="rounded-lg border border-zinc-700 bg-zinc-800 p-4 space-y-3">
              <h3 className="text-sm font-semibold text-white">
                Bulk Import — one indicator per line
              </h3>
              <textarea
                className="w-full rounded border border-zinc-600 bg-zinc-900 px-2 py-1.5 text-xs font-mono text-white outline-none focus:ring-1 ring-purple-500 h-28 resize-none"
                value={bulkText}
                onChange={(e) => setBulkText(e.target.value)}
                placeholder={"192.168.1.100\nevil.example.com\nd41d8cd98f00b204e9800998ecf8427e"}
              />
              <p className="text-xs text-zinc-500">
                Type is auto-detected. Risk defaults to Medium, source to "Manual Import".
              </p>
              <div className="flex gap-2">
                <button
                  className="rounded-md bg-purple-700 px-4 py-1.5 text-sm font-medium text-white hover:bg-purple-600 disabled:opacity-50"
                  onClick={handleBulkImport}
                  disabled={!bulkText.trim()}
                >
                  Import
                </button>
                <button
                  className="rounded-md border border-zinc-700 px-4 py-1.5 text-sm hover:border-zinc-500"
                  onClick={() => setShowBulk(false)}
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {/* Filter tabs */}
          <div className="flex gap-1 border-b border-zinc-700 pb-1">
            {(["all", "ip", "domain", "hash"] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`rounded-t px-3 py-1 text-xs font-medium transition-colors ${
                  activeTab === tab
                    ? "bg-zinc-700 text-white"
                    : "text-zinc-400 hover:text-zinc-200"
                }`}
              >
                {tab === "all" ? "All" : tab.toUpperCase()}
                <span className="ml-1 rounded-full bg-zinc-600 px-1.5 py-0.5 text-xs">
                  {counts[tab]}
                </span>
              </button>
            ))}
          </div>

          {/* Table */}
          {filtered.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-zinc-700 text-left text-xs text-zinc-400">
                    <th className="pb-2 pr-3">Indicator</th>
                    <th className="pb-2 pr-3">Type</th>
                    <th className="pb-2 pr-3">Risk</th>
                    <th className="pb-2 pr-3">Description</th>
                    <th className="pb-2 pr-3">Source</th>
                    <th className="pb-2 pr-3">Added</th>
                    <th className="pb-2">Delete</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((ioc) => (
                    <tr key={ioc.id} className="border-b border-zinc-800 hover:bg-zinc-800/50">
                      <td className="py-2 pr-3 font-mono text-xs text-white max-w-[180px] truncate">
                        {ioc.indicator}
                      </td>
                      <td className="py-2 pr-3">
                        <span
                          className={`rounded px-2 py-0.5 text-xs font-medium ${TYPE_COLORS[ioc.type]}`}
                        >
                          {ioc.type.toUpperCase()}
                        </span>
                      </td>
                      <td className="py-2 pr-3">
                        <span
                          className={`rounded px-2 py-0.5 text-xs font-medium ${RISK_COLORS[ioc.risk]}`}
                        >
                          {ioc.risk}
                        </span>
                      </td>
                      <td className="py-2 pr-3 text-xs text-zinc-300 max-w-[160px] truncate">
                        {ioc.description || <span className="text-zinc-600">—</span>}
                      </td>
                      <td className="py-2 pr-3 text-xs text-zinc-400">{ioc.source}</td>
                      <td className="py-2 pr-3 text-xs text-zinc-500">{ioc.addedAt}</td>
                      <td className="py-2">
                        <button
                          className="text-xs text-red-400 hover:text-red-300"
                          onClick={() => deleteIoc(ioc.id)}
                        >
                          ✕
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-sm text-zinc-500">
              {iocs.length === 0
                ? "No IOC indicators yet. Add one or bulk import."
                : "No indicators match this filter."}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

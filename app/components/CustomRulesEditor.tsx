"use client";
import { useState, useEffect, useRef } from "react";
import type { Language } from "@/lib/i18n";

export type CustomRule = {
  id: string;
  name: string;
  pattern: string;
  keywords: string;
  severity: "Low" | "Medium" | "High" | "Critical";
  tactic: string;
  technique: string;
  rootCause: string;
  impact: string;
  fix: string;
  enabled: boolean;
};

type Props = { language: Language; t: Record<string, string> };

const STORAGE_KEY = "soc_custom_rules";

const EMPTY_RULE: Omit<CustomRule, "id"> = {
  name: "",
  pattern: "",
  keywords: "",
  severity: "Medium",
  tactic: "",
  technique: "",
  rootCause: "",
  impact: "",
  fix: "",
  enabled: true,
};

const SEVERITY_COLORS: Record<string, string> = {
  Low: "bg-green-900 text-green-300",
  Medium: "bg-yellow-900 text-yellow-300",
  High: "bg-orange-900 text-orange-300",
  Critical: "bg-red-900 text-red-300",
};

// ── Hook ─────────────────────────────────────────────────────────────────────

export function useCustomRules() {
  const [rules, setRules] = useState<CustomRule[]>([]);
  useEffect(() => {
    try {
      setRules(JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]"));
    } catch {}
  }, []);
  const save = (r: CustomRule[]) => {
    setRules(r);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(r));
  };
  return {
    rules,
    addRule: (r: CustomRule) => save([...rules, r]),
    updateRule: (r: CustomRule) => save(rules.map((x) => (x.id === r.id ? r : x))),
    deleteRule: (id: string) => save(rules.filter((x) => x.id !== id)),
    toggleRule: (id: string) =>
      save(rules.map((x) => (x.id === id ? { ...x, enabled: !x.enabled } : x))),
  };
}

// ── Serializer ────────────────────────────────────────────────────────────────

export function serializeCustomRules(rules: CustomRule[]) {
  return rules
    .filter((r) => r.enabled)
    .map((r) => ({
      name: r.name,
      severity: r.severity,
      patternStr: r.pattern,
      keywords: r.keywords
        .split(",")
        .map((k) => k.trim())
        .filter(Boolean),
      rootCause: r.rootCause,
      impact: r.impact,
      fix: r.fix,
      tactic: r.tactic,
      technique: r.technique,
    }));
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function CustomRulesEditor({ language, t }: Props) {
  const { rules, addRule, updateRule, deleteRule, toggleRule } = useCustomRules();
  const [collapsed, setCollapsed] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<Omit<CustomRule, "id">>(EMPTY_RULE);
  const [patternError, setPatternError] = useState("");
  const [testLine, setTestLine] = useState("");
  const [testResult, setTestResult] = useState<boolean | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const activeCount = rules.filter((r) => r.enabled).length;

  function validatePattern(p: string): boolean {
    try {
      new RegExp(p);
      setPatternError("");
      return true;
    } catch (e: any) {
      setPatternError(e.message);
      return false;
    }
  }

  function handlePatternChange(p: string) {
    setForm((f) => ({ ...f, pattern: p }));
    if (p) validatePattern(p);
    else setPatternError("");
    setTestResult(null);
  }

  function handleTestPattern() {
    if (!form.pattern || !testLine) return;
    try {
      const rx = new RegExp(form.pattern, "i");
      setTestResult(rx.test(testLine));
    } catch {
      setTestResult(false);
    }
  }

  function handleSubmit() {
    if (!form.name.trim()) return;
    if (form.pattern && !validatePattern(form.pattern)) return;
    if (editingId) {
      updateRule({ ...form, id: editingId });
    } else {
      addRule({ ...form, id: crypto.randomUUID() });
    }
    setForm(EMPTY_RULE);
    setShowForm(false);
    setEditingId(null);
    setPatternError("");
    setTestLine("");
    setTestResult(null);
  }

  function handleEdit(rule: CustomRule) {
    const { id, ...rest } = rule;
    setForm(rest);
    setEditingId(id);
    setShowForm(true);
    setPatternError("");
    setTestLine("");
    setTestResult(null);
  }

  function handleCancel() {
    setForm(EMPTY_RULE);
    setShowForm(false);
    setEditingId(null);
    setPatternError("");
    setTestLine("");
    setTestResult(null);
  }

  function handleImport(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const imported: CustomRule[] = JSON.parse(ev.target?.result as string);
        const merged = [
          ...rules,
          ...imported.map((r) => ({ ...r, id: r.id || crypto.randomUUID() })),
        ];
        localStorage.setItem(STORAGE_KEY, JSON.stringify(merged));
        window.location.reload();
      } catch {
        alert("Invalid JSON file");
      }
    };
    reader.readAsText(file);
    e.target.value = "";
  }

  function handleExport() {
    const blob = new Blob([JSON.stringify(rules, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "soc-custom-rules.json";
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
          Custom Rules{" "}
          <span className="ml-1 rounded-full bg-cyan-900 px-2 py-0.5 text-xs text-cyan-300">
            {activeCount} active
          </span>
        </span>
        <span className="text-zinc-400">{collapsed ? "▸" : "▾"}</span>
      </button>

      {!collapsed && (
        <div className="border-t border-zinc-800 p-4 space-y-4">
          {/* Toolbar */}
          <div className="flex flex-wrap gap-2">
            <button
              className="rounded-md bg-cyan-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-cyan-500"
              onClick={() => {
                setShowForm(true);
                setEditingId(null);
                setForm(EMPTY_RULE);
              }}
            >
              + Add Rule
            </button>
            <button
              className="rounded-md border border-zinc-700 px-3 py-1.5 text-sm hover:border-cyan-500"
              onClick={() => fileInputRef.current?.click()}
            >
              Import JSON
            </button>
            <input
              ref={fileInputRef}
              type="file"
              accept=".json"
              className="hidden"
              onChange={handleImport}
            />
            <button
              className="rounded-md border border-zinc-700 px-3 py-1.5 text-sm hover:border-cyan-500"
              onClick={handleExport}
              disabled={rules.length === 0}
            >
              Export JSON
            </button>
          </div>

          {/* Table */}
          {rules.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-zinc-700 text-left text-xs text-zinc-400">
                    <th className="pb-2 pr-3">Name</th>
                    <th className="pb-2 pr-3">Pattern</th>
                    <th className="pb-2 pr-3">Severity</th>
                    <th className="pb-2 pr-3">Enabled</th>
                    <th className="pb-2">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {rules.map((rule) => (
                    <tr
                      key={rule.id}
                      className="border-b border-zinc-800 hover:bg-zinc-800/50"
                    >
                      <td className="py-2 pr-3 font-medium text-white">{rule.name}</td>
                      <td className="py-2 pr-3 font-mono text-xs text-zinc-300 max-w-[160px] truncate">
                        {rule.pattern || <span className="text-zinc-600">—</span>}
                      </td>
                      <td className="py-2 pr-3">
                        <span
                          className={`rounded px-2 py-0.5 text-xs font-medium ${SEVERITY_COLORS[rule.severity]}`}
                        >
                          {rule.severity}
                        </span>
                      </td>
                      <td className="py-2 pr-3">
                        <button
                          onClick={() => toggleRule(rule.id)}
                          className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                            rule.enabled ? "bg-cyan-600" : "bg-zinc-700"
                          }`}
                        >
                          <span
                            className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                              rule.enabled ? "translate-x-4" : "translate-x-1"
                            }`}
                          />
                        </button>
                      </td>
                      <td className="py-2 space-x-2">
                        <button
                          className="text-xs text-cyan-400 hover:text-cyan-300"
                          onClick={() => handleEdit(rule)}
                        >
                          Edit
                        </button>
                        <button
                          className="text-xs text-red-400 hover:text-red-300"
                          onClick={() => deleteRule(rule.id)}
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-sm text-zinc-500">No custom rules yet. Click "+ Add Rule" to create one.</p>
          )}

          {/* Inline Form */}
          {showForm && (
            <div className="rounded-lg border border-zinc-700 bg-zinc-800 p-4 space-y-3">
              <h3 className="font-semibold text-white text-sm">
                {editingId ? "Edit Rule" : "New Rule"}
              </h3>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div>
                  <label className="block text-xs text-zinc-400 mb-1">
                    Name <span className="text-red-400">*</span>
                  </label>
                  <input
                    className="w-full rounded border border-zinc-600 bg-zinc-900 px-2 py-1.5 text-sm text-white outline-none focus:ring-1 ring-cyan-500"
                    value={form.name}
                    onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                    placeholder="e.g. Suspicious PowerShell"
                  />
                </div>
                <div>
                  <label className="block text-xs text-zinc-400 mb-1">
                    Pattern (regex)
                  </label>
                  <input
                    className={`w-full rounded border bg-zinc-900 px-2 py-1.5 text-sm font-mono text-white outline-none focus:ring-1 ring-cyan-500 ${
                      patternError ? "border-red-500" : "border-zinc-600"
                    }`}
                    value={form.pattern}
                    onChange={(e) => handlePatternChange(e.target.value)}
                    placeholder="e.g. powershell.*-enc"
                  />
                  {patternError && (
                    <p className="mt-1 text-xs text-red-400">{patternError}</p>
                  )}
                </div>
                <div>
                  <label className="block text-xs text-zinc-400 mb-1">
                    Keywords (comma-separated)
                  </label>
                  <input
                    className="w-full rounded border border-zinc-600 bg-zinc-900 px-2 py-1.5 text-sm text-white outline-none focus:ring-1 ring-cyan-500"
                    value={form.keywords}
                    onChange={(e) => setForm((f) => ({ ...f, keywords: e.target.value }))}
                    placeholder="powershell, encoded, bypass"
                  />
                </div>
                <div>
                  <label className="block text-xs text-zinc-400 mb-1">Severity</label>
                  <select
                    className="w-full rounded border border-zinc-600 bg-zinc-900 px-2 py-1.5 text-sm text-white outline-none focus:ring-1 ring-cyan-500"
                    value={form.severity}
                    onChange={(e) =>
                      setForm((f) => ({
                        ...f,
                        severity: e.target.value as CustomRule["severity"],
                      }))
                    }
                  >
                    <option>Low</option>
                    <option>Medium</option>
                    <option>High</option>
                    <option>Critical</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-zinc-400 mb-1">Tactic</label>
                  <input
                    className="w-full rounded border border-zinc-600 bg-zinc-900 px-2 py-1.5 text-sm text-white outline-none focus:ring-1 ring-cyan-500"
                    value={form.tactic}
                    onChange={(e) => setForm((f) => ({ ...f, tactic: e.target.value }))}
                    placeholder="e.g. Execution"
                  />
                </div>
                <div>
                  <label className="block text-xs text-zinc-400 mb-1">Technique</label>
                  <input
                    className="w-full rounded border border-zinc-600 bg-zinc-900 px-2 py-1.5 text-sm text-white outline-none focus:ring-1 ring-cyan-500"
                    value={form.technique}
                    onChange={(e) => setForm((f) => ({ ...f, technique: e.target.value }))}
                    placeholder="e.g. T1059.001 PowerShell"
                  />
                </div>
                <div className="sm:col-span-2">
                  <label className="block text-xs text-zinc-400 mb-1">Root Cause</label>
                  <input
                    className="w-full rounded border border-zinc-600 bg-zinc-900 px-2 py-1.5 text-sm text-white outline-none focus:ring-1 ring-cyan-500"
                    value={form.rootCause}
                    onChange={(e) => setForm((f) => ({ ...f, rootCause: e.target.value }))}
                    placeholder="e.g. Encoded PowerShell execution detected"
                  />
                </div>
                <div>
                  <label className="block text-xs text-zinc-400 mb-1">Impact</label>
                  <input
                    className="w-full rounded border border-zinc-600 bg-zinc-900 px-2 py-1.5 text-sm text-white outline-none focus:ring-1 ring-cyan-500"
                    value={form.impact}
                    onChange={(e) => setForm((f) => ({ ...f, impact: e.target.value }))}
                    placeholder="e.g. Potential code execution"
                  />
                </div>
                <div>
                  <label className="block text-xs text-zinc-400 mb-1">
                    Recommended Fix
                  </label>
                  <input
                    className="w-full rounded border border-zinc-600 bg-zinc-900 px-2 py-1.5 text-sm text-white outline-none focus:ring-1 ring-cyan-500"
                    value={form.fix}
                    onChange={(e) => setForm((f) => ({ ...f, fix: e.target.value }))}
                    placeholder="e.g. Restrict PowerShell execution policy"
                  />
                </div>
              </div>

              {/* Test Pattern area */}
              {form.pattern && !patternError && (
                <div className="rounded border border-zinc-700 bg-zinc-900 p-3 space-y-2">
                  <label className="block text-xs font-medium text-zinc-300">
                    Test Pattern
                  </label>
                  <div className="flex gap-2">
                    <input
                      className="flex-1 rounded border border-zinc-600 bg-black px-2 py-1.5 text-xs font-mono text-white outline-none focus:ring-1 ring-cyan-500"
                      value={testLine}
                      onChange={(e) => {
                        setTestLine(e.target.value);
                        setTestResult(null);
                      }}
                      placeholder="Paste a log line here..."
                    />
                    <button
                      className="rounded border border-zinc-600 px-3 py-1.5 text-xs hover:border-cyan-500"
                      onClick={handleTestPattern}
                    >
                      Test
                    </button>
                  </div>
                  {testResult !== null && (
                    <p
                      className={`text-xs font-medium ${
                        testResult ? "text-green-400" : "text-red-400"
                      }`}
                    >
                      {testResult ? "✅ Match" : "❌ No match"}
                    </p>
                  )}
                </div>
              )}

              <div className="flex items-center gap-2 pt-1">
                <label className="flex items-center gap-2 text-sm text-zinc-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={form.enabled}
                    onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))}
                    className="rounded border-zinc-600 bg-zinc-800"
                  />
                  Enabled
                </label>
              </div>

              <div className="flex gap-2 pt-1">
                <button
                  className="rounded-md bg-cyan-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-50"
                  onClick={handleSubmit}
                  disabled={!form.name.trim() || !!patternError}
                >
                  {editingId ? "Save Changes" : "Add Rule"}
                </button>
                <button
                  className="rounded-md border border-zinc-700 px-4 py-1.5 text-sm hover:border-zinc-500"
                  onClick={handleCancel}
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

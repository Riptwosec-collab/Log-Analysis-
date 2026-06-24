"use client";

import { useEffect } from "react";

type StoredRule = {
  id?: string;
  name?: string;
  pattern?: string;
  keywords?: string;
  severity?: string;
  source?: string;
  tactic?: string;
  technique?: string;
  enabled?: boolean;
  rootCause?: string;
  impact?: string;
  fix?: string;
};

type WorkspaceRule = {
  id: string;
  name: { th: string; en: string };
  pattern: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  source: string;
  mitre: string;
  enabled: boolean;
  recommendation: { th: string; en: string };
};

function readJson<T>(key: string, fallback: T): T {
  try {
    const raw = window.localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function writeJson<T>(key: string, value: T): void {
  window.localStorage.setItem(key, JSON.stringify(value));
}

function normalizeSeverity(value?: string): WorkspaceRule["severity"] {
  return value === "Critical" || value === "High" || value === "Medium" || value === "Low" ? value : "Medium";
}

function syncRules(): void {
  const customRules = readJson<StoredRule[]>("soc_custom_rules", []);
  if (!customRules.length) return;

  const workspaceRules = readJson<WorkspaceRule[]>("soc_workspace_rules", []);
  const existing = new Set(workspaceRules.map((rule) => rule.id || rule.name.en || rule.name.th));
  const additions = customRules
    .filter((rule) => !existing.has(rule.id ?? "") && !workspaceRules.some((item) => item.name.en === rule.name || item.pattern === rule.pattern))
    .map<WorkspaceRule>((rule, index) => ({
      id: rule.id ?? `custom-${Date.now()}-${index}`,
      name: { th: rule.name ?? "กฎใหม่จาก Finding", en: rule.name ?? "Rule from finding" },
      pattern: rule.pattern ?? rule.keywords ?? ".*",
      severity: normalizeSeverity(rule.severity),
      source: rule.source ?? "Workflow",
      mitre: [rule.tactic, rule.technique].filter(Boolean).join(" / ") || "Mapped from workflow",
      enabled: rule.enabled !== false,
      recommendation: { th: rule.fix ?? rule.rootCause ?? "ตรวจหลักฐานและปรับ rule ให้เหมาะสม", en: rule.fix ?? rule.impact ?? "Review evidence and tune the rule" },
    }));

  if (additions.length) writeJson("soc_workspace_rules", [...additions, ...workspaceRules]);
}

export default function WorkflowSyncBridge() {
  useEffect(() => {
    const sync = () => syncRules();
    sync();
    const interval = window.setInterval(sync, 1200);
    window.addEventListener("storage", sync);
    return () => {
      window.clearInterval(interval);
      window.removeEventListener("storage", sync);
    };
  }, []);

  return null;
}

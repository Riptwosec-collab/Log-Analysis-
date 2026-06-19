"use client";
import { useState, useEffect } from "react";
import type { Language } from "@/lib/i18n";

type WebhookCfg = {
  url: string;
  threshold: number;
  minSeverity: "Low" | "Medium" | "High" | "Critical";
  slackFormat: boolean;
  enabled: boolean;
  lastSent: string;
};

const DEFAULT: WebhookCfg = {
  url: "",
  threshold: 70,
  minSeverity: "High",
  slackFormat: true,
  enabled: false,
  lastSent: "",
};

const STORAGE_KEY = "soc_webhook";

type Props = { language: Language; t: Record<string, string> };

// ── Exported helper ───────────────────────────────────────────────────────────

export function getWebhookConfig(): WebhookCfg {
  try {
    return { ...DEFAULT, ...JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}") };
  } catch {
    return DEFAULT;
  }
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function WebhookSettings({ language, t }: Props) {
  const [cfg, setCfg] = useState<WebhookCfg>(DEFAULT);
  const [saved, setSaved] = useState(false);
  const [testStatus, setTestStatus] = useState<"idle" | "sending" | "ok" | "error">("idle");
  const [testMsg, setTestMsg] = useState("");

  useEffect(() => {
    try {
      const stored = JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}");
      setCfg({ ...DEFAULT, ...stored });
    } catch {}
  }, []);

  function updateCfg(patch: Partial<WebhookCfg>) {
    setCfg((prev) => {
      const next = { ...prev, ...patch };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
      return next;
    });
    setSaved(true);
    setTimeout(() => setSaved(false), 1500);
  }

  async function handleTestWebhook() {
    if (!cfg.url) {
      setTestMsg("Please enter a webhook URL first.");
      setTestStatus("error");
      return;
    }
    setTestStatus("sending");
    setTestMsg("");
    try {
      const res = await fetch("/api/webhook", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          webhookUrl: cfg.url,
          slackFormat: cfg.slackFormat,
          payload: { test: true, message: "SOC Dashboard test alert" },
        }),
      });
      const data = await res.json();
      if (data.ok) {
        setTestStatus("ok");
        setTestMsg(`Webhook delivered (HTTP ${data.status})`);
        updateCfg({ lastSent: new Date().toISOString() });
      } else {
        setTestStatus("error");
        setTestMsg(data.error || `HTTP ${data.status}`);
      }
    } catch (e: any) {
      setTestStatus("error");
      setTestMsg(e.message || "Request failed");
    }
  }

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="font-semibold text-white">
          Alert Configuration{" "}
          <span className="text-zinc-500 font-normal">/ การแจ้งเตือน</span>
        </h2>
        {saved && <span className="text-xs text-green-400">Saved</span>}
      </div>

      {/* Enable toggle */}
      <label className="flex items-center gap-3 cursor-pointer">
        <button
          onClick={() => updateCfg({ enabled: !cfg.enabled })}
          className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
            cfg.enabled ? "bg-cyan-600" : "bg-zinc-700"
          }`}
        >
          <span
            className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
              cfg.enabled ? "translate-x-6" : "translate-x-1"
            }`}
          />
        </button>
        <span className="text-sm text-zinc-300">
          {cfg.enabled ? "Enabled" : "Disabled"}
        </span>
      </label>

      {/* Webhook URL */}
      <div>
        <label className="block text-xs text-zinc-400 mb-1">Webhook URL</label>
        <input
          className="w-full rounded border border-zinc-600 bg-black px-3 py-2 text-sm text-white outline-none focus:ring-1 ring-cyan-500"
          type="url"
          value={cfg.url}
          onChange={(e) => updateCfg({ url: e.target.value })}
          placeholder="https://hooks.slack.com/services/..."
        />
      </div>

      {/* Threshold slider */}
      <div>
        <div className="flex items-center justify-between mb-1">
          <label className="text-xs text-zinc-400">Risk Score Threshold</label>
          <span className="text-sm font-semibold text-cyan-400">{cfg.threshold}</span>
        </div>
        <input
          type="range"
          min={0}
          max={100}
          value={cfg.threshold}
          onChange={(e) => updateCfg({ threshold: Number(e.target.value) })}
          className="w-full accent-cyan-500"
        />
        <div className="flex justify-between text-xs text-zinc-600 mt-0.5">
          <span>0</span>
          <span>100</span>
        </div>
      </div>

      {/* Min severity */}
      <div>
        <label className="block text-xs text-zinc-400 mb-1">Minimum Severity</label>
        <select
          className="w-full rounded border border-zinc-600 bg-black px-3 py-2 text-sm text-white outline-none focus:ring-1 ring-cyan-500"
          value={cfg.minSeverity}
          onChange={(e) =>
            updateCfg({ minSeverity: e.target.value as WebhookCfg["minSeverity"] })
          }
        >
          <option>Low</option>
          <option>Medium</option>
          <option>High</option>
          <option>Critical</option>
        </select>
      </div>

      {/* Slack format toggle */}
      <label className="flex items-center gap-3 cursor-pointer">
        <button
          onClick={() => updateCfg({ slackFormat: !cfg.slackFormat })}
          className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
            cfg.slackFormat ? "bg-cyan-600" : "bg-zinc-700"
          }`}
        >
          <span
            className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
              cfg.slackFormat ? "translate-x-4" : "translate-x-1"
            }`}
          />
        </button>
        <span className="text-sm text-zinc-300">
          Slack Block Kit format{" "}
          <span className="text-zinc-500 text-xs">
            (off = raw JSON)
          </span>
        </span>
      </label>

      {/* Test button */}
      <div className="flex items-center gap-3">
        <button
          className="rounded-md bg-zinc-700 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-600 disabled:opacity-50"
          onClick={handleTestWebhook}
          disabled={testStatus === "sending"}
        >
          {testStatus === "sending" ? "Sending…" : "Test Webhook"}
        </button>
        {testStatus === "ok" && (
          <span className="text-xs text-green-400">{testMsg}</span>
        )}
        {testStatus === "error" && (
          <span className="text-xs text-red-400">{testMsg}</span>
        )}
      </div>

      {/* Last sent */}
      {cfg.lastSent && (
        <p className="text-xs text-zinc-500">
          Last alert sent:{" "}
          <span className="text-zinc-300">{new Date(cfg.lastSent).toLocaleString()}</span>
        </p>
      )}
      {!cfg.lastSent && (
        <p className="text-xs text-zinc-600">Last alert sent: never</p>
      )}
    </div>
  );
}

"use client";

import { useState, useRef, useCallback } from "react";
import { DEMO_SCENARIOS } from "@/lib/demoLogs";
import type { Language } from "@/lib/i18n";

interface Props {
  value: string;
  onChange: (v: string) => void;
  onAnalyze: () => void;
  onClear: () => void;
  isAnalyzing: boolean;
  language: Language;
  fileLabels: string[];
  setFileLabels: (labels: string[]) => void;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

const SEV_COLOR: Record<string, string> = {
  Critical: "text-red-400 border-red-800 bg-red-950/30",
  High:     "text-orange-400 border-orange-800 bg-orange-950/30",
  Medium:   "text-yellow-400 border-yellow-800 bg-yellow-950/30",
  Low:      "text-green-400 border-green-800 bg-green-950/30",
};

export default function LogInputPanel({
  value,
  onChange,
  onAnalyze,
  onClear,
  isAnalyzing,
  language,
  fileLabels,
  setFileLabels,
}: Props) {
  const [showDemoMenu, setShowDemoMenu] = useState(false);
  const [showPreview, setShowPreview] = useState(false);
  const [isDragOver, setIsDragOver] = useState(false);
  const [fileMeta, setFileMeta] = useState<{ name: string; size: number } | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const previewLines = value.split("\n").slice(0, 20);
  const totalLines = value.split("\n").filter(Boolean).length;

  const handleFiles = useCallback(async (files: File[]) => {
    if (!files.length) return;
    const valid = files.filter((f) =>
      [".log", ".txt", ".json", ".csv"].some((ext) => f.name.toLowerCase().endsWith(ext))
    );
    if (!valid.length) return;
    const contents = await Promise.all(valid.map((f) => f.text()));
    onChange(contents.join("\n"));
    setFileLabels(valid.map((f) => f.name));
    if (valid.length === 1) {
      setFileMeta({ name: valid[0].name, size: valid[0].size });
    } else {
      setFileMeta({ name: `${valid.length} files`, size: valid.reduce((s, f) => s + f.size, 0) });
    }
    setShowPreview(true);
  }, [onChange, setFileLabels]);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  };
  const handleDragLeave = () => setIsDragOver(false);
  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    handleFiles(Array.from(e.dataTransfer.files));
  };
  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    handleFiles(Array.from(e.target.files ?? []));
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const loadDemo = (id: string) => {
    const scenario = DEMO_SCENARIOS.find((s) => s.id === id);
    if (!scenario) return;
    onChange(scenario.content);
    setFileLabels([]);
    setFileMeta(null);
    setShowDemoMenu(false);
    setShowPreview(false);
  };

  const handleClear = () => {
    onClear();
    setFileMeta(null);
    setFileLabels([]);
    setShowPreview(false);
  };

  return (
    <div className="space-y-3">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2">
        {/* Demo selector */}
        <div className="relative">
          <button
            onClick={() => setShowDemoMenu((s) => !s)}
            className="flex items-center gap-1.5 rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-300 hover:border-cyan-500 hover:text-white"
          >
            📂 Load Demo <span className="text-zinc-500">▾</span>
          </button>
          {showDemoMenu && (
            <div
              className="absolute left-0 top-full z-50 mt-1 w-72 rounded-xl border border-zinc-700 bg-zinc-900 shadow-2xl"
              onMouseLeave={() => setShowDemoMenu(false)}
            >
              {DEMO_SCENARIOS.map((s) => (
                <button
                  key={s.id}
                  onClick={() => loadDemo(s.id)}
                  className="flex w-full items-start gap-3 px-4 py-3 text-left hover:bg-zinc-800 first:rounded-t-xl last:rounded-b-xl"
                >
                  <span className="text-xl shrink-0">{s.icon}</span>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-zinc-100">{s.label}</span>
                      <span className={`rounded-full border px-1.5 py-0.5 text-[10px] font-bold ${SEV_COLOR[s.severity]}`}>
                        {s.severity}
                      </span>
                    </div>
                    <p className="mt-0.5 text-xs text-zinc-500 leading-4">{s.description}</p>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Upload button */}
        <label className="flex cursor-pointer items-center gap-1.5 rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-300 hover:border-cyan-500 hover:text-white">
          📎 Upload File
          <input
            ref={fileInputRef}
            type="file"
            multiple
            accept=".log,.txt,.json,.csv"
            className="sr-only"
            onChange={handleFileInput}
          />
        </label>

        {/* Line count */}
        {totalLines > 0 && (
          <span className="rounded-md border border-zinc-800 bg-zinc-900 px-2 py-1.5 text-xs text-zinc-500">
            {totalLines.toLocaleString()} lines
          </span>
        )}

        {/* File meta */}
        {fileMeta && (
          <span className="flex items-center gap-1.5 rounded-md border border-zinc-800 bg-zinc-900 px-2 py-1.5 text-xs text-zinc-400">
            📄 {fileMeta.name}
            <span className="text-zinc-600">·</span>
            {formatBytes(fileMeta.size)}
          </span>
        )}

        {/* Preview toggle */}
        {value && (
          <button
            onClick={() => setShowPreview((s) => !s)}
            className={`rounded-md border px-3 py-2 text-xs ${showPreview ? "border-cyan-700 bg-cyan-500/10 text-cyan-300" : "border-zinc-700 text-zinc-400 hover:border-zinc-500"}`}
          >
            {showPreview ? "✕ Preview" : "👁 Preview"}
          </button>
        )}

        {/* Clear */}
        {value && (
          <button
            onClick={handleClear}
            className="rounded-md border border-zinc-700 px-3 py-2 text-xs text-zinc-400 hover:border-red-700 hover:text-red-400"
          >
            🗑 Clear
          </button>
        )}
      </div>

      {/* File labels */}
      {fileLabels.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {fileLabels.map((name) => (
            <span
              key={name}
              className="flex items-center gap-1 rounded-full bg-cyan-500/10 border border-cyan-800 px-3 py-1 text-xs text-cyan-300"
            >
              📄 {name}
              <button
                onClick={() => setFileLabels(fileLabels.filter((l) => l !== name))}
                className="ml-1 text-cyan-600 hover:text-red-400"
              >×</button>
            </span>
          ))}
        </div>
      )}

      {/* Drag & Drop + Textarea */}
      <div
        className={`relative rounded-lg border-2 transition-colors ${
          isDragOver
            ? "border-cyan-500 bg-cyan-500/5"
            : "border-zinc-800 bg-black"
        }`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        {isDragOver && (
          <div className="absolute inset-0 z-10 flex items-center justify-center rounded-lg bg-zinc-950/80">
            <div className="text-center">
              <p className="text-4xl">📂</p>
              <p className="mt-2 text-lg font-semibold text-cyan-300">Drop log files here</p>
              <p className="text-sm text-zinc-400">.log · .txt · .json · .csv</p>
            </div>
          </div>
        )}
        <textarea
          ref={textareaRef}
          className="h-64 w-full resize-y rounded-lg bg-transparent p-3 font-mono text-sm leading-6 text-zinc-200 outline-none ring-cyan-500 focus:ring-2 placeholder:text-zinc-600"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          spellCheck={false}
          placeholder={`Paste log content here, or drag & drop a file...\n\nSupported: Apache/Nginx · SSH Auth · Firewall · Windows Event · Linux Syslog\nAlso: FortiGate · Palo Alto · Cisco IOS · Meraki · Cloudflare · Microsoft 365`}
        />
        {!value && (
          <div className="absolute bottom-4 right-4 text-xs text-zinc-700 pointer-events-none">
            drag & drop .log .txt .json .csv
          </div>
        )}
      </div>

      {/* Preview */}
      {showPreview && value && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3">
          <div className="mb-2 flex items-center justify-between">
            <p className="text-xs font-semibold uppercase tracking-wider text-zinc-500">
              Preview — first {Math.min(20, previewLines.length)} of {totalLines} lines
            </p>
          </div>
          <div className="max-h-48 overflow-y-auto space-y-0.5">
            {previewLines.map((line, i) => (
              <div key={i} className="flex gap-3 text-xs font-mono">
                <span className="w-6 shrink-0 text-right text-zinc-700">{i + 1}</span>
                <span className="text-zinc-400 break-all">{line || <span className="text-zinc-700">―</span>}</span>
              </div>
            ))}
          </div>
          {totalLines > 20 && (
            <p className="mt-2 text-center text-xs text-zinc-600">
              ... {(totalLines - 20).toLocaleString()} more lines
            </p>
          )}
        </div>
      )}

      {/* Analyze + Cancel buttons — rendered by parent, but hint area here */}
    </div>
  );
}

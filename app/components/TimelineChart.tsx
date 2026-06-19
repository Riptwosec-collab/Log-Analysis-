"use client";

import { useEffect, useRef } from "react";
import type { Language } from "@/lib/i18n";

type TimelineEntry = {
  timestamp: string;
  count: number;
  severity: "Low" | "Medium" | "High" | "Critical";
};

type Props = {
  timeline: TimelineEntry[];
  language: Language;
  t: Record<string, string>;
};

const SEVERITY_COLOR: Record<string, string> = {
  Critical: "#f87171",
  High: "#fb923c",
  Medium: "#facc15",
  Low: "#4ade80",
};

declare global {
  interface Window {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    Chart: any;
  }
}

function formatLabel(timestamp: string): string {
  // Try to extract HH:MM from various timestamp formats
  // ISO: 2026-06-10T21:14:02Z
  const isoMatch = timestamp.match(/T(\d{2}:\d{2})/);
  if (isoMatch) return isoMatch[1];
  // "Jun 10 21:14:02" or "Jun 10 21:14"
  const timeMatch = timestamp.match(/\b(\d{2}:\d{2})(?::\d{2})?\b/);
  if (timeMatch) return timeMatch[1];
  // Fallback: truncate
  return timestamp.length > 8 ? timestamp.slice(-8, -3) : timestamp;
}

export default function TimelineChart({ timeline, language, t }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const chartRef = useRef<any>(null);
  const scriptLoadedRef = useRef(false);

  const title = language === "th" ? "กิจกรรมตามเวลา" : "Event Timeline";

  function buildChart() {
    if (!canvasRef.current || !window.Chart) return;

    // Destroy previous chart instance
    if (chartRef.current) {
      chartRef.current.destroy();
      chartRef.current = null;
    }

    if (timeline.length === 0) return;

    const labels = timeline.map((item) => formatLabel(item.timestamp));
    const data = timeline.map((item) => item.count);
    const colors = timeline.map((item) => SEVERITY_COLOR[item.severity] ?? SEVERITY_COLOR.Low);

    chartRef.current = new window.Chart(canvasRef.current, {
      type: "bar",
      data: {
        labels,
        datasets: [
          {
            label: language === "th" ? "จำนวน Event" : "Event Count",
            data,
            backgroundColor: colors,
            borderColor: colors,
            borderWidth: 1,
            borderRadius: 3,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              title: (items: { dataIndex: number }[]) => {
                const idx = items[0]?.dataIndex ?? 0;
                return timeline[idx]?.timestamp ?? "";
              },
              label: (item: { dataIndex: number; raw: number }) => {
                const idx = item.dataIndex;
                const entry = timeline[idx];
                return [
                  `${language === "th" ? "จำนวน" : "Count"}: ${item.raw}`,
                  `${language === "th" ? "ความรุนแรง" : "Severity"}: ${entry?.severity ?? ""}`,
                ];
              },
            },
            backgroundColor: "#18181b",
            titleColor: "#e4e4e7",
            bodyColor: "#a1a1aa",
            borderColor: "#3f3f46",
            borderWidth: 1,
          },
        },
        scales: {
          x: {
            ticks: {
              color: "#71717a",
              font: { size: 11, family: "ui-monospace, monospace" },
              maxRotation: 45,
            },
            grid: { color: "#27272a" },
          },
          y: {
            beginAtZero: true,
            ticks: {
              color: "#71717a",
              font: { size: 11 },
              stepSize: 1,
            },
            grid: { color: "#27272a" },
          },
        },
        animation: { duration: 300 },
      },
    });
  }

  // Load Chart.js once from CDN
  useEffect(() => {
    if (window.Chart) {
      buildChart();
      return;
    }
    if (scriptLoadedRef.current) return;
    scriptLoadedRef.current = true;

    const script = document.createElement("script");
    script.src =
      "https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js";
    script.async = true;
    script.onload = () => buildChart();
    document.head.appendChild(script);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Rebuild when timeline changes (after Chart.js is loaded)
  useEffect(() => {
    if (window.Chart) buildChart();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [timeline, language]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (chartRef.current) {
        chartRef.current.destroy();
        chartRef.current = null;
      }
    };
  }, []);

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
      <h3 className="mb-4 text-base font-semibold text-white">{title}</h3>
      {timeline.length === 0 ? (
        <p className="text-sm text-zinc-500">
          {t.noTimestamp ?? "No timestamps detected in log."}
        </p>
      ) : (
        <div className="relative h-56">
          <canvas ref={canvasRef} />
        </div>
      )}
    </div>
  );
}

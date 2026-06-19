"use client";

import type { Correlation } from "@/lib/logAnalyzer";
import type { Language } from "@/lib/i18n";
import { localize, severityLabel, severityClass } from "@/lib/i18n";

interface Props {
  correlations: Correlation[];
  language: Language;
  t: Record<string, string>;
}

export default function CorrelationPanel({ correlations, language, t }: Props) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
      <h2 className="text-lg font-semibold text-white">{t.correlationTitle}</h2>
      <div className="mt-4 space-y-3">
        {correlations.length === 0 && (
          <p className="text-sm text-zinc-500">{t.noCorrelation}</p>
        )}
        {correlations.map((item) => (
          <div
            key={`${item.title}-${item.sourceIp || "global"}`}
            className="rounded-md border border-zinc-800 bg-black p-3"
          >
            <div className="flex items-center justify-between gap-3">
              <p className="text-sm font-semibold text-white">
                {localize(item.title, language)}
              </p>
              <span
                className={`rounded px-2 py-1 text-xs font-semibold ${severityClass(item.severity)}`}
              >
                {severityLabel(item.severity, language)}
              </span>
            </div>
            <p className="mt-2 text-sm leading-5 text-zinc-400">
              {localize(item.description, language)}
            </p>
            <div className="mt-2 flex flex-wrap gap-2 text-xs text-zinc-400">
              {item.confidence !== undefined && (
                <span>Confidence: {item.confidence}%</span>
              )}
              {item.incidentType && (
                <span>Type: {localize(item.incidentType, language)}</span>
              )}
              {item.mitreTechniques?.slice(0, 3).map((technique) => (
                <span
                  key={technique}
                  className="rounded border border-zinc-700 px-2 py-1"
                >
                  {technique}
                </span>
              ))}
            </div>
            <p className="mt-2 text-xs text-cyan-300">
              {localize(item.recommendedAction, language)}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}

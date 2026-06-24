"use client";

import { useEffect, useMemo, useState } from "react";

type Language = "th" | "en";

type AlertDetail = {
  title: string;
  summary: string;
  rawText: string;
  fields: Array<{ label: string; value: string }>;
};

const copy: Record<Language, Record<string, string>> = {
  th: {
    title: "รายละเอียดการแจ้งเตือน",
    summary: "ข้อมูลเต็มของ Alert ที่เลือก",
    fullText: "ข้อความทั้งหมด",
    close: "ปิด",
    hint: "กดการ์ด Alert เพื่อเปิดรายละเอียดเต็ม",
    rule: "Rule",
    severity: "Severity / Status",
    sourceIp: "Source IP",
    asset: "Asset",
    mitre: "MITRE",
    confidence: "Confidence",
  },
  en: {
    title: "Alert details",
    summary: "Full details for the selected alert",
    fullText: "Full text",
    close: "Close",
    hint: "Click an alert card to open the full detail view",
    rule: "Rule",
    severity: "Severity / Status",
    sourceIp: "Source IP",
    asset: "Asset",
    mitre: "MITRE",
    confidence: "Confidence",
  },
};

function getLanguage(): Language {
  if (typeof window === "undefined") return "th";
  return window.localStorage.getItem("soc_language") === "en" ? "en" : "th";
}

function cleanText(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

function extractField(text: string, label: string): string {
  const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = text.match(new RegExp(`${escaped}\\s*:?\\s*([^·|]+?)(?=\\s+[A-Z][A-Za-z ]{2,}:|$)`, "i"));
  return cleanText(match?.[1] ?? "-");
}

function parseArticle(article: HTMLElement, language: Language): AlertDetail {
  const t = copy[language];
  const rawText = cleanText(article.innerText || article.textContent || "");
  const heading = cleanText(article.querySelector("h1,h2,h3")?.textContent || "");
  const badges = Array.from(article.querySelectorAll("span"))
    .map((item) => cleanText(item.textContent || ""))
    .filter(Boolean)
    .slice(0, 4)
    .join(" / ");

  const sourceIp = rawText.match(/(?:Source IP|Source\s*IP|ต้นทาง|Source)\s*:?\s*((?:\d{1,3}\.){3}\d{1,3})/i)?.[1]
    ?? rawText.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)?.[0]
    ?? "-";
  const mitre = rawText.match(/\bT\d{4}(?:\.\d{3})?\b/)?.[0] ?? extractField(rawText, "MITRE");
  const confidence = rawText.match(/(?:Confidence|ความมั่นใจ)\s*:?\s*(\d+%?)/i)?.[1] ?? "-";
  const asset = extractField(rawText, "Asset");

  return {
    title: heading || t.title,
    summary: t.summary,
    rawText,
    fields: [
      { label: t.rule, value: heading || "-" },
      { label: t.severity, value: badges || "-" },
      { label: t.sourceIp, value: sourceIp },
      { label: t.asset, value: asset },
      { label: t.mitre, value: mitre },
      { label: t.confidence, value: confidence },
    ],
  };
}

export default function AlertDetailEnhancer() {
  const [detail, setDetail] = useState<AlertDetail | null>(null);
  const [language, setLanguage] = useState<Language>("th");
  const t = copy[language];

  useEffect(() => {
    const syncLanguage = () => setLanguage(getLanguage());
    syncLanguage();
    const languageTimer = window.setInterval(syncLanguage, 700);

    const decorate = () => {
      if (!window.location.pathname.startsWith("/alerts")) return;
      document.querySelectorAll<HTMLElement>("main article").forEach((article) => {
        if (article.textContent?.match(/MITRE|Source IP|Confidence|ความมั่นใจ|แจ้งเตือน/i)) {
          article.classList.add("alert-detail-clickable");
          article.setAttribute("title", t.hint);
          article.setAttribute("role", "button");
          article.setAttribute("tabindex", "0");
        }
      });
    };

    const onClick = (event: MouseEvent) => {
      if (!window.location.pathname.startsWith("/alerts")) return;
      const target = event.target as HTMLElement | null;
      if (!target || target.closest("a,button,input,select,textarea")) return;
      const article = target.closest<HTMLElement>("article.alert-detail-clickable");
      if (!article) return;
      setDetail(parseArticle(article, getLanguage()));
    };

    const onKey = (event: KeyboardEvent) => {
      if (!window.location.pathname.startsWith("/alerts")) return;
      if (event.key !== "Enter" && event.key !== " ") return;
      const target = event.target as HTMLElement | null;
      const article = target?.closest<HTMLElement>("article.alert-detail-clickable");
      if (!article) return;
      event.preventDefault();
      setDetail(parseArticle(article, getLanguage()));
    };

    decorate();
    const observer = new MutationObserver(decorate);
    observer.observe(document.body, { childList: true, subtree: true });
    document.addEventListener("click", onClick);
    document.addEventListener("keydown", onKey);
    return () => {
      window.clearInterval(languageTimer);
      observer.disconnect();
      document.removeEventListener("click", onClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [t.hint]);

  const detailFields = useMemo(() => detail?.fields ?? [], [detail]);
  if (!detail) return null;

  return (
    <div className="alert-detail-backdrop" onClick={() => setDetail(null)}>
      <div className="alert-detail-modal" role="dialog" aria-modal="true" aria-label={t.title} onClick={(event) => event.stopPropagation()}>
        <header className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <p className="text-xs font-bold uppercase tracking-[0.22em] text-cyan-200">{t.title}</p>
            <h2 className="mt-2 text-2xl font-bold">{detail.title}</h2>
            <p className="mt-1 text-sm" style={{ color: "var(--text-muted)" }}>{detail.summary}</p>
          </div>
          <button type="button" onClick={() => setDetail(null)} className="rounded-2xl border px-4 py-2 text-sm font-bold" style={{ borderColor: "var(--border)", color: "var(--text-primary)" }}>
            {t.close}
          </button>
        </header>
        <section className="space-y-4">
          <div className="alert-detail-grid">
            {detailFields.map((field) => (
              <div key={field.label} className="alert-detail-field">
                <small>{field.label}</small>
                <strong>{field.value}</strong>
              </div>
            ))}
          </div>
          <div className="alert-detail-field">
            <small>{t.fullText}</small>
            <p>{detail.rawText}</p>
          </div>
        </section>
      </div>
    </div>
  );
}

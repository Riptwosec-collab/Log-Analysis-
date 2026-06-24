"use client";

import { useEffect, useState } from "react";

type Language = "th" | "en";

function getLanguage(): Language {
  if (typeof window === "undefined") return "th";
  return window.localStorage.getItem("soc_language") === "en" ? "en" : "th";
}

export default function GuideQuickAccess() {
  const [language, setLanguage] = useState<Language>("th");

  useEffect(() => {
    const sync = () => setLanguage(getLanguage());
    sync();
    const interval = window.setInterval(sync, 500);
    window.addEventListener("storage", sync);
    return () => {
      window.clearInterval(interval);
      window.removeEventListener("storage", sync);
    };
  }, []);

  const label = language === "th" ? "คู่มืออ่าน Log" : "Log guide";
  const hint = language === "th" ? "เลื่อนลงท้ายหน้า" : "Jump to bottom";

  const scrollToGuide = () => {
    const guide = document.getElementById("log-reading-guide");
    if (guide) {
      guide.scrollIntoView({ behavior: "smooth", block: "start" });
    } else {
      window.location.hash = "log-reading-guide";
    }
  };

  return (
    <button
      type="button"
      onClick={scrollToGuide}
      className="fixed bottom-4 left-4 z-[80] rounded-2xl border border-cyan-300/40 bg-slate-950/85 px-4 py-3 text-left shadow-2xl shadow-cyan-950/40 backdrop-blur-xl transition hover:-translate-y-1 hover:border-cyan-200 hover:bg-cyan-950/80 hover:shadow-cyan-500/20 lg:left-[272px]"
      aria-label={label}
      data-i18n-ignore
    >
      <span className="block text-sm font-bold text-cyan-100">📘 {label}</span>
      <span className="mt-0.5 block text-xs text-slate-400">{hint}</span>
    </button>
  );
}

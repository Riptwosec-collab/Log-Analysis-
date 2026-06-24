"use client";

import { useEffect } from "react";

type Language = "th" | "en";
type ThemeKey = "sentinel" | "aurora" | "daylight";

const themeClasses = ["theme-soc-sentinel", "theme-soc-aurora", "theme-soc-daylight"];
const themeKeys: ThemeKey[] = ["sentinel", "aurora", "daylight"];

const labels: Record<Language, { code: string; title: string }> = {
  th: { code: "12", title: "คู่มืออ่าน Log" },
  en: { code: "12", title: "Log Reading Guide" },
};

const themeLabels: Record<Language, Record<ThemeKey, { label: string; note: string }>> = {
  th: {
    sentinel: { label: "Midnight SOC", note: "เข้ม คม มืออาชีพ" },
    aurora: { label: "Black Gold", note: "ดำทอง หรู อ่านชัด" },
    daylight: { label: "Cream Clean", note: "ครีม สบายตา อ่านง่าย" },
  },
  en: {
    sentinel: { label: "Midnight SOC", note: "Dark professional" },
    aurora: { label: "Black Gold", note: "Premium black and gold" },
    daylight: { label: "Cream Clean", note: "Warm cream and readable" },
  },
};

function getLanguage(): Language {
  if (typeof window === "undefined") return "th";
  return window.localStorage.getItem("soc_language") === "en" ? "en" : "th";
}

function normalizeTheme(value: string | null): ThemeKey {
  return value === "aurora" || value === "daylight" || value === "sentinel" ? value : "sentinel";
}

function applyTheme(theme: ThemeKey): void {
  document.documentElement.classList.remove(...themeClasses, "light", "theme-cyberpunk", "theme-ocean", "theme-inferno", "theme-matrix");
  document.documentElement.classList.add(`theme-soc-${theme}`);
  document.documentElement.dataset.socTheme = theme;
  document.body.dataset.socTheme = theme;
  window.localStorage.setItem("soc_ux_theme", theme);
  window.localStorage.setItem("soc_theme", theme === "daylight" ? "light" : "dark");
}

function setGuideLinkContent(anchor: HTMLAnchorElement, language: Language): void {
  const active = window.location.pathname === "/guide";
  anchor.href = "/guide";
  anchor.dataset.guideMenuLink = "true";
  anchor.className = "guide-sidebar-link";
  anchor.classList.toggle("is-active", active);
  anchor.setAttribute("aria-current", active ? "page" : "false");

  let code = anchor.querySelector<HTMLSpanElement>("span[data-guide-code]");
  let title = anchor.querySelector<HTMLSpanElement>("span[data-guide-title]");
  if (!code) {
    code = document.createElement("span");
    code.dataset.guideCode = "true";
    anchor.appendChild(code);
  }
  if (!title) {
    title = document.createElement("span");
    title.dataset.guideTitle = "true";
    title.className = "truncate";
    anchor.appendChild(title);
  }
  code.textContent = labels[language].code;
  title.textContent = labels[language].title;
}

function injectGuideLinks(): void {
  const language = getLanguage();
  document.querySelectorAll<HTMLElement>("aside nav").forEach((nav) => {
    let link = nav.querySelector<HTMLAnchorElement>('a[data-guide-menu-link="true"]');
    if (!link) {
      link = document.createElement("a");
      const settingsTarget = Array.from(nav.children).find((child) => child.textContent?.includes("Settings") || child.textContent?.includes("ตั้งค่า"));
      if (settingsTarget) nav.insertBefore(link, settingsTarget);
      else nav.appendChild(link);
    }
    setGuideLinkContent(link, language);
  });
}

function fixThemePanel(): void {
  const language = getLanguage();
  const activeTheme = normalizeTheme(window.localStorage.getItem("soc_ux_theme"));
  document.querySelectorAll<HTMLButtonElement>(".ux-theme-list button").forEach((button, index) => {
    const theme = themeKeys[index];
    if (!theme) return;
    button.dataset.uxThemeKey = theme;
    button.classList.toggle("is-active", theme === activeTheme);
    button.setAttribute("aria-pressed", theme === activeTheme ? "true" : "false");
    const strong = button.querySelector("strong");
    const small = button.querySelector("small");
    if (strong) strong.textContent = themeLabels[language][theme].label;
    if (small) small.textContent = themeLabels[language][theme].note;
  });
}

function installStyleFixes(): void {
  if (document.getElementById("guide-theme-fixes")) return;
  const style = document.createElement("style");
  style.id = "guide-theme-fixes";
  style.textContent = `
    .guide-sidebar-link{display:flex!important;align-items:center;gap:.75rem;width:100%;border:1px solid transparent;border-radius:1rem;padding:.75rem;color:var(--text-muted);text-decoration:none;transition:transform .18s ease,border-color .18s ease,background .18s ease,color .18s ease,box-shadow .18s ease}
    .guide-sidebar-link [data-guide-code]{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;font-size:.75rem;color:var(--accent)}
    .guide-sidebar-link [data-guide-title]{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .guide-sidebar-link:hover,.guide-sidebar-link.is-active,.guide-sidebar-link[aria-current="page"]{border-color:var(--border-strong)!important;background:var(--accent-soft)!important;color:var(--text-primary)!important;box-shadow:inset 0 1px 0 rgba(255,255,255,.14),0 0 22px var(--accent-soft);transform:translateX(2px)}
    .ux-theme-list button,.ux-segment button,.ux-panel-toggle{pointer-events:auto!important;user-select:none;position:relative;z-index:2}
    .ux-theme-list button[data-ux-theme-key="aurora"] .ux-theme-dot{background:linear-gradient(180deg,#fff2a8,#f5c451 42%,#8b5a12)!important;box-shadow:0 0 26px rgba(245,196,81,.46)!important}
    .ux-theme-list button[data-ux-theme-key="daylight"] .ux-theme-dot{background:linear-gradient(180deg,#fff8ec,#f4d7a6 48%,#b86b1c)!important;box-shadow:0 0 22px rgba(184,107,28,.28)!important}
  `;
  document.head.appendChild(style);
}

export default function GuideMenuInjector() {
  useEffect(() => {
    const refresh = () => {
      installStyleFixes();
      injectGuideLinks();
      fixThemePanel();
    };

    const handleClick = (event: MouseEvent) => {
      const target = event.target instanceof HTMLElement ? event.target : null;
      const themeButton = target?.closest<HTMLButtonElement>(".ux-theme-list button");
      if (!themeButton) return;
      const theme = normalizeTheme(themeButton.dataset.uxThemeKey ?? null);
      applyTheme(theme);
      window.setTimeout(refresh, 0);
    };

    const savedTheme = normalizeTheme(window.localStorage.getItem("soc_ux_theme"));
    applyTheme(savedTheme);
    refresh();
    const observer = new MutationObserver(refresh);
    observer.observe(document.body, { childList: true, subtree: true });
    const interval = window.setInterval(refresh, 900);
    document.addEventListener("click", handleClick, true);
    window.addEventListener("storage", refresh);
    window.addEventListener("popstate", refresh);
    return () => {
      observer.disconnect();
      window.clearInterval(interval);
      document.removeEventListener("click", handleClick, true);
      window.removeEventListener("storage", refresh);
      window.removeEventListener("popstate", refresh);
    };
  }, []);

  return null;
}

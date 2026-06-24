"use client";

import { useEffect } from "react";

type Language = "th" | "en";
type ThemeKey = "sentinel" | "aurora" | "daylight";

const themeClasses = ["theme-soc-sentinel", "theme-soc-aurora", "theme-soc-daylight"];
const themeKeys: ThemeKey[] = ["sentinel", "aurora", "daylight"];

const themeCopy: Record<Language, Record<ThemeKey, { label: string; note: string }>> = {
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

const guideCopy: Record<Language, { code: string; title: string; aria: string }> = {
  th: { code: "12", title: "คู่มืออ่าน Log", aria: "เปิดคู่มืออ่าน Log" },
  en: { code: "12", title: "Log Reading Guide", aria: "Open Log Reading Guide" },
};

function getLanguage(): Language {
  if (typeof window === "undefined") return "th";
  return window.localStorage.getItem("soc_language") === "en" ? "en" : "th";
}

function normalizeTheme(value: string | null): ThemeKey {
  if (value === "aurora" || value === "daylight" || value === "sentinel") return value;
  return "sentinel";
}

function applyTheme(theme: ThemeKey): void {
  const html = document.documentElement;
  html.classList.remove(...themeClasses, "light", "theme-cyberpunk", "theme-ocean", "theme-inferno", "theme-matrix");
  html.classList.add(`theme-soc-${theme}`);
  html.dataset.socTheme = theme;
  document.body.dataset.socTheme = theme;
  window.localStorage.setItem("soc_ux_theme", theme);
  window.localStorage.setItem("soc_theme", theme === "daylight" ? "light" : "dark");
  window.dispatchEvent(new CustomEvent("soc-theme-change", { detail: { theme } }));
}

function setThemePanelText(language: Language): void {
  document.querySelectorAll<HTMLButtonElement>(".ux-theme-list button").forEach((button, index) => {
    const key = themeKeys[index];
    if (!key) return;
    const strong = button.querySelector("strong");
    const small = button.querySelector("small");
    if (strong) strong.textContent = themeCopy[language][key].label;
    if (small) small.textContent = themeCopy[language][key].note;
    button.setAttribute("data-ux-theme-key", key);
    button.setAttribute("aria-label", `${themeCopy[language][key].label} - ${themeCopy[language][key].note}`);
  });
}

function setActiveThemeButton(theme: ThemeKey): void {
  document.querySelectorAll<HTMLButtonElement>(".ux-theme-list button").forEach((button, index) => {
    const key = themeKeys[index];
    button.classList.toggle("is-active", key === theme);
    button.setAttribute("aria-pressed", key === theme ? "true" : "false");
  });
}

function createGuideLink(language: Language): HTMLAnchorElement {
  const anchor = document.createElement("a");
  anchor.href = "/guide";
  anchor.dataset.guideMenuLink = "true";
  anchor.setAttribute("aria-label", guideCopy[language].aria);
  anchor.className = "guide-sidebar-link";
  anchor.innerHTML = `<span data-guide-code>${guideCopy[language].code}</span><span data-guide-title>${guideCopy[language].title}</span>`;
  return anchor;
}

function ensureGuideInSidebar(): void {
  const language = getLanguage();
  const copy = guideCopy[language];
  document.querySelectorAll<HTMLElement>("aside nav").forEach((nav) => {
    let link = nav.querySelector<HTMLAnchorElement>('a[data-guide-menu-link="true"]');
    if (!link) {
      link = createGuideLink(language);
      const settingsTarget = Array.from(nav.children).find((child) => child.textContent?.includes("Settings") || child.textContent?.includes("ตั้งค่า"));
      if (settingsTarget) nav.insertBefore(link, settingsTarget);
      else nav.appendChild(link);
    }
    link.href = "/guide";
    link.classList.add("guide-sidebar-link");
    link.classList.toggle("is-active", window.location.pathname === "/guide");
    link.setAttribute("aria-current", window.location.pathname === "/guide" ? "page" : "false");
    link.setAttribute("aria-label", copy.aria);
    let code = link.querySelector<HTMLSpanElement>("[data-guide-code]");
    let title = link.querySelector<HTMLSpanElement>("[data-guide-title]");
    if (!code) {
      code = document.createElement("span");
      code.dataset.guideCode = "true";
      link.prepend(code);
    }
    if (!title) {
      title = document.createElement("span");
      title.dataset.guideTitle = "true";
      link.appendChild(title);
    }
    code.textContent = copy.code;
    title.textContent = copy.title;
  });
}

export default function UxReliabilityBridge() {
  useEffect(() => {
    const applySaved = () => {
      const language = getLanguage();
      const theme = normalizeTheme(window.localStorage.getItem("soc_ux_theme"));
      applyTheme(theme);
      setThemePanelText(language);
      setActiveThemeButton(theme);
      ensureGuideInSidebar();
    };

    applySaved();

    const handleClick = (event: MouseEvent) => {
      const target = event.target instanceof HTMLElement ? event.target : null;
      const themeButton = target?.closest<HTMLButtonElement>(".ux-theme-list button");
      if (themeButton) {
        const buttons = Array.from(document.querySelectorAll<HTMLButtonElement>(".ux-theme-list button"));
        const index = buttons.indexOf(themeButton);
        const theme = themeKeys[index] ?? normalizeTheme(themeButton.dataset.uxThemeKey ?? null);
        applyTheme(theme);
        setActiveThemeButton(theme);
        window.setTimeout(() => setActiveThemeButton(theme), 0);
      }
    };

    const observer = new MutationObserver(applySaved);
    observer.observe(document.body, { childList: true, subtree: true });
    const interval = window.setInterval(applySaved, 1000);
    document.addEventListener("click", handleClick, true);
    window.addEventListener("storage", applySaved);
    window.addEventListener("popstate", applySaved);

    return () => {
      observer.disconnect();
      window.clearInterval(interval);
      document.removeEventListener("click", handleClick, true);
      window.removeEventListener("storage", applySaved);
      window.removeEventListener("popstate", applySaved);
    };
  }, []);

  return null;
}

"use client";

import { useEffect } from "react";

type Language = "th" | "en";

const labels: Record<Language, { code: string; title: string }> = {
  th: { code: "12", title: "คู่มืออ่าน Log" },
  en: { code: "12", title: "Log Reading Guide" },
};

function getLanguage(): Language {
  if (typeof window === "undefined") return "th";
  return window.localStorage.getItem("soc_language") === "en" ? "en" : "th";
}

function setGuideLinkContent(anchor: HTMLAnchorElement, language: Language): void {
  const active = window.location.pathname === "/guide";
  anchor.href = "/guide";
  anchor.dataset.guideMenuLink = "true";
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
    const existing = nav.querySelector<HTMLAnchorElement>('a[data-guide-menu-link="true"]');
    if (existing) {
      setGuideLinkContent(existing, language);
      return;
    }

    const anchor = document.createElement("a");
    setGuideLinkContent(anchor, language);
    nav.appendChild(anchor);
  });
}

export default function GuideMenuInjector() {
  useEffect(() => {
    injectGuideLinks();
    const observer = new MutationObserver(injectGuideLinks);
    observer.observe(document.body, { childList: true, subtree: true });
    const interval = window.setInterval(injectGuideLinks, 900);
    window.addEventListener("storage", injectGuideLinks);
    window.addEventListener("popstate", injectGuideLinks);
    return () => {
      observer.disconnect();
      window.clearInterval(interval);
      window.removeEventListener("storage", injectGuideLinks);
      window.removeEventListener("popstate", injectGuideLinks);
    };
  }, []);

  return null;
}

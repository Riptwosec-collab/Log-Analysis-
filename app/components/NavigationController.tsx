"use client";

import { useEffect } from "react";

const NAV_ROUTES: Record<string, string> = {
  dashboard: "/",
  logs: "/logs",
  log: "/logs",
  alerts: "/alerts",
  "การแจ้งเตือน": "/alerts",
  incidents: "/incidents",
  incident: "/incidents",
  "เหตุการณ์": "/incidents",
  "threat intelligence": "/threat-intelligence",
  "ข่าวกรองภัยคุกคาม": "/threat-intelligence",
  "mitre att&ck": "/mitre",
  reports: "/reports",
  "รายงาน": "/reports",
  rules: "/rules",
  "กฎตรวจจับ": "/rules",
  assets: "/assets",
  "สินทรัพย์": "/assets",
  users: "/users",
  "ผู้ใช้": "/users",
  settings: "/settings",
  "ตั้งค่า": "/settings",
};

function normalizeLabel(value: string) {
  return value
    .replace(/^\s*\d+\s*/u, "")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function findRouteFromButton(button: HTMLButtonElement) {
  const text = normalizeLabel(button.innerText || button.textContent || "");
  return NAV_ROUTES[text];
}

export default function NavigationController() {
  useEffect(() => {
    const onClick = (event: MouseEvent) => {
      const target = event.target as HTMLElement | null;
      const button = target?.closest("aside nav button") as HTMLButtonElement | null;
      if (!button) return;

      const route = findRouteFromButton(button);
      if (!route) return;

      event.preventDefault();
      event.stopPropagation();

      if (window.location.pathname === route) {
        window.scrollTo({ top: 0, behavior: "smooth" });
        return;
      }

      window.location.assign(route);
    };

    window.addEventListener("click", onClick, true);
    return () => window.removeEventListener("click", onClick, true);
  }, []);

  return null;
}

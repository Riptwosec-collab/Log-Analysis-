"use client";

import { useEffect } from "react";

const DEFAULT_LOG_SIGNATURES = [
  "Failed password for invalid user admin from 185.220.101.21",
  "GET /login.php?id=1 UNION SELECT password FROM users",
  "SW_MATM-4-MACFLAP_NOTIF",
];

function clearTextarea(textarea: HTMLTextAreaElement) {
  const setter = Object.getOwnPropertyDescriptor(
    window.HTMLTextAreaElement.prototype,
    "value",
  )?.set;

  setter?.call(textarea, "");
  textarea.dispatchEvent(new Event("input", { bubbles: true }));
  textarea.dispatchEvent(new Event("change", { bubbles: true }));
}

export default function DefaultLogCleaner() {
  useEffect(() => {
    const clearDefaultSample = () => {
      const textareas = Array.from(document.querySelectorAll("textarea"));

      textareas.forEach((textarea) => {
        const hasDefaultSample = DEFAULT_LOG_SIGNATURES.some((signature) =>
          textarea.value.includes(signature),
        );

        if (hasDefaultSample) clearTextarea(textarea);
      });
    };

    clearDefaultSample();

    const observer = new MutationObserver(clearDefaultSample);
    observer.observe(document.body, { childList: true, subtree: true });

    return () => observer.disconnect();
  }, []);

  return null;
}

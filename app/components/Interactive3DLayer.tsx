"use client";

import { useEffect } from "react";

export default function Interactive3DLayer() {
  useEffect(() => {
    let frame = 0;

    const setPointer = (clientX: number, clientY: number): void => {
      window.cancelAnimationFrame(frame);
      frame = window.requestAnimationFrame(() => {
        const x = Math.round(clientX);
        const y = Math.round(clientY);
        document.documentElement.style.setProperty("--pointer-x", `${x}px`);
        document.documentElement.style.setProperty("--pointer-y", `${y}px`);
        document.documentElement.style.setProperty("--pointer-x-percent", `${Math.round((x / window.innerWidth) * 100)}%`);
        document.documentElement.style.setProperty("--pointer-y-percent", `${Math.round((y / window.innerHeight) * 100)}%`);
      });
    };

    const handlePointerMove = (event: PointerEvent): void => {
      if (event.pointerType === "touch") return;
      setPointer(event.clientX, event.clientY);
    };

    setPointer(window.innerWidth * 0.72, window.innerHeight * 0.28);
    window.addEventListener("pointermove", handlePointerMove, { passive: true });

    return () => {
      window.cancelAnimationFrame(frame);
      window.removeEventListener("pointermove", handlePointerMove);
    };
  }, []);

  return (
    <div className="interactive-3d-layer" aria-hidden="true">
      <div className="interactive-depth-grid" />
      <div className="interactive-spotlight" />
      <div className="interactive-orb interactive-orb-a" />
      <div className="interactive-orb interactive-orb-b" />
    </div>
  );
}

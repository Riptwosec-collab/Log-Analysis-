"use client";
import type { Finding } from "@/lib/logAnalyzer";
import type { Language } from "@/lib/i18n";
import { useState } from "react";

type Props = { findings: Finding[]; language: Language; t: Record<string, string> };

type Country = { code: string; name: string; x: number; y: number; w: number; h: number };

const COUNTRIES: Country[] = [
  { code: "US", name: "United States",  x: 80,  y: 160, w: 120, h: 70 },
  { code: "CA", name: "Canada",         x: 80,  y: 100, w: 110, h: 60 },
  { code: "MX", name: "Mexico",         x: 100, y: 225, w: 60,  h: 40 },
  { code: "BR", name: "Brazil",         x: 180, y: 260, w: 80,  h: 70 },
  { code: "GB", name: "United Kingdom", x: 330, y: 110, w: 25,  h: 20 },
  { code: "DE", name: "Germany",        x: 345, y: 115, w: 25,  h: 20 },
  { code: "FR", name: "France",         x: 335, y: 125, w: 25,  h: 20 },
  { code: "NL", name: "Netherlands",    x: 345, y: 110, w: 15,  h: 15 },
  { code: "RU", name: "Russia",         x: 400, y: 90,  w: 140, h: 60 },
  { code: "UA", name: "Ukraine",        x: 385, y: 115, w: 40,  h: 20 },
  { code: "PL", name: "Poland",         x: 360, y: 110, w: 25,  h: 18 },
  { code: "TR", name: "Turkey",         x: 400, y: 140, w: 40,  h: 22 },
  { code: "IR", name: "Iran",           x: 430, y: 145, w: 35,  h: 22 },
  { code: "CN", name: "China",          x: 540, y: 140, w: 90,  h: 60 },
  { code: "JP", name: "Japan",          x: 640, y: 140, w: 30,  h: 30 },
  { code: "KR", name: "South Korea",    x: 620, y: 145, w: 20,  h: 22 },
  { code: "IN", name: "India",          x: 500, y: 170, w: 50,  h: 50 },
  { code: "VN", name: "Vietnam",        x: 560, y: 185, w: 20,  h: 30 },
  { code: "ID", name: "Indonesia",      x: 570, y: 220, w: 60,  h: 30 },
  { code: "AU", name: "Australia",      x: 590, y: 280, w: 80,  h: 60 },
  { code: "SG", name: "Singapore",      x: 575, y: 210, w: 12,  h: 12 },
  { code: "ZA", name: "South Africa",   x: 370, y: 260, w: 40,  h: 35 },
  { code: "NG", name: "Nigeria",        x: 345, y: 210, w: 30,  h: 28 },
  { code: "EG", name: "Egypt",          x: 390, y: 165, w: 30,  h: 22 },
];

type HoveredState = {
  code: string;
  name: string;
  screenX: number;
  screenY: number;
  count: number;
} | null;

export default function WorldMap({ findings, language, t }: Props) {
  const [hovered, setHovered] = useState<HoveredState>(null);

  const countryCounts = findings.reduce((acc, f) => {
    if (f.geoCountry) acc[f.geoCountry] = (acc[f.geoCountry] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  function countryColor(code: string) {
    const n = countryCounts[code] ?? 0;
    if (n === 0) return "#1e293b";
    if (n <= 2) return "#ca8a04";
    if (n <= 5) return "#ea580c";
    return "#dc2626";
  }

  const hasData = Object.keys(countryCounts).length > 0;

  const top5 = Object.entries(countryCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  const total = Object.values(countryCounts).reduce((a, b) => a + b, 0);

  const title = language === "th" ? "แผนที่ต้นทางผู้โจมตี" : "Attacker Origin Map";
  const topCountriesLabel = language === "th" ? "ประเทศต้นทางสูงสุด" : "Top Source Countries";

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
      <h3 className="mb-4 text-base font-semibold text-white">{title}</h3>

      {!hasData ? (
        <p className="text-sm text-zinc-500 py-8 text-center">
          No geolocation data — enable AbuseIPDB for IP enrichment
        </p>
      ) : (
        <>
          <div className="relative overflow-x-auto">
            <svg
              viewBox="0 0 800 400"
              className="w-full rounded-md border border-zinc-800"
              style={{ minWidth: 480, background: "#0c1a2e" }}
            >
              {/* Ocean background */}
              <rect x="0" y="0" width="800" height="400" fill="#0c1a2e" />

              {COUNTRIES.map((c) => (
                <g key={c.code}>
                  <rect
                    x={c.x}
                    y={c.y}
                    width={c.w}
                    height={c.h}
                    fill={countryColor(c.code)}
                    stroke="#0f172a"
                    strokeWidth="1"
                    style={{ cursor: "pointer" }}
                    onMouseEnter={(e) => {
                      const svgEl = (e.currentTarget as SVGElement).closest("svg")!;
                      const svgRect = svgEl.getBoundingClientRect();
                      const scaleX = svgRect.width / 800;
                      const scaleY = svgRect.height / 400;
                      setHovered({
                        code: c.code,
                        name: c.name,
                        screenX: c.x * scaleX + svgRect.left,
                        screenY: c.y * scaleY + svgRect.top,
                        count: countryCounts[c.code] ?? 0,
                      });
                    }}
                    onMouseLeave={() => setHovered(null)}
                  />
                  {c.w >= 28 && c.h >= 14 && (
                    <text
                      x={c.x + c.w / 2}
                      y={c.y + c.h / 2 + 4}
                      textAnchor="middle"
                      fontSize={c.w >= 60 ? "10" : "8"}
                      fill={countryCounts[c.code] ? "#fff" : "#64748b"}
                      pointerEvents="none"
                      fontFamily="ui-monospace, monospace"
                    >
                      {c.code}
                    </text>
                  )}
                </g>
              ))}

              {/* Legend */}
              <g transform="translate(10, 360)">
                <rect x="0"   y="2" width="12" height="12" fill="#1e293b" stroke="#334155" strokeWidth="1" />
                <text x="15"  y="12" fontSize="9" fill="#64748b" fontFamily="sans-serif">None</text>
                <rect x="46"  y="2" width="12" height="12" fill="#ca8a04" />
                <text x="61"  y="12" fontSize="9" fill="#64748b" fontFamily="sans-serif">1–2</text>
                <rect x="80"  y="2" width="12" height="12" fill="#ea580c" />
                <text x="95"  y="12" fontSize="9" fill="#64748b" fontFamily="sans-serif">3–5</text>
                <rect x="114" y="2" width="12" height="12" fill="#dc2626" />
                <text x="129" y="12" fontSize="9" fill="#64748b" fontFamily="sans-serif">6+</text>
              </g>
            </svg>

            {/* Tooltip — fixed so it follows cursor position on screen */}
            {hovered && (
              <div
                className="pointer-events-none fixed z-50 rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-xs shadow-xl"
                style={{
                  left: hovered.screenX + 10,
                  top: hovered.screenY - 8,
                  transform: "translateY(-100%)",
                }}
              >
                <p className="font-semibold text-white">
                  {hovered.name}{" "}
                  <span className="text-zinc-400">({hovered.code})</span>
                </p>
                <p className="mt-1 text-zinc-400">
                  {hovered.count > 0
                    ? `${hovered.count} attack${hovered.count !== 1 ? "s" : ""} detected`
                    : "No attacks detected"}
                </p>
              </div>
            )}
          </div>

          {top5.length > 0 && (
            <div className="mt-4">
              <p className="mb-2 text-xs uppercase tracking-[0.15em] text-zinc-500">
                {topCountriesLabel}
              </p>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-zinc-800 text-xs text-zinc-500">
                    <th className="py-1 text-left font-normal">Country</th>
                    <th className="py-1 text-right font-normal">Attacks</th>
                    <th className="py-1 text-right font-normal">Share</th>
                  </tr>
                </thead>
                <tbody>
                  {top5.map(([code, count]) => {
                    const pct = total > 0 ? Math.round((count / total) * 100) : 0;
                    const country = COUNTRIES.find((c) => c.code === code);
                    return (
                      <tr key={code} className="border-b border-zinc-800/50 last:border-0">
                        <td className="py-2 text-zinc-200">
                          <span className="mr-2 font-mono text-zinc-400">{code}</span>
                          {country?.name ?? code}
                        </td>
                        <td className="py-2 text-right font-mono text-red-300">{count}</td>
                        <td className="py-2 text-right text-zinc-400">{pct}%</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}

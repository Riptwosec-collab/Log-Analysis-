import Link from "next/link";
import LogReadingGuide from "../components/LogReadingGuide";

const navItems = [
  ["01", "Dashboard", "/"],
  ["02", "Logs", "/logs"],
  ["03", "Alerts", "/alerts"],
  ["04", "Incidents", "/incidents"],
  ["05", "Threat Intel", "/threat-intelligence"],
  ["06", "MITRE", "/mitre"],
  ["07", "Reports", "/reports"],
  ["08", "Rules", "/rules"],
  ["09", "Assets", "/assets"],
  ["10", "Users", "/users"],
  ["11", "Settings", "/settings"],
  ["12", "Guide", "/guide"],
] as const;

export default function GuidePage() {
  return (
    <main data-i18n-ignore className="flex min-h-screen" style={{ backgroundColor: "var(--bg-primary)", color: "var(--text-primary)" }}>
      <aside className="sticky top-0 hidden h-screen w-72 shrink-0 border-r border-white/10 bg-black/35 p-4 backdrop-blur-xl lg:flex lg:flex-col">
        <Link href="/" className="mb-4 rounded-2xl border border-white/10 bg-white/[0.04] px-4 py-3 text-sm font-semibold text-white transition hover:border-cyan-400">SOC Console</Link>
        <nav className="space-y-1 overflow-y-auto pr-1">
          {navItems.map(([code, label, href]) => (
            <Link key={href} href={href} className={`group flex items-center gap-3 rounded-2xl border px-3 py-3 text-sm transition ${href === "/guide" ? "border-cyan-400/70 bg-cyan-400/12 text-cyan-50 shadow-lg shadow-cyan-950/30" : "border-transparent text-slate-400 hover:border-white/10 hover:bg-white/[0.04] hover:text-white"}`}>
              <span className="font-mono text-xs text-cyan-300">{code}</span>
              <span className="truncate">{label}</span>
            </Link>
          ))}
        </nav>
      </aside>
      <section className="min-w-0 flex-1 px-4 py-8 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-7xl space-y-6">
          <header className="rounded-[2rem] border border-white/10 bg-white/[0.05] p-5 shadow-2xl shadow-black/20 backdrop-blur-xl">
            <p className="text-xs font-bold uppercase tracking-[0.24em] text-cyan-300">SOC GUIDE</p>
            <h1 className="mt-2 text-3xl font-semibold text-white sm:text-4xl">Log Reading Guide</h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-300">Open this guide from the left menu as a separate page.</p>
          </header>
          <LogReadingGuide />
        </div>
      </section>
    </main>
  );
}

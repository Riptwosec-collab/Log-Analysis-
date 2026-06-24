import LogReadingGuide from "../components/LogReadingGuide";

export default function GuidePage() {
  return (
    <main data-i18n-ignore className="min-h-screen px-4 py-8 sm:px-6 lg:px-8" style={{ backgroundColor: "var(--bg-primary)", color: "var(--text-primary)" }}>
      <div className="mx-auto max-w-7xl space-y-6">
        <header className="rounded-[2rem] border border-white/10 bg-white/[0.05] p-5 shadow-2xl shadow-black/20 backdrop-blur-xl">
          <p className="text-xs font-bold uppercase tracking-[0.24em] text-cyan-300">SOC GUIDE</p>
          <h1 className="mt-2 text-3xl font-semibold text-white sm:text-4xl">Log Reading Guide</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-300">Open this guide from the left menu as a separate page.</p>
        </header>
        <LogReadingGuide embedded />
      </div>
    </main>
  );
}

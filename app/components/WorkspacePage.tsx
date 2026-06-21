import Link from "next/link";

const navItems = [
  { code: "01", label: "Dashboard", href: "/" },
  { code: "02", label: "Logs", href: "/logs" },
  { code: "03", label: "Alerts", href: "/alerts" },
  { code: "04", label: "Incidents", href: "/incidents" },
  { code: "05", label: "Threat Intelligence", href: "/threat-intelligence" },
  { code: "06", label: "MITRE ATT&CK", href: "/mitre" },
  { code: "07", label: "Reports", href: "/reports" },
  { code: "08", label: "Rules", href: "/rules" },
  { code: "09", label: "Assets", href: "/assets" },
  { code: "10", label: "Users", href: "/users" },
  { code: "11", label: "Settings", href: "/settings" },
];

type WorkspacePageProps = {
  title: string;
  eyebrow: string;
  description: string;
  cards: Array<{ title: string; body: string }>;
};

function isActive(title: string, label: string) {
  if (title === "Log") return label === "Logs";
  if (title === "Incident") return label === "Incidents";
  return title === label;
}

export default function WorkspacePage({ title, eyebrow, description, cards }: WorkspacePageProps) {
  return (
    <main className="flex min-h-screen bg-zinc-950 text-zinc-100">
      <aside className="sticky top-0 hidden h-screen w-64 shrink-0 border-r border-zinc-800 bg-zinc-950/95 p-3 backdrop-blur lg:flex lg:flex-col">
        <Link href="/" className="mb-4 rounded-xl border border-zinc-800 bg-black/70 px-3 py-3 text-left text-sm text-zinc-200 hover:border-cyan-500">
          SOC Console
        </Link>
        <nav className="space-y-1">
          {navItems.map((item) => {
            const active = isActive(title, item.label);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`group flex w-full items-center gap-3 rounded-xl border px-3 py-3 text-left text-sm transition ${active ? "border-cyan-500/60 bg-cyan-500/10 text-cyan-100" : "border-transparent text-zinc-400 hover:border-zinc-700 hover:bg-zinc-900 hover:text-zinc-100"}`}
              >
                <span className="font-mono text-xs text-cyan-300">{item.code}</span>
                <span className="flex-1 truncate">{item.label}</span>
              </Link>
            );
          })}
        </nav>
      </aside>

      <section className="flex-1 px-4 py-8 sm:px-8">
        <div className="mx-auto max-w-6xl space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-300">{eyebrow}</p>
              <h1 className="mt-2 text-3xl font-semibold text-white">{title}</h1>
              <p className="mt-2 max-w-3xl text-sm leading-6 text-zinc-400">{description}</p>
            </div>
            <Link href="/" className="rounded-xl border border-zinc-700 px-4 py-2 text-sm text-zinc-200 hover:border-cyan-500">
              Return to Dashboard
            </Link>
          </div>

          <section className="rounded-2xl border border-zinc-800 bg-zinc-900/80 p-5 shadow-2xl shadow-black/20">
            <h2 className="text-lg font-semibold text-white">What this page will include</h2>
            <div className="mt-4 grid gap-4 md:grid-cols-3">
              {cards.map((card) => (
                <div key={card.title} className="rounded-2xl border border-zinc-800 bg-black/70 p-4 transition hover:-translate-y-0.5 hover:border-cyan-500/50">
                  <h3 className="text-base font-semibold text-cyan-200">{card.title}</h3>
                  <p className="mt-2 text-sm leading-6 text-zinc-400">{card.body}</p>
                </div>
              ))}
            </div>
          </section>

          <section className="rounded-2xl border border-zinc-800 bg-zinc-900/80 p-5 shadow-2xl shadow-black/20">
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-300">Workspace module</p>
            <p className="mt-2 text-sm leading-6 text-zinc-400">
              Operational view for SOC workflow. Use the dashboard analyzer output as the source of truth while this module is expanded into a full data view.
            </p>
          </section>
        </div>
      </section>
    </main>
  );
}

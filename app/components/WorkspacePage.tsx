import Link from "next/link";

type WorkspacePageProps = {
  title: string;
  eyebrow: string;
  description: string;
  cards: Array<{
    title: string;
    body: string;
  }>;
};

export default function WorkspacePage({ title, eyebrow, description, cards }: WorkspacePageProps) {
  return (
    <main className="min-h-screen bg-zinc-950 px-4 py-8 text-zinc-100 sm:px-8">
      <div className="mx-auto max-w-6xl space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-300">{eyebrow}</p>
            <h1 className="mt-2 text-3xl font-semibold text-white">{title}</h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-zinc-400">{description}</p>
          </div>
          <Link href="/" className="rounded-md border border-zinc-700 px-4 py-2 text-sm text-zinc-200 hover:border-cyan-500">
            Return to Dashboard
          </Link>
        </div>

        <section className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
          <h2 className="text-lg font-semibold text-white">What this page will include</h2>
          <div className="mt-4 grid gap-4 md:grid-cols-3">
            {cards.map((card) => (
              <div key={card.title} className="rounded-xl border border-zinc-800 bg-black/70 p-4">
                <h3 className="text-base font-semibold text-cyan-200">{card.title}</h3>
                <p className="mt-2 text-sm leading-6 text-zinc-400">{card.body}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-300">Workspace module</p>
          <p className="mt-2 text-sm leading-6 text-zinc-400">
            Operational view for SOC workflow. Use the dashboard analyzer output as the source of truth while this module is expanded into a full data view.
          </p>
        </section>
      </div>
    </main>
  );
}

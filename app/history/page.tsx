import Link from "next/link";

const fields = [
  "Case ID",
  "Created time",
  "Risk score",
  "Risk level",
  "Finding count",
  "Top source IP",
  "Analyst note",
  "Status",
];

export default function HistoryPage() {
  return (
    <main className="min-h-screen bg-zinc-950 px-4 py-8 text-zinc-100 sm:px-8">
      <div className="mx-auto max-w-5xl space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-300">History</p>
            <h1 className="mt-2 text-3xl font-semibold text-white">Saved Cases</h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-zinc-400">
              The dashboard keeps recent analysis sessions in browser localStorage. Use this page as the product spec for the next persistent saved-cases phase.
            </p>
          </div>
          <Link href="/" className="rounded-md border border-zinc-700 px-4 py-2 text-sm text-zinc-200 hover:border-cyan-500">Back to dashboard</Link>
        </div>

        <section className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
          <h2 className="text-lg font-semibold text-white">Case fields</h2>
          <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {fields.map((field) => (
              <div key={field} className="rounded-md border border-zinc-800 bg-black px-3 py-2 text-sm text-zinc-300">{field}</div>
            ))}
          </div>
        </section>

        <section className="grid gap-4 md:grid-cols-3">
          {[
            ["New", "Newly analyzed case waiting for review."],
            ["Investigating", "Analyst is checking evidence and timeline."],
            ["Resolved", "Case has an outcome and export is ready."],
          ].map(([title, body]) => (
            <div key={title} className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
              <h2 className="text-lg font-semibold text-white">{title}</h2>
              <p className="mt-2 text-sm leading-6 text-zinc-400">{body}</p>
            </div>
          ))}
        </section>
      </div>
    </main>
  );
}

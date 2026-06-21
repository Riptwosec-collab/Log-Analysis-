import Link from "next/link";

const exports = [
  ["JSON", "Machine-readable full result for automation."],
  ["CSV", "Spreadsheet-friendly finding table."],
  ["Text / Markdown", "Readable incident summary for tickets."],
  ["PDF", "Manager-friendly report file."],
  ["CEF", "Common Event Format export."],
  ["LEEF", "Log Event Extended Format export."],
];

export default function ReportsPage() {
  return (
    <main className="min-h-screen bg-zinc-950 px-4 py-8 text-zinc-100 sm:px-8">
      <div className="mx-auto max-w-6xl space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-300">Reports</p>
            <h1 className="mt-2 text-3xl font-semibold text-white">Export Report Center</h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-zinc-400">
              The dashboard export menu supports analyst handoff, manager summary, and structured evidence export.
            </p>
          </div>
          <Link href="/" className="rounded-md border border-zinc-700 px-4 py-2 text-sm text-zinc-200 hover:border-cyan-500">Back to dashboard</Link>
        </div>

        <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {exports.map(([name, description]) => (
            <div key={name} className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
              <h2 className="text-lg font-semibold text-white">{name}</h2>
              <p className="mt-2 text-sm leading-6 text-zinc-400">{description}</p>
            </div>
          ))}
        </section>

        <section className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
          <h2 className="text-lg font-semibold text-white">Recommended report flow</h2>
          <ol className="mt-3 space-y-2 text-sm leading-6 text-zinc-300">
            <li>1. Analyze the logs and review the highest severity findings first.</li>
            <li>2. Open the detail drawer and confirm evidence, source, user, asset, and mapped technique.</li>
            <li>3. Copy RCA or manager summary for the ticket.</li>
            <li>4. Export JSON or CSV for evidence archive, then PDF for presentation.</li>
          </ol>
        </section>
      </div>
    </main>
  );
}

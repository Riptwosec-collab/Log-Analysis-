import Link from "next/link";

const settings = [
  ["Theme", "Dark, light, cyberpunk, ocean, inferno, and matrix themes."],
  ["Language", "Thai and English dashboard labels and analyst outputs."],
  ["Auto refresh", "Optional browser-side refresh while reviewing active data."],
  ["Custom rules", "Browser-local rule tuning for your environment."],
  ["IOC list", "Browser-local indicator watchlist."],
  ["Webhook", "Optional outbound alert delivery configuration."],
];

export default function SettingsPage() {
  return (
    <main className="min-h-screen bg-zinc-950 px-4 py-8 text-zinc-100 sm:px-8">
      <div className="mx-auto max-w-6xl space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-300">Settings</p>
            <h1 className="mt-2 text-3xl font-semibold text-white">Settings & Privacy</h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-zinc-400">
              Review local settings and privacy notes before using real operational data.
            </p>
          </div>
          <Link href="/" className="rounded-md border border-zinc-700 px-4 py-2 text-sm text-zinc-200 hover:border-cyan-500">Back to dashboard</Link>
        </div>

        <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {settings.map(([name, description]) => (
            <div key={name} className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
              <h2 className="text-lg font-semibold text-white">{name}</h2>
              <p className="mt-2 text-sm leading-6 text-zinc-400">{description}</p>
            </div>
          ))}
        </section>

        <section className="rounded-xl border border-amber-900/60 bg-amber-950/20 p-4">
          <h2 className="text-lg font-semibold text-amber-100">Privacy checklist</h2>
          <ul className="mt-3 space-y-2 text-sm leading-6 text-zinc-300">
            <li>Remove private values before sharing examples publicly.</li>
            <li>Mask customer names, emails, and private hostnames in screenshots.</li>
            <li>Use sample fixtures when opening public issues.</li>
            <li>Clear browser storage when working on a shared computer.</li>
          </ul>
        </section>
      </div>
    </main>
  );
}

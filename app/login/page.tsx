"use client";
import { useState } from "react";
import { signIn } from "next-auth/react";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    const res = await signIn("credentials", {
      username,
      password,
      redirect: false,
    });
    if (res?.error) {
      setError("Invalid username or password");
      setLoading(false);
    } else {
      window.location.href = "/";
    }
  }

  return (
    <main className="min-h-screen bg-zinc-950 flex items-center justify-center">
      <div className="w-full max-w-sm rounded-lg border border-zinc-800 bg-zinc-900 p-8">
        <h1 className="text-2xl font-semibold text-white mb-2">SOC Dashboard</h1>
        <p className="text-sm text-zinc-400 mb-6">Sign in to continue</p>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs text-zinc-400 mb-1">Username</label>
            <input
              className="w-full rounded-md border border-zinc-700 bg-black px-3 py-2 text-sm text-white outline-none focus:ring-2 ring-cyan-500"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              autoComplete="username"
            />
          </div>
          <div>
            <label className="block text-xs text-zinc-400 mb-1">Password</label>
            <input
              type="password"
              className="w-full rounded-md border border-zinc-700 bg-black px-3 py-2 text-sm text-white outline-none focus:ring-2 ring-cyan-500"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete="current-password"
            />
          </div>
          {error && <p className="text-sm text-red-400">{error}</p>}
          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-md bg-cyan-500 py-2 text-sm font-semibold text-zinc-950 hover:bg-cyan-400 disabled:opacity-60"
          >
            {loading ? "Signing in..." : "Sign In"}
          </button>
        </form>
        <p className="mt-6 text-xs text-zinc-600">
          Default: admin / soc2024 · Set ADMIN_USERNAME and ADMIN_PASSWORD env vars to
          change
        </p>
      </div>
    </main>
  );
}

import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SOC Analytics Dashboard",
  description: "Rule-based log analysis dashboard for common security events.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="bg-zinc-950 text-zinc-100">{children}</body>
    </html>
  );
}

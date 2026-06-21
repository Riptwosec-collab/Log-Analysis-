import type { Metadata } from "next";
import type { ReactNode } from "react";
import ExperienceProvider from "./components/ExperienceProvider";
import NavigationController from "./components/NavigationController";
import "./globals.css";
import "./experience.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://log-analysis-virid.vercel.app"),
  title: "Log Analysis SOC Dashboard",
  description: "Defensive SOC dashboard for log review, triage, filtering, MITRE mapping, and report export.",
  openGraph: {
    title: "Log Analysis SOC Dashboard",
    description: "Defensive SOC dashboard for log review and report export.",
    url: "https://log-analysis-virid.vercel.app/",
    siteName: "Log Analysis SOC Dashboard",
    type: "website",
  },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="th" suppressHydrationWarning>
      <body className="bg-zinc-950 text-zinc-100">
        <ExperienceProvider>
          <NavigationController />
          {children}
        </ExperienceProvider>
      </body>
    </html>
  );
}

import type { Metadata } from "next";
import type { ReactNode } from "react";
import CategorizedLogInsights from "./components/CategorizedLogInsights";
import DefaultLogCleaner from "./components/DefaultLogCleaner";
import ExperienceProvider from "./components/ExperienceProvider";
import GuideQuickAccess from "./components/GuideQuickAccess";
import Interactive3DLayer from "./components/Interactive3DLayer";
import LogReadingGuide from "./components/LogReadingGuide";
import NavigationController from "./components/NavigationController";
import PostAnalysisWorkflow from "./components/PostAnalysisWorkflow";
import "./globals.css";
import "./experience.css";
import "./interactive-3d.css";

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
          <Interactive3DLayer />
          <NavigationController />
          <DefaultLogCleaner />
          <GuideQuickAccess />
          {children}
          <CategorizedLogInsights />
          <PostAnalysisWorkflow />
          <LogReadingGuide />
        </ExperienceProvider>
      </body>
    </html>
  );
}

import WorkspacePage from "../components/WorkspacePage";

export default function LogsPage() {
  return (
    <WorkspacePage
      eyebrow="Logs"
      title="Logs"
      description="Central view for raw log ingestion, saved filters, and source parsing status."
      cards={[
        { title: "Live table and saved filters", body: "Review raw events, search by keyword, IP, host, user, and save common triage views." },
        { title: "Source health", body: "Track parser coverage for firewall, Windows, Linux, cloud, and application logs." },
        { title: "Export-ready workflow", body: "Move clean evidence into reports, tickets, or RCA output after analysis." },
      ]}
    />
  );
}

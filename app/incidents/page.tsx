import WorkspacePage from "../components/WorkspacePage";

export default function IncidentsPage() {
  return (
    <WorkspacePage
      eyebrow="Incidents"
      title="Incidents"
      description="Incident case board for RCA, evidence, timeline, business impact, and response status."
      cards={[
        { title: "Case lifecycle", body: "Move cases from New to Investigating, Contained, Resolved, or False Positive." },
        { title: "Evidence timeline", body: "Combine raw log lines, source IPs, users, assets, and MITRE mapping into one story." },
        { title: "RCA handoff", body: "Prepare manager summary, root cause, impact, and recommended remediation." },
      ]}
    />
  );
}

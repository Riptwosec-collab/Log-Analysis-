import WorkspacePage from "../components/WorkspacePage";

export default function AlertsPage() {
  return (
    <WorkspacePage
      eyebrow="Alerts"
      title="Alerts"
      description="SOC alert queue for severity, confidence, correlation, and escalation workflow."
      cards={[
        { title: "Severity queue", body: "Prioritize Critical and High alerts before Medium and Low signals." },
        { title: "Correlation context", body: "Group repeated indicators, users, assets, and techniques into incident candidates." },
        { title: "Role-based SOC actions", body: "Assign triage, acknowledge alerts, and prepare next-step fix commands." },
      ]}
    />
  );
}

import WorkspacePage from "../components/WorkspacePage";

export default function IntelPage() {
  return (
    <WorkspacePage
      eyebrow="Intelligence"
      title="Intelligence"
      description="Workspace for reviewing context, confidence, notes, and follow-up details."
      cards={[
        { title: "Context view", body: "Review signals found in analyzed logs and keep notes for follow-up." },
        { title: "Confidence flow", body: "Add asset importance, user context, and confidence scoring." },
        { title: "Report handoff", body: "Copy clean findings into reports, cases, and notes." },
      ]}
    />
  );
}

import WorkspacePage from "../components/WorkspacePage";

export default function MitrePage() {
  return (
    <WorkspacePage
      eyebrow="MITRE ATT&CK"
      title="MITRE ATT&CK"
      description="Tactic and technique coverage view for mapping findings to analyst-friendly categories."
      cards={[
        { title: "Coverage matrix", body: "Show tactics and techniques found in the current analysis result." },
        { title: "Technique detail", body: "Explain evidence, confidence, and recommended response for each mapping." },
        { title: "Report handoff", body: "Export a coverage summary for audit, RCA, and manager review." },
      ]}
    />
  );
}

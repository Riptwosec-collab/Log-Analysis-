import WorkspacePage from "../components/WorkspacePage";

export default function AssetsPage() {
  return (
    <WorkspacePage
      eyebrow="Assets"
      title="Assets"
      description="Asset inventory view for hosts, devices, cloud resources, and ownership context."
      cards={[
        { title: "Asset inventory", body: "Track names, owners, locations, and business criticality." },
        { title: "Risk context", body: "Connect findings to important assets and prioritize response work." },
        { title: "Operational notes", body: "Keep support notes, owner, and last review status in one view." },
      ]}
    />
  );
}

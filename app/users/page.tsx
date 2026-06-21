import WorkspacePage from "../components/WorkspacePage";

export default function UsersPage() {
  return (
    <WorkspacePage
      eyebrow="Users"
      title="Users"
      description="User workspace for accounts, activity context, and analyst notes."
      cards={[
        { title: "User timeline", body: "Review activity trends and recent notes for each account." },
        { title: "Context", body: "Connect events to user behavior, related assets, and review notes." },
        { title: "Case handoff", body: "Prepare a clear user-focused summary for tickets and reports." },
      ]}
    />
  );
}

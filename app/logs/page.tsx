import OperationalWorkspace from "../components/OperationalWorkspace";

const moduleName = "lo" + "gs";

export default function Page() {
  return <OperationalWorkspace module={moduleName as "logs"} />;
}

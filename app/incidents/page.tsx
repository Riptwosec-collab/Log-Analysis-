import OperationalWorkspace from "../components/OperationalWorkspace";

const moduleName = "inci" + "dents";

export default function Page() {
  return <OperationalWorkspace module={moduleName as "incidents"} />;
}

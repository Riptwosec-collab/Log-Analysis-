import type { ReactNode } from "react";
import OperationalWorkspace from "../components/OperationalWorkspace";

export default function RulesLayout(_props: { children: ReactNode }) {
  return <OperationalWorkspace module="rules" />;
}

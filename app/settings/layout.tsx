import type { ReactNode } from "react";
import OperationalWorkspace from "../components/OperationalWorkspace";

export default function SettingsLayout(_props: { children: ReactNode }) {
  return <OperationalWorkspace module="settings" />;
}

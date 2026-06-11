export type Severity = "Low" | "Medium" | "High" | "Critical";

export type LogType =
  | "Apache/Nginx"
  | "SSH Auth"
  | "Firewall"
  | "Windows Event"
  | "Linux Syslog"
  | "Cisco IOS"
  | "Meraki"
  | "Network Device"
  | "Application"
  | "Generic";

export type ParsedFields = {
  eventId: string | null;
  interfaceName: string | null;
  vlan: string | null;
  macAddress: string | null;
  action: string | null;
  protocol: string | null;
  httpMethod: string | null;
  urlPath: string | null;
  statusCode: string | null;
};

export type IocMatch = {
  value: string;
  type: "ip" | "domain" | "hash" | "keyword";
  severity: Severity;
  risk: number;
  source: string;
  note
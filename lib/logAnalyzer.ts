export type Severity = "Low" | "Medium" | "High" | "Critical";
export type LogType = "Apache/Nginx" | "SSH Auth" | "Firewall" | "Windows Event" | "Linux Syslog" | "Cisco IOS" | "Meraki" | "Network Device" | "Application" | "Generic";

type Rule = { name: string; severity: Severity; logType?: LogType; patterns: RegExp[]; keywords: string[]; rootCause: string; impact: string; fix: string; tactic: string; technique: string; confidence: number };
export type Finding = { id: string; lineNumber: number; timestamp
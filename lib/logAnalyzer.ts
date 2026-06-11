export type Severity="Low"|"Medium"|"High"|"Critical";
export type LogType="Apache/Nginx"|"SSH Auth"|"Firewall"|"Windows Event"|"Linux Syslog"|"Cisco IOS"|"Meraki"|"Network Device"|"Application"|"Generic";

type Rule={name:string;sev:Severity;pat:RegExp[];root:string;impact:string;fix:string;tactic:string;tech:string;conf:number};
export type Finding={id:string;lineNumber:number;timestamp:string|null;severity:Severity;logType:LogType;rule:string
/**
 * Demo log samples for the SOC Dashboard
 * 6 scenarios covering different attack types
 */

export type DemoScenario = {
  id: string;
  label: string;
  description: string;
  icon: string;
  severity: "Low" | "Medium" | "High" | "Critical";
  content: string;
};

export const DEMO_SCENARIOS: DemoScenario[] = [
  {
    id: "ssh-brute-force",
    label: "SSH Brute Force",
    description: "Multiple failed SSH login attempts from a single IP targeting various usernames",
    icon: "🔑",
    severity: "Critical",
    content: `Jun 10 21:14:02 web-01 sshd[1204]: Failed password for invalid user admin from 185.220.101.21 port 55110 ssh2
Jun 10 21:14:05 web-01 sshd[1205]: Failed password for invalid user root from 185.220.101.21 port 55111 ssh2
Jun 10 21:14:08 web-01 sshd[1206]: Failed password for invalid user ubuntu from 185.220.101.21 port 55112 ssh2
Jun 10 21:14:11 web-01 sshd[1207]: Failed password for invalid user pi from 185.220.101.21 port 55113 ssh2
Jun 10 21:14:14 web-01 sshd[1208]: Failed password for root from 185.220.101.21 port 55116 ssh2
Jun 10 21:14:17 web-01 sshd[1209]: Failed password for invalid user oracle from 185.220.101.21 port 55118 ssh2
Jun 10 21:14:20 web-01 sshd[1210]: Failed password for invalid user postgres from 185.220.101.21 port 55120 ssh2
Jun 10 21:14:23 web-01 sshd[1211]: Failed password for invalid user git from 185.220.101.21 port 55122 ssh2
Jun 10 21:14:26 web-01 sshd[1212]: Failed password for invalid user test from 185.220.101.21 port 55124 ssh2
Jun 10 21:14:29 web-01 sshd[1213]: Failed password for invalid user deploy from 185.220.101.21 port 55126 ssh2
Jun 10 21:14:32 web-01 sshd[1214]: Failed password for invalid user ansible from 185.220.101.21 port 55128 ssh2
Jun 10 21:14:35 web-01 sshd[1215]: Failed password for invalid user jenkins from 185.220.101.21 port 55130 ssh2
Jun 10 21:14:38 web-01 sshd[1216]: Failed password for root from 185.220.101.22 port 55132 ssh2
Jun 10 21:14:41 web-01 sshd[1217]: Failed password for root from 185.220.101.22 port 55134 ssh2
Jun 10 21:14:44 web-01 sshd[1218]: Failed password for invalid user admin from 185.220.101.22 port 55136 ssh2
Jun 10 21:15:00 web-01 sshd[1219]: Accepted password for backup from 10.0.0.5 port 44201 ssh2
Jun 10 21:15:04 web-01 sshd[1220]: Failed password for invalid user nagios from 45.77.10.2 port 55200 ssh2
Jun 10 21:15:08 web-01 sshd[1221]: Failed password for invalid user monitor from 45.77.10.2 port 55202 ssh2
Jun 10 21:15:12 web-01 sshd[1222]: Failed password for invalid user zabbix from 45.77.10.2 port 55204 ssh2
Jun 10 21:15:16 web-01 sshd[1223]: Connection closed by 45.77.10.2 port 55206 [preauth]`,
  },
  {
    id: "web-attack",
    label: "Web Attack Demo",
    description: "SQL Injection, Path Traversal, and XSS attempts against a web server",
    icon: "🕷️",
    severity: "High",
    content: `2026-06-10T21:16:40Z 198.51.100.44 "GET /login.php?id=1 UNION SELECT password,username FROM users-- HTTP/1.1" 403
2026-06-10T21:16:42Z 198.51.100.44 "GET /login.php?id=1' OR '1'='1 HTTP/1.1" 200
2026-06-10T21:16:45Z 198.51.100.44 "GET /search?q=1; DROP TABLE users-- HTTP/1.1" 500
2026-06-10T21:16:50Z 198.51.100.44 "GET /download?file=../../../../etc/passwd HTTP/1.1" 400
2026-06-10T21:16:53Z 198.51.100.44 "GET /download?file=../../../etc/shadow HTTP/1.1" 403
2026-06-10T21:16:56Z 198.51.100.44 "GET /download?file=../../windows/system32/config/SAM HTTP/1.1" 403
2026-06-10T21:17:00Z 198.51.100.44 "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1" 200
2026-06-10T21:17:02Z 198.51.100.44 "GET /profile?id=<img src=x onerror=alert(1)> HTTP/1.1" 200
2026-06-10T21:17:05Z 198.51.100.44 "GET /wp-admin/ HTTP/1.1" 401
2026-06-10T21:17:07Z 198.51.100.44 "GET /admin/config.php HTTP/1.1" 404
2026-06-10T21:17:09Z 198.51.100.44 "GET /.env HTTP/1.1" 200
2026-06-10T21:17:11Z 198.51.100.44 "GET /config.bak HTTP/1.1" 200
2026-06-10T21:17:14Z 203.0.113.9 "GET /api/users?id=1 UNION SELECT * FROM admin-- HTTP/1.1" 500
2026-06-10T21:17:17Z 203.0.113.9 "POST /login HTTP/1.1" body="username=admin&password=' OR 1=1--" 200
2026-06-10T21:17:20Z 10.0.0.15 "GET /api/health HTTP/1.1" 200
2026-06-10T21:17:22Z 10.0.0.15 "GET /api/status HTTP/1.1" 200
2026-06-10T21:17:25Z 198.51.100.44 "GET /phpinfo.php HTTP/1.1" 200
2026-06-10T21:17:28Z 198.51.100.44 "GET /server-status HTTP/1.1" 403`,
  },
  {
    id: "firewall-scan",
    label: "Firewall Port Scan",
    description: "Network reconnaissance with port scanning followed by repeated DROP rules",
    icon: "🔥",
    severity: "High",
    content: `2026-06-10T21:18:27Z firewall DROP SRC=45.77.10.2 DST=10.0.0.12 PROTO=TCP DPT=22 SYN
2026-06-10T21:18:28Z firewall DROP SRC=45.77.10.2 DST=10.0.0.12 PROTO=TCP DPT=23 SYN
2026-06-10T21:18:29Z firewall DROP SRC=45.77.10.2 DST=10.0.0.12 PROTO=TCP DPT=25 SYN
2026-06-10T21:18:30Z firewall DROP SRC=45.77.10.2 DST=10.0.0.12 PROTO=TCP DPT=80 SYN
2026-06-10T21:18:31Z firewall DROP SRC=45.77.10.2 DST=10.0.0.12 PROTO=TCP DPT=443 SYN
2026-06-10T21:18:32Z firewall DROP SRC=45.77.10.2 DST=10.0.0.12 PROTO=TCP DPT=3306 SYN
2026-06-10T21:18:33Z firewall DROP SRC=45.77.10.2 DST=10.0.0.12 PROTO=TCP DPT=3389 SYN
2026-06-10T21:18:34Z firewall DROP SRC=45.77.10.2 DST=10.0.0.12 PROTO=TCP DPT=445 SYN
2026-06-10T21:18:35Z firewall DROP SRC=45.77.10.2 DST=10.0.0.12 PROTO=TCP DPT=8080 SYN
2026-06-10T21:18:36Z firewall DROP SRC=45.77.10.2 DST=10.0.0.12 PROTO=TCP DPT=8443 SYN
2026-06-10T21:18:37Z firewall DROP SRC=45.77.10.2 DST=10.0.0.12 PROTO=TCP DPT=9200 SYN
2026-06-10T21:18:38Z firewall DROP SRC=45.77.10.2 DST=10.0.0.12 PROTO=TCP DPT=27017 SYN
2026-06-10T21:18:39Z firewall DROP SRC=45.77.10.2 DST=10.0.0.13 PROTO=TCP DPT=22 SYN
2026-06-10T21:18:40Z firewall DROP SRC=45.77.10.2 DST=10.0.0.14 PROTO=TCP DPT=22 SYN
2026-06-10T21:18:41Z firewall DROP SRC=45.77.10.2 DST=10.0.0.15 PROTO=TCP DPT=22 SYN
2026-06-10T21:18:45Z firewall ALLOW SRC=10.0.0.100 DST=8.8.8.8 PROTO=UDP DPT=53
2026-06-10T21:18:46Z firewall ALLOW SRC=10.0.0.100 DST=1.1.1.1 PROTO=UDP DPT=53
2026-06-10T21:19:00Z firewall DROP SRC=192.0.2.71 DST=10.0.0.12 PROTO=TCP DPT=1433 SYN
2026-06-10T21:19:01Z firewall DROP SRC=192.0.2.71 DST=10.0.0.12 PROTO=TCP DPT=5432 SYN
2026-06-10T21:19:02Z firewall DROP SRC=192.0.2.71 DST=10.0.0.12 PROTO=TCP DPT=6379 SYN`,
  },
  {
    id: "windows-login-failure",
    label: "Windows Login Failure",
    description: "Windows Event ID 4625 login failures and suspicious privilege escalation",
    icon: "🪟",
    severity: "High",
    content: `06/10/2026 09:19:44 PM Event ID 4625 Audit Failure Account Name: svc-backup Source Network Address: 192.0.2.71
06/10/2026 09:19:46 PM Event ID 4625 Audit Failure Account Name: svc-backup Source Network Address: 192.0.2.71
06/10/2026 09:19:48 PM Event ID 4625 Audit Failure Account Name: svc-backup Source Network Address: 192.0.2.71
06/10/2026 09:19:50 PM Event ID 4625 Audit Failure Account Name: svc-backup Source Network Address: 192.0.2.71
06/10/2026 09:19:52 PM Event ID 4625 Audit Failure Account Name: admin Source Network Address: 192.0.2.71
06/10/2026 09:19:54 PM Event ID 4625 Audit Failure Account Name: administrator Source Network Address: 192.0.2.71
06/10/2026 09:19:56 PM Event ID 4625 Audit Failure Account Name: finance01 Source Network Address: 192.0.2.71
06/10/2026 09:19:58 PM Event ID 4625 Audit Failure Account Name: hr-admin Source Network Address: 192.0.2.71
06/10/2026 09:20:00 PM Event ID 4625 Audit Failure Account Name: domain-admin Source Network Address: 192.0.2.71
06/10/2026 09:20:02 PM Event ID 4625 Audit Failure Account Name: sqlsvc Source Network Address: 192.0.2.71
06/10/2026 09:20:44 PM Event ID 4672 Special privileges assigned to new logon Account Name: admin Source Network Address: 192.0.2.71
06/10/2026 09:20:46 PM Event ID 4624 An account was successfully logged on Account Name: admin Source Network Address: 192.0.2.71
06/10/2026 09:21:44 PM Event ID 4720 A user account was created Account Name: temp-admin Source Network Address: 192.0.2.71
06/10/2026 09:22:00 PM Event ID 4732 A member was added to a security-enabled local group Group Name: Administrators Member Name: temp-admin
06/10/2026 09:22:44 PM Event ID 4740 A user account was locked out Account Name: finance01 Source Network Address: 192.0.2.71
06/10/2026 09:23:00 PM Event ID 4688 New Process Name: powershell.exe CommandLine: powershell -EncodedCommand SQBFAFgA
06/10/2026 09:23:15 PM Event ID 4688 New Process Name: cmd.exe CommandLine: cmd /c net user administrator /active:yes
06/10/2026 09:23:30 PM Event ID 4648 A logon was attempted using explicit credentials Account Name: temp-admin Source Network Address: 10.0.0.55`,
  },
  {
    id: "mixed-attack-chain",
    label: "Mixed Attack Chain",
    description: "Full attack chain: recon → web attack → SSH brute force → lateral movement",
    icon: "⛓️",
    severity: "Critical",
    content: `Jun 10 21:25:01 SW-CORE-01 %SW_MATM-4-MACFLAP_NOTIF: Host 6c3b.e51f.fd9f in vlan 2 is flapping between port Gi1/0/12 and port Gi1/0/20
Jun 10 21:25:12 SW-CORE-01 %SW_DAI-4-DHCP_SNOOPING_DENY: 1 Invalid ARPs on Gi1/0/15, vlan 2
2026-06-10T21:18:27Z firewall DROP SRC=185.220.101.21 DST=10.0.0.12 PROTO=TCP DPT=22 SYN
2026-06-10T21:18:31Z firewall DROP SRC=185.220.101.21 DST=10.0.0.12 PROTO=TCP DPT=80 SYN
2026-06-10T21:18:35Z firewall DROP SRC=185.220.101.21 DST=10.0.0.12 PROTO=TCP DPT=443 SYN
2026-06-10T21:18:39Z firewall DROP SRC=185.220.101.21 DST=10.0.0.12 PROTO=TCP DPT=3389 SYN
2026-06-10T21:18:42Z firewall DROP SRC=185.220.101.21 DST=10.0.0.12 PROTO=TCP DPT=445 SYN
2026-06-10T21:16:40Z 185.220.101.21 "GET /login.php?id=1 UNION SELECT password FROM users HTTP/1.1" 403
2026-06-10T21:17:11Z 185.220.101.21 "GET /download?file=../../../../etc/passwd HTTP/1.1" 400
Jun 10 21:14:02 web-01 sshd[1204]: Failed password for invalid user admin from 185.220.101.21 port 55110 ssh2
Jun 10 21:14:18 web-01 sshd[1208]: Failed password for root from 185.220.101.21 port 55116 ssh2
Jun 10 21:15:04 web-01 sshd[1213]: Failed password for invalid user oracle from 185.220.101.21 port 55122 ssh2
Jun 10 21:15:35 web-01 sshd[1219]: Failed password for invalid user postgres from 185.220.101.21 port 55130 ssh2
Jun 10 21:16:02 web-01 sshd[1220]: Failed password for invalid user test from 185.220.101.21 port 55134 ssh2
06/10/2026 09:19:44 PM Event ID 4625 Audit Failure Account Name: svc-backup Source Network Address: 192.0.2.71
06/10/2026 09:20:44 PM Event ID 4672 Special privileges assigned to new logon Account Name: admin Source Network Address: 192.0.2.71
06/10/2026 09:21:44 PM Event ID 4720 A user account was created Account Name: temp-admin Source Network Address: 192.0.2.71
06/10/2026 09:22:44 PM Event ID 4740 A user account was locked out Account Name: finance01 Source Network Address: 192.0.2.71
06/10/2026 09:23:00 PM Event ID 4688 New Process Name: powershell.exe CommandLine: powershell -EncodedCommand SQBFAFgA
2026-06-10T21:24:01Z endpoint alert file_hash=44d88612fea8a8f36de82e1278abb02f domain=evil.example.com`,
  },
  {
    id: "clean-normal",
    label: "Clean Normal Logs",
    description: "Normal operational logs with no suspicious activity — expected result: Low risk",
    icon: "✅",
    severity: "Low",
    content: `Jun 10 09:00:01 web-01 sshd[801]: Accepted publickey for deploy from 10.0.0.5 port 44201 ssh2
Jun 10 09:00:05 web-01 systemd[1]: Started nginx.service
Jun 10 09:00:10 web-01 kernel: eth0: renamed from veth7a1b2c3
2026-06-10T09:01:00Z 10.0.0.100 "GET / HTTP/1.1" 200
2026-06-10T09:01:01Z 10.0.0.100 "GET /api/status HTTP/1.1" 200
2026-06-10T09:01:02Z 10.0.0.100 "GET /favicon.ico HTTP/1.1" 200
2026-06-10T09:02:00Z 10.0.0.101 "GET /api/health HTTP/1.1" 200
Jun 10 09:03:00 web-01 sshd[920]: Accepted publickey for ops from 10.0.0.6 port 44220 ssh2
2026-06-10T09:04:00Z firewall ALLOW SRC=10.0.0.100 DST=8.8.8.8 PROTO=UDP DPT=53
2026-06-10T09:04:01Z firewall ALLOW SRC=10.0.0.100 DST=1.1.1.1 PROTO=UDP DPT=53
06/10/2026 09:05:00 AM Event ID 4624 An account was successfully logged on Account Name: john.doe Source Network Address: 10.0.0.50
Jun 10 09:10:01 web-01 cron[1001]: (root) CMD (/usr/lib/apt/apt.systemd.daily)
Jun 10 09:15:00 web-01 sshd[1100]: Accepted publickey for backup from 10.0.0.5 port 44250 ssh2
2026-06-10T09:20:00Z 10.0.0.102 "GET /api/metrics HTTP/1.1" 200
2026-06-10T09:20:01Z 10.0.0.102 "POST /api/logs HTTP/1.1" 201
Jun 10 09:25:00 web-01 systemd[1]: nginx.service: Reloading
Jun 10 09:25:01 web-01 nginx[1200]: reload signal received`,
  },
];

export const DEFAULT_DEMO_ID = "mixed-attack-chain";

export function getDemoLog(id: string): string {
  return DEMO_SCENARIOS.find((s) => s.id === id)?.content ?? DEMO_SCENARIOS[4].content;
}

import { analyzeLog } from "../lib/logAnalyzer";

describe("detectLogType via analyzeLog", () => {
  test("SSH brute force detected", () => {
    const log = Array(6)
      .fill(
        "Jun 10 12:00:01 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2"
      )
      .join("\n");
    const result = analyzeLog(log);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.some((f) => f.logType === "SSH Auth")).toBe(true);
  });

  test("SQL Injection detected", () => {
    const log =
      '192.168.1.1 - - [10/Jun/2026:12:00:00 +0000] "GET /index.php?id=1 UNION SELECT 1,2,3-- HTTP/1.1" 200 512';
    const result = analyzeLog(log);
    expect(
      result.findings.some(
        (f) =>
          f.rule.toLowerCase().includes("sql") ||
          f.detectedKeywords.some((k) => k.toLowerCase().includes("union"))
      )
    ).toBe(true);
  });

  test("Risk score is 0 for clean logs", () => {
    const log = "Jun 10 12:00:00 server systemd[1]: Started nginx.service.";
    const result = analyzeLog(log);
    expect(result.summary.riskScore).toBe(0);
  });

  test("Critical severity sets riskScore above 50", () => {
    const log = Array(10)
      .fill(
        "Jun 10 12:00:01 server sshd[1]: Failed password for invalid user root from 1.2.3.4 port 9999 ssh2"
      )
      .join("\n");
    const result = analyzeLog(log);
    expect(result.summary.riskScore).toBeGreaterThan(50);
  });

  test("Windows Event ID 4625 detected as failed logon", () => {
    const log =
      "06/10/2026 12:00:00 AM,Security,Audit Failure,4625,,An account failed to log on.";
    const result = analyzeLog(log);
    expect(result.summary.failedLogins).toBeGreaterThan(0);
  });

  test("AnalysisResult has required shape", () => {
    const result = analyzeLog("test");
    expect(result).toHaveProperty("generatedAt");
    expect(result).toHaveProperty("summary");
    expect(result).toHaveProperty("findings");
    expect(Array.isArray(result.findings)).toBe(true);
  });

  test("Correlations generated for brute force burst", () => {
    const lines = Array.from(
      { length: 8 },
      (_, i) =>
        `Jun 10 12:0${i}:01 server sshd[${i}]: Failed password for invalid user admin from 10.0.0.1 port ${50000 + i} ssh2`
    ).join("\n");
    const result = analyzeLog(lines);
    expect(result.summary.correlations.length).toBeGreaterThan(0);
  });
});

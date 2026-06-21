import { NextResponse } from "next/server";
import { analyzeLog } from "../../../lib/logAnalyzer";
import type { Finding } from "../../../lib/logAnalyzer";

// Simple in-memory rate limiter: 30 req/min per IP
const rateLimitMap = new Map<string, { count: number; reset: number }>();
const MAX_BODY_BYTES = 2 * 1024 * 1024; // 2MB

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || now > entry.reset) {
    rateLimitMap.set(ip, { count: 1, reset: now + 60_000 });
    return true;
  }
  if (entry.count >= 30) return false;
  entry.count++;
  return true;
}

const ABUSEIPDB_KEY = process.env.ABUSEIPDB_API_KEY;
const abuseCache = new Map<string, { score: number; country: string; isp: string }>();

async function lookupAbuseIPDB(ip: string) {
  if (abuseCache.has(ip)) return abuseCache.get(ip)!;
  if (!ABUSEIPDB_KEY) return null;
  try {
    const r = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      {
        headers: { Key: ABUSEIPDB_KEY, Accept: "application/json" },
        signal: AbortSignal.timeout(3000),
      }
    );
    if (!r.ok) return null;
    const { data } = await r.json();
    const result = {
      score: data.abuseConfidenceScore,
      country: data.countryCode,
      isp: data.isp,
    };
    abuseCache.set(ip, result);
    return result;
  } catch {
    return null;
  }
}

export async function POST(req: Request) {
  const ip =
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";

  try {
    if (!checkRateLimit(ip)) {
      return NextResponse.json(
        { error: "Rate limit exceeded. Try again in a minute." },
        { status: 429 }
      );
    }

    const contentType = req.headers.get("content-type") || "";
    let logContent = "";
    let body: any = {};

    if (contentType.includes("multipart/form-data")) {
      const formData = await req.formData();
      const file = formData.get("file") as File | null;
      logContent = file ? await file.text() : String(formData.get("log") || "");
    } else {
      // Body size check for JSON
      const contentLength = Number(req.headers.get("content-length") ?? 0);
      if (contentLength > MAX_BODY_BYTES) {
        return NextResponse.json(
          { error: "Log too large. Maximum 2MB." },
          { status: 413 }
        );
      }
      body = await req.json();
      logContent = readLogValue(body?.log);
    }

    if (!logContent.trim()) {
      return NextResponse.json(
        { error: "Log content is required." },
        { status: 400 }
      );
    }

    const result = analyzeLog(logContent);

    // Apply custom rules
    if (Array.isArray(body.customRules)) {
      const lines = logContent.split("\n");
      body.customRules
        .filter((r: any) => r.enabled !== false)
        .forEach((r: any, ri: number) => {
          try {
            const rx = new RegExp(r.patternStr || r.pattern, "i");
            lines.forEach((line, li) => {
              if (rx.test(line)) {
                result.findings.push({
                  id: `CUSTOM-${ri}-${li}`,
                  lineNumber: li + 1,
                  timestamp: null,
                  severity: r.severity || "Medium",
                  logType: "Generic",
                  rule: r.name,
                  detectedKeywords: r.keywords || [],
                  possibleRootCause: r.rootCause || "",
                  impact: r.impact || "",
                  recommendedFix: r.fix || "",
                  sourceIp: null,
                  destinationIp: null,
                  destinationPort: null,
                  username: null,
                  asset: null,
                  tactic: r.tactic || "Custom",
                  technique: r.technique || "T0000 Custom",
                  confidence: 70,
                  evidence: line.slice(0, 200),
                  raw: line,
                  repeatedCount: 1,
                } as Finding);
              }
            });
          } catch {}
        });
    }

    // Apply custom IOCs
    if (Array.isArray(body.customIocs)) {
      const lines = logContent.split("\n");
      body.customIocs.forEach((ioc: any, ii: number) => {
        if (!ioc.indicator) return;
        const escaped = ioc.indicator.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const rx = new RegExp(escaped, "i");
        lines.forEach((line, li) => {
          if (rx.test(line)) {
            result.findings.push({
              id: `IOC-${ii}-${li}`,
              lineNumber: li + 1,
              timestamp: null,
              severity: ioc.risk || "High",
              logType: "Generic",
              rule: `Custom IOC: ${ioc.indicator}`,
              detectedKeywords: [ioc.indicator],
              possibleRootCause: `Known malicious indicator: ${ioc.indicator}`,
              impact: ioc.description || "Threat indicator detected",
              recommendedFix: "Block indicator and investigate",
              sourceIp: ioc.type === "ip" ? ioc.indicator : null,
              destinationIp: null,
              destinationPort: null,
              username: null,
              asset: null,
              tactic: "Indicator Match",
              technique: "T9998 Custom IOC",
              confidence: 85,
              evidence: line.slice(0, 200),
              raw: line,
              repeatedCount: 1,
              iocType: ioc.type,
              iocRisk: ioc.risk,
              iocDescription: ioc.description,
            } as Finding & { iocType?: string; iocRisk?: string; iocDescription?: string });
          }
        });
      });
    }

    // Enrich findings with live AbuseIPDB data if API key is set
    if (ABUSEIPDB_KEY) {
      const publicIps = [
        ...new Set(
          result.findings
            .map((f: Finding) => f.sourceIp)
            .filter(
              (ip): ip is string =>
                !!ip &&
                !ip.startsWith("10.") &&
                !ip.startsWith("192.168.") &&
                !ip.startsWith("127.")
            )
        ),
      ].slice(0, 10); // limit to 10 IPs per request to avoid rate limit

      await Promise.all(
        publicIps.map(async (ip) => {
          const abuse = await lookupAbuseIPDB(ip);
          if (!abuse) return;
          result.findings.forEach((f: Finding) => {
            if (f.sourceIp === ip) {
              if (abuse.score > (f.abuseScore ?? -1)) f.abuseScore = abuse.score;
              if (!f.geoCountry) f.geoCountry = abuse.country;
            }
          });
        })
      );
    }

    // Audit logging
    try {
      const { appendFile } = await import("fs/promises");
      const { join } = await import("path");
      const entry =
        JSON.stringify({
          ts: new Date().toISOString(),
          ip,
          logSize: logContent.length,
          riskScore: result.summary.riskScore,
          riskLevel: result.summary.riskLevel,
          findingCount: result.findings.length,
          criticalCount: result.summary.criticalAlerts,
          status: "success",
        }) + "\n";
      await appendFile(join(process.cwd(), "audit.log"), entry, "utf8");
    } catch {}

    return NextResponse.json(result, { status: 200 });
  } catch (error) {
    // Audit logging for errors
    try {
      const { appendFile } = await import("fs/promises");
      const { join } = await import("path");
      const entry =
        JSON.stringify({
          ts: new Date().toISOString(),
          ip,
          logSize: 0,
          riskScore: null,
          riskLevel: null,
          findingCount: null,
          criticalCount: null,
          status: "error",
        }) + "\n";
      await appendFile(join(process.cwd(), "audit.log"), entry, "utf8");
    } catch {}

    console.error("Analyze API error:", error);
    return NextResponse.json(
      { error: "Unable to analyze the submitted log." },
      { status: 500 }
    );
  }
}

function readLogValue(value: unknown): string {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(readLogValue).join("\n");
  if (value && typeof value === "object" && "value" in value) {
    return readLogValue((value as { value: unknown }).value);
  }
  return "";
}

/**
 * Extended type definitions for Mini SIEM / SOC Log Analyzer
 * Wraps and extends the core types from lib/logAnalyzer.ts
 */

import type { Severity, LogType, Finding, Correlation } from "@/lib/logAnalyzer";
export type { Severity, LogType, Finding, Correlation };

// ─── Parsed Event ────────────────────────────────────────────────────────────
export type ParsedEvent = {
  id: string;
  lineNumber: number;
  raw: string;
  timestamp: string | null;
  sourceType: LogType;
  host: string | null;
  sourceIp: string | null;
  destinationIp: string | null;
  destinationPort: string | null;
  username: string | null;
  method: string | null;
  path: string | null;
  statusCode: number | null;
  port: number | null;
  protocol: string | null;
  action: string | null;
  eventId: string | null;
};

// ─── Detection Alert ─────────────────────────────────────────────────────────
export type DetectionAlert = {
  id: string;
  ruleId: string;
  ruleName: string;
  description: string;
  severity: Severity;
  sourceIp: string | null;
  destinationIp: string | null;
  username: string | null;
  host: string | null;
  logType: LogType;
  tactic: string;
  technique: string;
  techniqueId: string;
  recommendation: string;
  playbook: string[];
  evidence: string[];           // raw log lines
  evidenceCount: number;
  firstSeen: string | null;
  lastSeen: string | null;
  confidence: number;           // 0-100
  repeatedCount: number;
};

// ─── Detection Rule ──────────────────────────────────────────────────────────
export type DetectionRule = {
  ruleId: string;
  name: string;
  description: string;
  severity: Severity;
  sourceType: LogType | "Any";
  mitreTactic: string;
  mitreTechnique: string;
  mitreTechniqueId: string;
  enabled: boolean;
  matchedCount?: number;
  tags: string[];
  recommendation: string;
};

// ─── Timeline Item ───────────────────────────────────────────────────────────
export type TimelineItem = {
  id: string;
  timestamp: string;
  eventType: string;
  severity: Severity;
  sourceIp: string | null;
  message: string;
  relatedAlertId?: string;
  logType: LogType;
};

// ─── MITRE Technique ─────────────────────────────────────────────────────────
export type MitreTechniqueEntry = {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  alertCount: number;
  severity: Severity;
  sourceIps: string[];
};

// ─── Risk Breakdown ──────────────────────────────────────────────────────────
export type RiskFactor = {
  label: string;
  score: number;
  reason: string;
};

export type RiskBreakdown = {
  total: number;
  level: "Low" | "Medium" | "High" | "Critical";
  factors: RiskFactor[];
};

// ─── Correlated Incident ─────────────────────────────────────────────────────
export type CorrelatedIncident = {
  id: string;
  title: string;
  severity: Severity;
  attackChain: string[];
  sourceIp: string | null;
  affectedHosts: string[];
  affectedUsers: string[];
  mitreTechniques: string[];
  alertCount: number;
  firstSeen: string | null;
  lastSeen: string | null;
  story: string;
  recommendation: string;
};

// ─── Analysis Result (extended) ──────────────────────────────────────────────
export type AnalysisMeta = {
  id: string;
  createdAt: string;
  fileName?: string;
  fileSize?: number;
  totalLines: number;
  analysisMs: number;
};

export type ExtendedAnalysisResult = {
  meta: AnalysisMeta;
  riskBreakdown: RiskBreakdown;
  alerts: DetectionAlert[];
  correlations: CorrelatedIncident[];
  timeline: TimelineItem[];
  mitreCoverage: MitreTechniqueEntry[];
  topSourceIps: Array<{ ip: string; count: number; severity: Severity }>;
  summary: {
    totalEvents: number;
    criticalAlerts: number;
    highAlerts: number;
    mediumAlerts: number;
    lowAlerts: number;
    suspiciousIps: number;
    failedLogins: number;
    webAttacks: number;
    firewallDrops: number;
    correlationCount: number;
    mitreTechniqueCount: number;
    topSourceIp: string | null;
  };
  aiSummary: {
    whatHappened: string;
    whyItMatters: string;
    mitreMapping: string;
    recommendedActions: string[];
    nextSteps: string[];
    verdict: "Benign" | "Suspicious" | "Malicious" | "Critical";
  };
};

// ─── History Entry ───────────────────────────────────────────────────────────
export type HistoryEntry = {
  id: string;
  createdAt: string;
  label: string;
  fileName?: string;
  totalEvents: number;
  riskScore: number;
  riskLevel: Severity;
  criticalCount: number;
  summary: string;
};

// ─── Report Data ─────────────────────────────────────────────────────────────
export type ReportData = {
  generatedAt: string;
  riskBreakdown: RiskBreakdown;
  executiveSummary: string;
  topFindings: DetectionAlert[];
  timeline: TimelineItem[];
  mitreCoverage: MitreTechniqueEntry[];
  topSourceIps: Array<{ ip: string; count: number; severity: Severity }>;
  recommendations: string[];
  rawEvidenceCount: number;
};

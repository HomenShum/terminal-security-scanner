/**
 * Audit report generation.
 * Produces both console output and structured JSON.
 */

import type { Finding, Severity } from "./detectors.js";
import type { ScanTarget } from "./targets.js";

export interface AuditReport {
  timestamp: string;
  targetsScanned: number;
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  byDetector: Record<string, number>;
  byCategory: Record<string, number>;
  findings: Finding[];
  targets: Array<{ path: string; category: string; findings: number }>;
  summary: string;
}

export function generateReport(findings: Finding[], targets: ScanTarget[]): AuditReport {
  const bySeverity: Record<Severity, number> = { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  const byDetector: Record<string, number> = {};
  const byCategory: Record<string, number> = {};

  for (const f of findings) {
    bySeverity[f.severity]++;
    byDetector[f.detector] = (byDetector[f.detector] || 0) + 1;
  }

  const targetSummaries = targets.map((t) => {
    const count = findings.filter((f) => f.file === t.path).length;
    byCategory[t.category] = (byCategory[t.category] || 0) + count;
    return { path: t.path, category: t.category, findings: count };
  });

  const summary = buildSummary(findings, targets, bySeverity);

  return {
    timestamp: new Date().toISOString(),
    targetsScanned: targets.length,
    totalFindings: findings.length,
    bySeverity,
    byDetector,
    byCategory,
    findings,
    targets: targetSummaries,
    summary,
  };
}

function buildSummary(
  findings: Finding[],
  targets: ScanTarget[],
  bySeverity: Record<Severity, number>,
): string {
  const lines: string[] = [];

  if (findings.length === 0) {
    lines.push("No security findings detected. Your terminal environment looks clean.");
    lines.push(`Scanned ${targets.length} files across shell history, dotfiles, and project scripts.`);
    return lines.join("\n");
  }

  lines.push(`Found ${findings.length} potential security issue${findings.length === 1 ? "" : "s"} across ${targets.length} files.`);

  if (bySeverity.HIGH > 0) {
    lines.push(`${bySeverity.HIGH} HIGH severity finding${bySeverity.HIGH === 1 ? "" : "s"} require immediate attention.`);
  }
  if (bySeverity.MEDIUM > 0) {
    lines.push(`${bySeverity.MEDIUM} MEDIUM severity finding${bySeverity.MEDIUM === 1 ? "" : "s"} should be reviewed.`);
  }
  if (bySeverity.LOW > 0) {
    lines.push(`${bySeverity.LOW} LOW severity finding${bySeverity.LOW === 1 ? "" : "s"} flagged for awareness.`);
  }

  return lines.join("\n");
}

export function printReport(report: AuditReport, verbose = false): void {
  console.log("");
  console.log("╔══════════════════════════════════════════════════════════════════╗");
  console.log("║  TERMINAL SECURITY AUDIT REPORT                                ║");
  console.log("╠══════════════════════════════════════════════════════════════════╣");
  console.log(`║  Timestamp: ${report.timestamp.padEnd(51)}║`);
  console.log(`║  Files scanned: ${String(report.targetsScanned).padEnd(47)}║`);
  console.log(`║  Total findings: ${String(report.totalFindings).padEnd(46)}║`);
  console.log("╠══════════════════════════════════════════════════════════════════╣");
  console.log("║  SEVERITY BREAKDOWN                                            ║");
  console.log("╠══════════════════════════════════════════════════════════════════╣");

  const severityColors: Record<Severity, string> = {
    HIGH: "\x1b[31m",    // Red
    MEDIUM: "\x1b[33m",  // Yellow
    LOW: "\x1b[36m",     // Cyan
    INFO: "\x1b[90m",    // Gray
  };
  const reset = "\x1b[0m";

  for (const sev of ["HIGH", "MEDIUM", "LOW", "INFO"] as Severity[]) {
    const count = report.bySeverity[sev];
    const bar = count > 0 ? "█".repeat(Math.min(count, 30)) : "";
    console.log(`║  ${severityColors[sev]}${sev.padEnd(8)}${reset} ${String(count).padStart(4)} ${bar}`.padEnd(75 + (count > 0 ? 9 : 0)) + "║");
  }

  console.log("╠══════════════════════════════════════════════════════════════════╣");
  console.log("║  DETECTOR BREAKDOWN                                            ║");
  console.log("╠══════════════════════════════════════════════════════════════════╣");

  const detectorLabels: Record<string, string> = {
    homograph: "Homograph attacks",
    ansi: "ANSI injections",
    url: "Suspicious URLs",
  };

  for (const [detector, count] of Object.entries(report.byDetector)) {
    const label = detectorLabels[detector] || detector;
    console.log(`║  ${label.padEnd(30)} ${String(count).padStart(4)}`.padEnd(66) + "║");
  }

  if (report.totalFindings > 0) {
    console.log("╠══════════════════════════════════════════════════════════════════╣");
    console.log("║  FILES WITH FINDINGS                                           ║");
    console.log("╠══════════════════════════════════════════════════════════════════╣");

    const filesWithFindings = report.targets
      .filter((t) => t.findings > 0)
      .sort((a, b) => b.findings - a.findings);

    for (const target of filesWithFindings) {
      const shortPath = target.path.length > 45
        ? "..." + target.path.slice(-42)
        : target.path;
      console.log(`║  ${shortPath.padEnd(48)} ${String(target.findings).padStart(4)} findings`.padEnd(66) + "║");
    }
  }

  if (verbose && report.findings.length > 0) {
    console.log("╠══════════════════════════════════════════════════════════════════╣");
    console.log("║  DETAILED FINDINGS                                             ║");
    console.log("╠══════════════════════════════════════════════════════════════════╣");

    // Group by severity, HIGH first
    const sorted = [...report.findings].sort((a, b) => {
      const order: Record<Severity, number> = { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 };
      return order[a.severity] - order[b.severity];
    });

    for (const finding of sorted) {
      const color = severityColors[finding.severity];
      console.log(`║                                                                  ║`);
      console.log(`║  ${color}[${finding.severity}]${reset} ${finding.detector.toUpperCase()}`.padEnd(75 + 9) + "║");

      const shortFile = finding.file.length > 40
        ? "..." + finding.file.slice(-37)
        : finding.file;
      console.log(`║  File: ${shortFile}:${finding.line}:${finding.column}`.padEnd(66) + "║");

      // Word-wrap description
      const descWords = finding.description.split(" ");
      let line = "║  ";
      for (const word of descWords) {
        if ((line + word).length > 64) {
          console.log(line.padEnd(66) + "║");
          line = "║  " + word + " ";
        } else {
          line += word + " ";
        }
      }
      if (line.trim() !== "║") console.log(line.padEnd(66) + "║");

      if (finding.snippet) {
        const safeSnippet = finding.snippet.slice(0, 55);
        console.log(`║  > ${safeSnippet}`.padEnd(66) + "║");
      }
    }
  }

  console.log("╠══════════════════════════════════════════════════════════════════╣");
  console.log("║  SUMMARY                                                       ║");
  console.log("╠══════════════════════════════════════════════════════════════════╣");

  for (const line of report.summary.split("\n")) {
    console.log(`║  ${line}`.padEnd(66) + "║");
  }

  console.log("╚══════════════════════════════════════════════════════════════════╝");
  console.log("");
}

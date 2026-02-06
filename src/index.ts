#!/usr/bin/env node

/**
 * Terminal Security Scanner
 *
 * Scans your dev environment for:
 * - Homograph attacks (Unicode characters mimicking ASCII)
 * - ANSI escape injections (clipboard access, cursor manipulation, hidden text)
 * - Suspicious URL patterns (data:, javascript:, IDN homograph domains)
 *
 * Usage:
 *   npx terminal-security-scanner                  # Scan home + current directory
 *   npx terminal-security-scanner --project ./app  # Scan specific project
 *   npx terminal-security-scanner --verbose         # Show all findings in detail
 *   npx terminal-security-scanner --json            # Output structured JSON
 */

import * as path from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";
import { scanContent, type Finding } from "./detectors.js";
import { discoverTargets, readTarget, type ScanTarget } from "./targets.js";
import { generateReport, printReport, type AuditReport } from "./report.js";

// ── CLI argument parsing ──────────────────────────────────────────────
const args = process.argv.slice(2);

if (args.includes("--help") || args.includes("-h")) {
  console.log(`
Terminal Security Scanner v1.0.0

Scans your dev environment for homograph attacks, ANSI injections,
and suspicious URL patterns in shell history, dotfiles, and CI scripts.

Usage:
  terminal-security-scanner [options]

Options:
  --project <path>   Project directory to scan (default: current directory)
  --verbose, -v      Show detailed findings with line numbers and snippets
  --json             Output structured JSON instead of formatted report
  --no-home          Skip scanning home directory files (history, dotfiles)
  --help, -h         Show this help
  --version          Show version

Examples:
  terminal-security-scanner                    # Full scan
  terminal-security-scanner --project ./myapp  # Scan specific project
  terminal-security-scanner --verbose --json   # Detailed JSON output
`);
  process.exit(0);
}

if (args.includes("--version")) {
  console.log("1.0.0");
  process.exit(0);
}

const verbose = args.includes("--verbose") || args.includes("-v");
const jsonOutput = args.includes("--json");
const skipHome = args.includes("--no-home");

const projectIdx = args.indexOf("--project");
const projectRoot = projectIdx !== -1 && args[projectIdx + 1]
  ? path.resolve(args[projectIdx + 1])
  : process.cwd();

// ── Main scan pipeline ────────────────────────────────────────────────

function run(): AuditReport {
  const startTime = Date.now();

  // Phase 1: Discover targets
  if (!jsonOutput) {
    console.log("Discovering scan targets...");
  }

  let targets = discoverTargets(projectRoot);

  // Filter out home directory targets if --no-home
  if (skipHome) {
    const home = os.homedir();
    targets = targets.filter((t) => !t.path.startsWith(home));
  }

  if (!jsonOutput) {
    console.log(`Found ${targets.length} files to scan.`);
    const byCategory: Record<string, number> = {};
    for (const t of targets) {
      byCategory[t.category] = (byCategory[t.category] || 0) + 1;
    }
    for (const [cat, count] of Object.entries(byCategory)) {
      console.log(`  ${cat}: ${count} files`);
    }
    console.log("");
    console.log("Scanning for security issues...");
  }

  // Phase 2: Scan all targets
  const allFindings: Finding[] = [];
  let scannedCount = 0;

  for (const target of targets) {
    const content = readTarget(target);
    if (!content) continue;

    const findings = scanContent(content, target.path);
    allFindings.push(...findings);
    scannedCount++;

    if (!jsonOutput && findings.length > 0) {
      const shortPath = target.path.length > 60
        ? "..." + target.path.slice(-57)
        : target.path;
      console.log(`  [${findings.length} findings] ${shortPath}`);
    }
  }

  // Phase 3: Generate report
  const report = generateReport(allFindings, targets);

  const elapsed = Date.now() - startTime;
  if (!jsonOutput) {
    console.log(`\nScan completed in ${elapsed}ms.`);
  }

  return report;
}

// ── Execute ───────────────────────────────────────────────────────────

const report = run();

if (jsonOutput) {
  console.log(JSON.stringify(report, null, 2));
} else {
  printReport(report, verbose);
}

// Write JSON report to file regardless
const reportPath = path.join(projectRoot, "security-audit-report.json");
try {
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  if (!jsonOutput) {
    console.log(`Full report saved to: ${reportPath}`);
  }
} catch {
  // Can't write to project root — write to temp
  const tempPath = path.join(os.tmpdir(), "security-audit-report.json");
  try {
    fs.writeFileSync(tempPath, JSON.stringify(report, null, 2));
    if (!jsonOutput) {
      console.log(`Full report saved to: ${tempPath}`);
    }
  } catch {
    // Silently skip file output
  }
}

// Exit with non-zero if HIGH findings
if (report.bySeverity.HIGH > 0) {
  process.exit(1);
}

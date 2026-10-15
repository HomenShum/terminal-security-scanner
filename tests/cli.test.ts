import { afterAll, describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { createRequire } from "node:module";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const tsxCli = createRequire(import.meta.url).resolve("tsx/cli");

const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "terminal-scanner-cli-"));
const home = path.join(fixture, "home");
const temp = path.join(fixture, "tmp");
fs.mkdirSync(home);
fs.mkdirSync(temp);
fs.writeFileSync(path.join(home, ".bash_history"), "url=javascript:homeHistoryMarker\n");
fs.writeFileSync(path.join(home, ".bashrc"), "export MARKER=home\u200bDotfile\n");
const guard = path.join(fixture, "home-guard.cjs");
fs.writeFileSync(guard, `
const fs = require('node:fs');
const path = require('node:path');
const home = path.resolve(process.env.SCANNER_TEST_HOME);
if (path.resolve(require('node:os').homedir()) !== home) throw new Error('synthetic HOME guard failed');
const personal = new Set(['.bash_history','.zsh_history','.history','.node_repl_history','.python_history','.psql_history','.mysql_history','.irb_history','.bashrc','.bash_profile','.bash_login','.profile','.zshrc','.zprofile','.zshenv','.zlogin','.inputrc','.curlrc','.wgetrc','.npmrc','.gitconfig','.ssh/config','.ssh/authorized_keys','.ssh/known_hosts'].map(p => path.resolve(home,p)));
const access = [];
for (const method of ['statSync','readFileSync','openSync']) {
  const original = fs[method];
  fs[method] = function(file, ...args) {
    if (typeof file === 'string' && personal.has(path.resolve(file))) access.push({method,path:path.resolve(file)});
    return original.call(this,file,...args);
  };
}
require('node:module').syncBuiltinESMExports();
process.on('exit', () => fs.writeFileSync(process.env.SCANNER_TEST_TRACE, JSON.stringify({homeVerified:true,access})));
`);

function project(folder: string, clean = false, sparse = false) {
  fs.mkdirSync(folder, { recursive: true });
  fs.writeFileSync(path.join(folder, "package.json"), '{"name":"synthetic-scanner-fixture","private":true}\n');
  fs.writeFileSync(path.join(folder, "build.sh"), clean ? "echo clean-fixture\n" : "url=javascript:scriptMarker\n");
  if (!sparse) {
    fs.mkdirSync(path.join(folder, ".github", "workflows"), { recursive: true });
    fs.writeFileSync(path.join(folder, ".github", "workflows", "scan.yml"), clean ? "name: Clean fixture\n" : "url: javascript:ciMarker\n");
    fs.writeFileSync(path.join(folder, ".env"), clean ? "MARKER=synthetic-clean\n" : "MARKER=synthetic\u200bEnvironment\n");
  }
  return folder;
}

let sequence = 0;
async function scan(projectRoot: string, includeHome = false) {
  const trace = path.join(fixture, `access-${sequence++}.json`);
  const runtimeEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    ["PATH", "SystemRoot", "WINDIR", "COMSPEC", "PATHEXT"].includes(key)));
  const args = [tsxCli, "--require", guard, "src/index.ts", "--project", projectRoot, "--json"];
  if (!includeHome) args.push("--no-home");
  const run = await new Promise<{ code: number; stdout: string }>((resolve, reject) => {
    execFile(process.execPath, args, {
      cwd: process.cwd(),
      env: { ...runtimeEnv, HOME: home, USERPROFILE: home, TEMP: temp, TMP: temp, SCANNER_TEST_HOME: home, SCANNER_TEST_TRACE: trace },
      timeout: 15_000,
      maxBuffer: 1024 * 1024,
      encoding: "utf8",
      windowsHide: true,
    }, (error, stdout, stderr) => {
      if (stderr || (error && error.code !== 1)) return reject(error ?? new Error(stderr));
      resolve({ code: error ? 1 : 0, stdout });
    });
  });
  const access = JSON.parse(fs.readFileSync(trace, "utf8"));
  expect(access.homeVerified).toBe(true);
  return { ...run, report: JSON.parse(run.stdout), personalAccess: access.access };
}

afterAll(() => {
  expect(path.dirname(fixture)).toBe(path.resolve(os.tmpdir()));
  expect(path.basename(fixture)).toMatch(/^terminal-scanner-cli-/);
  fs.rmSync(fixture, { recursive: true });
});

describe("Developer project scans without personal home discovery", () => {
  it("keeps CI, scripts and environment findings for inside-home, outside and near-prefix projects in two concurrent bursts", async () => {
    const locations = [path.join(home, "projects", "inside"), path.join(fixture, "outside"), path.join(fixture, "home-sibling", "project")].map(folder => project(folder));
    for (let wave = 0; wave < 2; wave++) {
      const results = await Promise.all(locations.map(folder => scan(folder)));
      for (const result of results) {
        expect(result.code).toBe(1);
        expect(result.report.targetsScanned).toBe(4);
        expect(result.report.bySeverity.HIGH).toBe(3);
        expect(new Set(result.report.targets.map((target: { category: string }) => target.category))).toEqual(new Set(["ci_config", "project_script", "env_file"]));
        expect(result.personalAccess).toEqual([]);
      }
    }
  }, 30_000);

  it("keeps home history and dotfile scanning enabled by default", async () => {
    const result = await scan(project(path.join(home, "projects", "default")), true);
    expect(result.code).toBe(1);
    expect(result.report.targetsScanned).toBe(6);
    expect(result.report.bySeverity.HIGH).toBe(5);
    expect(result.report.targets.filter((target: { category: string }) => ["shell_history", "dotfile"].includes(target.category))).toHaveLength(2);
    expect(result.personalAccess.length).toBeGreaterThan(0);
  }, 15_000);

  it("handles a clean project and a project missing optional CI/environment files without inspecting personal files", async () => {
    const [clean, sparse] = await Promise.all([
      scan(project(path.join(home, "projects", "clean"), true)),
      scan(project(path.join(home, "projects", "sparse"), false, true)),
    ]);
    expect(clean.code).toBe(0);
    expect(clean.report.targetsScanned).toBe(4);
    expect(clean.report.totalFindings).toBe(0);
    expect(sparse.code).toBe(1);
    expect(sparse.report.targetsScanned).toBe(2);
    expect(sparse.report.bySeverity.HIGH).toBe(1);
    expect(clean.personalAccess).toEqual([]);
    expect(sparse.personalAccess).toEqual([]);
  }, 15_000);

  it("keeps repeated scans and their saved reports isolated from prior scan state", async () => {
    const folder = project(path.join(home, "projects", "repeated"));
    for (let run = 0; run < 6; run++) {
      const result = await scan(folder);
      expect(result.code).toBe(1);
      expect(result.report.targetsScanned).toBe(4);
      expect(result.report.bySeverity.HIGH).toBe(3);
      expect(result.personalAccess).toEqual([]);
      const saved = JSON.parse(fs.readFileSync(path.join(folder, "security-audit-report.json"), "utf8"));
      expect(saved).toEqual(result.report);
    }
  }, 30_000);
});

describe("Incomplete discovered-file reads", () => {
  it("fails before publishing JSON or replacing the prior report when a discovered file disappears", async () => {
    const folder = project(path.join(fixture, "read-failure"), true, true);
    const reportPath = path.join(folder, "security-audit-report.json");
    const priorReport = JSON.stringify({
      timestamp: "2026-01-01T00:00:00.000Z", targetsScanned: 1, totalFindings: 0,
      bySeverity: { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }, byDetector: {}, byCategory: {},
      findings: [], targets: [], summary: "Previous successful synthetic scan",
    });
    fs.writeFileSync(reportPath, priorReport);
    const trace = path.join(fixture, "read-failure-access.json");
    const raceTrace = path.join(fixture, "read-failure-race.json");
    const raceGuard = path.join(fixture, "read-failure-guard.cjs");
    fs.writeFileSync(raceGuard, [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      "const root = fs.realpathSync(process.env.SCANNER_TEST_ROOT);",
      "const project = fs.realpathSync(process.env.SCANNER_RACE_PROJECT);",
      "const target = path.resolve(project, 'build.sh');",
      "const trace = path.resolve(process.env.SCANNER_RACE_TRACE);",
      "if (!project.startsWith(root + path.sep) || path.dirname(trace) !== root) throw new Error('owned race fixture guard failed');",
      "const stat = fs.statSync, read = fs.readFileSync, write = fs.writeFileSync;",
      "const state = { stats: 0, removed: false, code: null };",
      "fs.statSync = function(file, ...args) { const result = stat(file, ...args); if (typeof file === 'string' && path.resolve(file) === target && result.isFile()) state.stats++; return result; };",
      "fs.readFileSync = function(file, ...args) {",
      "  if (typeof file === 'string' && path.resolve(file) === target) {",
      "    if (!state.stats || state.removed || fs.realpathSync(path.dirname(target)) !== project || !fs.lstatSync(target).isFile() || read(target, 'utf8') !== 'echo clean-fixture\\n') throw new Error('exact owned target guard failed');",
      "    fs.unlinkSync(target); state.removed = true;",
      "    try { return read(file, ...args); } catch (error) { state.code = error.code; throw error; }",
      "  }",
      "  return read(file, ...args);",
      "};",
      "require('node:module').syncBuiltinESMExports();",
      "process.on('exit', () => write(trace, JSON.stringify(state)));",
    ].join("\n"));
    const runtimeEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
      ["PATH", "SystemRoot", "WINDIR", "COMSPEC", "PATHEXT"].includes(key)));
    const result = await new Promise<{ code: string | number | null; stdout: string; stderr: string }>((resolve) => {
      execFile(process.execPath, [tsxCli, "--require", guard, "--require", raceGuard, "src/index.ts", "--project", folder, "--json", "--no-home"], {
        cwd: process.cwd(),
        env: { ...runtimeEnv, HOME: home, USERPROFILE: home, TEMP: temp, TMP: temp, SCANNER_TEST_HOME: home, SCANNER_TEST_TRACE: trace, SCANNER_TEST_ROOT: fixture, SCANNER_RACE_PROJECT: folder, SCANNER_RACE_TRACE: raceTrace },
        timeout: 15_000, maxBuffer: 1024 * 1024, encoding: "utf8", windowsHide: true,
      }, (error, stdout, stderr) => resolve({ code: error ? error.code ?? null : 0, stdout, stderr }));
    });
    expect(result.code).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("Unable to read scan target");
    expect(result.stderr).toContain("ENOENT");
    expect(fs.readFileSync(reportPath, "utf8")).toBe(priorReport);
    const race = JSON.parse(fs.readFileSync(raceTrace, "utf8"));
    expect(race.stats).toBeGreaterThan(0);
    expect(race.removed).toBe(true);
    expect(race.code).toBe("ENOENT");
    expect(JSON.parse(fs.readFileSync(trace, "utf8"))).toEqual({ homeVerified: true, access: [] });
  }, 15_000);
});

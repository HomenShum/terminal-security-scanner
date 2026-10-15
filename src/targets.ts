/**
 * Scan target discovery — finds files worth scanning in a dev environment.
 *
 * Target categories:
 * 1. Shell history files (~/.bash_history, ~/.zsh_history, etc.)
 * 2. Shell config / dotfiles (~/.bashrc, ~/.zshrc, ~/.profile, etc.)
 * 3. CI configuration (.github/workflows/*.yml, .gitlab-ci.yml, etc.)
 * 4. Project scripts (Makefile, Dockerfile, *.sh, package.json scripts)
 * 5. Environment files (.env, .env.local, etc.)
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

export interface ScanTarget {
  path: string;
  category: "shell_history" | "dotfile" | "ci_config" | "project_script" | "env_file";
  sizeBytes: number;
}

const HOME = os.homedir();

// Shell history files to check
const SHELL_HISTORY_FILES = [
  ".bash_history",
  ".zsh_history",
  ".history",
  ".node_repl_history",
  ".python_history",
  ".psql_history",
  ".mysql_history",
  ".irb_history",
].map((f) => path.join(HOME, f));

// Shell config / dotfiles to check
const DOTFILES = [
  ".bashrc",
  ".bash_profile",
  ".bash_login",
  ".profile",
  ".zshrc",
  ".zprofile",
  ".zshenv",
  ".zlogin",
  ".inputrc",
  ".curlrc",
  ".wgetrc",
  ".npmrc",
  ".gitconfig",
  ".ssh/config",
  ".ssh/authorized_keys",
  ".ssh/known_hosts",
].map((f) => path.join(HOME, f));

// CI config patterns (relative to project root)
const CI_CONFIG_PATTERNS = [
  ".github/workflows",
  ".gitlab-ci.yml",
  ".circleci/config.yml",
  ".travis.yml",
  "Jenkinsfile",
  "azure-pipelines.yml",
  "bitbucket-pipelines.yml",
];

// Project scripts
const PROJECT_SCRIPT_PATTERNS = [
  "Makefile",
  "Dockerfile",
  "docker-compose.yml",
  "docker-compose.yaml",
  "package.json",
  "Taskfile.yml",
];

// Environment files
const ENV_PATTERNS = [
  ".env",
  ".env.local",
  ".env.development",
  ".env.production",
  ".env.staging",
];

function fileExists(filePath: string): boolean {
  try {
    return fs.statSync(filePath).isFile();
  } catch {
    return false;
  }
}

function dirExists(dirPath: string): boolean {
  try {
    return fs.statSync(dirPath).isDirectory();
  } catch {
    return false;
  }
}

function getFileSize(filePath: string): number {
  try {
    return fs.statSync(filePath).size;
  } catch {
    return 0;
  }
}

function discoverTarget(filePath: string, category: ScanTarget["category"]): ScanTarget | null {
  if (!fileExists(filePath)) return null;
  const sizeBytes = getFileSize(filePath);
  // Skip files larger than 50MB
  if (sizeBytes > 50 * 1024 * 1024) return null;
  return { path: filePath, category, sizeBytes };
}

function findYmlFiles(dirPath: string): string[] {
  if (!dirExists(dirPath)) return [];
  try {
    return fs.readdirSync(dirPath)
      .filter((f) => f.endsWith(".yml") || f.endsWith(".yaml"))
      .map((f) => path.join(dirPath, f));
  } catch {
    return [];
  }
}

function findShellScripts(projectRoot: string, maxDepth = 3): string[] {
  const scripts: string[] = [];

  function walk(dir: string, depth: number) {
    if (depth > maxDepth) return;
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.name.startsWith(".") || entry.name === "node_modules" || entry.name === "dist") continue;
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          walk(fullPath, depth + 1);
        } else if (entry.isFile() && entry.name.endsWith(".sh")) {
          scripts.push(fullPath);
        }
      }
    } catch {
      // Permission denied or other error — skip
    }
  }

  walk(projectRoot, 0);
  return scripts;
}

/**
 * Discover all scannable targets in the user's environment.
 *
 * @param projectRoot - Optional project directory to scan for CI/scripts
 * @param includeHome - Discover personal shell history and dotfiles (default true)
 * @returns Array of discovered scan targets
 */
export function discoverTargets(projectRoot?: string, includeHome = true): ScanTarget[] {
  const targets: ScanTarget[] = [];

  if (includeHome) {
    // 1. Shell history
    for (const histFile of SHELL_HISTORY_FILES) {
      const target = discoverTarget(histFile, "shell_history");
      if (target) targets.push(target);
    }

    // 2. Dotfiles
    for (const dotfile of DOTFILES) {
      const target = discoverTarget(dotfile, "dotfile");
      if (target) targets.push(target);
    }
  }

  // 3. CI configuration (project-relative)
  if (projectRoot) {
    for (const ciPattern of CI_CONFIG_PATTERNS) {
      const fullPath = path.join(projectRoot, ciPattern);
      if (dirExists(fullPath)) {
        // It's a directory (e.g., .github/workflows) — scan all yml files
        for (const ymlFile of findYmlFiles(fullPath)) {
          const target = discoverTarget(ymlFile, "ci_config");
          if (target) targets.push(target);
        }
      } else {
        const target = discoverTarget(fullPath, "ci_config");
        if (target) targets.push(target);
      }
    }

    // 4. Project scripts
    for (const scriptPattern of PROJECT_SCRIPT_PATTERNS) {
      const fullPath = path.join(projectRoot, scriptPattern);
      const target = discoverTarget(fullPath, "project_script");
      if (target) targets.push(target);
    }

    // Shell scripts in project
    for (const shellScript of findShellScripts(projectRoot)) {
      const target = discoverTarget(shellScript, "project_script");
      if (target) targets.push(target);
    }

    // 5. Environment files
    for (const envPattern of ENV_PATTERNS) {
      const fullPath = path.join(projectRoot, envPattern);
      const target = discoverTarget(fullPath, "env_file");
      if (target) targets.push(target);
    }
  }

  return targets;
}

/**
 * Read a scan target's contents, handling large files by reading first 5MB.
 */
export function readTarget(target: ScanTarget): string {
  const MAX_READ = 5 * 1024 * 1024; // 5MB
  try {
    if (target.sizeBytes > MAX_READ) {
      const fd = fs.openSync(target.path, "r");
      const buffer = Buffer.alloc(MAX_READ);
      fs.readSync(fd, buffer, 0, MAX_READ, 0);
      fs.closeSync(fd);
      return buffer.toString("utf-8");
    }
    return fs.readFileSync(target.path, "utf-8");
  } catch {
    return "";
  }
}

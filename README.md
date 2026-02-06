# Terminal Security Scanner

Scans your dev environment for security blind spots that browsers protect against but terminals don't: homograph attacks, ANSI escape injections, and suspicious URL patterns.

Built as a weekend project inspired by [Tirith](https://github.com/sheeki03/tirith) — a Rust tool addressing the same gap. This scanner focuses on the files developers touch every day: shell history, dotfiles, CI scripts, and project configuration.

## What It Finds

| Detector | What | Severity | Example |
|----------|------|----------|---------|
| **Homograph** | Unicode characters mimicking ASCII | HIGH/MEDIUM | Cyrillic `а` (U+0430) vs Latin `a` in URLs |
| **Homograph** | Invisible zero-width characters | HIGH | BOM/ZWS hiding in env files or scripts |
| **ANSI Injection** | OSC clipboard access (OSC 52) | HIGH | `\x1b]52;c;...` reads/writes clipboard |
| **ANSI Injection** | Title spoofing, cursor manipulation | MEDIUM | Fake terminal titles, hidden output |
| **ANSI Injection** | Encoded escapes in shell scripts | LOW | `\033[31m` — may be legitimate styling |
| **URL** | `data:` and `javascript:` URLs | HIGH | Code execution vectors |
| **URL** | Punycode/IDN domains | MEDIUM | `xn--pple-43d.com` looks like `apple.com` |
| **URL** | Credential confusion (`@` in URLs) | MEDIUM | `https://good.com@evil.com/payload` |

## Quick Start

```bash
# Scan current project + home directory
npx tsx src/index.ts

# Scan a specific project
npx tsx src/index.ts --project ./my-app

# Verbose output with all details
npx tsx src/index.ts --verbose

# JSON output for CI integration
npx tsx src/index.ts --json
```

## What We Found (Real Results)

We ran this against our own production repository ([nodebench-ai](https://github.com/nodebench/nodebench-ai)) — 19 files scanned in 24ms:

**1 HIGH severity finding:**
- **BOM (U+FEFF) at column 1 of `.env.local`** — An invisible byte-order mark at the very start of the environment file. This causes the first variable to silently fail to parse in many `.env` loaders. The variable name becomes `\uFEFF# Deployment...` instead of `# Deployment...`. Most editors don't show it. Most linters don't catch it.

**9 LOW severity findings:**
- ANSI escape codes (`\033[0;31m`, etc.) in shell scripts — legitimate color output, flagged for awareness since these are the same escape mechanism that attackers exploit.

The BOM finding was a real bug in our codebase that had gone undetected.

## How It Works

The scanner checks three layers:

### 1. Homograph Detection
Maps 50+ Unicode confusables from the [Unicode Technical Report #36](https://unicode.org/reports/tr36/). Cyrillic, Greek, and fullwidth characters that are visually identical to Latin ASCII. Also flags invisible characters (zero-width spaces, joiners, BOM).

### 2. ANSI Injection Detection
Identifies 8 categories of escape sequences, from critical (OSC 52 clipboard access) to informational (encoded escapes in shell scripts). Distinguishes between standard color output and dangerous terminal manipulation.

### 3. Suspicious URL Detection
Catches 7 URL patterns: executable `data:` URLs, `javascript:` schemes, Punycode/IDN domains, credential confusion with `@`, percent-encoded path traversal, IP-based URLs, and shortened URL redirects.

## Scan Targets

The scanner automatically discovers and reads:

| Category | Files | Examples |
|----------|-------|---------|
| Shell history | `~/.bash_history`, `~/.zsh_history`, `~/.node_repl_history` | Command history with URLs, paths |
| Dotfiles | `~/.bashrc`, `~/.zshrc`, `~/.gitconfig`, `~/.ssh/config` | Shell configs, SSH settings |
| CI config | `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile` | CI/CD pipelines |
| Project scripts | `Makefile`, `Dockerfile`, `*.sh`, `package.json` | Build and deploy scripts |
| Environment | `.env`, `.env.local`, `.env.production` | Environment variables |

## Using with NodeBench MCP

If you're using [nodebench-mcp](https://www.npmjs.com/package/nodebench-mcp), the scanner results integrate with the verification methodology:

1. **Recon phase**: `run_recon` to map the scan targets, `log_recon_finding` for each security issue
2. **Verification phase**: `start_verification_cycle` to track remediation, `log_test_result` for each detector layer (static analysis, unit tests, integration tests)
3. **Quality gate**: `run_quality_gate` to enforce zero HIGH-severity findings before deploy
4. **Knowledge**: `record_learning` to bank patterns for future scans

## Tests

```bash
npm test
```

21 tests covering all three detector engines with both positive detection and clean-file verification.

## Options

```
--project <path>   Project directory to scan (default: current directory)
--verbose, -v      Show detailed findings with line numbers and snippets
--json             Output structured JSON instead of formatted report
--no-home          Skip scanning home directory files
--help, -h         Show help
```

## License

MIT

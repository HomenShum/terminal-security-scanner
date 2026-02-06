/**
 * Detection engines for terminal security threats.
 *
 * Three detector classes:
 * 1. Homograph — Unicode characters that visually mimic ASCII
 * 2. ANSI Injection — Escape sequences that can manipulate terminal state
 * 3. Suspicious URLs — data:, javascript:, IDN homograph domains
 */

export type Severity = "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface Finding {
  detector: "homograph" | "ansi" | "url";
  severity: Severity;
  file: string;
  line: number;
  column: number;
  snippet: string;
  description: string;
  remediation: string;
}

// ═══════════════════════════════════════════════════════════════════════════
// HOMOGRAPH DETECTION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Unicode confusables — characters from other scripts that look like Latin ASCII.
 * Source: Unicode Technical Report #36 (Security Considerations)
 *
 * Format: { lookalike_codepoint: { looks_like: "ascii_char", script: "origin_script" } }
 */
const CONFUSABLES: Record<number, { looksLike: string; script: string }> = {
  // Cyrillic confusables (most dangerous — visually identical)
  0x0430: { looksLike: "a", script: "Cyrillic" },  // а
  0x0435: { looksLike: "e", script: "Cyrillic" },  // е
  0x043e: { looksLike: "o", script: "Cyrillic" },  // о
  0x0440: { looksLike: "p", script: "Cyrillic" },  // р
  0x0441: { looksLike: "c", script: "Cyrillic" },  // с
  0x0443: { looksLike: "y", script: "Cyrillic" },  // у
  0x0445: { looksLike: "x", script: "Cyrillic" },  // х
  0x0410: { looksLike: "A", script: "Cyrillic" },  // А
  0x0412: { looksLike: "B", script: "Cyrillic" },  // В
  0x0415: { looksLike: "E", script: "Cyrillic" },  // Е
  0x041a: { looksLike: "K", script: "Cyrillic" },  // К
  0x041c: { looksLike: "M", script: "Cyrillic" },  // М
  0x041d: { looksLike: "H", script: "Cyrillic" },  // Н
  0x041e: { looksLike: "O", script: "Cyrillic" },  // О
  0x0420: { looksLike: "P", script: "Cyrillic" },  // Р
  0x0421: { looksLike: "C", script: "Cyrillic" },  // С
  0x0422: { looksLike: "T", script: "Cyrillic" },  // Т
  0x0425: { looksLike: "X", script: "Cyrillic" },  // Х

  // Greek confusables
  0x0391: { looksLike: "A", script: "Greek" },      // Α
  0x0392: { looksLike: "B", script: "Greek" },      // Β
  0x0395: { looksLike: "E", script: "Greek" },      // Ε
  0x0396: { looksLike: "Z", script: "Greek" },      // Ζ
  0x0397: { looksLike: "H", script: "Greek" },      // Η
  0x0399: { looksLike: "I", script: "Greek" },      // Ι
  0x039a: { looksLike: "K", script: "Greek" },      // Κ
  0x039c: { looksLike: "M", script: "Greek" },      // Μ
  0x039d: { looksLike: "N", script: "Greek" },      // Ν
  0x039f: { looksLike: "O", script: "Greek" },      // Ο
  0x03a1: { looksLike: "P", script: "Greek" },      // Ρ
  0x03a4: { looksLike: "T", script: "Greek" },      // Τ
  0x03a5: { looksLike: "Y", script: "Greek" },      // Υ
  0x03a7: { looksLike: "X", script: "Greek" },      // Χ
  0x03bf: { looksLike: "o", script: "Greek" },      // ο
  0x03c1: { looksLike: "p", script: "Greek" },      // ρ

  // Fullwidth Latin (used in CJK contexts)
  0xff21: { looksLike: "A", script: "Fullwidth" },  // Ａ
  0xff22: { looksLike: "B", script: "Fullwidth" },  // Ｂ
  0xff23: { looksLike: "C", script: "Fullwidth" },  // Ｃ

  // Invisible/zero-width characters (HIGH severity)
  0x200b: { looksLike: "", script: "Zero-Width Space" },
  0x200c: { looksLike: "", script: "Zero-Width Non-Joiner" },
  0x200d: { looksLike: "", script: "Zero-Width Joiner" },
  0x2060: { looksLike: "", script: "Word Joiner" },
  0xfeff: { looksLike: "", script: "BOM/Zero-Width No-Break" },
};

export function detectHomographs(content: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split("\n");

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx];
    for (let col = 0; col < line.length; col++) {
      const codePoint = line.codePointAt(col);
      if (codePoint === undefined) continue;

      const confusable = CONFUSABLES[codePoint];
      if (confusable) {
        const isInvisible = confusable.looksLike === "";
        const severity: Severity = isInvisible ? "HIGH" : "MEDIUM";

        const start = Math.max(0, col - 20);
        const end = Math.min(line.length, col + 20);
        const snippet = line.slice(start, end);

        findings.push({
          detector: "homograph",
          severity,
          file: filePath,
          line: lineIdx + 1,
          column: col + 1,
          snippet,
          description: isInvisible
            ? `Invisible character (${confusable.script}) at column ${col + 1}. Could hide malicious content.`
            : `${confusable.script} '${String.fromCodePoint(codePoint)}' looks like Latin '${confusable.looksLike}' at column ${col + 1}.`,
          remediation: isInvisible
            ? "Remove invisible Unicode characters. They can hide commands or alter string comparisons."
            : `Replace ${confusable.script} character with ASCII equivalent '${confusable.looksLike}'.`,
        });
      }

      // Skip surrogate pair second half
      if (codePoint > 0xffff) col++;
    }
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
// ANSI INJECTION DETECTION
// ═══════════════════════════════════════════════════════════════════════════

interface AnsiPattern {
  pattern: RegExp;
  severity: Severity;
  description: string;
  remediation: string;
}

const ANSI_PATTERNS: AnsiPattern[] = [
  // OSC (Operating System Command) — can set window title, clipboard
  {
    pattern: /\x1b\](?:0|1|2);[^\x07\x1b]*(?:\x07|\x1b\\)/g,
    severity: "HIGH",
    description: "OSC title-setting sequence. Can spoof terminal window title to mislead user.",
    remediation: "Strip OSC sequences from untrusted input. Configure terminal to ignore OSC from non-local sources.",
  },
  // OSC 52 — clipboard access (critical)
  {
    pattern: /\x1b\]52;[^\x07\x1b]*(?:\x07|\x1b\\)/g,
    severity: "HIGH",
    description: "OSC 52 clipboard manipulation. Can read/write system clipboard without user consent.",
    remediation: "Disable OSC 52 in terminal settings. Most terminals support osc52 allow/deny lists.",
  },
  // DCS (Device Control String) — can download fonts, set terminal state
  {
    pattern: /\x1bP[^\x1b]*\x1b\\/g,
    severity: "HIGH",
    description: "DCS (Device Control String). Can alter terminal state or download resources.",
    remediation: "Filter DCS sequences from all untrusted input streams.",
  },
  // CSI cursor manipulation — can overwrite visible output
  {
    pattern: /\x1b\[\d*[ABCDEFGHJ]/g,
    severity: "MEDIUM",
    description: "Cursor movement/erase sequence. Can overwrite visible terminal output to hide commands.",
    remediation: "Sanitize CSI sequences in log viewers and output processors.",
  },
  // CSI SGR with unusual parameters (could be used for social engineering)
  {
    pattern: /\x1b\[(?:8|30;40|37;47)m/g,
    severity: "MEDIUM",
    description: "Hidden text SGR (invisible ink). Text rendered same color as background.",
    remediation: "Flag or strip invisible-text SGR sequences from untrusted content.",
  },
  // Raw escape byte in unexpected contexts
  {
    pattern: /\x1b(?!\[[\d;]*m)(?!\[[\d;]*[ABCDEFGHJ])(?!\])/g,
    severity: "LOW",
    description: "Raw ESC byte outside standard color/cursor sequences. May indicate injection attempt.",
    remediation: "Audit raw ESC bytes in configuration and script files.",
  },
  // Hex/octal escape patterns in shell scripts (potential obfuscation)
  {
    pattern: /\\x1[bB]|\\033|\\e\[/g,
    severity: "LOW",
    description: "Encoded ANSI escape in shell script. Could be legitimate styling or obfuscated injection.",
    remediation: "Verify that encoded escapes serve a legitimate purpose (e.g., PS1 prompt coloring).",
  },
  // printf/echo with escape interpretation
  {
    pattern: /(?:printf|echo\s+-e)\s+.*\\(?:x1b|033|e)\[/g,
    severity: "MEDIUM",
    description: "Shell command generating ANSI escapes. Verify these are intentional (prompt, color output).",
    remediation: "Use tput instead of raw escape codes for portable, auditable terminal formatting.",
  },
];

export function detectAnsiInjections(content: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split("\n");

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx];

    for (const ansiPattern of ANSI_PATTERNS) {
      // Reset regex lastIndex for each line
      const regex = new RegExp(ansiPattern.pattern.source, ansiPattern.pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(line)) !== null) {
        const start = Math.max(0, match.index - 15);
        const end = Math.min(line.length, match.index + match[0].length + 15);
        const snippet = line.slice(start, end);

        findings.push({
          detector: "ansi",
          severity: ansiPattern.severity,
          file: filePath,
          line: lineIdx + 1,
          column: match.index + 1,
          snippet: snippet.replace(/[\x00-\x1f]/g, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`),
          description: ansiPattern.description,
          remediation: ansiPattern.remediation,
        });
      }
    }
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
// SUSPICIOUS URL DETECTION
// ═══════════════════════════════════════════════════════════════════════════

interface UrlPattern {
  pattern: RegExp;
  severity: Severity;
  description: string;
  remediation: string;
}

const URL_PATTERNS: UrlPattern[] = [
  // data: URLs (can execute code in some contexts)
  {
    pattern: /data:\s*(?:text\/html|application\/javascript|text\/javascript)[;,][^\s'")]+/gi,
    severity: "HIGH",
    description: "Executable data: URL. Can run JavaScript or render HTML in certain contexts.",
    remediation: "Never follow data: URLs from untrusted sources. Block in URL handlers.",
  },
  // javascript: URLs
  {
    pattern: /javascript\s*:/gi,
    severity: "HIGH",
    description: "javascript: URL scheme. Direct code execution vector.",
    remediation: "Block javascript: URLs entirely. They have no legitimate use in terminal workflows.",
  },
  // Punycode/IDN domains (xn--)
  {
    pattern: /https?:\/\/[^\s/]*xn--[^\s/]+/gi,
    severity: "MEDIUM",
    description: "Punycode (IDN) domain detected. May be a homograph attack on a legitimate domain.",
    remediation: "Manually verify the actual Unicode domain. Compare against the intended target.",
  },
  // IP-based URLs (potential phishing/C2)
  {
    pattern: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?/g,
    severity: "LOW",
    description: "IP-based URL. Could be legitimate (local dev) or suspicious (C2, phishing redirect).",
    remediation: "Verify IP ownership. Flag if not a known development or CI server.",
  },
  // URLs with @ symbol (credential confusion)
  {
    pattern: /https?:\/\/[^\s]*@[^\s]+/g,
    severity: "MEDIUM",
    description: "URL with @ symbol. Browser ignores text before @, which can spoof the apparent domain.",
    remediation: "Remove @ from URLs. The text before @ is treated as credentials, not the domain.",
  },
  // URLs with encoded characters that could hide intent
  {
    pattern: /https?:\/\/[^\s]*%(?:2[eE]|2[fF]|5[cC]|00)[^\s]*/g,
    severity: "MEDIUM",
    description: "URL with suspicious percent-encoding (dots, slashes, or null bytes). May hide true destination.",
    remediation: "Decode and inspect the full URL before following.",
  },
  // Shortened URLs (potential redirect to malicious target)
  {
    pattern: /https?:\/\/(?:bit\.ly|t\.co|tinyurl\.com|goo\.gl|is\.gd|buff\.ly|ow\.ly|rb\.gy)\/\S+/gi,
    severity: "LOW",
    description: "Shortened URL. True destination is hidden behind redirect.",
    remediation: "Expand shortened URLs before following. Use a URL expander service.",
  },
];

export function detectSuspiciousUrls(content: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split("\n");

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx];

    for (const urlPattern of URL_PATTERNS) {
      const regex = new RegExp(urlPattern.pattern.source, urlPattern.pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(line)) !== null) {
        const start = Math.max(0, match.index - 10);
        const end = Math.min(line.length, match.index + match[0].length + 10);
        const snippet = line.slice(start, end);

        findings.push({
          detector: "url",
          severity: urlPattern.severity,
          file: filePath,
          line: lineIdx + 1,
          column: match.index + 1,
          snippet,
          description: urlPattern.description,
          remediation: urlPattern.remediation,
        });
      }
    }
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
// COMBINED SCAN
// ═══════════════════════════════════════════════════════════════════════════

export function scanContent(content: string, filePath: string): Finding[] {
  return [
    ...detectHomographs(content, filePath),
    ...detectAnsiInjections(content, filePath),
    ...detectSuspiciousUrls(content, filePath),
  ];
}

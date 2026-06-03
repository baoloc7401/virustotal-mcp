import { describe, it, expect } from "vitest";
import {
  formatFileReport,
  formatUrlReport,
  formatDomainReport,
  formatIpReport,
  formatAnalysis,
} from "../src/format.js";

describe("formatFileReport", () => {
  it("renders all fields including notable detections and structured summary", () => {
    const { text, structured } = formatFileReport({
      data: {
        id: "abc123",
        attributes: {
          meaningful_name: "evil.exe",
          last_analysis_stats: { malicious: 2, suspicious: 1, harmless: 3, undetected: 4, timeout: 1 },
          type_description: "Win32 EXE",
          reputation: -5,
          sha256: "deadbeef",
          last_analysis_date: 1_700_000_000,
          last_analysis_results: {
            EngA: { engine_name: "EngA", category: "malicious", result: "Trojan" },
            EngB: { engine_name: "EngB", category: "suspicious" },
            EngC: { engine_name: "EngC", category: "harmless", result: "clean" },
          },
        },
      },
    });
    expect(text).toContain("File report — evil.exe");
    expect(text).toContain("2/11 engines flagged malicious (1 suspicious, 3 harmless, 4 undetected)");
    expect(text).toContain("Type: Win32 EXE");
    expect(text).toContain("Reputation: -5");
    expect(text).toContain("SHA-256: deadbeef");
    expect(text).toContain("Notable: EngA: Trojan; EngB: suspicious");
    expect(text).toContain("Last analyzed: 2023-11-14T22:13:20.000Z");
    expect(text).toContain("Permalink: https://www.virustotal.com/gui/file/abc123");

    expect(structured.stats).toEqual({
      malicious: 2,
      suspicious: 1,
      harmless: 3,
      undetected: 4,
      timeout: 1,
      total: 11,
    });
    expect(structured.reputation).toBe(-5);
    expect(structured.notable).toEqual(["EngA: Trojan", "EngB: suspicious"]);
    expect(structured.lastAnalysisDate).toBe("2023-11-14T22:13:20.000Z");
    expect(structured.permalink).toBe("https://www.virustotal.com/gui/file/abc123");
  });

  it("falls back through names then id, and omits optional lines", () => {
    const { text, structured } = formatFileReport({ data: { id: "id1", attributes: { names: ["a.bin"] } } });
    expect(text).toContain("File report — a.bin");
    expect(text).toContain("0/0 engines flagged malicious");
    expect(text).not.toContain("Type:");
    expect(text).not.toContain("Reputation:");
    expect(text).not.toContain("SHA-256:");
    expect(text).not.toContain("Notable:");
    expect(text).not.toContain("Last analyzed:");
    expect(structured.reputation).toBeUndefined();
    expect(structured.notable).toBeUndefined();
    expect(structured.lastAnalysisDate).toBeUndefined();
  });

  it("uses id when no meaningful_name or names, and handles empty input", () => {
    expect(formatFileReport({ data: { id: "onlyid", attributes: {} } }).text).toContain("File report — onlyid");
    expect(formatFileReport(undefined as never).text).toContain("File report — ");
  });
});

describe("formatUrlReport", () => {
  it("renders url, title, reputation, notable, date, permalink", () => {
    const { text, structured } = formatUrlReport({
      data: {
        id: "u1",
        attributes: {
          url: "https://x.test",
          title: "X Site",
          reputation: 0,
          last_analysis_date: 1_700_000_000,
          last_analysis_stats: { malicious: 1 },
          last_analysis_results: { E: { engine_name: "E", category: "malicious", result: "phish" } },
        },
      },
    });
    expect(text).toContain("URL report — https://x.test");
    expect(text).toContain("Title: X Site");
    expect(text).toContain("Reputation: 0");
    expect(text).toContain("Notable: E: phish");
    expect(text).toContain("Last analyzed: 2023-11-14T22:13:20.000Z");
    expect(text).toContain("Permalink: https://www.virustotal.com/gui/url/u1");
    expect(structured.notable).toEqual(["E: phish"]);
    expect(structured.permalink).toBe("https://www.virustotal.com/gui/url/u1");
  });

  it("falls back to last_final_url then id and omits optionals", () => {
    expect(formatUrlReport({ data: { id: "u2", attributes: { last_final_url: "https://final" } } }).text).toContain(
      "URL report — https://final",
    );
    const { text } = formatUrlReport({ data: { id: "u3", attributes: {} } });
    expect(text).toContain("URL report — u3");
    expect(text).not.toContain("Title:");
    expect(text).not.toContain("Notable:");
    expect(text).not.toContain("Last analyzed:");
  });

  it("handles empty input via nullish fallbacks", () => {
    expect(formatUrlReport(undefined as never).text).toContain("URL report — ");
  });
});

describe("formatDomainReport", () => {
  it("renders reputation, deduped categories, registrar, date", () => {
    const { text, structured } = formatDomainReport({
      data: {
        id: "example.com",
        attributes: {
          reputation: 7,
          categories: { vendorA: "malware", vendorB: "malware", vendorC: "phishing" },
          registrar: "GoDaddy",
          last_analysis_date: 1_700_000_000,
          last_analysis_stats: { harmless: 80 },
        },
      },
    });
    expect(text).toContain("Domain report — example.com");
    expect(text).toContain("Reputation: 7");
    expect(text).toContain("Categories: malware, phishing");
    expect(text).toContain("Registrar: GoDaddy");
    expect(text).toContain("Last analyzed: 2023-11-14T22:13:20.000Z");
    expect(structured.reputation).toBe(7);
    expect(structured.permalink).toBe("https://www.virustotal.com/gui/domain/example.com");
  });

  it("omits categories, registrar and date when absent", () => {
    const { text } = formatDomainReport({ data: { id: "d.com", attributes: {} } });
    expect(text).not.toContain("Categories:");
    expect(text).not.toContain("Registrar:");
    expect(text).not.toContain("Last analyzed:");
  });

  it("handles empty input via nullish fallbacks", () => {
    expect(formatDomainReport(undefined as never).text).toContain("Domain report — ");
  });
});

describe("formatIpReport", () => {
  it("renders as_owner with asn, country, reputation, date", () => {
    const { text, structured } = formatIpReport({
      data: {
        id: "8.8.8.8",
        attributes: { reputation: 1, as_owner: "Google", asn: 15169, country: "US", last_analysis_date: 1_700_000_000 },
      },
    });
    expect(text).toContain("IP report — 8.8.8.8");
    expect(text).toContain("AS owner: Google (AS15169)");
    expect(text).toContain("Country: US");
    expect(text).toContain("Reputation: 1");
    expect(text).toContain("Last analyzed: 2023-11-14T22:13:20.000Z");
    expect(structured.permalink).toBe("https://www.virustotal.com/gui/ip-address/8.8.8.8");
  });

  it("uses ? when asn missing and omits country and date", () => {
    const { text } = formatIpReport({ data: { id: "1.1.1.1", attributes: { as_owner: "Cloudflare" } } });
    expect(text).toContain("AS owner: Cloudflare (AS?)");
    expect(text).not.toContain("Country:");
    expect(text).not.toContain("Last analyzed:");
  });

  it("handles empty input via nullish fallbacks", () => {
    expect(formatIpReport(undefined as never).text).toContain("IP report — ");
  });
});

describe("formatAnalysis", () => {
  it("renders status, stats, notable, date, permalink", () => {
    const { text, structured } = formatAnalysis({
      data: {
        id: "an1",
        attributes: {
          status: "completed",
          stats: { malicious: 3 },
          date: 1_700_000_000,
          results: { E: { engine_name: "E", category: "malicious", result: "mal" } },
        },
      },
    });
    expect(text).toContain("Analysis an1 — status: completed");
    expect(text).toContain("3/3 engines flagged malicious");
    expect(text).toContain("Notable: E: mal");
    expect(text).toContain("Analyzed: 2023-11-14T22:13:20.000Z");
    expect(text).toContain("Permalink: https://www.virustotal.com/gui/analysis/an1");
    expect(structured.status).toBe("completed");
    expect(structured.analysisId).toBe("an1");
    expect(structured.stats?.malicious).toBe(3);
  });

  it("defaults status to unknown and omits stats/notable/date when absent", () => {
    const { text, structured } = formatAnalysis({ data: { id: "an2", attributes: {} } });
    expect(text).toContain("Analysis an2 — status: unknown");
    expect(text).not.toContain("engines flagged");
    expect(text).not.toContain("Notable:");
    expect(text).not.toContain("Analyzed:");
    expect(structured.stats).toBeUndefined();
    expect(structured.notable).toBeUndefined();
  });

  it("handles empty input via nullish fallbacks", () => {
    expect(formatAnalysis(undefined as never).text).toContain("Analysis  — status: unknown");
  });
});

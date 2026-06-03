/**
 * Condense large VirusTotal v3 responses into compact text summaries so the
 * model gets the signal (verdict counts, reputation, notable flags, permalink)
 * without burning tokens on the full JSON blob.
 *
 * Each formatter returns both the human-readable `text` and a small `structured`
 * summary object, so MCP clients can consume verdicts programmatically (returned
 * as a tool's `structuredContent`) without re-parsing the text.
 */

import { VT_GUI } from "./vtClient.js";
import type {
  AnalysisStats,
  EngineResults,
  FileAttributes,
  UrlAttributes,
  DomainAttributes,
  IpAttributes,
  AnalysisAttributes,
  VtResponse,
} from "./vtTypes.js";

/** Detection counts, fully resolved (no undefined) plus an engine total. */
export interface DetectionStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  timeout: number;
  total: number;
}

/** Machine-readable verdict summary attached as a tool's structuredContent. */
export interface Summary {
  stats?: DetectionStats;
  reputation?: number;
  permalink?: string;
  status?: string;
  analysisId?: string;
  lastAnalysisDate?: string;
  notable?: string[];
  // Open index signature so a Summary is assignable to the SDK's
  // structuredContent type (`Record<string, unknown>`).
  [key: string]: unknown;
}

export interface Formatted {
  text: string;
  structured: Summary;
}

function detectionStats(stats: AnalysisStats = {}): DetectionStats {
  const malicious = stats.malicious ?? 0;
  const suspicious = stats.suspicious ?? 0;
  const harmless = stats.harmless ?? 0;
  const undetected = stats.undetected ?? 0;
  const timeout = stats.timeout ?? 0;
  return {
    malicious,
    suspicious,
    harmless,
    undetected,
    timeout,
    total: malicious + suspicious + harmless + undetected + timeout,
  };
}

function statsLine(s: DetectionStats): string {
  return `${s.malicious}/${s.total} engines flagged malicious (${s.suspicious} suspicious, ${s.harmless} harmless, ${s.undetected} undetected)`;
}

/** A few engine names that flagged the item, for quick triage. */
function topDetections(results: EngineResults = {}, limit = 5): string[] {
  return Object.values(results)
    .filter((r) => r?.category === "malicious" || r?.category === "suspicious")
    .map((r) => `${r.engine_name}: ${r.result ?? r.category}`)
    .slice(0, limit);
}

function permalink(kind: string, id: string): string {
  return `${VT_GUI}/${kind}/${encodeURIComponent(id)}`;
}

/** VT timestamps are unix seconds; render as ISO, or undefined when absent. */
function isoDate(seconds?: number): string | undefined {
  return typeof seconds === "number" ? new Date(seconds * 1_000).toISOString() : undefined;
}

export function formatFileReport(data: VtResponse<FileAttributes>): Formatted {
  const attr = data?.data?.attributes ?? {};
  const id = data?.data?.id ?? "";
  const stats = detectionStats(attr.last_analysis_stats);
  const notable = topDetections(attr.last_analysis_results);
  const date = isoDate(attr.last_analysis_date);
  const link = permalink("file", id);

  const lines: string[] = [];
  lines.push(`File report — ${attr.meaningful_name ?? attr.names?.[0] ?? id}`);
  lines.push(statsLine(stats));
  if (attr.type_description) lines.push(`Type: ${attr.type_description}`);
  if (typeof attr.reputation === "number") lines.push(`Reputation: ${attr.reputation}`);
  if (attr.sha256) lines.push(`SHA-256: ${attr.sha256}`);
  if (notable.length) lines.push(`Notable: ${notable.join("; ")}`);
  if (date) lines.push(`Last analyzed: ${date}`);
  lines.push(`Permalink: ${link}`);

  return {
    text: lines.join("\n"),
    structured: {
      stats,
      reputation: typeof attr.reputation === "number" ? attr.reputation : undefined,
      notable: notable.length ? notable : undefined,
      lastAnalysisDate: date,
      permalink: link,
    },
  };
}

export function formatUrlReport(data: VtResponse<UrlAttributes>): Formatted {
  const attr = data?.data?.attributes ?? {};
  const id = data?.data?.id ?? "";
  const stats = detectionStats(attr.last_analysis_stats);
  const notable = topDetections(attr.last_analysis_results);
  const date = isoDate(attr.last_analysis_date);
  const link = permalink("url", id);

  const lines: string[] = [];
  lines.push(`URL report — ${attr.url ?? attr.last_final_url ?? id}`);
  lines.push(statsLine(stats));
  if (attr.title) lines.push(`Title: ${attr.title}`);
  if (typeof attr.reputation === "number") lines.push(`Reputation: ${attr.reputation}`);
  if (notable.length) lines.push(`Notable: ${notable.join("; ")}`);
  if (date) lines.push(`Last analyzed: ${date}`);
  lines.push(`Permalink: ${link}`);

  return {
    text: lines.join("\n"),
    structured: {
      stats,
      reputation: typeof attr.reputation === "number" ? attr.reputation : undefined,
      notable: notable.length ? notable : undefined,
      lastAnalysisDate: date,
      permalink: link,
    },
  };
}

export function formatDomainReport(data: VtResponse<DomainAttributes>): Formatted {
  const attr = data?.data?.attributes ?? {};
  const id = data?.data?.id ?? "";
  const stats = detectionStats(attr.last_analysis_stats);
  const date = isoDate(attr.last_analysis_date);
  const link = permalink("domain", id);

  const lines: string[] = [];
  lines.push(`Domain report — ${id}`);
  lines.push(statsLine(stats));
  if (typeof attr.reputation === "number") lines.push(`Reputation: ${attr.reputation}`);
  const cats = attr.categories ? Object.values(attr.categories) : [];
  if (cats.length) lines.push(`Categories: ${[...new Set(cats)].slice(0, 6).join(", ")}`);
  if (attr.registrar) lines.push(`Registrar: ${attr.registrar}`);
  if (date) lines.push(`Last analyzed: ${date}`);
  lines.push(`Permalink: ${link}`);

  return {
    text: lines.join("\n"),
    structured: {
      stats,
      reputation: typeof attr.reputation === "number" ? attr.reputation : undefined,
      lastAnalysisDate: date,
      permalink: link,
    },
  };
}

export function formatIpReport(data: VtResponse<IpAttributes>): Formatted {
  const attr = data?.data?.attributes ?? {};
  const id = data?.data?.id ?? "";
  const stats = detectionStats(attr.last_analysis_stats);
  const date = isoDate(attr.last_analysis_date);
  const link = permalink("ip-address", id);

  const lines: string[] = [];
  lines.push(`IP report — ${id}`);
  lines.push(statsLine(stats));
  if (typeof attr.reputation === "number") lines.push(`Reputation: ${attr.reputation}`);
  if (attr.as_owner) lines.push(`AS owner: ${attr.as_owner} (AS${attr.asn ?? "?"})`);
  if (attr.country) lines.push(`Country: ${attr.country}`);
  if (date) lines.push(`Last analyzed: ${date}`);
  lines.push(`Permalink: ${link}`);

  return {
    text: lines.join("\n"),
    structured: {
      stats,
      reputation: typeof attr.reputation === "number" ? attr.reputation : undefined,
      lastAnalysisDate: date,
      permalink: link,
    },
  };
}

/** Summarize an /analyses/{id} response (the result of a submission). */
export function formatAnalysis(data: VtResponse<AnalysisAttributes>): Formatted {
  const attr = data?.data?.attributes ?? {};
  const id = data?.data?.id ?? "";
  const status = attr.status ?? "unknown";
  const notable = topDetections(attr.results);
  const date = isoDate(attr.date);
  const link = permalink("analysis", id);
  const hasStats = attr.stats !== undefined;
  const stats = hasStats ? detectionStats(attr.stats) : undefined;

  const lines: string[] = [];
  lines.push(`Analysis ${id} — status: ${status}`);
  if (stats) lines.push(statsLine(stats));
  if (notable.length) lines.push(`Notable: ${notable.join("; ")}`);
  if (date) lines.push(`Analyzed: ${date}`);
  lines.push(`Permalink: ${link}`);

  return {
    text: lines.join("\n"),
    structured: {
      status,
      analysisId: id,
      stats,
      notable: notable.length ? notable : undefined,
      lastAnalysisDate: date,
      permalink: link,
    },
  };
}

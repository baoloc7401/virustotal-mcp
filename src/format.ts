/**
 * Condense large VirusTotal v3 responses into compact text summaries so the
 * model gets the signal (verdict counts, reputation, notable flags, permalink)
 * without burning tokens on the full JSON blob.
 */

import { VT_GUI } from "./vtClient.js";

interface AnalysisStats {
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  timeout?: number;
}

function statsLine(stats: AnalysisStats = {}): string {
  const malicious = stats.malicious ?? 0;
  const suspicious = stats.suspicious ?? 0;
  const harmless = stats.harmless ?? 0;
  const undetected = stats.undetected ?? 0;
  const timeout = stats.timeout ?? 0;
  const total = malicious + suspicious + harmless + undetected + timeout;
  return `${malicious}/${total} engines flagged malicious (${suspicious} suspicious, ${harmless} harmless, ${undetected} undetected)`;
}

/** A few engine names that flagged the item, for quick triage. */
function topDetections(results: Record<string, any> = {}, limit = 5): string[] {
  return Object.values(results)
    .filter((r: any) => r?.category === "malicious" || r?.category === "suspicious")
    .map((r: any) => `${r.engine_name}: ${r.result ?? r.category}`)
    .slice(0, limit);
}

function permalink(kind: string, id: string): string {
  return `${VT_GUI}/${kind}/${encodeURIComponent(id)}`;
}

export function formatFileReport(data: any): string {
  const attr = data?.data?.attributes ?? {};
  const id = data?.data?.id ?? "";
  const lines: string[] = [];
  lines.push(`File report — ${attr.meaningful_name ?? attr.names?.[0] ?? id}`);
  lines.push(statsLine(attr.last_analysis_stats));
  if (attr.type_description) lines.push(`Type: ${attr.type_description}`);
  if (typeof attr.reputation === "number") lines.push(`Reputation: ${attr.reputation}`);
  if (attr.sha256) lines.push(`SHA-256: ${attr.sha256}`);
  const dets = topDetections(attr.last_analysis_results);
  if (dets.length) lines.push(`Notable: ${dets.join("; ")}`);
  lines.push(`Permalink: ${permalink("file", id)}`);
  return lines.join("\n");
}

export function formatUrlReport(data: any): string {
  const attr = data?.data?.attributes ?? {};
  const id = data?.data?.id ?? "";
  const lines: string[] = [];
  lines.push(`URL report — ${attr.url ?? attr.last_final_url ?? id}`);
  lines.push(statsLine(attr.last_analysis_stats));
  if (attr.title) lines.push(`Title: ${attr.title}`);
  if (typeof attr.reputation === "number") lines.push(`Reputation: ${attr.reputation}`);
  const dets = topDetections(attr.last_analysis_results);
  if (dets.length) lines.push(`Notable: ${dets.join("; ")}`);
  lines.push(`Permalink: ${permalink("url", id)}`);
  return lines.join("\n");
}

export function formatDomainReport(data: any): string {
  const attr = data?.data?.attributes ?? {};
  const id = data?.data?.id ?? "";
  const lines: string[] = [];
  lines.push(`Domain report — ${id}`);
  lines.push(statsLine(attr.last_analysis_stats));
  if (typeof attr.reputation === "number") lines.push(`Reputation: ${attr.reputation}`);
  const cats = attr.categories ? Object.values(attr.categories) : [];
  if (cats.length) lines.push(`Categories: ${[...new Set(cats)].slice(0, 6).join(", ")}`);
  if (attr.registrar) lines.push(`Registrar: ${attr.registrar}`);
  lines.push(`Permalink: ${permalink("domain", id)}`);
  return lines.join("\n");
}

export function formatIpReport(data: any): string {
  const attr = data?.data?.attributes ?? {};
  const id = data?.data?.id ?? "";
  const lines: string[] = [];
  lines.push(`IP report — ${id}`);
  lines.push(statsLine(attr.last_analysis_stats));
  if (typeof attr.reputation === "number") lines.push(`Reputation: ${attr.reputation}`);
  if (attr.as_owner) lines.push(`AS owner: ${attr.as_owner} (AS${attr.asn ?? "?"})`);
  if (attr.country) lines.push(`Country: ${attr.country}`);
  lines.push(`Permalink: ${permalink("ip-address", id)}`);
  return lines.join("\n");
}

/** Summarize an /analyses/{id} response (the result of a submission). */
export function formatAnalysis(data: any): string {
  const attr = data?.data?.attributes ?? {};
  const id = data?.data?.id ?? "";
  const status = attr.status ?? "unknown";
  const lines: string[] = [];
  lines.push(`Analysis ${id} — status: ${status}`);
  if (attr.stats) lines.push(statsLine(attr.stats));
  const dets = topDetections(attr.results);
  if (dets.length) lines.push(`Notable: ${dets.join("; ")}`);
  return lines.join("\n");
}

/**
 * Minimal type definitions for the slice of VirusTotal v3 responses this server
 * actually consumes. These are intentionally partial — every field is optional
 * because VT omits fields it has no data for — but they let `format.ts` navigate
 * responses with compile-time field checking instead of untyped `any`.
 */

export interface AnalysisStats {
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  timeout?: number;
}

export interface EngineResult {
  engine_name?: string;
  category?: string;
  result?: string | null;
}

export type EngineResults = Record<string, EngineResult>;

export interface FileAttributes {
  meaningful_name?: string;
  names?: string[];
  type_description?: string;
  reputation?: number;
  sha256?: string;
  last_analysis_stats?: AnalysisStats;
  last_analysis_results?: EngineResults;
  last_analysis_date?: number;
}

export interface UrlAttributes {
  url?: string;
  last_final_url?: string;
  title?: string;
  reputation?: number;
  last_analysis_stats?: AnalysisStats;
  last_analysis_results?: EngineResults;
  last_analysis_date?: number;
}

export interface DomainAttributes {
  reputation?: number;
  categories?: Record<string, string>;
  registrar?: string;
  last_analysis_stats?: AnalysisStats;
  last_analysis_date?: number;
}

export interface IpAttributes {
  reputation?: number;
  as_owner?: string;
  asn?: number;
  country?: string;
  last_analysis_stats?: AnalysisStats;
  last_analysis_date?: number;
}

export interface AnalysisAttributes {
  status?: string;
  stats?: AnalysisStats;
  results?: EngineResults;
  date?: number;
}

/** Common VT envelope: `{ data: { id, type, attributes } }`. */
export interface VtObject<A> {
  id?: string;
  type?: string;
  attributes?: A;
}

export interface VtResponse<A> {
  data?: VtObject<A>;
}

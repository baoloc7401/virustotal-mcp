/** Shared helpers for building MCP tool results. */

import { z } from "zod";
import { VtError } from "../vtClient.js";
import type { Summary } from "../format.js";

export interface ToolResult {
  content: { type: "text"; text: string }[];
  structuredContent?: Summary;
  isError?: boolean;
  // The SDK's CallToolResult carries an open index signature; mirror it so our
  // handlers' return type is assignable.
  [key: string]: unknown;
}

/**
 * Shared `outputSchema` (raw Zod shape) advertised by every tool so MCP clients
 * know the shape of `structuredContent`. All fields are optional because which
 * ones are present depends on the resource and whether a scan has completed.
 */
export const summaryOutputSchema = {
  stats: z
    .object({
      malicious: z.number(),
      suspicious: z.number(),
      harmless: z.number(),
      undetected: z.number(),
      timeout: z.number(),
      total: z.number(),
    })
    .optional(),
  reputation: z.number().optional(),
  permalink: z.string().optional(),
  status: z.string().optional(),
  analysisId: z.string().optional(),
  lastAnalysisDate: z.string().optional(),
  notable: z.array(z.string()).optional(),
};

export function toolResult(text: string, structured?: Summary): ToolResult {
  const result: ToolResult = { content: [{ type: "text", text }] };
  if (structured !== undefined) result.structuredContent = structured;
  return result;
}

/** Render any thrown error as a non-crashing, model-readable tool error. */
export function errorResult(err: unknown): ToolResult {
  const message =
    err instanceof VtError
      ? err.message
      : err instanceof Error
        ? err.message
        : String(err);
  return { content: [{ type: "text", text: `Error: ${message}` }], isError: true };
}

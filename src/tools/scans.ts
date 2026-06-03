/** VirusTotal submission tools: scan a URL, upload a file, rescan, fetch an analysis. */

import { z } from "zod";
import { readFile, stat } from "node:fs/promises";
import { basename } from "node:path";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { vtGet, vtPostForm, vtPostMultipart } from "../vtClient.js";
import { toolResult, errorResult, summaryOutputSchema } from "./helpers.js";
import { formatAnalysis } from "../format.js";
import { envInt } from "../env.js";
import type { AnalysisAttributes, VtResponse } from "../vtTypes.js";

/** Free-tier file upload ceiling for POST /files. */
const MAX_FILE_BYTES = 32 * 1024 * 1024;

/** A VT submission response carries the new analysis id. */
interface SubmitResponse {
  data?: { id?: string };
}

const submissionId = (submit: SubmitResponse): string => submit.data?.id ?? "";

/**
 * Poll /analyses/{id} until completed, or until the retry budget is exhausted.
 * Returns whether it actually completed so callers can flag still-running scans.
 * Polling parameters are configurable via env:
 * - `VT_ANALYSIS_MAX_ATTEMPTS` (default 10)
 * - `VT_ANALYSIS_POLL_MS` initial delay (default 3000)
 * - `VT_ANALYSIS_POLL_CAP_MS` backoff cap (default 15000)
 */
async function waitForAnalysis(
  id: string,
): Promise<{ analysis: VtResponse<AnalysisAttributes>; completed: boolean }> {
  const maxAttempts = envInt("VT_ANALYSIS_MAX_ATTEMPTS", 10);
  let delayMs = envInt("VT_ANALYSIS_POLL_MS", 3_000);
  const cap = envInt("VT_ANALYSIS_POLL_CAP_MS", 15_000);
  let last: VtResponse<AnalysisAttributes> = {};
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    last = await vtGet<VtResponse<AnalysisAttributes>>(`/analyses/${id}`);
    if (last?.data?.attributes?.status === "completed") {
      return { analysis: last, completed: true };
    }
    await new Promise((r) => setTimeout(r, delayMs));
    delayMs = Math.min(delayMs * 1.5, cap); // backoff, capped
  }
  return { analysis: last, completed: false };
}

/** Shared tail for submission tools: poll (or not) and build the result. */
async function reportSubmission(subject: string, id: string, wait: boolean) {
  if (!wait) {
    return toolResult(
      `Submitted ${subject} for scanning. Analysis id: ${id}\n` +
        "Use get_analysis with this id to retrieve the result.",
      { analysisId: id, status: "pending" },
    );
  }
  const { analysis, completed } = await waitForAnalysis(id);
  const { text, structured } = formatAnalysis(analysis);
  if (!completed) {
    return toolResult(
      `Scan of ${subject} is still being analyzed — not finished after polling. ` +
        `Use get_analysis with id ${id} to check later.\n${text}`,
      structured,
    );
  }
  return toolResult(`Scanned ${subject}\n${text}`, structured);
}

export function registerScanTools(server: McpServer): void {
  server.registerTool(
    "scan_url",
    {
      title: "Scan URL",
      description:
        "Submit a URL to VirusTotal for a fresh scan. By default waits for the analysis " +
        "to complete and returns the verdict; set wait=false to return the analysis id immediately.",
      inputSchema: {
        url: z.string().url().describe("The full URL to scan"),
        wait: z.boolean().optional().describe("Wait for analysis to complete (default: true)"),
      },
      outputSchema: summaryOutputSchema,
    },
    async ({ url, wait = true }) => {
      try {
        const submit = await vtPostForm<SubmitResponse>("/urls", { url });
        return reportSubmission(url, submissionId(submit), wait);
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    "scan_file",
    {
      title: "Scan File",
      description:
        "Upload a local file to VirusTotal for scanning (free-tier limit: 32 MB). By default " +
        "waits for the analysis to complete and returns the verdict; set wait=false to return the id.",
      inputSchema: {
        path: z.string().min(1).describe("Absolute path to the local file to upload"),
        wait: z.boolean().optional().describe("Wait for analysis to complete (default: true)"),
      },
      outputSchema: summaryOutputSchema,
    },
    async ({ path, wait = true }) => {
      try {
        const info = await stat(path);
        if (info.size > MAX_FILE_BYTES) {
          return errorResult(
            new Error(
              `File is ${(info.size / 1024 / 1024).toFixed(1)} MB, over the 32 MB free-tier upload limit. ` +
                "Larger files require the upload_url flow (not supported in this server).",
            ),
          );
        }
        const bytes = await readFile(path);
        const form = new FormData();
        form.append("file", new Blob([bytes]), basename(path));

        const submit = await vtPostMultipart<SubmitResponse>("/files", form);
        return reportSubmission(basename(path), submissionId(submit), wait);
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    "rescan_file",
    {
      title: "Rescan File",
      description:
        "Re-trigger analysis of a file VirusTotal has already seen, by hash (MD5/SHA-1/SHA-256), " +
        "without re-uploading it. Useful when a cached report looks stale. By default waits for " +
        "the fresh verdict; set wait=false to return the analysis id immediately.",
      inputSchema: {
        hash: z
          .string()
          .regex(/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/, "Must be an MD5, SHA-1, or SHA-256 hex hash")
          .describe("File hash: MD5 (32), SHA-1 (40), or SHA-256 (64) hex characters"),
        wait: z.boolean().optional().describe("Wait for analysis to complete (default: true)"),
      },
      outputSchema: summaryOutputSchema,
    },
    async ({ hash, wait = true }) => {
      try {
        const submit = await vtPostForm<SubmitResponse>(`/files/${hash}/analyse`, {});
        return reportSubmission(hash, submissionId(submit), wait);
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    "get_analysis",
    {
      title: "Get Analysis",
      description:
        "Retrieve the result of a previously submitted scan by its analysis id " +
        "(returned by scan_url, scan_file, or rescan_file when wait=false).",
      inputSchema: {
        id: z.string().min(1).describe("Analysis id from a prior scan submission"),
      },
      outputSchema: summaryOutputSchema,
    },
    async ({ id }) => {
      try {
        const data = await vtGet<VtResponse<AnalysisAttributes>>(`/analyses/${id}`);
        const { text, structured } = formatAnalysis(data);
        return toolResult(text, structured);
      } catch (err) {
        return errorResult(err);
      }
    },
  );
}

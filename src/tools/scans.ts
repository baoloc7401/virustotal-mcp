/** VirusTotal submission tools: scan a URL, upload a file, fetch an analysis. */

import { z } from "zod";
import { readFile, stat } from "node:fs/promises";
import { basename } from "node:path";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { vtGet, vtPostForm, vtPostMultipart } from "../vtClient.js";
import { toolResult, errorResult } from "./helpers.js";
import { formatAnalysis } from "../format.js";

/** Free-tier file upload ceiling for POST /files. */
const MAX_FILE_BYTES = 32 * 1024 * 1024;

/** Poll /analyses/{id} until completed, or until the retry budget is exhausted. */
async function waitForAnalysis(id: string, maxAttempts = 10): Promise<any> {
  let delayMs = 3_000;
  let last: any;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    last = await vtGet(`/analyses/${id}`);
    if (last?.data?.attributes?.status === "completed") {
      return last;
    }
    await new Promise((r) => setTimeout(r, delayMs));
    delayMs = Math.min(delayMs * 1.5, 15_000); // backoff, capped
  }
  return last;
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
    },
    async ({ url, wait = true }) => {
      try {
        const submit = await vtPostForm("/urls", { url });
        const id = submit?.data?.id as string;
        if (!wait) {
          return toolResult(`Submitted URL for scanning. Analysis id: ${id}\nUse get_analysis with this id to retrieve the result.`);
        }
        const analysis = await waitForAnalysis(id);
        return toolResult(`Scanned ${url}\n${formatAnalysis(analysis)}`);
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

        const submit = await vtPostMultipart("/files", form);
        const id = submit?.data?.id as string;
        if (!wait) {
          return toolResult(`Uploaded ${basename(path)} for scanning. Analysis id: ${id}\nUse get_analysis with this id to retrieve the result.`);
        }
        const analysis = await waitForAnalysis(id);
        return toolResult(`Scanned ${basename(path)}\n${formatAnalysis(analysis)}`);
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
        "(returned by scan_url or scan_file when wait=false).",
      inputSchema: {
        id: z.string().min(1).describe("Analysis id from a prior scan submission"),
      },
    },
    async ({ id }) => {
      try {
        const data = await vtGet(`/analyses/${id}`);
        return toolResult(formatAnalysis(data));
      } catch (err) {
        return errorResult(err);
      }
    },
  );
}

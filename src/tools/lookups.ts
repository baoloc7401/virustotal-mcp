/** Read-only VirusTotal lookup tools: file hash, URL, domain, IP. */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { vtGet, urlId } from "../vtClient.js";
import { toolResult, errorResult } from "./helpers.js";
import { formatFileReport, formatUrlReport, formatDomainReport, formatIpReport } from "../format.js";

export function registerLookupTools(server: McpServer): void {
  server.registerTool(
    "get_file_report",
    {
      title: "Get File Report",
      description:
        "Look up a file's VirusTotal report by hash (MD5, SHA-1, or SHA-256). " +
        "Returns engine detection stats, type, reputation, and notable verdicts.",
      inputSchema: {
        hash: z
          .string()
          .regex(/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/, "Must be an MD5, SHA-1, or SHA-256 hex hash")
          .describe("File hash: MD5 (32), SHA-1 (40), or SHA-256 (64) hex characters"),
      },
    },
    async ({ hash }) => {
      try {
        const data = await vtGet(`/files/${hash}`);
        return toolResult(formatFileReport(data));
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    "get_url_report",
    {
      title: "Get URL Report",
      description:
        "Look up a URL's existing VirusTotal report. Does not submit a new scan — " +
        "use scan_url for that. Returns detection stats, title, and notable verdicts.",
      inputSchema: {
        url: z.string().url().describe("The full URL to look up (e.g. https://example.com/path)"),
      },
    },
    async ({ url }) => {
      try {
        const data = await vtGet(`/urls/${urlId(url)}`);
        return toolResult(formatUrlReport(data));
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    "get_domain_report",
    {
      title: "Get Domain Report",
      description:
        "Look up a domain's VirusTotal report: detection stats, reputation, categories, registrar.",
      inputSchema: {
        domain: z.string().min(1).describe("Domain name, e.g. example.com"),
      },
    },
    async ({ domain }) => {
      try {
        const data = await vtGet(`/domains/${encodeURIComponent(domain)}`);
        return toolResult(formatDomainReport(data));
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    "get_ip_report",
    {
      title: "Get IP Address Report",
      description:
        "Look up an IP address's VirusTotal report: detection stats, reputation, AS owner, country.",
      inputSchema: {
        ip: z.string().min(1).describe("IPv4 or IPv6 address, e.g. 8.8.8.8"),
      },
    },
    async ({ ip }) => {
      try {
        const data = await vtGet(`/ip_addresses/${encodeURIComponent(ip)}`);
        return toolResult(formatIpReport(data));
      } catch (err) {
        return errorResult(err);
      }
    },
  );
}

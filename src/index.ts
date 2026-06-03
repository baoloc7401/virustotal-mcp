#!/usr/bin/env node
/** Entry point: connect the VirusTotal MCP server over stdio. */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createServer } from "./server.js";

async function main(): Promise<void> {
  // Fail loud and early (on stderr) when misconfigured, instead of only when the
  // first tool call hits VirusTotal. The server still starts so tools/list works.
  if (!process.env.VT_API_KEY) {
    console.error(
      "Warning: VT_API_KEY is not set — VirusTotal tool calls will fail until it is configured " +
        "(get a free key at https://www.virustotal.com/gui/my-apikey).",
    );
  }
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Never write to stdout here — stdout is the JSON-RPC channel. Logs go to stderr.
  console.error("virustotal-mcp server running on stdio");
}

main().catch((err) => {
  console.error("Fatal error starting virustotal-mcp:", err);
  process.exit(1);
});

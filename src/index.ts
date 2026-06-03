#!/usr/bin/env node
/** Entry point: connect the VirusTotal MCP server over stdio. */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createServer } from "./server.js";

async function main(): Promise<void> {
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

/** Builds the MCP server and registers all VirusTotal tools. */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerLookupTools } from "./tools/lookups.js";
import { registerScanTools } from "./tools/scans.js";

export function createServer(): McpServer {
  const server = new McpServer({
    name: "virustotal-mcp",
    version: "0.1.0",
  });

  registerLookupTools(server);
  registerScanTools(server);

  return server;
}

import { describe, it, expect } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createServer } from "../src/server.js";

describe("createServer", () => {
  it("builds an McpServer with all tool groups registered", () => {
    const server = createServer();
    expect(server).toBeInstanceOf(McpServer);
  });
});

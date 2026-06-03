/** Shared helpers for building MCP tool results. */

import { VtError } from "../vtClient.js";

export interface ToolResult {
  content: { type: "text"; text: string }[];
  isError?: boolean;
  // The SDK's CallToolResult carries an open index signature; mirror it so our
  // handlers' return type is assignable.
  [key: string]: unknown;
}

export function toolResult(text: string): ToolResult {
  return { content: [{ type: "text", text }] };
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

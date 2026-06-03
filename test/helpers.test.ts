import { describe, it, expect } from "vitest";
import { toolResult, errorResult } from "../src/tools/helpers.js";
import { VtError } from "../src/vtClient.js";

describe("toolResult", () => {
  it("wraps text in a content array", () => {
    expect(toolResult("hi")).toEqual({ content: [{ type: "text", text: "hi" }] });
  });

  it("attaches structuredContent when provided", () => {
    const r = toolResult("hi", { reputation: 5 });
    expect(r.structuredContent).toEqual({ reputation: 5 });
  });
});

describe("errorResult", () => {
  it("uses VtError message", () => {
    const r = errorResult(new VtError(404, "not seen"));
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toBe("Error: not seen");
  });

  it("uses generic Error message", () => {
    expect(errorResult(new Error("boom")).content[0].text).toBe("Error: boom");
  });

  it("stringifies non-error values", () => {
    expect(errorResult("plain").content[0].text).toBe("Error: plain");
  });
});

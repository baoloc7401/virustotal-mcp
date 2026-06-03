import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/** Stub the transport so importing the entry point never touches real stdio. */
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => ({
  StdioServerTransport: class {},
}));

beforeEach(() => {
  vi.resetModules();
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.doUnmock("../src/server.js");
});

describe("index entry point", () => {
  it("connects the server and logs to stderr on success", async () => {
    const connect = vi.fn().mockResolvedValue(undefined);
    vi.doMock("../src/server.js", () => ({ createServer: () => ({ connect }) }));
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    await import("../src/index.js");

    await vi.waitFor(() => expect(connect).toHaveBeenCalledTimes(1));
    expect(errSpy).toHaveBeenCalledWith("virustotal-mcp server running on stdio");
  });

  it("logs and exits(1) when startup fails", async () => {
    const err = new Error("connect boom");
    vi.doMock("../src/server.js", () => ({
      createServer: () => ({ connect: vi.fn().mockRejectedValue(err) }),
    }));
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const exitSpy = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);

    await import("../src/index.js");

    await vi.waitFor(() => expect(exitSpy).toHaveBeenCalledWith(1));
    expect(errSpy).toHaveBeenCalledWith("Fatal error starting virustotal-mcp:", err);
  });
});

import { describe, it, expect, vi, beforeEach, type Mock } from "vitest";
import { registerLookupTools } from "../src/tools/lookups.js";
import { vtGet, urlId } from "../src/vtClient.js";

vi.mock("../src/vtClient.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/vtClient.js")>();
  return { ...actual, vtGet: vi.fn() };
});

const mGet = vtGet as Mock;

type Handler = (args: Record<string, unknown>) => Promise<{ content: { text: string }[]; isError?: boolean }>;

function collectTools(): Map<string, Handler> {
  const tools = new Map<string, Handler>();
  const server = { registerTool: (name: string, _cfg: unknown, handler: Handler) => tools.set(name, handler) };
  registerLookupTools(server as never);
  return tools;
}

let tools: Map<string, Handler>;
beforeEach(() => {
  mGet.mockReset();
  tools = collectTools();
});

describe("get_file_report", () => {
  it("returns a formatted report", async () => {
    mGet.mockResolvedValue({ data: { id: "h", attributes: { sha256: "h" } } });
    const r = await tools.get("get_file_report")!({ hash: "a".repeat(64) });
    expect(mGet).toHaveBeenCalledWith(`/files/${"a".repeat(64)}`);
    expect(r.content[0].text).toContain("File report");
  });

  it("surfaces errors via errorResult", async () => {
    mGet.mockRejectedValue(new Error("nope"));
    const r = await tools.get("get_file_report")!({ hash: "b".repeat(32) });
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toBe("Error: nope");
  });
});

describe("get_url_report", () => {
  it("looks up by url id", async () => {
    mGet.mockResolvedValue({ data: { id: "u", attributes: { url: "https://x" } } });
    const r = await tools.get("get_url_report")!({ url: "https://x" });
    expect(mGet).toHaveBeenCalledWith(`/urls/${urlId("https://x")}`);
    expect(r.content[0].text).toContain("URL report");
  });

  it("surfaces errors", async () => {
    mGet.mockRejectedValue(new Error("bad"));
    const r = await tools.get("get_url_report")!({ url: "https://x" });
    expect(r.isError).toBe(true);
  });
});

describe("get_domain_report", () => {
  it("encodes the domain", async () => {
    mGet.mockResolvedValue({ data: { id: "ex.com", attributes: {} } });
    const r = await tools.get("get_domain_report")!({ domain: "ex.com" });
    expect(mGet).toHaveBeenCalledWith("/domains/ex.com");
    expect(r.content[0].text).toContain("Domain report");
  });

  it("surfaces errors", async () => {
    mGet.mockRejectedValue(new Error("bad"));
    const r = await tools.get("get_domain_report")!({ domain: "ex.com" });
    expect(r.isError).toBe(true);
  });
});

describe("get_ip_report", () => {
  it("encodes the ip", async () => {
    mGet.mockResolvedValue({ data: { id: "8.8.8.8", attributes: {} } });
    const r = await tools.get("get_ip_report")!({ ip: "8.8.8.8" });
    expect(mGet).toHaveBeenCalledWith("/ip_addresses/8.8.8.8");
    expect(r.content[0].text).toContain("IP report");
  });

  it("surfaces errors", async () => {
    mGet.mockRejectedValue(new Error("bad"));
    const r = await tools.get("get_ip_report")!({ ip: "8.8.8.8" });
    expect(r.isError).toBe(true);
  });
});

import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from "vitest";
import { registerScanTools } from "../src/tools/scans.js";
import { vtGet, vtPostForm, vtPostMultipart } from "../src/vtClient.js";
import { stat, readFile } from "node:fs/promises";

vi.mock("../src/vtClient.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/vtClient.js")>();
  return { ...actual, vtGet: vi.fn(), vtPostForm: vi.fn(), vtPostMultipart: vi.fn() };
});

vi.mock("node:fs/promises", () => ({ stat: vi.fn(), readFile: vi.fn() }));

const mGet = vtGet as Mock;
const mForm = vtPostForm as Mock;
const mMulti = vtPostMultipart as Mock;
const mStat = stat as unknown as Mock;
const mRead = readFile as unknown as Mock;

type Handler = (args: Record<string, unknown>) => Promise<{ content: { text: string }[]; isError?: boolean }>;

function collectTools(): Map<string, Handler> {
  const tools = new Map<string, Handler>();
  const server = { registerTool: (name: string, _cfg: unknown, handler: Handler) => tools.set(name, handler) };
  registerScanTools(server as never);
  return tools;
}

let tools: Map<string, Handler>;
beforeEach(() => {
  [mGet, mForm, mMulti, mStat, mRead].forEach((m) => m.mockReset());
  tools = collectTools();
});

const completed = { data: { id: "an", attributes: { status: "completed", stats: { malicious: 0 } } } };
const queued = { data: { id: "an", attributes: { status: "queued" } } };

describe("scan_url", () => {
  it("returns the analysis id immediately when wait=false", async () => {
    mForm.mockResolvedValue({ data: { id: "an1" } });
    const r = await tools.get("scan_url")!({ url: "https://x", wait: false });
    expect(mForm).toHaveBeenCalledWith("/urls", { url: "https://x" });
    expect(r.content[0].text).toContain("Analysis id: an1");
    expect(mGet).not.toHaveBeenCalled();
  });

  it("waits for completion by default", async () => {
    mForm.mockResolvedValue({ data: { id: "an" } });
    mGet.mockResolvedValue(completed);
    const r = await tools.get("scan_url")!({ url: "https://x" });
    expect(r.content[0].text).toContain("Scanned https://x");
    expect(r.content[0].text).toContain("status: completed");
  });

  it("surfaces errors", async () => {
    mForm.mockRejectedValue(new Error("submit failed"));
    const r = await tools.get("scan_url")!({ url: "https://x" });
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toBe("Error: submit failed");
  });
});

describe("scan_file", () => {
  it("rejects files over the 32 MB limit", async () => {
    mStat.mockResolvedValue({ size: 33 * 1024 * 1024 });
    const r = await tools.get("scan_file")!({ path: "/big.bin" });
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toMatch(/over the 32 MB/);
    expect(mRead).not.toHaveBeenCalled();
  });

  it("uploads and returns the id when wait=false", async () => {
    mStat.mockResolvedValue({ size: 10 });
    mRead.mockResolvedValue(Buffer.from("data"));
    mMulti.mockResolvedValue({ data: { id: "an2" } });
    const r = await tools.get("scan_file")!({ path: "/dir/sample.exe", wait: false });
    expect(mMulti).toHaveBeenCalledWith("/files", expect.any(FormData));
    expect(r.content[0].text).toContain("Uploaded sample.exe");
    expect(r.content[0].text).toContain("Analysis id: an2");
  });

  it("uploads and waits for completion by default", async () => {
    mStat.mockResolvedValue({ size: 10 });
    mRead.mockResolvedValue(Buffer.from("data"));
    mMulti.mockResolvedValue({ data: { id: "an" } });
    mGet.mockResolvedValue(completed);
    const r = await tools.get("scan_file")!({ path: "/dir/sample.exe" });
    expect(r.content[0].text).toContain("Scanned sample.exe");
  });

  it("surfaces fs errors", async () => {
    mStat.mockRejectedValue(new Error("no such file"));
    const r = await tools.get("scan_file")!({ path: "/missing" });
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toBe("Error: no such file");
  });
});

describe("get_analysis", () => {
  it("fetches and formats an analysis", async () => {
    mGet.mockResolvedValue(completed);
    const r = await tools.get("get_analysis")!({ id: "an" });
    expect(mGet).toHaveBeenCalledWith("/analyses/an");
    expect(r.content[0].text).toContain("status: completed");
  });

  it("surfaces errors", async () => {
    mGet.mockRejectedValue(new Error("gone"));
    const r = await tools.get("get_analysis")!({ id: "an" });
    expect(r.isError).toBe(true);
  });
});

describe("waitForAnalysis polling", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("polls again after a backoff when not yet completed", async () => {
    mForm.mockResolvedValue({ data: { id: "an" } });
    mGet.mockResolvedValueOnce(queued).mockResolvedValue(completed);
    const p = tools.get("scan_url")!({ url: "https://x" });
    await vi.advanceTimersByTimeAsync(3_000);
    const r = await p;
    expect(mGet).toHaveBeenCalledTimes(2);
    expect(r.content[0].text).toContain("status: completed");
  });

  it("gives up after the retry budget, returning the last response", async () => {
    mForm.mockResolvedValue({ data: { id: "an" } });
    mGet.mockResolvedValue(queued);
    const p = tools.get("scan_url")!({ url: "https://x" });
    await vi.advanceTimersByTimeAsync(200_000);
    const r = await p;
    expect(mGet).toHaveBeenCalledTimes(10);
    expect(r.content[0].text).toContain("status: queued");
  });
});

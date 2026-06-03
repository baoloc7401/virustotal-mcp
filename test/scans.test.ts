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

type Result = { content: { text: string }[]; structuredContent?: Record<string, unknown>; isError?: boolean };
type Handler = (args: Record<string, unknown>) => Promise<Result>;

function collectTools(): Map<string, Handler> {
  const tools = new Map<string, Handler>();
  const server = { registerTool: (name: string, _cfg: unknown, handler: Handler) => tools.set(name, handler) };
  registerScanTools(server as never);
  return tools;
}

const POLL_ENV = ["VT_ANALYSIS_MAX_ATTEMPTS", "VT_ANALYSIS_POLL_MS", "VT_ANALYSIS_POLL_CAP_MS"];

let tools: Map<string, Handler>;
beforeEach(() => {
  [mGet, mForm, mMulti, mStat, mRead].forEach((m) => m.mockReset());
  POLL_ENV.forEach((k) => delete process.env[k]);
  tools = collectTools();
});

const completed = { data: { id: "an", attributes: { status: "completed", stats: { malicious: 0 } } } };
const queued = { data: { id: "an", attributes: { status: "queued" } } };

describe("scan_url", () => {
  it("returns the analysis id immediately when wait=false", async () => {
    mForm.mockResolvedValue({ data: { id: "an1" } });
    const r = await tools.get("scan_url")!({ url: "https://x", wait: false });
    expect(mForm).toHaveBeenCalledWith("/urls", { url: "https://x" });
    expect(r.content[0].text).toContain("Submitted https://x for scanning");
    expect(r.content[0].text).toContain("Analysis id: an1");
    expect(r.structuredContent).toEqual({ analysisId: "an1", status: "pending" });
    expect(mGet).not.toHaveBeenCalled();
  });

  it("defaults the id to empty string when the submission omits it", async () => {
    mForm.mockResolvedValue({});
    const r = await tools.get("scan_url")!({ url: "https://x", wait: false });
    expect(r.isError).toBeUndefined();
    expect(r.content[0].text).toContain("Analysis id: \n");
  });

  it("waits for completion by default", async () => {
    mForm.mockResolvedValue({ data: { id: "an" } });
    mGet.mockResolvedValue(completed);
    const r = await tools.get("scan_url")!({ url: "https://x" });
    expect(r.content[0].text).toContain("Scanned https://x");
    expect(r.content[0].text).toContain("status: completed");
    expect(r.structuredContent?.status).toBe("completed");
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
    expect(r.content[0].text).toContain("Submitted sample.exe for scanning");
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

describe("rescan_file", () => {
  it("re-triggers analysis by hash and returns the id when wait=false", async () => {
    mForm.mockResolvedValue({ data: { id: "an3" } });
    const r = await tools.get("rescan_file")!({ hash: "a".repeat(64), wait: false });
    expect(mForm).toHaveBeenCalledWith(`/files/${"a".repeat(64)}/analyse`, {});
    expect(r.content[0].text).toContain("Analysis id: an3");
  });

  it("waits for the fresh verdict by default", async () => {
    mForm.mockResolvedValue({ data: { id: "an" } });
    mGet.mockResolvedValue(completed);
    const r = await tools.get("rescan_file")!({ hash: "b".repeat(64) });
    expect(r.content[0].text).toContain(`Scanned ${"b".repeat(64)}`);
    expect(r.content[0].text).toContain("status: completed");
  });

  it("surfaces errors", async () => {
    mForm.mockRejectedValue(new Error("rescan failed"));
    const r = await tools.get("rescan_file")!({ hash: "c".repeat(64) });
    expect(r.isError).toBe(true);
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

  it("flags a still-running scan after the retry budget is exhausted", async () => {
    mForm.mockResolvedValue({ data: { id: "an" } });
    mGet.mockResolvedValue(queued);
    const p = tools.get("scan_url")!({ url: "https://x" });
    await vi.advanceTimersByTimeAsync(200_000);
    const r = await p;
    expect(mGet).toHaveBeenCalledTimes(10);
    expect(r.content[0].text).toContain("still being analyzed");
    expect(r.content[0].text).toContain("Use get_analysis with id an");
    expect(r.content[0].text).toContain("status: queued");
  });

  it("honours a configurable max-attempts budget", async () => {
    process.env.VT_ANALYSIS_MAX_ATTEMPTS = "2";
    mForm.mockResolvedValue({ data: { id: "an" } });
    mGet.mockResolvedValue(queued);
    const p = tools.get("scan_url")!({ url: "https://x" });
    await vi.advanceTimersByTimeAsync(200_000);
    await p;
    expect(mGet).toHaveBeenCalledTimes(2);
  });
});

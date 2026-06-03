import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { VtError, vtGet, vtPostForm, vtPostMultipart, urlId, VT_BASE } from "../src/vtClient.js";

/** Build a minimal Response-like stub. */
function res(opts: { ok?: boolean; status?: number; json?: () => Promise<unknown> }): Response {
  return {
    ok: opts.ok ?? true,
    status: opts.status ?? 200,
    json: opts.json ?? (() => Promise.resolve({})),
  } as unknown as Response;
}

const fetchMock = vi.fn();

// Monotonic fake clock. Each test jumps far past the previous one so the
// module-level throttle (`lastRequestAt`) never schedules an unexpected wait.
let clock = 1_700_000_000_000;

beforeEach(() => {
  vi.useFakeTimers();
  clock += 1_000_000;
  vi.setSystemTime(clock);
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockReset();
  process.env.VT_API_KEY = "test-key";
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("urlId", () => {
  it("computes base64url with padding stripped", () => {
    expect(urlId("https://example.com")).toBe("aHR0cHM6Ly9leGFtcGxlLmNvbQ");
  });
});

describe("apiKey via request", () => {
  it("throws a 401 VtError when VT_API_KEY is unset", async () => {
    delete process.env.VT_API_KEY;
    await expect(vtGet("/files/x")).rejects.toMatchObject({ name: "VtError", status: 401 });
  });
});

describe("vtGet", () => {
  it("sends the api key + accept headers and returns parsed JSON", async () => {
    fetchMock.mockResolvedValue(res({ json: () => Promise.resolve({ data: 1 }) }));
    const out = await vtGet("/files/abc");
    expect(out).toEqual({ data: 1 });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(`${VT_BASE}/files/abc`);
    expect(init.headers["x-apikey"]).toBe("test-key");
    expect(init.headers.accept).toBe("application/json");
  });
});

describe("toError mapping", () => {
  it.each([
    [401, /rejected the API key/],
    [404, /not been seen/],
    [429, /rate limit/],
  ])("maps %i to a descriptive VtError", async (status, re) => {
    fetchMock.mockResolvedValue(res({ ok: false, status, json: () => Promise.resolve({}) }));
    await expect(vtGet("/x")).rejects.toMatchObject({ status, message: expect.stringMatching(re) });
  });

  it("includes error.message detail for other statuses", async () => {
    fetchMock.mockResolvedValue(
      res({ ok: false, status: 400, json: () => Promise.resolve({ error: { message: "bad hash" } }) }),
    );
    await expect(vtGet("/x")).rejects.toThrow(/failed \(400\): bad hash/);
  });

  it("falls back to error.code when message absent", async () => {
    fetchMock.mockResolvedValue(
      res({ ok: false, status: 400, json: () => Promise.resolve({ error: { code: "BadRequest" } }) }),
    );
    await expect(vtGet("/x")).rejects.toThrow(/failed \(400\): BadRequest/);
  });

  it("tolerates a non-JSON error body", async () => {
    fetchMock.mockResolvedValue(
      res({ ok: false, status: 500, json: () => Promise.reject(new Error("no body")) }),
    );
    await expect(vtGet("/x")).rejects.toThrow(/failed \(500\)\./);
  });
});

describe("vtPostForm", () => {
  it("POSTs urlencoded body", async () => {
    fetchMock.mockResolvedValue(res({ json: () => Promise.resolve({ ok: true }) }));
    await vtPostForm("/urls", { url: "https://a.test/?x=1" });
    const [, init] = fetchMock.mock.calls[0];
    expect(init.method).toBe("POST");
    expect(init.headers["content-type"]).toBe("application/x-www-form-urlencoded");
    expect(init.body).toBe("url=https%3A%2F%2Fa.test%2F%3Fx%3D1");
  });
});

describe("vtPostMultipart", () => {
  it("POSTs the FormData body", async () => {
    fetchMock.mockResolvedValue(res({ json: () => Promise.resolve({ ok: true }) }));
    const form = new FormData();
    form.append("file", new Blob(["x"]), "f.bin");
    await vtPostMultipart("/files", form);
    const [, init] = fetchMock.mock.calls[0];
    expect(init.method).toBe("POST");
    expect(init.body).toBe(form);
  });
});

describe("throttle", () => {
  it("waits MIN_REQUEST_INTERVAL_MS between back-to-back requests", async () => {
    fetchMock.mockResolvedValue(res({ json: () => Promise.resolve({}) }));
    await vtGet("/first");
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const second = vtGet("/second");
    // Without advancing the clock the throttled second call has not fired yet.
    await Promise.resolve();
    expect(fetchMock).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(1_000);
    await second;
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

describe("VtError", () => {
  it("carries status and name", () => {
    const e = new VtError(418, "teapot");
    expect(e.status).toBe(418);
    expect(e.name).toBe("VtError");
    expect(e.message).toBe("teapot");
  });
});

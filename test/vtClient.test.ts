import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { VtError, vtGet, vtPostForm, vtPostMultipart, urlId, VT_BASE } from "../src/vtClient.js";

/** Build a minimal Response-like stub (incl. a headers.get for Retry-After). */
function res(opts: {
  ok?: boolean;
  status?: number;
  retryAfter?: string;
  json?: () => Promise<unknown>;
}): Response {
  return {
    ok: opts.ok ?? true,
    status: opts.status ?? 200,
    headers: { get: (name: string) => (name === "retry-after" ? (opts.retryAfter ?? null) : null) },
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
  // Keep most tests fast and deterministic: short spacing, no retries.
  process.env.VT_MIN_REQUEST_INTERVAL_MS = "1000";
  process.env.VT_MAX_RETRIES = "0";
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
  it("waits the configured interval between back-to-back requests", async () => {
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

  it.each([
    ["unset", undefined],
    ["empty", ""],
    ["non-numeric", "abc"],
    ["negative", "-100"],
  ])("falls back to the 15s default when the interval is %s", async (_label, value) => {
    if (value === undefined) delete process.env.VT_MIN_REQUEST_INTERVAL_MS;
    else process.env.VT_MIN_REQUEST_INTERVAL_MS = value;
    fetchMock.mockResolvedValue(res({ json: () => Promise.resolve({}) }));

    await vtGet("/first");
    const second = vtGet("/second");
    await Promise.resolve();
    expect(fetchMock).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(15_000);
    await second;
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

describe("429 retry", () => {
  it("retries with backoff (no Retry-After header) then succeeds", async () => {
    process.env.VT_MAX_RETRIES = "2";
    fetchMock
      .mockResolvedValueOnce(res({ ok: false, status: 429 }))
      .mockResolvedValueOnce(res({ json: () => Promise.resolve({ ok: 1 }) }));

    const p = vtGet("/x");
    await vi.advanceTimersByTimeAsync(1_000); // RETRY_BASE_MS * 2^0
    await expect(p).resolves.toEqual({ ok: 1 });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("honours a numeric Retry-After header", async () => {
    process.env.VT_MAX_RETRIES = "1";
    process.env.VT_MIN_REQUEST_INTERVAL_MS = "0";
    fetchMock
      .mockResolvedValueOnce(res({ ok: false, status: 429, retryAfter: "2" }))
      .mockResolvedValueOnce(res({ json: () => Promise.resolve({ ok: 2 }) }));

    const p = vtGet("/x");
    await vi.advanceTimersByTimeAsync(2_000);
    await expect(p).resolves.toEqual({ ok: 2 });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("gives up and throws once retries are exhausted", async () => {
    process.env.VT_MAX_RETRIES = "1";
    process.env.VT_MIN_REQUEST_INTERVAL_MS = "0";
    fetchMock.mockResolvedValue(res({ ok: false, status: 429 }));

    const p = vtGet("/x").catch((e) => e);
    await vi.advanceTimersByTimeAsync(5_000);
    const err = await p;
    expect(err).toMatchObject({ status: 429 });
    expect(fetchMock).toHaveBeenCalledTimes(2); // initial attempt + one retry
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

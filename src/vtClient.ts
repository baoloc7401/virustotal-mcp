/**
 * Thin VirusTotal API v3 HTTP client.
 *
 * Auth: header `x-apikey: <VT_API_KEY>`.
 * Tuned for the free/public tier (4 req/min, 500 req/day): we apply a
 * concurrency-safe client-side throttle, retry transient 429s with backoff, and
 * translate the common HTTP statuses (401/404/429) into clear, model-friendly
 * errors instead of leaking raw responses.
 *
 * Tunables (all optional env vars):
 * - `VT_MIN_REQUEST_INTERVAL_MS` — min spacing between requests
 *   (default 15000 = 4/min, the free-tier ceiling).
 * - `VT_MAX_RETRIES` — how many times to retry a 429 before giving up (default 2).
 */

import { envInt } from "./env.js";

export const VT_BASE = "https://www.virustotal.com/api/v3";
export const VT_GUI = "https://www.virustotal.com/gui";

/** Free tier allows 4 req/min => one request every 15s. */
const DEFAULT_MIN_REQUEST_INTERVAL_MS = 15_000;
const DEFAULT_MAX_RETRIES = 2;
/** Backoff used for 429 retries when the server sends no Retry-After header. */
const RETRY_BASE_MS = 1_000;
const RETRY_CAP_MS = 30_000;

function minRequestInterval(): number {
  return envInt("VT_MIN_REQUEST_INTERVAL_MS", DEFAULT_MIN_REQUEST_INTERVAL_MS);
}

function maxRetries(): number {
  return envInt("VT_MAX_RETRIES", DEFAULT_MAX_RETRIES);
}

const delay = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/**
 * Error thrown for non-2xx VirusTotal responses. Carries the HTTP status so
 * callers (and tool handlers) can react — e.g. treat 404 as "not seen yet".
 */
export class VtError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "VtError";
  }
}

function apiKey(): string {
  const key = process.env.VT_API_KEY;
  if (!key) {
    throw new VtError(
      401,
      "VT_API_KEY is not set. Configure it in the MCP server environment " +
        "(get a free key at https://www.virustotal.com/gui/my-apikey).",
    );
  }
  return key;
}

// A promise-chained mutex so concurrent callers can't all read the same
// `lastRequestAt` and burst past the limit: each call waits for the previous
// one's gate before spacing itself out.
let lastRequestAt = 0;
let gate: Promise<void> = Promise.resolve();
async function throttle(): Promise<void> {
  const prev = gate;
  let release!: () => void;
  gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  await prev;
  const wait = minRequestInterval() - (Date.now() - lastRequestAt);
  if (wait > 0) await delay(wait);
  lastRequestAt = Date.now();
  release();
}

/** Turn a non-OK response into a descriptive VtError. */
async function toError(res: Response): Promise<VtError> {
  let detail = "";
  try {
    const body = (await res.json()) as { error?: { message?: string; code?: string } };
    detail = body?.error?.message ?? body?.error?.code ?? "";
  } catch {
    /* response had no JSON body */
  }

  switch (res.status) {
    case 401:
      return new VtError(401, "VirusTotal rejected the API key (401 Unauthorized). Check VT_API_KEY.");
    case 404:
      return new VtError(404, "Not found in VirusTotal (404) — this item has not been seen/analyzed yet.");
    case 429:
      return new VtError(
        429,
        "VirusTotal rate limit hit (429). The free tier allows 4 requests/min and 500/day. " +
          "Wait a moment and try again.",
      );
    default:
      return new VtError(res.status, `VirusTotal request failed (${res.status})${detail ? `: ${detail}` : ""}.`);
  }
}

/** How long to wait before retrying a 429: honour Retry-After, else back off. */
function retryDelayMs(res: Response, attempt: number): number {
  const header = res.headers.get("retry-after");
  const secs = header === null ? NaN : Number(header);
  if (Number.isFinite(secs)) return secs * 1_000;
  return Math.min(RETRY_BASE_MS * 2 ** attempt, RETRY_CAP_MS);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const retries = maxRetries();
  for (let attempt = 0; ; attempt++) {
    await throttle();
    const res = await fetch(`${VT_BASE}${path}`, {
      ...init,
      headers: {
        "x-apikey": apiKey(),
        accept: "application/json",
        ...(init.headers ?? {}),
      },
    });

    if (res.ok) return (await res.json()) as T;
    if (res.status === 429 && attempt < retries) {
      await delay(retryDelayMs(res, attempt));
      continue;
    }
    throw await toError(res);
  }
}

export function vtGet<T = unknown>(path: string): Promise<T> {
  return request<T>(path);
}

/** POST application/x-www-form-urlencoded (URL submission, file rescan). */
export function vtPostForm<T = unknown>(path: string, fields: Record<string, string>): Promise<T> {
  const body = new URLSearchParams(fields).toString();
  return request<T>(path, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });
}

/** POST multipart/form-data (used for file upload). */
export function vtPostMultipart<T = unknown>(path: string, form: FormData): Promise<T> {
  return request<T>(path, { method: "POST", body: form });
}

/** VirusTotal URL identifier: base64url(url) with padding stripped. */
export function urlId(url: string): string {
  return Buffer.from(url).toString("base64url").replace(/=+$/, "");
}

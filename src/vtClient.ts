/**
 * Thin VirusTotal API v3 HTTP client.
 *
 * Auth: header `x-apikey: <VT_API_KEY>`.
 * Tuned for the free/public tier (4 req/min, 500 req/day): we apply a small
 * client-side throttle and translate the common HTTP statuses (401/404/429)
 * into clear, model-friendly errors instead of leaking raw responses.
 */

export const VT_BASE = "https://www.virustotal.com/api/v3";
export const VT_GUI = "https://www.virustotal.com/gui";

/** Minimum spacing between requests. Free tier allows 4/min => 1 req / 15s. */
const MIN_REQUEST_INTERVAL_MS = 1_000;

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

let lastRequestAt = 0;
async function throttle(): Promise<void> {
  const wait = MIN_REQUEST_INTERVAL_MS - (Date.now() - lastRequestAt);
  if (wait > 0) {
    await new Promise((r) => setTimeout(r, wait));
  }
  lastRequestAt = Date.now();
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

async function request(path: string, init: RequestInit = {}): Promise<any> {
  await throttle();
  const res = await fetch(`${VT_BASE}${path}`, {
    ...init,
    headers: {
      "x-apikey": apiKey(),
      accept: "application/json",
      ...(init.headers ?? {}),
    },
  });

  if (!res.ok) {
    throw await toError(res);
  }
  return res.json();
}

export function vtGet(path: string): Promise<any> {
  return request(path);
}

/** POST application/x-www-form-urlencoded (used for URL submission). */
export function vtPostForm(path: string, fields: Record<string, string>): Promise<any> {
  const body = new URLSearchParams(fields).toString();
  return request(path, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });
}

/** POST multipart/form-data (used for file upload). */
export function vtPostMultipart(path: string, form: FormData): Promise<any> {
  return request(path, { method: "POST", body: form });
}

/** VirusTotal URL identifier: base64url(url) with padding stripped. */
export function urlId(url: string): string {
  return Buffer.from(url).toString("base64url").replace(/=+$/, "");
}

# IMPROVEMENTS

Backlog of potential improvements for `virustotal-mcp`, grouped by theme. Each item
notes the rationale and a rough effort estimate. Items marked **DONE** have been
implemented; items that fall outside the project's stated
[scope](../CLAUDE.md#scope-intentional-limits) (premium API features) are explicitly
flagged and intentionally left unimplemented.

## Correctness

- **DONE — Throttle interval now matches the documented free-tier rate.** The default
  is `15_000`ms (4 req/min) and is overridable via `VT_MIN_REQUEST_INTERVAL_MS` so
  paid-tier users can lower it. See [vtClient.ts](../src/vtClient.ts) (`minRequestInterval`).

- **DONE — The throttle is now concurrency-safe.** Requests pass through a
  promise-chained mutex (`throttle()` in [vtClient.ts](../src/vtClient.ts)), so
  concurrent callers can no longer read the same `lastRequestAt` and burst past the
  limit — each call waits for the previous one's gate before spacing itself out.

- **DONE — Client-side retry on 429.** Rate-limited requests are retried with backoff
  (honouring `Retry-After` when present), up to `VT_MAX_RETRIES` (default 2), before the
  error surfaces. See `retryDelayMs` / `request` in [vtClient.ts](../src/vtClient.ts).

- **DONE — `waitForAnalysis` timeout is no longer silent.** It now returns a
  `{ analysis, completed }` pair; when polling is exhausted the tool result says the
  scan is still being analyzed and hands back the analysis id for a later `get_analysis`.
  See [scans.ts](../src/tools/scans.ts) (`waitForAnalysis`, `reportSubmission`).

## Type safety

- **DONE — `any` replaced with typed VT responses.** Minimal response interfaces live in
  [vtTypes.ts](../src/vtTypes.ts); `vtGet`/`vtPostForm`/`vtPostMultipart` are generic
  (`<T>`), and `format.ts` navigates typed `VtResponse<…>` values.

- **DONE — ESLint tightened against `any`.** `@typescript-eslint/no-explicit-any` is now
  `error` (was `off`) in [eslint.config.js](../eslint.config.js); the codebase is clean.

## Features (in scope — free public API)

- **DONE — Structured output alongside the text summary.** Each formatter returns
  `{ text, structured }`; tools attach the `structured` object as MCP `structuredContent`
  and advertise a shared `outputSchema` (`summaryOutputSchema` in
  [helpers.ts](../src/tools/helpers.ts)) so clients can consume verdicts programmatically.

- **DONE — GUI permalink in `get_analysis` / scan results.** `formatAnalysis` now emits
  an analysis permalink (and includes it in `structuredContent`), matching the report
  formatters. See [format.ts](../src/format.ts).

- **DONE — Analysis / last-seen timestamps surfaced.** Reports and analyses render a
  `Last analyzed:` / `Analyzed:` line (ISO) from `last_analysis_date` / `date`, also
  exposed as `lastAnalysisDate` in `structuredContent`. See [format.ts](../src/format.ts).

- **DONE — `rescan_file` tool.** Re-triggers analysis of an already-known file via
  `POST /files/{hash}/analyse` without re-uploading bytes. See [scans.ts](../src/tools/scans.ts).

## Robustness & DX

- **DONE — `VT_API_KEY` validated at startup.** [index.ts](../src/index.ts) logs a
  clear stderr warning when the key is missing, instead of only failing on first tool call.

- **DONE — `waitForAnalysis` polling parameters are configurable.** `VT_ANALYSIS_MAX_ATTEMPTS`,
  `VT_ANALYSIS_POLL_MS`, and `VT_ANALYSIS_POLL_CAP_MS` tune attempts, base delay, and the
  backoff cap. See [scans.ts](../src/tools/scans.ts).

- **Consider streaming/IDs for large files.** `scan_file` reads the whole file into
  memory via `readFile`. Fine within the 32 MB cap, but worth a note if the cap ever
  changes. The `upload_url` flow for >32 MB files remains intentionally unimplemented.
  *(out of scope for now)*

## Out of scope (premium API)

These are recorded for completeness but are explicitly excluded by the project scope:

- VT Intelligence search, relationship traversal (passive DNS, sibling domains,
  contacted IPs), comments/votes, and Livehunt all require the premium API and are
  **not** planned.

## Documentation

- **DONE — Tool reference table.** The [README](../README.md) lists every tool (including
  `rescan_file`) with its purpose, plus a configuration table for the env-var tunables.

- **DONE — EICAR / `google.com` fixtures documented.** The [README](../README.md) testing
  section lists the known-good smoke-test fixtures.

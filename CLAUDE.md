# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

- `npm install` — install deps (runs `prepare` → `build`).
- `npm run build` — compile `src/` → `dist/` via `tsc`.
- `npm run dev` — run the server from source with `tsx` (needs `VT_API_KEY` in env).
- `npm start` — run the compiled `dist/index.js`.
- `npm run lint` — ESLint (flat config, `eslint.config.js`); `npm run lint:fix` to autofix.
- `npm test` — run the Vitest suite (`test/*.test.ts`); `npm run coverage` enforces 100% coverage.

## Workflow rules

- **Always run `npm run lint` before considering any task done** — it must pass clean.
- **Always run `npm test` before considering any task done** — the suite must pass; `npm run coverage` is gated at 100% lines/branches/functions/statements (see `vitest.config.ts`).
- **Keep tests in sync with code.** When a change breaks a test or a test needs to change, update the test as part of the same change — never delete, skip, or weaken a test just to make it pass, and never lower the coverage thresholds. New behaviour ships with new tests; the suite must stay green and at 100% coverage.
- **You may `git commit` (no co-authoring), but do not `git push`** unless explicitly asked.
- **Commit messages use Conventional Commits:** `<type>: <msg>` where type is one of
  `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `build` (e.g. `feat: add scan_url tool`).
- **Permissions** are pre-approved in `.claude/settings.json`: the build/lint/test scripts, read-only git, and `git commit`. Server-start commands (`npm run dev`, `npm start`) are intentionally left out — the user runs the server themselves. `.env` reads and `git push` are denied; personal overrides go in `.claude/settings.local.json` (gitignored).

Unit tests run under Vitest (`npm test`); they mock `fetch` and `node:fs/promises`, so no network or API key is needed. For end-to-end confidence, also verify changes two ways:

- **Stdio smoke test** (no API key needed for `tools/list`): pipe MCP frames into the server and confirm tools register.
  ```bash
  printf '%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
    '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
    | VT_API_KEY=dummy node dist/index.js 2>/dev/null
  ```
- **Live / interactive**: `npx @modelcontextprotocol/inspector node dist/index.js` with a real `VT_API_KEY`. Known fixtures: EICAR SHA-256 `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` (many malicious) and domain `google.com` (mostly harmless).

## Architecture

A stdio MCP server wrapping the **VirusTotal API v3**, built on `@modelcontextprotocol/sdk` v1. The layering matters more than any single file:

- `src/index.ts` — entry point. Connects `StdioServerTransport`. **stdout is the JSON-RPC channel — never write to it; all logging goes to stderr (`console.error`).**
- `src/server.ts` — `createServer()` builds the `McpServer` and calls the per-domain `registerXTools(server)` functions. Adding a tool group = a new `register*` function called here.
- `src/vtClient.ts` — the only place that talks HTTP. Holds `VT_BASE`, the `x-apikey` auth, a **client-side throttle** (`MIN_REQUEST_INTERVAL_MS`) for the free tier, and `toError()` which maps 401/404/429 to `VtError` with human-readable messages (404 = "not seen yet", 429 = quota hit). `urlId()` computes the base64url URL identifier. All network calls go through `vtGet` / `vtPostForm` / `vtPostMultipart`.
- `src/format.ts` — pure functions that condense large VT JSON into compact text summaries (detection counts, reputation, notable verdicts, GUI permalink). Tools return these strings, **not** raw API JSON, to keep token usage low.
- `src/tools/lookups.ts` / `src/tools/scans.ts` — tool definitions. Each handler is a thin shell: validate via Zod `inputSchema`, call `vtClient`, pass the response through `format.ts`, wrap with the helpers below. Submission tools poll `/analyses/{id}` via `waitForAnalysis` (bounded retries + backoff).
- `src/tools/helpers.ts` — `toolResult(text)` and `errorResult(err)`. **Every handler wraps its body in try/catch and returns `errorResult(err)`** so failures surface as `{ isError: true }` tool results rather than crashing the server. `ToolResult` carries an open index signature to stay assignable to the SDK's `CallToolResult`.

### Conventions

- SDK v1 import paths end in `.js` (e.g. `@modelcontextprotocol/sdk/server/mcp.js`), and `registerTool`'s `inputSchema` is a **raw Zod shape** (`{ field: z.string() }`), not `z.object(...)`. The in-flux v2 (`@modelcontextprotocol/server`) is a different package — do not mix them.
- ESM throughout (`"type": "module"`, `NodeNext`). Relative imports must include the `.js` extension.
- Relies on Node 18+ built-ins (`fetch`, `FormData`, `Blob`) — no HTTP or polyfill deps.

## Scope (intentional limits)

Targets the **free public API** (4 req/min, 500/day). File uploads cap at 32 MB (`scan_file` rejects larger — the `upload_url` flow is not implemented). VT Intelligence search, relationships, comments, and Livehunt (premium) are out of scope.

# virustotal-mcp

An [MCP](https://modelcontextprotocol.io) server that exposes [VirusTotal](https://www.virustotal.com)
lookups and scan submissions as tools for Claude Code (and any MCP client).

Built for the **free / public VirusTotal API** (4 requests/min, 500/day). The server
applies a small client-side throttle and turns rate-limit / auth / not-found errors
into clear messages instead of crashing.

## Tools

| Tool | Purpose |
| --- | --- |
| `get_file_report` | Look up a file by hash (MD5 / SHA-1 / SHA-256) |
| `get_url_report` | Look up an existing report for a URL |
| `get_domain_report` | Look up a domain's reputation and categories |
| `get_ip_report` | Look up an IP address's reputation and AS owner |
| `scan_url` | Submit a URL for a fresh scan (waits for the verdict by default) |
| `scan_file` | Upload a local file (≤ 32 MB) for scanning |
| `get_analysis` | Fetch the result of a prior submission by analysis id |

Each tool returns a compact summary — detection counts (e.g. `12/70 engines flagged
malicious`), reputation, notable engine verdicts, and a VirusTotal permalink — rather
than the full API JSON, to keep responses small.

## Setup

```bash
npm install
npm run build
```

Get a free API key from <https://www.virustotal.com/gui/my-apikey>.

## Add to Claude Code

```bash
claude mcp add virustotal -e VT_API_KEY=your_key_here -- node /absolute/path/to/virustotal-mcp/dist/index.js
```

On Windows the path looks like `node D:/WORK/GITHUB/virustotal-mcp/dist/index.js`.

Or add it manually to your MCP config (`.mcp.json` in a project, or the Claude Code
user config):

```json
{
  "mcpServers": {
    "virustotal": {
      "command": "node",
      "args": ["D:/WORK/GITHUB/virustotal-mcp/dist/index.js"],
      "env": { "VT_API_KEY": "your_key_here" }
    }
  }
}
```

Then start a session and ask, e.g. *"Check this hash on VirusTotal: <sha256>"*.

## Development

```bash
npm run dev      # run from source with tsx (set VT_API_KEY in your env)
```

Inspect tools interactively without Claude:

```bash
npx @modelcontextprotocol/inspector node dist/index.js
```

Known-good fixtures for a smoke test:

- `get_file_report` with the EICAR test file SHA-256
  `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` → many malicious detections.
- `get_domain_report` with `google.com` → mostly harmless.

## Limitations (v1)

- Files larger than 32 MB (requires the VirusTotal `upload_url` flow) are not supported.
- VT Intelligence search, relationships, comments, and Livehunt (premium API) are out of scope.

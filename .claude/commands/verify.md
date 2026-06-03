---
description: End-to-end smoke test — build, then confirm the MCP server registers its tools over stdio
allowed-tools: Bash(npm run build), Bash(node dist/index.js:*)
---

Verify the VirusTotal MCP server end-to-end:

1. Run `npm run build` so `dist/` is current.
2. Pipe the MCP handshake + `tools/list` into the compiled server and confirm the
   expected tools register (no real API key needed for `tools/list`):

   ```bash
   printf '%s\n' \
     '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
     '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
     '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
     | VT_API_KEY=dummy node dist/index.js 2>/dev/null
   ```

3. Report which tools registered. If the list looks wrong or the server errors, dig in.

For a live check the user can run manually (needs a real `VT_API_KEY`):
`npx @modelcontextprotocol/inspector node dist/index.js` — fixtures: EICAR SHA-256
`275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` (many malicious),
domain `google.com` (mostly harmless).

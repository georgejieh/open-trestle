# MCP stdio server

`trestle mcp` exposes a deliberately narrow Model Context Protocol server for coding assistants and other MCP hosts. It uses the same authenticated daemon client and canonical review-run contracts as the CLI.

```sh
export OPEN_TRESTLE_API_URL=http://127.0.0.1:8741
export OPEN_TRESTLE_API_TOKEN="replace-with-a-random-secret-of-at-least-32-bytes"
trestle mcp
```

The process reads newline-delimited UTF-8 JSON-RPC messages from standard input and writes only JSON-RPC messages to standard output. Diagnostics go to standard error. Input is bounded to 1 MiB per line. Redirects and remote plaintext daemon URLs remain forbidden by the shared client.

The server implements the stateless MCP `2026-07-28` request model. Each request must declare `io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities` in `_meta`. `server/discover` reports the exact supported version and tool capability. Unsupported versions return the standard `-32022` error with the supported version list.

Current tools are deterministic and JSON-Schema described:

- `open_trestle.run_status` reads one secret-free run receipt. It is read-only, idempotent, and closed-world.
- `open_trestle.submit_run` submits canonical plan JSON that an authorized planner already produced. Repeating the exact plan is idempotent. Submission cannot weaken policy or directly authorize publication.

The server does not expose credentials, raw lease capabilities, source files, arbitrary filesystem reads, shell execution, policy mutation, provider selection overrides, or publication. Repository strings and returned receipt text remain untrusted data. Tool annotations are hints for host confirmation and never replace daemon authorization.

The implementation follows the MCP `2026-07-28` specification and TypeScript schema inspected from these primary sources:

- https://modelcontextprotocol.io/specification/2026-07-28
- https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio
- https://modelcontextprotocol.io/specification/2026-07-28/server/tools
- https://github.com/modelcontextprotocol/specification/blob/main/schema/2026-07-28/schema.ts

Only the modern stateless protocol is claimed. Legacy initialize-session behavior is not silently inferred.

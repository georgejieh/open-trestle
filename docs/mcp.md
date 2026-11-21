# MCP stdio server

`trestle mcp` is a Model Context Protocol server that lets coding assistants and other MCP hosts read and submit Open Trestle review runs. It talks to the daemon through the same authenticated client and review-run contracts as the CLI.

```sh
export OPEN_TRESTLE_API_URL=http://127.0.0.1:8741
export OPEN_TRESTLE_API_TOKEN="replace-with-a-random-secret-of-at-least-32-bytes"
trestle mcp
```

## Transport

The process reads newline-delimited UTF-8 JSON-RPC messages from standard input and writes only JSON-RPC messages to standard output. Diagnostics go to standard error. Input is limited to 1 MiB per line.

Text that is not JSON receives `-32700` with a null id. Valid JSON that is not a valid request receives `-32600`. That reply uses the request's own id when the request carries a well-formed one, so a client never waits on a reply that it cannot match to its request. The shared client still forbids redirects and plaintext daemon URLs that are not local.

## Protocol version

The server implements the stateless MCP `2026-07-28` request model. Each request must declare `io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities` in `_meta`. `server/discover` reports the supported version and the tool capability. An unsupported version gets the standard `-32022` error with the list of supported versions.

Only the modern stateless protocol is supported. The server does not guess at the behavior of the older initialize-session protocol.

## Tools

The server offers two tools. Both are described by JSON Schema. Both return the canonical run receipt as structured content, and their output schemas accept receipt versions 1, 2 and 3.

`open_trestle.run_status` reads one run receipt, which contains no secrets. It is read-only, idempotent and closed-world. If the daemon answers that the run was not found because intake refused the scope's webhook delivery, the tool returns an error result. That result names the fixed reason and its explanation and includes the `open-trestle/webhook-delivery-refusal` record, which has no content, instead of a bare read failure. Any other read failure returns `The review run could not be read.`

`open_trestle.submit_run` submits canonical plan JSON that an authorized planner has already produced. Submitting the same plan again is idempotent. Submission cannot weaken policy or authorize publication directly.

The server does not expose credentials, raw lease capabilities, source files, arbitrary filesystem reads, shell execution, policy changes, provider selection overrides or publication. Repository strings and the receipt text it returns are treated as data; see the [prompt-injection boundary](prompt-injection-boundary.md). Tool annotations are hints that help a host ask for confirmation. They do not replace the daemon's own authorization.

The implementation follows the [MCP `2026-07-28` specification](https://modelcontextprotocol.io/specification/2026-07-28).

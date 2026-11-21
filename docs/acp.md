# Read-only ACP review agent

`trestle acp` lets an editor that supports Agent Client Protocol v1 show one existing Open Trestle review run. It only observes a run that the daemon already has, so it cannot start a review.

```sh
export OPEN_TRESTLE_API_TOKEN="replace-with-the-daemon-credential"
trestle acp \
  --tenant example \
  --repository repository \
  --run run-123 \
  --server http://127.0.0.1:8741
```

## Protocol

The process implements ACP v1 initialization, `session/new`, `session/prompt`, `session/update` and `session/cancel` over newline-delimited JSON-RPC on standard input and output. Messages are limited to 1 MiB, and standard output carries only protocol messages. If a client requests a protocol version above 1, the agent answers with version 1, as ACP negotiation requires. Only a missing or zero version is rejected.

The agent advertises no filesystem, terminal, remote MCP, image, audio, embedded-context, session-load or authentication-flow capabilities. Prompts may contain text and resource-link blocks, because ACP requires those baseline forms. The agent displays them. It does not fetch a link or read text as a command.

## Sessions

Each process is bound to the tenant, repository and run given when it is launched. Session IDs are cryptographically random and exist only within the process. At most 64 sessions can exist at once.

Open Trestle validates and accepts a prompt before it starts a worker. At most eight prompts can be active at once, and only one per session. Each prompt holds its place until its output is complete. An invalid, duplicate or excess request does not start a worker. If the output stream stalls, the agent applies backpressure instead of piling up workers.

Creating a session requires an absolute, clean working directory, which the agent does not read. It rejects additional directories and MCP servers supplied by the client.

## What a prompt returns

A prompt returns the current run receipt, which contains no secrets, and the canonical diagnostic set when one is available. If the daemon answers that the run was not found because intake refused the scope's webhook delivery, the agent returns the fixed reason, its explanation and the refusal record, which has no content. Any other read failure still returns `Review status is unavailable.`

The label on the diagnostics depends on the diagnostic-set version:

- Versions 1 through 5 and 8 are labeled `Verified diagnostics`. For version 8 the message also says how many findings are on removed base lines, whose lines are base-revision lines, not head lines.
- Version 6 is labeled `Deterministic review observations`. It is not described as verified.
- Version 7 is labeled `Final review diagnostics` and states the terminal outcome. A failed result that records a context route refusal adds a `Context refusal` line. For `route_context_insufficient` it also adds a `Hint` line, with the same text as the local review.
- A result recorded after its evidence expired adds an `Evidence expired` line.

Notices for omitted content, which are aware of the schema, preserve the same distinction.

The agent sends one `agent_message_chunk` followed by `stopReason: end_turn`. The size limit counts JSON-string escaping and newline framing. If the diagnostic set does not fit, the response keeps the receipt and adds an explicit notice that diagnostics were omitted. It does not truncate the canonical diagnostics. If the client cancels while the run or the diagnostics are being retrieved, the agent returns `stopReason: cancelled` without a normal state update.

The returned review text is labeled as untrusted. The adapter cannot edit files, run commands, request hidden permissions, change policy, select a provider, obtain worker leases or publish review output.

## Sources

The implementation follows the ACP v1 schema and these references:

- https://agentclientprotocol.com/protocol/v1/overview
- https://agentclientprotocol.com/protocol/v1/schema
- https://agentclientprotocol.com/protocol/v1/transports
- https://github.com/agentclientprotocol/agent-client-protocol/releases/latest/download/schema.json

The adapter does not claim any ACP v2 draft capability.

# Read-only ACP review agent

`trestle acp` exposes one exact Open Trestle review run to editors that support Agent Client Protocol v1. It is an interoperability adapter, not a privileged coding agent.

```sh
export OPEN_TRESTLE_API_TOKEN="replace-with-the-daemon-credential"
trestle acp \
  --tenant example \
  --repository repository \
  --run run-123 \
  --server http://127.0.0.1:8741
```

The process implements ACP v1 initialization, `session/new`, `session/prompt`, `session/update`, and `session/cancel` over newline-delimited JSON-RPC stdio. Messages are bounded to 1 MiB. Standard output contains protocol messages only.

Each process is bound to the tenant, repository, and run from its launch configuration. Sessions are cryptographically random, process-local, and capped at 64. Prompt requests are validated and admitted before a worker starts. At most eight prompts may be active, with one per session; their admission remains held until output completes. Invalid, duplicate, or excess requests create no prompt worker. A stalled output stream applies bounded backpressure rather than accumulating workers. Session creation requires an absolute clean working directory but never reads it. Additional directories and client-provided MCP servers are rejected.

The agent advertises no filesystem, terminal, remote MCP, image, audio, embedded-context, session-load, or authentication-flow capabilities. Prompt input supports bounded text and resource-link blocks because ACP requires those baseline forms, but it treats them as untrusted display input and does not fetch a link or interpret text as authority.

A prompt returns the current secret-free run receipt and, when available, the independently verified diagnostic set. It sends one `agent_message_chunk` followed by `stopReason: end_turn`. The size limit includes JSON-string escaping and newline framing. If the diagnostic set cannot fit, the response retains the receipt and an explicit omission notice rather than truncating canonical diagnostics. Cancellation during either run or diagnostic retrieval returns `stopReason: cancelled` without a normal state update. Returned review text is explicitly labeled untrusted. The adapter cannot edit files, run commands, request hidden permissions, change policy, select a provider, obtain worker leases, or publish review output.

The implementation was checked against the current ACP v1 schema and these primary references:

- https://agentclientprotocol.com/protocol/v1/overview
- https://agentclientprotocol.com/protocol/v1/schema
- https://agentclientprotocol.com/protocol/v1/transports
- https://github.com/agentclientprotocol/agent-client-protocol/releases/latest/download/schema.json

No ACP v2 draft capability is claimed.

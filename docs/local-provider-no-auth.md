# Local inference without bearer authentication

Runtime policy schema v2 supports `credential_mode: "none"` for an approved `local` route whose endpoint is canonical numeric loopback. This works with `openai_responses` and `openai_chat_completions`.

A connection can use:

```json
{
  "implementation": "openai_chat_completions",
  "adapter_id": "local-chat",
  "endpoint": "http://127.0.0.1:1234/v1",
  "credential_mode": "none"
}
```

Do not include `credential_environment`, even as an empty string or null. No key, placeholder or environment reference is needed. Trestle does not resolve credentials or send an Authorization header for this connection. A matching approved local inventory namespace is still required. Schema v2 also requires its explicit independent verification route grant. Use the existing protected runtime policy and route inventory arguments to `trestle local-git model-review`.

Omitting `credential_mode` preserves bearer authentication and requires the existing credential environment. Schema v2 also accepts explicit `"bearer"` without changing that connection's identity. Schema v1 does not accept `credential_mode`.

`none` is rejected for remote endpoints, remote route zones, hostname loopback such as `localhost`, or conflicting credential authority. It does not approve a route, weaken sanitization or logging policy, change model-discovery credentials, or establish that a local server cannot forward content elsewhere. Keep independent route approval and runtime evidence current.

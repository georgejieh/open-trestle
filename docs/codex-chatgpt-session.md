# Codex ChatGPT session status

`trestle config codex-session status` reports the disabled
`codex_chatgpt_session_v1` profile. This is an observational command: it does not
read credentials, start sign-in, register a client, open a browser, contact a
provider, or admit a review. Exit 0 means the status was written, not that the
profile is available. Extra arguments and login operations are refused.

The JSON result uses `open-trestle/codex-chatgpt-session-status`, schema version 1:

```json
{
  "contract": "open-trestle/codex-chatgpt-session-status",
  "schema_version": 1,
  "status": "blocked",
  "profile": "codex_chatgpt_session_v1",
  "runtime_available": false,
  "privacy_exception": "non-zdr",
  "blocker": "hard_output_bound_unavailable",
  "reason": "ChatGPT-plan Responses preview does not support max_output_tokens; hard output and spend admission unavailable",
  "limitations": [
    "Status inspection does not authenticate an account or qualify a provider.",
    "No token exchange, session persistence, or model dispatch is implemented.",
    "Hard output and spend admission remains unavailable; client cancellation is not a server billing bound."
  ]
}
```

## Exact upstream capability blocker

Current official [Sign in with ChatGPT preview limitations][limitations] require
HTTP inference with `store: false` and `stream: true`. The exact unsupported-fields
list includes `max_output_tokens`. Open Trestle must not silently omit its hard
output-token and per-request spend controls to enable this profile. A client
byte limit, deadline, or canceled connection does not establish that the server
stopped generation or billing. Runtime admission always refuses, including after
a successful hypothetical sign-in. This is not a missing API key.

The official [models and inference guide][inference] documents the public
`POST https://api.openai.com/v1/responses` endpoint for OAuth tokens authorized
for ChatGPT plan use. It explicitly says not to use ChatGPT `backend-api`
endpoints. These tokens would come from Open Trestle's own explicit OAuth flow,
not an existing Codex credential cache. This implementation does not exchange
codes, verify tokens, write credentials, or send inference.

## App-server is not a tool-free substitute

The official [app-server interface][app-server] supports managed ChatGPT login,
login cancellation and logout, plus Codex thread/turn agent execution. It says:
"App-server authentication has never been permitted for commercial or hosted
services." It permits existing local/open-source use and recommends SIWC.
It also says the app-server command and WebSocket transport are experimental
and unsupported for production workloads. No production-stability claim is made.

The inspected [ThreadStartParams][thread] and [TurnStartParams][turn] expose no
universal empty tool allowlist. An empty dynamic-tools array, read-only sandbox,
approval refusal, or "do not use tools" prompt is not tool-free enforcement.
The internal [ToolPolicy][tool-policy] does permit an empty allowed-tools list,
but is supplied through Rust `ExtensionDataInit`, not the inspected RPC surface.
Open Trestle does not start or impersonate an app-server client, execute its
review agent, extract tokens, replay browser sessions or invent a backend route.

## Offline authorization boundary

The `adapters/providers/codexsession` package prepares one in-memory authorization
attempt using the [official registration and sign-in fields][sign-in]. It opens
no listener or browser. The caller must first establish its approved callback
listener and provide a persisted UUIDv4 host ID. Only numeric loopback HTTP at
`/auth/callback` with an explicit canonical port is accepted. This implementation
uses the documented UUID host-ID option, not the other optional host-ID formats.

Initial registration requests the actual app name `Open Trestle`,
`dynamic_agent_client`, fresh random state/nonce, S256 PKCE, the documented
identity/plan scopes, and the fixed official resource. Returning authorization
uses the saved issued client ID. The prepared browser URL contains sensitive
attempt state and must never be logged or opened without explicit user intent.

A callback must match its pending state, lifetime and client registration.
Cancellation or expiry invalidates the local attempt; late callbacks cannot
reactivate it. A callback produces only a redacted code-exchange plan, never an
authenticated session. Its explicit form/nonce accessors contain secrets for a
future approved OAuth client and must not feed diagnostics. Code exchange, OIDC
verification, protected credential writes and session activation are absent.

The proposed protected record contract for such a future client is:

- A separate record per issued client ID and verified issuer/subject identity.
  Email alone does not identify a workspace registration.
- Persist the host ID independently of sign-out and process restart. Keep a
  pending attempt separate from the previously active registration.
- Verify ID-token signature via official JWKS, issuer, audience, expiry, nonce
  and returning identity before replacing credentials. Require the token
  response's granted `chatgpt.tokens.use.direct` scope before plan inference.
- Keep access, refresh and retained ID tokens in app-owned protected storage,
  using the existing file-authority boundary, atomic writes and owner-only
  permissions. No token-cache discovery/import, browser storage or secret logs.
- Serialize rotating refreshes and replace tokens, expiry and scopes together.
  Stop requests before sign-out; attempt renewable-session revocation via the
  official discovery document's endpoint, then clear local tokens. Report
  unconfirmed remote revocation honestly. Retain the account/client mapping.

The official [accounts and sessions guide][sessions] defines those lifecycle
requirements. They are not implemented or qualified by this offline package.
No caller may treat a code-exchange plan or arbitrary JWT as a verified session.

## Error and cancellation contract

The package classifies documented [SIWC error codes][errors] without retaining
provider messages or credentials. Usage-limit failures pause plan requests;
temporary availability permits later bounded retry; unsupported capabilities
require a request correction; ineligible users remain unavailable. Terminal
refresh-token errors require reauthorization. Apply `invalid_grant` to refresh
failure only; for code exchange it requires a fresh authorization attempt.
Unknown codes stop. There is no automatic API-key/provider/billing fallback.

A future stream path would require `response.completed`; partial text,
`response.failed`, `response.incomplete`, EOF and canceled HTTP contexts are not
successful reviews. Client cancellation would not claim remote rollback,
quiescence or zero billing. No live stream adapter is exposed by this profile.

## Non-ZDR exception

The disabled profile is explicitly `non-zdr`. `store: false` does not prove
retention, training or privacy posture. The [Codex authentication guide][auth]
distinguishes ChatGPT workspace policies from API-organization settings. This
profile cannot inherit an API-key ZDR assertion from the API hostname. Any future
admission requires explicit repository/account/privacy approval and the existing
sanitization, dispatch-proof, model-independence and budget controls. Sign-in
alone grants no source egress or publication authority.

The offline tests cover fixed auth fields, callback binding, PKCE, cancel/expiry,
redaction, documented error classification and unconditional capability refusal.
They do not qualify OAuth deployment, accounts, models, privacy or billing.

[limitations]: https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations
[inference]: https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference
[sign-in]: https://developers.openai.com/siwc/token-sharing-open-source/sign-in
[sessions]: https://developers.openai.com/siwc/token-sharing-open-source/profiles-and-sessions
[errors]: https://developers.openai.com/siwc/token-sharing-open-source/errors-and-recovery
[app-server]: https://learn.chatgpt.com/docs/app-server
[auth]: https://learn.chatgpt.com/docs/auth
[thread]: https://github.com/openai/codex/blob/67f0994b532b8740f14b5b738af7b7b2a915b1d6/codex-rs/app-server-protocol/src/protocol/v2/thread.rs
[turn]: https://github.com/openai/codex/blob/67f0994b532b8740f14b5b738af7b7b2a915b1d6/codex-rs/app-server-protocol/src/protocol/v2/turn.rs
[tool-policy]: https://github.com/openai/codex/blob/67f0994b532b8740f14b5b738af7b7b2a915b1d6/codex-rs/ext/extension-api/src/tool_policy.rs

# Codex ChatGPT session status

`trestle config codex-session status` reports the state of the `codex_chatgpt_session_v1` profile, which is disabled. The command only observes. It does not read credentials, start a sign-in, register a client, open a browser, contact a provider or accept a review. Exit code 0 means the status was written, not that the profile is available. The command refuses extra arguments and login operations.

The result is JSON of type `open-trestle/codex-chatgpt-session-status`, schema version 1:

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

## Why the profile is blocked

The current official [Sign in with ChatGPT preview limitations][limitations] require HTTP inference with `store: false` and `stream: true`. The list of unsupported fields includes `max_output_tokens`. Open Trestle will not quietly drop its hard output-token limit and its per-request spend limit to enable this profile.

A byte limit on the client, a deadline or a canceled connection does not prove that the server stopped generating or billing. For that reason the runtime always refuses this profile, even after a hypothetical successful sign-in. The blocker is not a missing API key.

The official [models and inference guide][inference] documents the public `POST https://api.openai.com/v1/responses` endpoint for OAuth tokens that are authorized for ChatGPT plan use. It says not to use the ChatGPT `backend-api` endpoints. Those tokens would come from Open Trestle's own explicit OAuth flow, not from an existing Codex credential cache. This implementation does not exchange codes, verify tokens, write credentials or send inference requests.

## The app-server is not a tool-free alternative

The official [app-server interface][app-server] supports managed ChatGPT login, login cancellation and logout, and it runs Codex thread and turn agent execution. It states: "App-server authentication has never been permitted for commercial or hosted services." It permits existing local and open-source use, and it recommends Sign in with ChatGPT (SIWC). It also says that the app-server command and its WebSocket transport are experimental and unsupported for production workloads. Open Trestle makes no claim that they are stable for production.

The [ThreadStartParams][thread] and [TurnStartParams][turn] that were inspected offer no universal empty tool allowlist. None of the following enforces a tool-free session: an empty dynamic-tools array, a read-only sandbox, refusing approvals, or a prompt that says "do not use tools". The internal [ToolPolicy][tool-policy] does allow an empty allowed-tools list, but a caller supplies it through the Rust `ExtensionDataInit`, not through the RPC surface that was inspected.

Open Trestle does not start or impersonate an app-server client, run its review agent, extract tokens, replay browser sessions or invent a backend route.

## Offline authorization boundary

The `adapters/providers/codexsession` package prepares one in-memory authorization attempt, using the [official registration and sign-in fields][sign-in]. It opens no listener and no browser.

The caller must first set up its own approved callback listener and provide a persisted UUIDv4 host ID. The package accepts only numeric loopback HTTP at `/auth/callback` with an explicit canonical port. It uses the documented UUID host-ID option and none of the other optional host-ID formats.

A first registration requests these values:

- the actual app name `Open Trestle`
- `dynamic_agent_client`
- a fresh random state and nonce
- S256 PKCE
- the documented identity and plan scopes
- the fixed official resource

A returning authorization uses the client ID that was issued and saved earlier. The prepared browser URL contains sensitive attempt state. Never log it, and never open it unless the user explicitly intends to.

A callback must match its pending state, its lifetime and its client registration. Cancellation or expiry invalidates the local attempt, and a late callback cannot reactivate it. A callback produces only a redacted code-exchange plan, never an authenticated session. The explicit form and nonce accessors on that plan contain secrets meant for a future approved OAuth client, and they must not feed diagnostics. Code exchange, OIDC verification, protected credential writes and session activation do not exist yet.

### Proposed record contract for a future client

If a future client is built, its protected records should follow these rules:

- Keep a separate record for each issued client ID and verified issuer and subject identity. An email address alone does not identify a workspace registration.
- Persist the host ID independently of sign-out and process restarts. Keep a pending attempt separate from the previously active registration.
- Before replacing credentials, verify the ID-token signature against the official JWKS, and verify the issuer, audience, expiry, nonce and returning identity. Require the `chatgpt.tokens.use.direct` scope in the token response before any plan inference.
- Keep access, refresh and retained ID tokens in protected storage that the app owns. Use the existing file-authority boundary, atomic writes and owner-only permissions. Do not discover or import token caches, use browser storage, or write secrets to logs.
- Serialize rotating refreshes, and replace tokens, expiry and scopes together.
- Stop requests before sign-out. Then try to revoke a renewable session through the endpoint in the official discovery document, and clear the local tokens. Report honestly when remote revocation is unconfirmed. Keep the account and client mapping.

The official [accounts and sessions guide][sessions] defines these lifecycle requirements. This offline package neither implements nor qualifies them. No caller may treat a code-exchange plan or an arbitrary JWT as a verified session.

## Error and cancellation contract

The package classifies the documented [SIWC error codes][errors] without keeping provider messages or credentials. The classes behave as follows:

- Usage-limit failures pause plan requests.
- Temporary unavailability allows a later, bounded retry.
- Unsupported capabilities require a corrected request.
- Ineligible users stay unavailable.
- Terminal refresh-token errors require a new authorization.
- `invalid_grant` applies to a refresh failure only. For a code exchange it requires a fresh authorization attempt.
- Unknown codes stop the flow.

There is no automatic fallback to an API key, another provider or other billing.

A future stream path would require `response.completed`. Partial text, `response.failed`, `response.incomplete`, EOF and canceled HTTP contexts are not successful reviews. Client cancellation would not claim a remote rollback, quiescence or zero billing. This profile exposes no live stream adapter.

## Non-ZDR exception

The disabled profile is explicitly `non-zdr`, meaning it does not claim zero data retention. `store: false` does not prove anything about retention, training or privacy. The [Codex authentication guide][auth] distinguishes ChatGPT workspace policies from API-organization settings, so this profile cannot inherit an API-key zero-data-retention assertion from the API hostname.

Any future admission would need explicit repository, account and privacy approval, together with the existing sanitization, dispatch-proof, model-independence and budget controls. Signing in alone grants no authority to send source code or to publish.

The offline tests cover the fixed auth fields, callback binding, PKCE, cancellation and expiry, redaction, classification of the documented errors, and the unconditional capability refusal. They do not qualify an OAuth deployment, accounts, models, privacy or billing.

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

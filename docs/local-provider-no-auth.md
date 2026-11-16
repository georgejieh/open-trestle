# Local inference without bearer authentication

Some local model servers do not need an API key. Runtime policy schema v2 lets you declare that with `credential_mode: "none"` on a connection. It applies to an approved `local` route whose endpoint is a canonical numeric loopback address, and it works with the `openai_responses` and `openai_chat_completions` implementations.

## How to configure it

A connection that uses no authentication looks like this:

```json
{
  "implementation": "openai_chat_completions",
  "adapter_id": "local-chat",
  "endpoint": "http://127.0.0.1:1234/v1",
  "credential_mode": "none"
}
```

Do not include `credential_environment`, even as an empty string or null. No key, placeholder or environment reference is needed. Open Trestle does not resolve credentials or send an Authorization header for this connection.

Two other things are still required. The inventory must contain a matching approved `local` namespace, and schema v2 requires its explicit grant for an independent verification route. Pass the protected runtime policy and route inventory to `trestle local-git model-review` as usual.

If you omit `credential_mode`, the connection keeps bearer authentication and still requires its credential environment. Schema v2 also accepts an explicit `"bearer"`, which does not change that connection's identity. Schema v1 does not accept `credential_mode`.

## Where `none` is refused

Open Trestle rejects `none` for any of these:

- a remote endpoint
- a remote route zone
- a loopback hostname, such as `localhost`
- a connection with conflicting credential authority

## What `none` does not do

Setting `none` does not approve a route. It does not weaken sanitization or logging policy, and it does not change the credentials used for model discovery. It also cannot show that a local server will not forward content elsewhere. Keep the independent route approval and the runtime evidence current.

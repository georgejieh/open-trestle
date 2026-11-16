# Runtime configuration validation

`trestle config validate` checks a route inventory and its runtime policy offline, before you start the daemon (`trestled`). Run it whenever you write or change either file.

```text
trestle config validate --route-inventory inventory.json --runtime-policy policy.json
```

On success the command prints one JSON object of type `open-trestle/runtime-configuration-validation-result` (version 1). It contains the contract and schema fields, a `status` of `valid`, the identities of the inventory, the runtime policy and the review policy, and the route and connection counts. The strict public shape is `schemas/runtime/configuration-validation-result-v1.schema.json`.

The command does not read provider credentials, contact provider endpoints, open source repositories, or grant publication authority. It exits with code 1 when validation fails and with code 2 when the command is used incorrectly.

## What the command checks

The validator uses the same size-bounded decoders as `trestled`. It checks that the runtime policy is bound to the identity of the decoded inventory. It checks route evidence manifests and then discards them. It validates credential environment names but never prints them.

A runtime policy is accepted only when each adapter ID maps to one unambiguous route namespace across the inventory. The namespace is made up of the zone, provider, connection and content-logging authority. Several models may share one namespace. If one adapter ID has different provider, connection, zone or logging declarations, the policy is rejected before the daemon or setup is built.

Each connection endpoint must also match the zone its adapter supports: a numeric loopback address for `local`, and a non-loopback HTTPS address for `private_remote`. Conventional localhost names and non-unicast numeric addresses are rejected.

Setup validation adds more checks: profile posture, route readiness, budget, explicit approval and independent verification.

## What the command does not check

Validation confirms that the files are well formed and that their identities match. It does not establish any of the following:

- That a route is healthy right now.
- That a route has been approved.
- That the generation model and verifier model you selected satisfy the independence requirement. Use `config bind` to check that pair offline. Startup and dispatch also check eligibility on their own.

Publication policy is enforced separately. It may require stronger independence than an advisory review needs.

## Stricter checks at daemon startup

`trestled` adds filesystem checks that `config validate` does not make. Every runtime file you give it must be a regular file, not a symlink, and must not be writable by the group or by others.

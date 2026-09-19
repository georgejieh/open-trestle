# Runtime configuration validation

Use the CLI to validate a route inventory and its exact runtime policy before daemon startup:

```text
trestle config validate --route-inventory inventory.json --runtime-policy policy.json
```

Success prints one `open-trestle/runtime-configuration-validation-result` version 1 JSON object containing only its contract and schema discriminators, the inventory, runtime-policy, and review-policy identities, and route and connection counts. The strict public shape is `schemas/runtime/configuration-validation-result-v1.schema.json`. It does not resolve or read provider credentials, contact provider endpoints, open source repositories, or grant publication authority. Failure returns exit code 1. Invalid command usage returns exit code 2.

The validator applies the same bounded decoders used by `trestled`. The runtime policy must bind the decoded inventory identity. Route evidence manifests are checked and discarded. Credential environment names are validated but are not printed in the result.

Daemon startup adds stricter filesystem authority checks. Runtime files supplied to `trestled` must be non-symlinked regular files that are not group- or world-writable.

A runtime policy is decoded only when each adapter ID maps to one unambiguous route namespace across the bound inventory. The namespace includes zone, provider, connection, and content-logging authority. Multiple models may share it. Divergent provider, connection, zone, or logging declarations under one adapter ID are rejected before daemon or setup construction. Connection endpoints must also match the adapter-supported zone: numeric loopback for `local` and non-loopback HTTPS for `private_remote`. Conventional localhost names and non-unicast numeric addresses are rejected. Setup validation adds profile posture, route readiness, budget, explicit approval, and independent-verification checks.

# Read-only LSP diagnostics

`trestle lsp` exposes independently verified findings from diagnostic-set versions 1 through 5 and the verified portion of final version 7 through the Language Server Protocol 3.17 pull-diagnostic interface. Version 6 deterministic observations are not verified findings and therefore produce an empty LSP item list with the exact diagnostic-set result identity. A final version 7 without verified findings also returns an empty list, not repository clearance. Candidate model output cannot enter this interface directly.

For live daemon-backed retrieval:

```sh
export OPEN_TRESTLE_API_TOKEN="replace-with-the-daemon-credential"
trestle lsp --server http://127.0.0.1:8741
```

For an immutable offline export:

```sh
trestle lsp --diagnostics verified-diagnostics.json
```

The server uses standard `Content-Length` framing and writes only protocol messages to standard output. Headers are bounded to 8 KiB and message bodies to 1 MiB. It advertises UTF-16 positions, no document synchronization, no workspace diagnostics, and no code actions or write operations.

Initialization options bind the process to one exact review scope:

```json
{
  "tenant_id": "example",
  "repository_id": "repository",
  "review_run_id": "run-123"
}
```

The `rootUri` must be a file URI. Diagnostic requests outside that root are rejected. Findings use one-based physical review lines converted to zero-based whole-line LSP ranges. Each diagnostic contains its stable fingerprint, verified finding identity, evidence references, diagnostic-set identity, reviewed snapshot identity, and exact head revision. For final version 7 findings, `data.snapshot_identity` is the selected review snapshot, not the separate physical-head snapshot. The result identity remains the final diagnostic-set identity. Messages explicitly label review output as untrusted and require verification before editing.

Clients can send `previousResultId`. An exact set identity returns an unchanged report. A new identity returns a complete report, including an empty list when the verified set has no findings.

The public transport contracts are `schemas/diagnostics/verified-diagnostic-set-v1.schema.json` through `schemas/diagnostics/verified-diagnostic-set-v5.schema.json` plus `schemas/diagnostics/deterministic-diagnostic-set-v6.schema.json` and `schemas/diagnostics/full-review-diagnostic-set-v7.schema.json`. Version 2 adds exact candidate outcomes. Version 3 adds the validated verification-context identity and bounded source counts. Version 4 adds sorted content-free aggregate omission reasons. Version 5 adds one exact deterministic check bound to its source check, analysis result, and change. Version 6 replaces the verified-finding fields with an analysis-result identity and exact deterministic observations. The internal review adapter creates versions 1 through 5 only when the independent verification receipt, verified finding set, snapshot, and review scope all match. The deterministic analysis path creates version 6 without independent-verification authority. Final version 7 preserves the terminal outcome and any exact verified portion; the LSP item list contains only that portion.

The daemon keeps one immutable diagnostic set per exact review scope in a private crash-safe store. The authenticated API exposes only retrieval. It has no public diagnostic upload endpoint, so unverified callers cannot place arbitrary findings into editor output. The local export mode remains available for air-gapped use. Push refresh notifications remain separate work; editors obtain updates through standard pull requests and result identities.

Primary reference:

- https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_diagnostic

The packaged [VS Code extension](vscode.md) uses this live daemon-backed mode, machine-scoped settings, SecretStorage, a bounded child environment, and a client-side pull-only diagnostic gate.

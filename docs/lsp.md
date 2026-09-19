# Read-only LSP diagnostics

`trestle lsp` exposes independently verified findings through the Language Server Protocol 3.17 pull-diagnostic interface. Candidate model output cannot enter this interface directly.

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

The `rootUri` must be a file URI. Diagnostic requests outside that root are rejected. Findings use one-based physical review lines converted to zero-based whole-line LSP ranges. Each diagnostic contains its stable fingerprint, verified finding identity, evidence references, diagnostic-set identity, reviewed snapshot identity, and exact head revision. Messages explicitly label review output as untrusted and require verification before editing.

Clients can send `previousResultId`. An exact set identity returns an unchanged report. A new identity returns a complete report, including an empty list when the verified set has no findings.

The public transport contracts are `schemas/diagnostics/verified-diagnostic-set-v1.schema.json` through `schemas/diagnostics/verified-diagnostic-set-v5.schema.json`. Version 2 adds exact candidate outcomes. Version 3 adds the validated verification-context identity and bounded source counts. Version 4 adds sorted content-free aggregate omission reasons. Version 5 adds one exact deterministic check bound to its source check, analysis result, and change. Versions 1 through 4 remain accepted without inventing newer evidence. The internal review adapter creates diagnostics only when the independent verification receipt, verified finding set, snapshot, and review scope all match.

The daemon keeps one immutable diagnostic set per exact review scope in a private crash-safe store. The authenticated API exposes only retrieval. It has no public diagnostic upload endpoint, so unverified callers cannot place arbitrary findings into editor output. The local export mode remains available for air-gapped use. Push refresh notifications remain separate work; editors obtain updates through standard pull requests and result identities.

Primary reference:

- https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_diagnostic

The packaged [VS Code extension](vscode.md) uses this live daemon-backed mode, machine-scoped settings, SecretStorage, a bounded child environment, and a client-side pull-only diagnostic gate.

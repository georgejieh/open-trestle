# Read-only LSP diagnostics

`trestle lsp` is a Language Server Protocol 3.17 server that shows Open Trestle's verified review findings as diagnostics in an editor. It is read-only: it cannot start a review, edit files or publish anything. It serves the findings of reviews that already exist, through the pull-diagnostic interface of the protocol.

The server returns only verified findings, and it handles each diagnostic-set version as follows:

- Versions 1 through 5 return their verified findings.
- Version 6 holds deterministic observations, which are not verified findings. They produce an empty list of items, with the result identity of the diagnostic set.
- Final version 7 returns the verified portion of its findings. A final version 7 with no verified findings also returns an empty list. That is not a clean bill of health for the repository.

To fetch diagnostics from a running daemon:

```sh
export OPEN_TRESTLE_API_TOKEN="replace-with-the-daemon-credential"
trestle lsp --server http://127.0.0.1:8741
```

To read an exported, unchanging file instead, with no daemon:

```sh
trestle lsp --diagnostics verified-diagnostics.json
```

## Protocol behavior

The server uses standard `Content-Length` framing and writes only protocol messages to standard output. Headers are limited to 8 KiB and message bodies to 1 MiB. It advertises UTF-16 positions. It advertises no document synchronization, no workspace diagnostics, no code actions and no write operations.

The client's initialization options tie the process to one review scope:

```json
{
  "tenant_id": "example",
  "repository_id": "repository",
  "review_run_id": "run-123"
}
```

The `rootUri` must be a file URI, and the server rejects diagnostic requests for files outside that root. Findings use one-based physical review lines, which the server converts to zero-based LSP ranges that cover whole lines. Each diagnostic carries these values:

- Its stable fingerprint.
- The verified finding identity.
- The evidence references.
- The diagnostic-set identity.
- The reviewed snapshot identity.
- The head revision.

For final version 7 findings, `data.snapshot_identity` is the selected review snapshot, not the separate snapshot of the physical head. The result identity remains the identity of the final diagnostic set. Each message ends with `[untrusted review output; verify before editing]`.

A client can send `previousResultId`. If it matches the current set identity, the server returns an unchanged report. A new identity returns a complete report, which is an empty list when the verified set has no findings.

## Diagnostic-set versions

The public transport contracts are the schemas `schemas/diagnostics/verified-diagnostic-set-v5.schema.json`, `schemas/diagnostics/deterministic-diagnostic-set-v6.schema.json` and `schemas/diagnostics/full-review-diagnostic-set-v7.schema.json`.

- Version 5 holds the verified findings, the candidate outcomes, the verification-context identity, the source counts, the aggregate omission reasons and one deterministic check, tied to its source check, its analysis result and the change.
- Version 6 replaces the verified-finding fields with an analysis-result identity and the deterministic observations.
- Version 7 is the final result. It keeps the terminal outcome and any verified portion.

The internal review adapter creates version 5 only when the verification receipt, the verified finding set, the snapshot and the review scope all match. The deterministic analysis path creates version 6 without verification. The LSP item list for version 7 contains only the verified portion.

The server shows nothing about the run as a whole. It does not report the terminal outcome, a refusal to route context, or a result recorded after its evidence expired (`evidence_expired`, which has no verified portion and so gives an empty item list). An empty list therefore does not mean the review was clean. Use `trestle runs status`, the TUI, ACP or the web console to see the run-level result.

Version 8 (`schemas/diagnostics/verified-diagnostic-set-v8.schema.json`) is version 5 plus findings on removed base lines. Such a finding is marked `"side":"base"` and has an optional `head_line`. Open Trestle uses version 8 when a finding on removed base lines exists, and final version 7 may embed it in place of version 5. The open document in the editor holds head lines, so the server does not place base lines on it. A finding on the base side becomes a file-level diagnostic (range 0:0) with these properties:

- Its message starts with `Base lines a-b (removed code):`.
- The warning stays last in the message.
- Its data carries `side`, `base_start_line` and `base_end_line`.

A removed file has no open head document, so its findings appear in the other outputs only.

## Storage and updates

The daemon keeps one immutable diagnostic set for each review scope, in a private store that survives crashes. The authenticated API can only retrieve diagnostics. It has no public endpoint for uploading them. The local export mode is available for air-gapped use.

The server cannot push refresh notifications yet, and that work is separate. Editors get updates by sending ordinary pull requests and comparing result identities.

The packaged [VS Code extension](vscode.md) uses the daemon-backed mode. It also uses machine-scoped settings, SecretStorage, a restricted child process environment and a client-side gate that allows only pull diagnostics.

Reference: <https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_diagnostic>

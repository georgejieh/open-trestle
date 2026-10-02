# Open Trestle for VS Code

Open Trestle for VS Code displays independently verified review findings from diagnostic versions 1 through 5 through the read-only Open Trestle LSP server. Version 6 deterministic observations remain outside LSP findings and are available through the CLI, TUI, and web console. The extension does not edit files, execute repository commands, offer code actions, change policy, call a model directly, or publish review results.

## Requirements

Install the `trestle` CLI on the extension host. Configure an HTTPS daemon URL or a canonical loopback IP HTTP URL. The daemon must already contain the exact review run and canonical diagnostic set. A version 6 set is a valid empty LSP result because its deterministic observations are not independently verified findings.

## Connect

1. Open a trusted workspace folder at the reviewed repository root.
2. Set the machine-scoped `openTrestle.server`, `openTrestle.tenant`, `openTrestle.repository`, and `openTrestle.run` settings.
3. Run **Open Trestle: Set API Token**. The token is stored in VS Code SecretStorage.
4. Run **Open Trestle: Connect to Review Run**.

The extension starts the exact configured `trestle` executable without a shell and passes `lsp --server URL`. Only a bounded environment allowlist and `OPEN_TRESTLE_API_TOKEN` reach the child process. The LSP initialization options bind the tenant, repository, and run. Diagnostics outside the active workspace root are rejected by the server.

`openTrestle.executable`, the server and scope settings, and `openTrestle.autoStart` use VS Code's machine configuration scope so repository settings cannot turn workspace text into process authority. Automatic startup is disabled by default. The extension refuses to start in an untrusted workspace.

## Security boundary

The extension uses standard pull diagnostics, removes push-diagnostic capability, discards push notifications, and strips all other client capabilities. Client-side middleware discards document synchronization and dynamic registrations, returns no code actions, completions, code lenses, links, inline suggestions, formatting, or rename operations, and rejects workspace edits and external document opens. Diagnostic messages remain untrusted review output. Verify source and evidence before editing.

The token is never written to extension settings, output, diagnostics, command arguments, or status text. Clearing the token stops the client before deleting it from SecretStorage.

Bundled dependency license texts are included in the VSIX.

See [the Open Trestle LSP contract](../../docs/lsp.md) for protocol limits and evidence semantics.

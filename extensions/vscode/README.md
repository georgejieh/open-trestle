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

The extension uses Microsoft protocol and JSON-RPC packages for a narrow pull-diagnostic adapter. It never sends document contents or synchronization notifications. Push diagnostics and dynamic registrations have no effect. Server requests cannot edit files, open documents, execute commands, or install editor features. Workspace edits and document opens receive explicit refusals; configuration requests receive bounded null values. Diagnostic messages remain untrusted review output. Verify source and evidence before editing.

The token is never written to extension settings, output, diagnostics, command arguments, or status text. Changing or clearing the token invalidates diagnostics immediately, before awaiting process shutdown. A failed shutdown never permits a successor to overlap the prior child. Clearing the token deletes it from SecretStorage even if child closure cannot be confirmed.

Bundled dependency license texts are included in the VSIX.

See [the Open Trestle LSP contract](../../docs/lsp.md) for protocol limits and evidence semantics.

## Refresh and failure behavior

After connection, each eligible visible file is pulled once. Revealing a file again may reuse its exact result identity. Restart explicitly refreshes visible files from a new process with no prior baselines. There is no polling, background workspace scan, save/change refresh, or automatic reconnect. Hidden-file findings remain in Problems until document close or session retirement. Empty findings do not certify repository safety.

The selected local file workspace folder is the only root. Other roots, nested separately selected folders, virtual documents and unsafe URIs are not eligible. Results are validated before publication to the native **Open Trestle verified findings** diagnostic collection. Diagnostic text remains plain, inert review output.

Fixed resource limits are 128 tracked URIs, one pull in flight, 1,000 diagnostics per report and 16 KiB UTF-8 per diagnostic message. Total stdout admission is 8 MiB per session, counted before Microsoft's framing reader. Crossing a limit retires the session rather than truncating findings. This lifetime budget is not a per-frame or measured peak-memory bound; long valid sessions can require an explicit Restart.

Initialize and pull requests have a 35-second deadline. Stop first invalidates all publication authority, attempts graceful shutdown for one second, then allows one second each after SIGTERM and SIGKILL. Cancellation or JSON-RPC disposal is not proof of exit. A successor starts only after the owned direct child's `close` event. If closure is not observed, attention status remains and Restart can recheck it later. These are direct-child controls, not a portable process-tree containment guarantee. Raw child stderr and protocol errors are never logged.

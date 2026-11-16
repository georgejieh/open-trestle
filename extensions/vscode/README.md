# Open Trestle for VS Code

Open Trestle for VS Code shows the findings of an Open Trestle review in the
editor's Problems panel. It connects to a review run that the Open Trestle
daemon already holds, through the read-only `trestle lsp` server, and displays
the findings that an independent model has verified, from diagnostic
versions 1 through 5. Version 6 deterministic observations remain outside LSP
findings, because they are not verified findings; the CLI, the terminal UI and
the web console show them.

The extension only displays results. It does not start a review, edit files, run
repository commands, offer code actions, change policy, call a model or publish
anything.

## Requirements

You need the `trestle` CLI on the extension host and a daemon that already holds
the review run and its diagnostic set. The daemon URL must use HTTPS, or HTTP on
a loopback IP address. A run whose set holds only deterministic observations
(version 6) is valid and shows no findings.

## Connect

1. Open the reviewed repository's root folder as a trusted workspace.
2. Set the machine-scoped `openTrestle.server`, `openTrestle.tenant`,
   `openTrestle.repository` and `openTrestle.run` settings.
3. Run **Open Trestle: Set API Token**. The token is stored in VS Code
   SecretStorage.
4. Run **Open Trestle: Connect to Review Run**.

The extension starts the configured `trestle` executable directly, without a
shell, and passes `lsp --server URL`. The child process receives only a short
allowlist of environment variables plus `OPEN_TRESTLE_API_TOKEN`. The tenant,
repository and run are fixed in the LSP initialization options, and the server
rejects diagnostics for files outside the active workspace folder.

`openTrestle.executable`, the server and scope settings, and
`openTrestle.autoStart` use VS Code's machine configuration scope. A repository's
own settings therefore cannot choose which program runs. Automatic startup is
off by default, and the extension refuses to start in an untrusted workspace.

## Security

The extension uses Microsoft's protocol and JSON-RPC packages, but only for a
narrow adapter that pulls diagnostics. It never sends document contents or
synchronization notifications, and it ignores pushed diagnostics and dynamic
registrations. Requests from the server cannot edit files, open documents, run
commands or install editor features: workspace edits and document opens are
refused explicitly, and configuration requests get bounded null values.

Diagnostic messages are review output and are not trusted. Check the source and
the evidence before you edit anything.

The token never appears in extension settings, output, diagnostics, command
arguments or status text. When you change or clear the token, the extension
withdraws its diagnostics immediately, before it waits for the process to shut
down. A new process never overlaps one whose shutdown failed. Clearing the token
removes it from SecretStorage even when the extension cannot confirm that the
child process closed.

The license texts of bundled dependencies are included in the VSIX. The
[LSP guide](https://github.com/georgejieh/open-trestle/blob/main/docs/lsp.md) describes the protocol limits and what the
findings mean.

## Refreshing and failures

After you connect, the extension pulls findings once for each eligible visible
file. Showing a file again may reuse its earlier result. **Restart** refreshes
the visible files from a new process that starts with no earlier results. The
extension does not poll, scan the workspace in the background, refresh on save
or change, or reconnect on its own. Findings for a file you have hidden stay in
the Problems panel until you close the document or the session ends. An empty
list of findings does not mean the repository is safe.

Only the selected local workspace folder is eligible. Other roots, separately
selected nested folders, virtual documents and unsafe URIs are not. Results are
validated before they appear in the **Open Trestle verified findings**
diagnostic collection, and diagnostic text is shown as plain text.

The extension tracks at most 128 files, keeps one pull in flight, accepts at most
1,000 diagnostics per report and 16 KiB of UTF-8 per diagnostic message, and
reads at most 8 MiB of standard output per session, counted before Microsoft's
framing reader. When any limit is crossed, the extension ends the session rather
than truncating findings. The 8 MiB budget covers the whole session, not a single
message or peak memory, so a long session can need an explicit **Restart**.

Initialize and pull requests time out after 35 seconds. To stop, the extension
first withdraws its right to publish diagnostics, then asks the server to shut
down and waits one second, then sends SIGTERM and waits one second, then sends
SIGKILL and waits one second more. A canceled request or a disposed JSON-RPC
connection does not prove that the process exited, so a new process starts only
after the child's `close` event. If that event never arrives, the status keeps
asking for attention, and **Restart** can check again later. These controls
apply to the direct child process; they do not guarantee that every descendant
process is contained. Raw child standard error and protocol errors are never
logged.

# VS Code extension

Use the Node version in `.node-version` for reproducible packaging. `extensions/vscode` packages a read-only Open Trestle diagnostic client. It starts the existing `trestle lsp` process and does not implement a second review engine.

## Install from a local build

```sh
npm ci --prefix extensions/vscode
npm run format:check --prefix extensions/vscode
npm test --prefix extensions/vscode
npm run check --prefix extensions/vscode
npm run package --prefix extensions/vscode
npm run dist:check --prefix extensions/vscode
```

Install `extensions/vscode/dist/open-trestle.vsix` through VS Code's **Install from VSIX** command. The packaging step uses locale-independent filename order and fixes ZIP calendar timestamps to UTC. The checker reads raw DOS date/time fields rather than converting them through the caller's timezone. Two packages from the same source and toolchain are byte-identical across host timezones.

The `package` script delegates its single build to VSCE's standard `vscode:prepublish` hook before normalization. `@vscode/vsce` and its transitive packaging modules are development tools only; `--no-dependencies` and the explicit extension file list keep them out of the VSIX.

The committed distribution consists only of `extension.js`, `bundle-meta.json`, and `open-trestle.vsix`; transient raw packages stay ignored. CI snapshots the checked-out directory before packaging, builds under UTC and America/Los_Angeles to check cross-timezone reproducibility, then compares the generated directory directly with the snapshot. This check remains effective even if a local checkout has not yet tracked the files.

The extension is not published to a marketplace by this repository workflow.

## Configure

Install the `trestle` CLI on the extension host. In machine settings, configure:

- `openTrestle.executable`: an absolute path or a bare executable name, never a shell command or workspace-relative path. This operator-selected executable remains part of the host trust boundary;
- `openTrestle.server`: an HTTPS URL or canonical loopback-IP HTTP URL with no credentials, query, fragment, or path;
- `openTrestle.tenant`;
- `openTrestle.repository`;
- `openTrestle.run`; and
- `openTrestle.autoStart`, which defaults to false.

All settings use VS Code's machine scope so repository settings cannot become process or connection authority. Open a trusted local workspace at the reviewed repository root. Run **Open Trestle: Set API Token**, then **Open Trestle: Connect to Review Run**.

The token is stored in VS Code SecretStorage. It is passed to the child only as `OPEN_TRESTLE_API_TOKEN`. The child environment allowlist contains path, home, temporary-directory, certificate, and HTTP proxy settings needed to start the CLI and reach an operator-configured daemon. Unrelated provider, cloud, forge, and application credentials are not forwarded.

## Capability boundary

The extension strips initialization capabilities down to pull diagnostics and applies a second client-side protocol gate. Push-diagnostic capability is removed and any `textDocument/publishDiagnostics` notification is discarded. It discards document synchronization, dynamic registrations, code actions, completions, code lenses, links, color presentations, inline suggestions, formatting, rename, and execute-command behavior. It rejects `workspace/applyEdit` and `window/showDocument` requests without invoking VS Code.

The extension:

- requests standard pull diagnostics for eligible visible file documents under the exact initialized workspace;
- displays only independently verified diagnostic sets returned by the daemon, so it does not show run failures, failure reasons such as a context route refusal, or their hints (use `trestle runs status`, the TUI, or the web console for those);
- has no document synchronization, code action, edit, terminal, repository command, model, worker, policy, or publication capability;
- refuses to start without workspace trust, a workspace folder, safe machine-scoped configuration, and a SecretStorage token; and
- invalidates diagnostics before changing credentials and blocks replacement until owned-child closure is observed.

The LSP server independently rejects requests outside its initialized file root and binds every response to the exact tenant, repository, run, snapshot, head revision, verified set, finding, and evidence identities.

## Distribution boundary

esbuild produces one CommonJS extension-host bundle with `vscode` left external. Source maps and build-host paths are rejected. The build metadata inventories every bundled npm package and the distribution check fails if that set changes without a matching license review. The VSIX is limited to 1 MiB and contains exactly the manifest, bundle, icon, project license, notice, changelog, README, and complete license texts for the Microsoft protocol/JSON-RPC family. The current bundle does not use telemetry or a network library other than the spawned Open Trestle LSP process.

## Adapter limits and refresh

The extension deliberately uses the maintained Microsoft protocol/JSON-RPC packages, not a full language client or a custom framing parser. It pulls currently visible files after initialization and when they become visible. Explicit Restart refreshes the current files. It does not poll, scan the workspace, refresh on edits/saves, or restart automatically after failure. Hidden findings remain until document close or session retirement. Empty findings are not clearance.

The fixed limits are 128 tracked URIs, one request in flight, 1,000 diagnostics per report, 16 KiB UTF-8 per message, and 8 MiB lifetime stdout admission before the Microsoft reader. Exceeding a limit retires the whole session without partial publication. The lifetime byte budget is not a per-message or peak-heap guarantee and can require Restart during a long valid session. Other roots and separately selected nested workspace folders are excluded; diagnostic payload fields cannot open or execute anything.

Initialize/pull deadlines are 35 seconds. Stop invalidates publication synchronously, then permits one second for graceful shutdown and one second each for SIGTERM and SIGKILL. Only the owned direct-child `close` event proves closure for successor admission. Failed stop stays in attention status and keeps the owner; explicit Restart may recheck later closure. This does not guarantee termination of arbitrary descendants. No raw stderr or protocol error text is logged.

The bundle targets Node 20 APIs for the declared minimum VS Code 1.95 host; the build toolchain remains the repository-pinned Node version. Actual extension-host qualification records the tested application and platform separately from mock/unit tests.

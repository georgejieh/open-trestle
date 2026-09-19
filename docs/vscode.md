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

- requests standard pull diagnostics for file documents under the initialized workspace;
- displays only independently verified diagnostic sets returned by the daemon;
- has no document synchronization, code action, edit, terminal, repository command, model, worker, policy, or publication capability;
- refuses to start without workspace trust, a workspace folder, safe machine-scoped configuration, and a SecretStorage token; and
- stops the LSP process before clearing credentials.

The LSP server independently rejects requests outside its initialized file root and binds every response to the exact tenant, repository, run, snapshot, head revision, verified set, finding, and evidence identities.

## Distribution boundary

esbuild produces one CommonJS extension-host bundle with `vscode` left external. Source maps and build-host paths are rejected. The build metadata inventories every bundled npm package and the distribution check fails if that set changes without a matching license review. The VSIX is limited to 1 MiB and contains exactly the manifest, bundle, icon, project license, notice, changelog, README, and complete license texts for the Microsoft language-client family, balanced-match, brace-expansion, minimatch, and semver. The current bundle does not use telemetry or a network library other than the spawned Open Trestle LSP process.

# VS Code extension

The Open Trestle VS Code extension shows the diagnostics of an existing review run inside the editor. It is read-only. It observes one run that a `trestled` daemon already holds. It cannot start a review, and it is not how you review the change you are editing: use `trestle review` for that. It is not in any release or marketplace.

The extension lives in `extensions/vscode`. It starts the existing `trestle lsp` process and does not contain a second review engine. Use the Node version in `.node-version` so that the packaged output is reproducible.

## Install from a local build

Build and check the package, then install it into VS Code:

```sh
npm ci --prefix extensions/vscode
npm run format:check --prefix extensions/vscode
npm test --prefix extensions/vscode
npm run check --prefix extensions/vscode
npm run package --prefix extensions/vscode
npm run dist:check --prefix extensions/vscode
```

Install `extensions/vscode/dist/open-trestle.vsix` with VS Code's **Install from VSIX** command.

The packaging step sorts filenames in a way that does not depend on the locale, and it sets ZIP calendar timestamps to UTC. The checker reads the raw DOS date and time fields instead of converting them through the caller's timezone. Two packages built from the same source and toolchain are therefore byte-identical on hosts in different timezones.

The `package` script runs a single build, through VSCE's standard `vscode:prepublish` hook, before it normalizes the package. `@vscode/vsce` and its transitive packaging modules are development tools only. The `--no-dependencies` flag and the explicit extension file list keep them out of the VSIX.

The committed distribution consists only of `extension.js`, `bundle-meta.json` and `open-trestle.vsix`. Raw packages that are only intermediate output stay ignored. In CI, the checked-out directory is first snapshotted. CI then builds the package under UTC and under America/Los_Angeles to check that the result does not depend on the timezone, and compares the generated directory directly with the snapshot. This check works even if a local checkout does not yet track the files.

This repository's workflow does not publish the extension to a marketplace.

## Configure the extension

Install the `trestle` CLI on the extension host. Then set these values in your machine settings:

- `openTrestle.executable`: an absolute path or a bare executable name, never a shell command or a path relative to the workspace. The executable you choose is part of the host's trust boundary.
- `openTrestle.server`: an HTTPS URL, or an HTTP URL that uses a canonical loopback IP address. It must have no credentials, query, fragment or path.
- `openTrestle.tenant`.
- `openTrestle.repository`.
- `openTrestle.run`.
- `openTrestle.autoStart`, which defaults to false.

All settings use VS Code's machine scope, so settings in a repository cannot decide which process runs or which server the extension connects to. Open a trusted local workspace at the root of the reviewed repository. Then run **Open Trestle: Set API Token**, followed by **Open Trestle: Connect to Review Run**.

VS Code SecretStorage holds the token. The extension passes it to the child process only as `OPEN_TRESTLE_API_TOKEN`. The environment of the child process is limited to an allowlist: path, home, temporary directory, certificate and HTTP proxy settings. These are what the process needs to start the CLI and reach a daemon that you configured. Unrelated provider, cloud, forge and application credentials are not passed on.

## What the extension can do

The extension strips the capabilities offered during initialization down to pull diagnostics, and it adds a second protocol gate on the client side. The gate removes the push-diagnostic capability and discards any `textDocument/publishDiagnostics` notification. It also discards document synchronization, dynamic registrations, code actions, completions, code lenses, links, color presentations, inline suggestions, formatting, rename and execute-command behavior. It rejects `workspace/applyEdit` and `window/showDocument` requests without calling VS Code.

Within that boundary, the extension does the following:

- It requests standard pull diagnostics for eligible visible file documents under the exact initialized workspace.
- It displays only independently verified diagnostic sets that the daemon returns. It therefore does not show run failures, failure reasons such as a context route refusal, or their hints. Use `trestle runs status`, the TUI or the web console for those.
- It has no document synchronization, code action, edit, terminal, repository command, model, worker, policy or publication capability.
- It refuses to start without workspace trust, a workspace folder, safe machine-scoped configuration and a token in SecretStorage.
- Before it changes credentials, it invalidates its diagnostics. It blocks a replacement until it has seen the child process it started close.

The LSP server separately rejects requests outside the file root it was initialized with. It ties every response to the exact tenant, repository, run, snapshot, head revision, verified set, finding and evidence identities.

## Distribution

esbuild produces one CommonJS bundle for the extension host, with `vscode` left external. The build rejects source maps and build-host paths. The build metadata lists every bundled npm package, and the distribution check fails if that set changes without a matching license review.

The VSIX is limited to 1 MiB. It contains exactly the manifest, the bundle, the icon, the project license, a notice, the changelog, the README and the complete license texts for the Microsoft protocol and JSON-RPC packages. The current bundle uses no telemetry and no network library, other than the spawned Open Trestle LSP process.

## Limits and refresh behavior

The extension uses the maintained Microsoft protocol and JSON-RPC packages deliberately, instead of a full language client or a custom framing parser. After initialization, and whenever a file becomes visible, it pulls diagnostics for the files that are currently visible. The Restart command refreshes the current files. The extension does not poll, scan the workspace, refresh on edits or saves, or restart automatically after a failure. Findings for a hidden document remain until the document closes or the session ends. An empty list of findings is not a clean result.

The fixed limits are:

- 128 tracked URIs.
- One request in flight.
- 1,000 diagnostics per report.
- 16 KiB of UTF-8 per message.
- 8 MiB of standard output accepted over the lifetime of the session, before the Microsoft reader sees it.

If any limit is exceeded, the whole session ends and no partial diagnostics are published. The lifetime byte budget is not a limit per message or on peak heap use, and a long but valid session may need a Restart. The extension excludes other roots and separately selected nested workspace folders. Fields in a diagnostic payload cannot open or execute anything.

Initialization and pull requests each have a 35-second deadline. When the extension stops the child process, it first invalidates publication synchronously. It then allows one second for graceful shutdown, and one second each for SIGTERM and SIGKILL. Only the `close` event of the directly owned child proves that it has closed, and only then can a successor start. If the stop fails, the extension stays in an attention status and keeps the owner, and an explicit Restart can check again later whether the child closed. This does not guarantee that arbitrary descendant processes end. The extension logs no raw stderr and no protocol error text.

The bundle targets Node 20 APIs for the declared minimum, VS Code 1.95. The build toolchain remains the Node version pinned in the repository. Qualification in a real extension host records the tested application and platform separately from the mock and unit tests.

## Qualifying in a real extension host

The unit tests use a mock of the VS Code API. To check the extension in a real VS Code extension host, run `extensions/vscode/scripts/test-extension-host.mjs` with Node. It takes three absolute paths: the VS Code executable, an `xvfb-run` style virtual display wrapper, and a new folder for the run's artifacts, which it creates.

```sh
node extensions/vscode/scripts/test-extension-host.mjs \
  --vscode=/absolute/path/to/code \
  --xvfb=/usr/bin/xvfb-run \
  --artifacts=/absolute/path/to/new-folder
```

Add `--scenario=manifest-persistence` to check that a saved API token survives a restart of VS Code and is refused once it has been cleared; the default scenario runs one session. The script writes a receipt for each phase into the artifacts folder and fails if one is missing. It is a manual qualification step, and CI does not run it.

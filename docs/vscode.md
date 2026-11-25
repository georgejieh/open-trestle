# VS Code extension

The Open Trestle VS Code extension reviews the current branch with
`trestle review` and shows the findings in the Problems panel. It lives in
`extensions/vscode` and is not in any release or marketplace.

## Install from a local build

Use the Node version in `.node-version`, so that the package matches the
committed one. Build and check it, then install it:

```sh
npm ci --prefix extensions/vscode
npm run format:check --prefix extensions/vscode
npm test --prefix extensions/vscode
npm run check --prefix extensions/vscode
npm run package --prefix extensions/vscode
npm run dist:check --prefix extensions/vscode
```

Install `extensions/vscode/dist/open-trestle.vsix` with VS Code's **Install
from VSIX** command. CI rebuilds `extensions/vscode/dist` under two timezones
and fails when it differs from the committed copy.

## Use it

1. Install the `trestle` CLI, and set up the repository once with
   `trestle init`. **Open Trestle: Set Up Repository** runs `trestle init` in a
   terminal.
2. Open a local folder of the repository as a trusted workspace. A subfolder
   works too.
3. Commit your change, then run **Open Trestle: Review Current Branch**.

The command runs `trestle review --format sarif --stop-on-stdin-close` in the
folder of the active editor, or in the first folder. Like `trestle review`, it
reviews the committed `HEAD` against its merge base with the default branch;
uncommitted edits are not included. The progress notification shows the CLI's
latest line, and the **Open Trestle** output channel keeps every line. Cancel
closes the CLI's input, which stops the review the way Ctrl-C does. One review
runs at a time.

When the review writes a SARIF result, its findings replace the earlier ones,
and a one-line summary gives the status, the commit and the number of findings.
An empty list is not a clearance. Findings that have no line in `HEAD`, such as
findings on removed lines, are written to the output channel. When the review
writes no result, the earlier findings stay and the CLI's last line is shown.
**Open Trestle: Clear Findings**
removes them.

## Setting

`openTrestle.executable`, default `trestle`, is the command name on `PATH` or
the absolute path of the CLI. It is a machine setting, so a repository's own
settings cannot change which program runs. When the program is not found, the
extension asks you to set it.

## Trust and what leaves the machine

The extension works only in a trusted workspace, because a review runs git in
the repository, may run its [checks](repository-checks.md) in a sandbox, and
sends the change to the setup's models.

What leaves the machine is what `trestle review` sends with your setup; see
[local model review](local-model-review.md). The extension starts the CLI
without a shell and passes only the paths, temporary folders, proxy and
certificate settings, `XDG_*` folders and `OPEN_TRESTLE_PROVIDER_*` key
variables from its environment. It stores no keys.

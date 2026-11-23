# Open Trestle for VS Code

Open Trestle for VS Code reviews the current branch with `trestle review` and
shows the findings in the Problems panel.

## Requirements

- The `trestle` CLI, on `PATH` or set in `openTrestle.executable`.
- A local folder of a Git repository, opened as a trusted workspace.
- A setup for the repository, made once with `trestle init`. **Open Trestle:
  Set Up Repository** runs it in a terminal.

## Commands

- **Open Trestle: Review Current Branch** runs
  `trestle review --format sarif --stop-on-stdin-close` in the folder of the
  active editor, or the first folder. It reviews the committed `HEAD` against
  its merge base with the default branch; uncommitted edits are not included.
  The progress notification shows the CLI's latest line, and the **Open
  Trestle** output channel keeps all of them. Cancel stops the review the way
  Ctrl-C does. One review runs at a time.
- **Open Trestle: Clear Findings** removes the findings from the Problems panel.
- **Open Trestle: Set Up Repository** opens a terminal that runs `trestle init`.

A finished review replaces the earlier findings and shows a one-line summary.
A finding's message ends with its unverified fix guidance, when there is one,
and a reminder to check it against the source before you edit. An empty list
is not a clearance. When the review writes no result, the earlier findings
stay and the CLI's last line is shown, for example "Run trestle init here
first".

## Setting

`openTrestle.executable` (default `trestle`) is the command name or the
absolute path of the CLI. It is a machine setting, so a repository's own
settings cannot change it.

## What runs and what is sent

The extension starts the CLI directly, without a shell, with a short list of
environment variables: the paths, temporary folders and proxy settings it
needs, the `XDG_*` folders and the `OPEN_TRESTLE_PROVIDER_*` key variables.
Other variables, such as `OPEN_TRESTLE_API_TOKEN`, are not passed on. The
extension stores no keys.

A review sends what `trestle review` sends with your setup; see
[local model review](https://github.com/georgejieh/open-trestle/blob/main/docs/local-model-review.md).
It runs git in the repository and may run the repository's checks in a
sandbox, so the extension works only in a trusted workspace.

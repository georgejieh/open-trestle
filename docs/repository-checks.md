# Repository checks

A review can run the repository's own tests and linters before it calls any model, so that code, not a model, says whether the change broke something. Running a repository's tests runs its code, so this happens only inside a sandbox and only when you allow it. It is off until you turn it on.

## Turn it on or off

- `trestle init` asks once: "Run this repository's tests inside a sandbox on this machine? It has no network and no access to your home folder or keys." The answer is saved for the setup. With `--no-input`, pass `--checks` to answer yes; without it the answer is no.
- `trestle checks on`, `trestle checks off` and `trestle checks status` change or show the answer later (add `--directory PATH` for a setup in another folder). `status` also says whether this machine has what the sandbox needs.
- If a review runs with no saved answer, it asks in the terminal: Allow this time, Deny, or Always allow for this repository. Without a terminal it runs no checks and says so.
- `trestle review --checks` runs them for one review, and `--no-checks` skips them, whatever the saved answer says. `trestle local-git model-review --repository-checks` is the same consent for the direct command; it cannot be combined with `--investigation-policy`.

The answer is kept in `checks.json` in the setup folder, a protected file like the rest of the setup.

## What runs

The checks are detected from the files of the head commit:

| Stack | Check | Results read from |
| --- | --- | --- |
| Go (each `go.mod`) | `go test -json` and `go vet`, for the packages of the changed Go files and of the files that depend on them, or the whole module when `go.mod`, `go.sum` or `go.work` changes | `go test -json` events; `go vet`'s exit status |
| Node (`package.json` with a `test` script) | `node --test` with a TAP reporter when the script is a plain `node --test` call; otherwise the `test` script through npm, pnpm or yarn | TAP results; otherwise the exit status |
| Python (files named `test_*.py` or `*_test.py`) | `python -m pytest` when the repository configures pytest, otherwise `python -m unittest discover -v -b`, each for the whole suite | the JUnit report the harness asks pytest to write; unittest's verbose result lines |
| Rust (`Cargo.toml`) | `cargo test --offline` | the test result lines |

The files that depend on the change come from the [repository index](repository-index.md) that the review already builds. When it is unavailable, the checks cover the changed files only, and the review says so. Only stacks with a changed file run. Each check runs twice on the base commit and twice on the head commit, each time on a fresh copy of the tree read from the repository's Git objects, never your working tree. A test that passes on base and fails on head is a regression. A test whose two runs on one side disagree is flaky and is dropped. Results come only from the exit status and the runner output that Open Trestle asked for, never from a file the tests write about themselves. When output reports one test twice, the failure counts, and a run that exits with a failure although every reported test passed is a failure of the check itself. A test that passed on base, and whose package, class or file reports nothing at all on head, is a regression marked "did not run on head", unless the change deletes or renames a test file. A module the repository itself provides is never a missing dependency: when a change renames it, the tests that import it fail.

Both models receive the outcomes as the `check_runs` object: each check's name, whether it ran, the regressions, new failing tests and flaky tests dropped, and whether the dependents were included. Test names and reasons come from the repository, so they are treated as untrusted data, kept short, and secret-scanned like other content before any remote request. The walkthrough has one "what ran" line, for example `ran 3 of 4 checks in the sandbox: 1 regression, 0 flaky dropped, 1 could not run (npm test: missing dependency: ...)`.

## What the sandbox allows

| | Linux | Windows | macOS |
| --- | --- | --- | --- |
| Mechanism | unprivileged user, mount, PID, network, IPC, UTS and cgroup namespaces, a seccomp filter, `no_new_privs` | an AppContainer with no capabilities, in a job object | `sandbox-exec` with a deny-by-default profile |
| Network | none; only the sandbox's own loopback | none, including DNS and the host's loopback | none |
| Reads | `/usr`, `/etc`, `/bin`, `/lib*`, the toolchain folders and the Go module cache, read-only (the whole cache, which can hold modules of your other repositories) | Windows' own folders, and the toolchain folders and Go module cache | the system folders, the toolchain folders and the Go module cache |
| Writes | its scratch only (a size-bounded tmpfs holding the tree copy, a private home and `/tmp`) | its scratch only | its scratch only |
| Home folder, keys, other repositories | not mounted | not readable | not readable |
| Environment | a short allowlist; no key or token variable | the same | the same |
| Terminal | none: a new session without a controlling terminal, and no `/dev/tty` | none: the process starts without a console | none: a new session without a controlling terminal |
| Processes | a fresh PID namespace; the whole tree is killed at the end or on timeout | the job object; the whole tree is killed at the end or on timeout | its process group is killed at the end or on timeout |

On Windows, a toolchain folder that does not already grant read access to sandboxed apps (as Windows' own folders and most of `Program Files` do by default) is given a read-and-execute entry for an Open Trestle capability once, so later runs find it there. A folder whose permissions only an administrator can change cannot be granted, and its checks report that.

## Limits

Each run has 3 minutes, 4 GiB of memory (per process on Linux, for the whole tree on Windows), 1,024 processes (threads count on Linux), 8 MiB of standard output and of standard error, and 2 GiB of scratch space including the tree copy. All the checks of one review share 10 minutes. Before the first Go run, the host's own Go toolchain compiles the standard library packages the trees import (read from the Go files without running anything) into a build cache, and each run starts from a copy of it, so a run compiles only the repository's own packages. cgo is off in the sandbox. On Windows and macOS the scratch size is measured every quarter second, so a burst of writes can pass the limit briefly before the run is stopped. macOS has no per-tree process or memory limit without administrator rights, so those fall back to the system's per-user limits, and a process that starts a new session escapes the kill at the end of the run, though it stays inside the sandbox. On Windows the AppContainer's own profile folder counts toward the scratch space, since the sandbox can write there too.

## Could not run

A check that could not run is a gap in coverage, never a pass and never a finding. The reasons are:

- The sandbox is not available. On Linux, unprivileged user namespaces can be turned off (`kernel.unprivileged_userns_clone=0` or `user.max_user_namespaces=0`), or restricted by AppArmor (`kernel.apparmor_restrict_unprivileged_userns=1`, the default from Ubuntu 24.04), and a container may not allow them. Open Trestle never runs a check without the sandbox.
- The toolchain is not installed, or the sandbox cannot see it.
- Missing dependency. Checks run offline and never install packages: a Go module missing from the module cache, a Python package that is not installed, a Node package whose dependencies are not installed (`node_modules` is not in the commit), or a Rust crate with dependencies (the crate registry is not shown to the sandbox) cannot run.
- On Windows, the program needs the `NUL` device and the device grants nothing to sandboxed (AppContainer) processes. Granting that access needs an administrator, which Open Trestle does not ask for. The Go command opens `NUL` for every tool it starts, so Go checks cannot run on such a system.
- The run passed its time, output or scratch limit, or the review's time for checks ran out.
- The runner exited with an error and reported no results.

## Not verified

The macOS sandbox is built and its profile is tested, but it has not been run on a Mac. Apple marks `sandbox-exec` as deprecated, though it ships with macOS.

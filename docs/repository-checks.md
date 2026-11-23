# Repository checks

A review can run the repository's own tests and linters before it calls any model, so that code, not a model, says whether the change broke something. Running a repository's tests runs its code, so this happens only inside a sandbox and only when you allow it. It is off until you turn it on.

## Turn it on or off

- `trestle init` asks once, when you choose to run the first review: "Run this repository's tests inside a sandbox on this machine? It has no network and no access to your home folder or keys." The answer is saved for the setup. If no review runs, the first review asks instead. With `--no-input`, pass `--checks` to answer yes; without it the answer is no.
- `trestle checks on`, `trestle checks off` and `trestle checks status` change or show the answer later (add `--directory PATH` for a setup in another folder). `status` also says whether this machine has what the sandbox needs.
- If a review runs with no saved answer, it asks in the terminal: Allow this time, Deny, or Always allow for this repository. Without a terminal it runs no checks and says so.
- `trestle review --checks` runs them for one review, and `--no-checks` skips them, whatever the saved answer says. `trestle local-git model-review --repository-checks` is the same consent for the direct command; it cannot be combined with `--investigation-policy`.

The answer is kept in `checks.json` in the setup folder, a protected file like the rest of the setup, with the repository's root commits it was given for. A different repository in the same folder, or one that uses the same setup folder, is asked again.

## What runs

The checks are detected from the files of the head commit:

| Stack | Check | Results read from |
| --- | --- | --- |
| Go (each `go.mod`) | `go test -json` and `go vet`, for the packages of the changed Go files and of the files that depend on them, or the whole module when `go.mod`, `go.sum` or `go.work` changes; base runs only the packages it has. A module with `vendor/modules.txt` builds from its vendor folder. A check of a module below the root names its folder, for example `go test ./x (in tools)` | `go test -json` events; `go vet`'s diagnostics |
| Node (`package.json` with a `test` script) | `node --test` with a TAP reporter when the script is a plain `node --test` call; otherwise the `test` script through npm, pnpm or yarn | TAP results; otherwise the exit status |
| Python (files named `test_*.py` or `*_test.py`) | `python -m pytest` when the repository configures pytest, otherwise `python -m unittest discover -v -b`, each for the whole suite | the JUnit report the harness asks pytest to write; unittest's verbose result lines |
| Rust (`Cargo.toml`) | `cargo test --offline` | the test result lines, each test named by the test binary cargo ran it in |
| Go linters (each `go.mod`, for the same packages as `go vet`) | `staticcheck`; with golangci-lint 2, `golangci-lint run --fix=false --new=false --path-mode=abs --max-issues-per-linter=0 --max-same-issues=0` with one-line text output on standard output | the diagnostics |
| Python linters (a changed Python file or linter configuration) | `ruff check --no-cache --no-fix --output-format=concise --quiet .`; `flake8 .`; `mypy --cache-dir=$TMPDIR/mypy-cache --no-error-summary --no-pretty --no-color-output .` | the diagnostics |
| Rust linter (`Cargo.toml`) | `cargo clippy --offline --message-format=short` | the diagnostics |

A linter or type checker runs only when the repository uses it: a configuration file, CI workflow, task runner or pre-commit hook of the head commit names it, as `trestle profile` reads them. Node linters and type checkers (eslint, tsc, pyright) do not run, because `node_modules` is not in the commit.

The files that depend on the change come from the [repository index](repository-index.md) that the review already builds. When it is unavailable, the checks cover the changed files only; when it does not cover the whole change (a build cut by its time bound, a closure cut by its limits), they cover only some of the dependents. The review says which. Only stacks with a changed file run, and a change that no check applies to says so. Each test check runs twice on the base commit and twice on the head commit, and each linter once on each, each time on a fresh copy of the tree read from the repository's Git objects, never your working tree.

How the outcomes are read:

- A test that passes on base and fails on head is a regression. So is a package, module or file that fails as a whole on head (a build failure, a module that cannot be imported) while tests in it passed on base, and a run that passes its time, output or scratch limit, or exits with a failure and no results, on head after base ran within them.
- A test that passed on base and has no result on head, with nothing on head failing in its package, class or file, stopped running. Such tests are listed apart: a rename or removal does the same, so they are not regressions. Tests of a test file the change deletes are left out, for Go packages, Python modules and Rust integration tests.
- Tests that failed on base and pass on head are counted as fixed, and tests that fail on both as still failing.
- A test whose two runs on one side disagree is flaky and is dropped.
- A linter or type checker reports diagnostics, lines of the form `path:line[:column]: message`, and each is a failure. They are compared by path and message, not line, so a diagnostic that only moved is not new; a message repeated in one file is counted in line order. A diagnostic only on head is a new failure, listed as `path:line: message` with its head line; one on both sides is still failing; one only on base is not reported. A linter that exits with a failure and prints no diagnostic it can read fails as a run, like a test runner without results.
- When output reports one test twice, the failure counts, and a run that exits with a failure although every reported test passed is a failure of the check itself.
- A missing dependency is read only from the runner's own records (a Go build that failed, a pytest collection error, a test module or file that could not be imported) or from a run that produced no results, never from what tests print. A module the repository itself provides is never a missing dependency: when a change renames it, the tests that import it fail.

Results come only from the exit status and the runner output that Open Trestle asked for, never from a file the tests write about themselves. That output still comes from the code under test, and for some runners, such as pytest's JUnit report or anything the test process prints, from the test process itself. A regression is therefore strong evidence that the change broke something, but a pass is not proof: it is only as trustworthy as the head code that reported it.

Both models receive the outcomes as the `check_runs` object: each check's name, whether it ran or why not (naming the base or head side where that matters), the regressions, new failing tests and new linter diagnostics, tests that stopped running, the fixed and still-failing counts, flaky tests dropped, and how many of the dependents were included. Test names and reasons come from the repository, so they are treated as untrusted data, kept short, shown with the home folder as `~`, and secret-scanned like other content before any remote request. The walkthrough has one "what ran" line, for example `ran 3 of 4 checks in the sandbox: 1 regression, 2 tests stopped running, 0 flaky dropped, 1 could not run (npm test: missing dependency: jest on base)`.

## What the sandbox allows

| | Linux | Windows |
| --- | --- | --- |
| Mechanism | unprivileged user, mount, PID, network, IPC, UTS and cgroup namespaces, a seccomp filter, `no_new_privs` | an AppContainer with no capabilities, under a restricted token with no privilege but bypassing traverse checking, in which your account's SID and every group except Everyone, Users, Authenticated Users and the sign-in's logon session only deny, so it keeps none of your account's or an administrator's rights, in a job object |
| Network | none; only the sandbox's own loopback | none, including DNS and the host's loopback |
| Reads | `/usr`, `/etc`, `/bin`, `/lib*`, the toolchain folders and the Go module cache, read-only (the whole cache, which can hold modules of your other repositories) | Windows' own folders, and the toolchain folders and Go module cache |
| Writes | its scratch only (a size-bounded tmpfs holding the tree copy, a private home and `/tmp`) | its scratch and its AppContainer profile folder (see Limits for what it can leave there) |
| Home folder, keys, other repositories | not mounted | not readable |
| Environment | a short allowlist; no key or token variable | the same; your registry hive (`HKCU`), including the variables `setx` saves in `HKCU\Environment`, is not readable through your account's rights |
| Terminal | none: a new session without a controlling terminal, and no `/dev/tty` | none: the process starts without a console |
| Processes | a fresh PID namespace; the whole tree is killed at the end or on timeout; they start as the kernel's first choice when memory runs out | the job object; the whole tree is killed at the end or on timeout |

On Windows, a toolchain folder that does not already grant read access to sandboxed apps (as Windows' own folders and most of `Program Files` do by default) is given a read-and-execute entry for an Open Trestle capability once, so later runs find it there. Since the sandbox's token does not match your account, a toolchain folder that only your account can read (as most folders in your home) is also given a read-and-execute entry for the logon session SID of your current sign-in (not for a group other accounts are in); the first run after the next sign-in replaces it. The scratch and the AppContainer profile folder get the logon session's entry for the length of the run. A folder whose permissions only an administrator can change cannot be granted, and its checks report that. Each grant is recorded in `~/.local/state/open-trestle/sandbox-grants` (under `XDG_STATE_HOME` when that is set), and `trestle checks off` takes the recorded grants back.

A review that runs checks first removes what earlier runs left when they were killed: scratch folders, tree copies and Go seed folders in the temporary folder older than an hour, and on Windows the sandboxes' AppContainer profiles of the same age.

## Limits

Each run has 3 minutes, 4 GiB of memory (for the whole tree on Windows; on Linux for each process's own data), 1,024 processes (threads count on Linux), 8 MiB of standard output and of standard error, and 2 GiB of scratch space including the tree copy. All the checks of one review share 10 minutes. Before the first Go run, the host's own Go toolchain compiles the standard library packages the trees import (read from the Go files without running anything) into a build cache, and each run starts from a copy of it, so a run compiles only the repository's own packages. cgo is off in the sandbox.

On Linux, the total memory of all the sandbox's processes together and shared memory such as `memfd` files are not bounded; only each process's data and the scratch size are. On Linux kernels before 5.14 the process limit counts all of your account's processes, so the sandbox allows for the number already running when it starts.

On Windows the scratch size is a measurement, not a quota. Every quarter second Open Trestle adds up what is stored in the folders the sandbox can write, NTFS alternate data streams included, and checks how far the free space of their volume has fallen since the run started, which also counts files deleted while still open. A burst of writes can pass the limit briefly before the run is stopped, and other programs filling the same volume during the run count too. On Windows the AppContainer's own profile folder counts toward the scratch space, since the sandbox can write there too.

On Windows the sandbox cannot change the permissions of what it has written, but Windows lets it create a folder with permissions of its own choosing, and such a folder can deny your account, even as its owner, the right to delete it. Removing the scratch then fails, the review reports a scratch it could not remove, and only an administrator can delete that folder (with `takeown /r` and `icacls /reset /t`).

## Could not run

A check that could not run is a gap in coverage, never a pass and never a finding. The reasons are:

- The sandbox is not available. On Linux, unprivileged user namespaces can be turned off (`kernel.unprivileged_userns_clone=0` or `user.max_user_namespaces=0`), or restricted by AppArmor (`kernel.apparmor_restrict_unprivileged_userns=1`, the default from Ubuntu 24.04), and a container may not allow them. Open Trestle never runs a check without the sandbox.
- The toolchain is not installed, or the sandbox cannot see it.
- Missing dependency. Checks run offline and never install packages: a Go module missing from the module cache, a Python package that is not installed, a Node package the tests import that is not installed (`node_modules` is not in the commit), or a Rust crate with dependencies (the crate registry is not shown to the sandbox) cannot run. A Node package's declared dependencies alone do not stop its tests: they run, and only a package a run fails to find counts.
- On Windows, the program needs the `NUL` device and the device grants nothing to sandboxed (AppContainer) processes. Granting that access needs an administrator, which Open Trestle does not ask for. The Go command opens `NUL` for every tool it starts, so Go checks cannot run on such a system.
- The run passed its time, output or scratch limit on base, or the review's time for checks ran out. The same on head after a clean base is a regression, not a gap.
- The runner exited with an error and reported no results on base, or reported more than 50,000 results.

Reasons that belong to one side end with "on base" or "on head".

## macOS

Checks are off on macOS, and every check reports that the sandbox is not available. See [platforms](platforms.md#macos).

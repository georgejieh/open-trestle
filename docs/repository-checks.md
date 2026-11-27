# Repository checks

A review can run the repository's own tests and linters before it calls any model, so that code, not a model, decides whether the change broke something. Running a repository's tests means running its code, so this happens only inside a sandbox and only when you allow it. It is off until you turn it on.

## Turn it on or off

- `trestle init` asks once, when you choose to run the first review: "Run this repository's tests inside a sandbox on this machine? It has no network and no access to your home folder or keys." The answer is saved for the setup. If no review runs, the first review asks instead. With `--no-input`, pass `--checks` to answer yes. Without it, the answer is no.
- `trestle checks on`, `trestle checks off` and `trestle checks status` change or show the answer later (add `--directory PATH` for a setup in another folder). `status` also says whether this machine has what the sandbox needs.
- If a review runs with no saved answer, it asks in the terminal whether to Allow this time, Deny, or Always allow for this repository. Without a terminal, it runs no checks and says so.
- `trestle review --checks` runs the checks for one review, and `--no-checks` skips them, whatever the saved answer says. For the direct command, `trestle local-git model-review --repository-checks` gives the same consent. It cannot be combined with `--investigation-policy`.

The answer is kept in `checks.json` in the setup folder, a protected file like the rest of the setup, together with the root commits of the repository it was given for. The question is asked again for a different repository in the same folder, or for one that uses the same setup folder.

## What runs

The checks are detected from the files of the head commit:

| Stack | Check | Results read from |
| --- | --- | --- |
| Go (each `go.mod`) | `go test -json` and `go vet` for the packages of the changed Go files and of the files that depend on them, or for the whole module when `go.mod`, `go.sum` or `go.work` changes (see the notes below) | `go test -json` events; `go vet`'s diagnostics |
| Node (`package.json` with a `test` script) | `node --test` with a TAP reporter when the script is a plain `node --test` call; otherwise the `test` script through npm, pnpm or yarn | TAP results; otherwise the exit status |
| Python (files named `test_*.py` or `*_test.py`) | `python -m pytest` when the repository configures pytest, otherwise `python -m unittest discover -v -b`, each for the whole suite | the JUnit report the harness asks pytest to write; unittest's verbose result lines |
| Rust (`Cargo.toml`) | `cargo test --offline` | the test result lines, each test named by the test binary cargo ran it in |
| Go linters (each `go.mod`, for the same packages as `go vet`) | `staticcheck`; with golangci-lint 2, `golangci-lint run --fix=false --new=false --path-mode=abs --max-issues-per-linter=0 --max-same-issues=0` with one-line text output on standard output | the diagnostics |
| Python linters (a changed Python file or linter configuration) | `ruff check --no-cache --no-fix --output-format=concise --quiet .`; `flake8 .`; `mypy --cache-dir=$TMPDIR/mypy-cache --no-error-summary --no-pretty --no-color-output .` | the diagnostics |
| Rust linter (`Cargo.toml`) | `cargo clippy --offline --message-format=short` | the diagnostics |

For Go, the base commit runs only the packages that exist in it. A module with `vendor/modules.txt` builds from its vendor folder. A check of a module below the repository root names its folder, for example `go test ./x (in tools)`.

A linter or type checker runs only when the repository uses it: a configuration file, CI workflow, task runner or pre-commit hook in the head commit names it, as `trestle profile` reads them. Node linters and type checkers (eslint, tsc, pyright) do not run, because `node_modules` is not in the commit.

The files that depend on the change come from the [repository index](repository-index.md) that the review already builds. When the index is unavailable, the checks cover only the changed files. When the index does not cover the whole change (a build cut short by its time bound, or a closure cut by its limits), the checks cover only some of the dependents. The review says which applies. Only stacks with a changed file run, and if no check applies to a change, the review says so. Each test check runs twice on the base commit and twice on the head commit, and each linter runs once on each. Each run uses a fresh copy of the tree from the repository's Git objects, never your working tree.

The outcomes are read as follows:

- A test that passes on base and fails on head is a regression. So is a package, module or file that fails as a whole on head (a build failure, or a module that cannot be imported) while tests in it passed on base. A run on head is also a regression if it passes its time, output or scratch limit, or exits with a failure and no results, after base ran within those limits.
- A test that passed on base and has no result on head, while nothing on head failed in its package, class or file, has stopped running. They are listed separately, not as regressions, because a rename or removal looks the same. Tests in a test file that the change deletes are left out for Go packages, Python modules and Rust integration tests.
- Tests that failed on base and pass on head are counted as fixed, and tests that fail on both as still failing.
- A test whose two runs on the same side disagree is flaky and is dropped.
- A linter or type checker reports diagnostics (lines of the form `path:line[:column]: message`), and each one is a failure. Diagnostics are compared by path and message, not line, so a diagnostic that only moved is not new. When a message repeats within one file, the copies are counted in line order. A diagnostic found only on head is a new failure, listed as `path:line: message` with its head line. One found on both sides is still failing, and one found only on base is not reported. If a linter exits with a failure but prints no readable diagnostic, the run fails as a whole, like a test runner without results.
- When the output reports the same test twice, the failure counts. A run that exits with a failure even though every reported test passed counts as a failure of the check itself.
- A missing dependency is read only from the runner's own records (a Go build that failed, a pytest collection error, or a test module or file that could not be imported) or from a run that produced no results, never from what the tests print. A module that the repository itself provides is never treated as a missing dependency, so when a change renames it, the tests that import it fail.

Results come only from the exit status and the runner output that Open Trestle asked for, never from a file the tests write about themselves. That output still comes from the code under test, and for some runners, such as pytest's JUnit report or anything the test process prints, it comes from the test process itself. A regression is therefore strong evidence that the change broke something, but a pass is not proof, since it is only as trustworthy as the head code that reported it.

Both models receive the outcomes as the `check_runs` object. It holds each check's name, whether it ran or why not (naming the base or head side where that matters), the regressions, new failing tests and new linter diagnostics, the tests that stopped running, the fixed and still-failing counts, the flaky tests dropped, and how many of the dependents were included. Test names and reasons come from the repository, so they are treated as untrusted data: kept short, shown with the home folder as `~`, and secret-scanned like other content before any remote request. The walkthrough has one "what ran" line, for example `ran 3 of 4 checks in the sandbox: 1 regression, 2 tests stopped running, 0 flaky dropped, 1 could not run (npm test: missing dependency: jest on base)`.

Regressions do not depend on the models. The review reports each one as a [check regression](local-model-review.md#check-regressions) with source `repository_check`, naming the check and the test, in every output format. The result is then `blocked` (exit 4 unless `--exit-code-policy always-zero`). This holds even when the models found nothing or the model review failed, and then the output says that the model review did not finish. New failing tests, new linter diagnostics and tests that stopped running remain hints for the models.

## Model-written checks

With `--model-checks`, the checker also writes a test for each of up to 3 verified findings, in the style of the repository's own tests. The review keeps a test only when it shows the regression.

```sh
trestle review --model-checks
trestle local-git model-review ... --repository-checks --model-checks
```

- It needs the repository checks. `trestle review --model-checks` refuses to send anything when the checks are off for that review. Combining `--model-checks` with `--no-checks`, or using it on the direct command without `--repository-checks`, is a usage error. It is not saved in the setup.
- The checker is asked only for the frameworks whose checks ran on head: `go_test`, `pytest` and `unittest`. It returns a framework and the file text, never a path. If a check in an answer is invalid, too large or extra, the check is dropped and counted, and the answer keeps its verdict.
- The host writes each file next to its finding, as `trestle_check_<n>_test.go` or `test_trestle_check_<n>.py`, into fresh base and head trees. It then runs only that file's tests, twice on each side, in the same sandbox, within 5 minutes for all of them.
- Before it runs, each file is checked and may be at most 12 KiB. A Go test must use the folder's package or its `_test` package. It may not have build constraints, `TestMain`, `init`, `//go:embed`, `//go:linkname` or cgo, or import any of `os`, `os/exec`, `io/ioutil`, `io/fs`, `path/filepath`, `text/template`, `html/template`, `embed`, `go/...`, `runtime/...`, `debug/...`, `unsafe`, `syscall`, `plugin` or `net/...`. A Python test may not name `open`, `__file__`, `inspect`, `subprocess`, `os`, `socket`, `importlib`, `pathlib`, `pytest_plugins` or `conftest`.
- A test that passes in both base runs and fails in both head runs is kept as `regression`. One that does not build on base but builds and fails in both head runs is kept as `fails_on_head`. Every other test is discarded and only counted.

The result lists the kept tests in `model_written_checks` (see [local model review](local-model-review.md#model-written-checks)). They never change the status, the CI disposition or the exit code, because the model wrote each test and so controls what it reports. Nothing is saved to your working tree.

## What the sandbox allows

| | Linux | Windows |
| --- | --- | --- |
| Mechanism | unprivileged user, mount, PID, network, IPC, UTS and cgroup namespaces, a seccomp filter, `no_new_privs` | an AppContainer with no capabilities, under a restricted token, in a job object (see the note below) |
| Network | none; only the sandbox's own loopback | none, including DNS and the host's loopback |
| Reads | `/usr`, `/etc`, `/bin`, `/lib*`, the toolchain folders and the Go module cache, read-only (the whole cache, which can hold modules of your other repositories) | Windows' own folders, and the toolchain folders and Go module cache |
| Writes | its scratch only (a size-bounded tmpfs holding the tree copy, a private home and `/tmp`) | its scratch and its AppContainer profile folder (see Limits for what it can leave there) |
| Home folder, keys, other repositories | not mounted | not readable |
| Environment | a short allowlist; no key or token variable | the same; your registry hive (`HKCU`), including the variables `setx` saves in `HKCU\Environment`, cannot be read through your account's rights |
| Terminal | none: a new session without a controlling terminal, and no `/dev/tty` | none: the process starts without a console |
| Processes | a fresh PID namespace; the whole tree is killed at the end or on timeout; processes are the kernel's first choice to kill when memory runs out | the job object; the whole tree is killed at the end or on timeout |

On Windows, the restricted token has no privilege except bypassing traverse checking. In that token, your account's SID and every group except Everyone, Users, Authenticated Users and the sign-in's logon session can only deny access, so the sandbox keeps none of your account's rights or an administrator's.

If a toolchain folder on Windows does not already grant read access to sandboxed apps (as Windows' own folders and most of `Program Files` do by default), Open Trestle gives it a read-and-execute entry for an Open Trestle capability once, so later runs find it. Because the sandbox's token does not match your account, a toolchain folder that only your account can read (like most folders in your home) also gets a read-and-execute entry for the logon session SID of your current sign-in, not for a group that other accounts belong to. The first run after your next sign-in replaces that entry. The scratch and the AppContainer profile folder get the logon session's entry for the length of the run. A folder whose permissions only an administrator can change cannot be granted access, and its checks report that. Each grant is recorded in `~/.local/state/open-trestle/sandbox-grants` (under `XDG_STATE_HOME` when that is set), and `trestle checks off` revokes the recorded grants.

A review that runs checks first removes what earlier runs left when they were killed: scratch folders, tree copies and Go seed folders in the temporary folder that are older than an hour, and on Windows, the sandboxes' AppContainer profiles of the same age.

## Limits

Each run has 3 minutes, 4 GiB of memory (for the whole process tree on Windows, and for each process's own data on Linux), 1,024 processes (on Linux, threads count), 8 MiB each of standard output and standard error, and 2 GiB of scratch space including the tree copy. All the checks of one review share 10 minutes. Before the first Go run, the host's own Go toolchain compiles the standard library packages that the trees import (found by reading the Go files, without running anything) into a build cache. Each run starts from a copy of that cache, so a run compiles only the repository's own packages. In the sandbox, cgo is off.

On Linux, neither the total memory of all the sandbox's processes nor shared memory such as `memfd` files is bounded. Only each process's data and the scratch size are. On Linux kernels before 5.14, the process limit counts all of your account's processes, so the sandbox allows for the number already running when it starts.

On Windows, the scratch size is a measurement, not a quota. Every quarter second, Open Trestle adds up what is stored in the folders the sandbox can write, including NTFS alternate data streams. It also checks how far the free space on their volume has fallen since the run started, which also counts files deleted while still open. A burst of writes can pass the limit briefly before the run is stopped, and other programs filling the same volume during the run count too. The AppContainer's own profile folder counts toward the scratch space, because the sandbox can write there.

On Windows, the sandbox cannot change the permissions of what it has written, but Windows lets it create a folder with permissions of its own choosing, and such a folder can deny your account the right to delete it, even as its owner. Removing the scratch then fails, the review reports a scratch folder it could not remove, and only an administrator can delete that folder (with `takeown /r` and `icacls /reset /t`).

## Could not run

A check that could not run is a gap in coverage, never a pass and never a finding. The reasons are:

- The sandbox is not available. On Linux, unprivileged user namespaces can be turned off (`kernel.unprivileged_userns_clone=0` or `user.max_user_namespaces=0`) or restricted by AppArmor (`kernel.apparmor_restrict_unprivileged_userns=1`, the default since Ubuntu 24.04), and a container may not allow them. Open Trestle never runs a check without the sandbox.
- The toolchain is not installed, or the sandbox cannot see it.
- A dependency is missing. Checks run offline and never install packages, so a check cannot run when it needs a Go module missing from the module cache, a Python package that is not installed, a Node package that the tests import and that is not installed (`node_modules` is not in the commit), or a Rust crate with dependencies (the crate registry is not shown to the sandbox). A Node package's declared dependencies alone do not stop its tests: they run, and only a package that a run fails to find counts.
- On Windows, the program needs the `NUL` device, but on some systems that device grants nothing to sandboxed (AppContainer) processes. Granting that access needs an administrator, which Open Trestle does not ask for. Because the Go command opens `NUL` for every tool it starts, Go checks cannot run on such a system.
- The run passed its time, output or scratch limit on base, or the review's time for checks ran out. The same failure on head after a clean base is a regression, not a gap.
- The runner exited with an error and reported no results on base, or it reported more than 50,000 results.

Reasons that belong to one side end with "on base" or "on head".

## macOS

Checks are off on macOS, and every check reports that the sandbox is not available. See [platforms](platforms.md#macos).

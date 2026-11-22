# Platforms

Open Trestle supports Linux and Windows. macOS is not supported; see
[macOS](#macos). This page says what each system can do now, so that you
can tell a missing feature from a mistake. See the
[roadmap](roadmap.md#next-release) for what the release adds.

## What works today

| Capability | Linux amd64 (packaged install) | Linux, development build | Windows |
| --- | --- | --- | --- |
| Packaged install | Yes, [unsigned](install.md) | No | No |
| `go build` of `trestle` (reviews refused, no scan helper) | Yes | Yes | Compiles |
| Development build with the scan helper | Yes | Yes | Yes |
| Review with a model server on this machine | Yes | Yes | Yes |
| Remote providers (OpenRouter, Ollama Cloud, OpenCode Go, `ollama-signin`) | Yes | Yes | Yes |
| Secret scan helper | Yes | Yes | Yes |
| Hidden key entry | Yes | Yes | Code present, untested |
| Saving a key with `trestle keys set` | Yes | Yes | Yes |
| Protected setup, credential and usage files | Yes | Yes | Yes |
| Repository index (`trestle index`) | Yes | Yes | Yes |
| [Repository checks](repository-checks.md) sandbox | Yes, where unprivileged user namespaces are allowed | Same | Yes; Go checks cannot run unless an administrator opens the `NUL` device to sandboxed apps |
| `trestle update` | Yes | Refused | Refused |
| Home screen | Yes | Yes | Untested |

How to read the cells:

- Yes means that the code supports the capability, and that a test or a run on
  that system exercises it.
- Compiles means that continuous integration builds the binary and its tests for
  that system on amd64. It does not run them there.
- Untested means that no platform guard in the code refuses the capability, and
  that no test or recorded run exists on that system.
- Refused means that the code stops and says why.

Tested systems: end-to-end tests run a review through the real helper on Linux
amd64 and Windows amd64 (with an offline fixture provider). arm64 on Linux and
Windows builds but is untested.
The packaged install and `trestle update` are Linux amd64 only.

## Why each refusal happens

Every review scans every model request twice before it is sent, whether the
model server is on this machine or remote. The scan runs in the secret scan
helper. Snapshot investigations (`--investigation-policy`) are the exception:
their requests are not scanned, so they run only with a model server on this
machine. A plain `go build` pins no helper, so it refuses every review with
`this build pins no secret scan helper; build trestle with its helper by
python3 tools/package_secret_scanner.py --development DIR`. See
[remote model review](remote-model-review.md#prerequisite-1-a-trestle-with-its-secret-scanner).

`trestle update` is refused off Linux amd64. It updates only the packaged install,
the one with a receipt at
`/usr/local/share/open-trestle/distribution/receipt.json`, and it says so without
changing anything elsewhere. See [updates](updates.md).

## Paths

The defaults use the XDG layout (`~/.config`, `~/.local/state`,
`~/.local/share`). No separate locations exist yet for Windows. See [environment variables and files](environment-and-files.md#paths).

## Protected files on Windows

On Windows, Open Trestle checks the owner and access control list of setup,
credential, usage and repository index files instead of their mode. Apart from your account and
the system's own accounts (SYSTEM, Administrators and TrustedInstaller), no
account may read or change them, and no other account may remove, rename or
replace a folder above them. Open Trestle creates its folders and files that
way. It refuses an existing folder or file that gives another account more
access and does not change it. See
[troubleshooting](troubleshooting.md#a-folder-is-refused-as-not-private).

## macOS

macOS is not supported. Nothing in Open Trestle has run on a Mac, so nothing is
claimed to work there.

The macOS code is kept as a starting point for a port. Continuous integration
compiles the tree for macOS, so it keeps building. The parts that differ on
macOS are in files named `*_darwin.go`:

| Part | Files |
| --- | --- |
| Hidden key entry | `cmd/trestle/secret_input_darwin.go` |
| Secret scan helper: private cache and helper start | `internal/secretscan/acl_darwin.go`, `session_darwin.go`; `workers/secret-scanner/internal/scanhelper/acl_darwin.go`, `re2cache_darwin.go` |
| Syntax worker memory limit | `internal/syntaxworker/memory_darwin.go` |
| Repository checks sandbox (`sandbox-exec`) | `internal/checksandbox/sandbox_darwin.go`, `hostscratch_darwin.go`, `unlock_darwin.go`, `seatbelt.go` |

Repository checks are switched off on macOS, because a sandbox that has never
run cannot be trusted to keep your files from the tests it runs. To turn them
on, run the sandbox tests in `internal/checksandbox` on a Mac, fix what fails,
and set `verified` in `sandbox_darwin.go` to `true`.

A port also needs the whole test suite run on a Mac, and a package or
installer. See [CONTRIBUTING](../CONTRIBUTING.md).

## For the first release

The release needs a native package or installer for Windows, and
`trestle update` there. Until those exist, this page lists what works on
Windows.

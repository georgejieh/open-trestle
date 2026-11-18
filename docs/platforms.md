# Platforms

Linux, macOS and Windows all run the same review loop with the same secret scan
helper. This page says what each system can do now, so that you can tell a
missing feature from a mistake. See the [roadmap](roadmap.md#next-release) for
what the release adds.

## What works today

| Capability | Linux amd64 (packaged install) | Linux, development build | macOS | Windows |
| --- | --- | --- | --- | --- |
| Packaged install | Yes, [unsigned](install.md) | No | No | No |
| `go build` of `trestle` (reviews refused, no scan helper) | Yes | Yes | Compiles | Compiles |
| Development build with the scan helper | Yes | Yes | Builds, untested on a Mac | Yes |
| Review with a model server on this machine | Yes | Yes | Untested | Yes |
| Remote providers (OpenRouter, Ollama Cloud, OpenCode Go, `ollama-signin`) | Yes | Yes | Untested | Yes |
| Secret scan helper | Yes | Yes | Untested | Yes |
| Hidden key entry | Yes | Yes | Code present, untested | Code present, untested |
| Saving a key with `trestle keys set` | Yes | Yes | Untested | Yes |
| Protected setup, credential and usage files | Yes | Yes | Untested | Yes |
| Repository index (`trestle index`) | Yes | Yes | Untested | Yes |
| `trestle update` | Yes | Refused | Refused | Refused |
| Home screen | Yes | Yes | Untested | Untested |

How to read the cells:

- Yes means that the code supports the capability, and that a test or a run on
  that system exercises it.
- Compiles means that continuous integration builds the binary and its tests for
  that system on amd64. It does not run them there.
- Untested means that no platform guard in the code refuses the capability, and
  that no test or recorded run exists on that system.
- Refused means that the code stops and says why.

Tested systems: end-to-end tests run a review through the real helper on Linux
amd64 and Windows amd64 (with an offline fixture provider). On macOS the code
builds and vets for amd64 and arm64, but the access-list check and the helper
have not run on a real Mac. arm64 on Linux and Windows builds but is untested.
The packaged install and `trestle update` are Linux amd64 only.

## Why each refusal happens

Every review scans every model request twice before it is sent, whether the
model server is on this machine or remote. The scan runs in the secret scan
helper. A plain `go build` pins no helper, so it refuses every review with
`this build pins no secret scan helper; build it with
tools/package_secret_scanner.py`. Build with
`python3 tools/package_secret_scanner.py --development DIR` instead. See
[remote model review](remote-model-review.md#prerequisite-1-a-trestle-with-its-secret-scanner).

`trestle update` is refused off Linux amd64. It updates only the packaged install,
the one with a receipt at
`/usr/local/share/open-trestle/distribution/receipt.json`, and it says so without
changing anything elsewhere. See [updates](updates.md).

## Paths

The defaults use the XDG layout on Linux and macOS (`~/.config`,
`~/.local/state`, `~/.local/share`). No separate locations exist yet for Windows
or macOS. See [environment variables and files](environment-and-files.md#paths).

## Protected files on Windows

On Windows, Open Trestle checks the owner and access control list of setup,
credential, usage and repository index files instead of their mode. Apart from your account and
the system's own accounts (SYSTEM, Administrators and TrustedInstaller), no
account may read or change them, and no other account may remove, rename or
replace a folder above them. Open Trestle creates its folders and files that
way. It refuses an existing folder or file that gives another account more
access and does not change it. See
[troubleshooting](troubleshooting.md#a-folder-is-refused-as-not-private).

## For the first release

The release has one goal: the same review loop on all three systems. That still
needs native packages or installers for macOS and Windows, and `trestle update`
on each. Until those exist, this page lists what works on macOS and Windows.

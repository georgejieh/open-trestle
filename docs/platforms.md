# Platforms

The first release will support Linux, macOS and Windows. Today only Linux
amd64 has a tested path. This page says what each system can do now, so you can
tell a missing feature from a mistake. See the [roadmap](roadmap.md#next-release)
for what the release adds.

## What works today

| Capability | Linux amd64 (packaged install) | Linux, development build | macOS | Windows |
| --- | --- | --- | --- | --- |
| Packaged install | Yes, [unsigned](install.md) | No | No | No |
| `go build` of `trestle` | Yes | Yes | Compiles | Compiles |
| Review with a model server on this machine | Yes | Yes | Untested | Refused |
| Remote providers (OpenRouter, Ollama Cloud, OpenCode Go, `ollama-signin`) | Yes | Refused | Refused | Refused |
| Secret scanner | Yes, sandboxed | None | None | None |
| Hidden key entry | Yes | Yes | Code present, untested | Code present, untested |
| Saving a key with `trestle keys set` | Yes | Yes | Untested | Refused |
| Protected setup, credential and usage files | Yes | Yes | Untested | Refused |
| `trestle update` | Yes | Refused | Refused | Refused |
| Home screen | Yes | Yes | Untested | Untested |

How to read the cells:

- **Yes** means the code supports it and a test or a run on Linux exercises it.
- **Compiles** means continuous integration builds the binary and its tests for
  that system on amd64. It does not run them there.
- **Untested** means the code has no platform guard that refuses it, and no
  test or recorded run exists on that system.
- **Refused** means the code stops and says why.

## Why each refusal happens

- **Remote providers off the packaged Linux install.** Every request to a remote
  route passes two scans in a sandboxed secret scanner before it leaves the
  machine. The scanner exists only for Linux amd64, and a plain `go build` has
  no scanner digests, so the check fails closed. The message is
  `sandboxed secret scanner is available only on Linux` or names the missing
  install. See
  [remote model review](remote-model-review.md#prerequisite-1-a-scanner-bound-binary-and-installed-scanner).
- **Protected files on Windows.** Setup, credential and usage files are checked
  for owner and mode (`0700` folders, `0600` files). Windows has no ownership
  check yet, so the check cannot pass and the files are refused. Saving a key
  is refused; a typed key lasts for that session only. The release will use
  access control lists. See [API keys](keys.md#threat-model).
- **`trestle update` off Linux amd64.** It updates only the packaged install, the
  one with a receipt at `/usr/local/share/open-trestle/distribution/receipt.json`,
  and says so without changing anything elsewhere. See [updates](updates.md).

## Paths

The defaults use the XDG layout on Linux and macOS (`~/.config`,
`~/.local/state`, `~/.local/share`). No separate Windows or macOS locations
exist yet. See [environment variables and files](environment-and-files.md#paths).

## For the first release

The release keeps one scope: the same loop on all three systems. That means a
secret scanner that runs on each, protected files on Windows with access control
lists, native packages or installers for macOS and Windows, and `trestle
update` on each. Until those exist, treat this page as the whole truth for
macOS and Windows.

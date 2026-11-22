# Install

This page shows how to get a `trestle` binary, update it, and remove it. Nothing
is released yet, so there is no download page, package manager entry or signed
installer. Today there are two ways to get a binary, and the one you need depends
on where the models run.

| You want | Use | Systems |
| --- | --- | --- |
| Any model, on your machine or remote (Ollama, llama.cpp, vLLM, LM Studio, OpenRouter, Ollama Cloud, OpenCode Go) | A development build | Linux or Windows; see [platforms](platforms.md) |
| The same, as an installed package | The packaged Linux amd64 install | Linux amd64 only |

Planned for the first release: a native package or installer for Windows,
and `trestle update` there. See the [roadmap](roadmap.md#next-release).

## A development build

You need a clone of this repository, Go 1.26.11 and Python 3.

```sh
python3 tools/package_secret_scanner.py --development DIR
DIR/bin/trestle build-info
```

This writes `DIR/bin/trestle`, `DIR/bin/trestled` and the secret scan helper at
`DIR/libexec/open-trestle/open-trestle-scan-helper` (`.exe` names on Windows).
Keep the helper where it is: the program looks for it at
`../libexec/open-trestle/open-trestle-scan-helper` next to its own folder.
`DIR` is relative to the current directory. Add `--target GOOS/GOARCH` to build
for another system. Run `DIR/bin/trestle` by its path. A plain `go build` pins no
helper, so the program it makes refuses every review. Then continue with
[getting started](getting-started.md).

## The packaged Linux amd64 install

The package places `trestle`, `trestled` and the secret scan helper under
`/usr/local`, owned by root. Every request is scanned before it leaves the
machine, and the helper is the program that scans it.

You build the package from a clean committed checkout, because no prebuilt,
signed archive exists yet. The build, the checks to run first and the install
commands are in
[operations](operations.md#build-and-inspect-the-unsigned-linux-amd64-candidate).
In short:

1. Build the scanner staging tree and run the passive
   [vulnerability gate](vulnerability-gate.md).
2. Build the archive with `tools/linux_distribution.py`. It writes
   `open-trestle-linux-amd64.pyz` and a `.sha256` file.
3. Check the digest against one that you obtained through a separate trusted
   channel: `sha256sum -c open-trestle-linux-amd64.pyz.sha256`. The archive is
   unsigned, and its checksum alone does not say who built it.
4. Install and verify:

   ```sh
   sudo ./open-trestle-linux-amd64.pyz install
   sudo ./open-trestle-linux-amd64.pyz verify-installed
   ```

Installing needs root and writes only below `/usr/local`. It does not start a
service and creates no configuration.

## Update

On the packaged install, one command updates:

```sh
trestle update
```

The command finds a newer version, shows it, asks you to confirm, and runs that
version's own `upgrade` with `sudo`. No release is signed yet, so today it
installs only an unsigned local build left in
`~/.local/share/open-trestle/updates/`, or a file named with `--from`.
`trestle update --check` reports without installing. See [updates](updates.md).

## Remove

```sh
sudo /usr/local/libexec/open-trestle/open-trestle-distribution.pyz uninstall
```

The `rollback-version` action returns to the build that the last upgrade
replaced, and `rollback` is the other complete removal action. See
[the lifecycle](operations.md#candidate-lifecycle). Your setup folders, saved
keys and usage records stay where they are; see
[environment variables and files](environment-and-files.md#paths).

## Check the install

```sh
trestle build-info
trestle --help
```

If a command is not found or a step is refused, see
[troubleshooting](troubleshooting.md).

# Install

Nothing is released yet, so there is no download page, package manager entry or
signed installer. Today there are two ways to get a `trestle` binary. Which one
you need depends on where the models run.

| You want | Use | Systems |
| --- | --- | --- |
| A model server on your machine (Ollama, llama.cpp, vLLM, LM Studio) | A development build | Linux; see [platforms](platforms.md) for the others |
| OpenRouter, Ollama Cloud, OpenCode Go, or Ollama signed in to Ollama Cloud | The packaged Linux amd64 install | Linux amd64 only |

Other systems are planned for the first release: native packages or
installers for macOS and Windows, a secret scanner that runs there, and
`trestle update` on each. See the [roadmap](roadmap.md#next-release).

## A development build

You need a clone of this repository and Go. `go.mod` names the Go version.

```sh
go build -o trestle ./cmd/trestle
./trestle build-info
```

Run it by its path, or put it on your `PATH`. A plain `go build` has no secret
scanner, so it works with a model server on your machine and refuses to send
source to a remote provider. Then continue with
[getting started](getting-started.md).

## The packaged Linux amd64 install

The package places `trestle`, `trestled` and the sandboxed secret scanner under
`/usr/local`, owned by root. Remote providers need it, because every request is
scanned before it leaves the machine.

The package is built from a clean committed checkout; no prebuilt, signed
archive exists yet. The build, the checks to run first and the install
commands are in
[operations](operations.md#build-and-inspect-the-unsigned-linux-amd64-candidate).
In short:

1. Build the scanner staging tree and run the passive
   [vulnerability gate](vulnerability-gate.md).
2. Build the archive with `tools/linux_distribution.py`. It writes
   `open-trestle-linux-amd64.pyz` and a `.sha256` file.
3. Check the digest against one you obtained through a separate trusted
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

It finds a newer version, shows it, asks, and runs that version's own
`upgrade` with `sudo`. No release is signed yet, so today it installs an
unsigned local build left in `~/.local/share/open-trestle/updates/`, or a file
named with `--from`. `trestle update --check` reports without installing. See
[updates](updates.md).

## Remove

```sh
sudo /usr/local/libexec/open-trestle/open-trestle-distribution.pyz uninstall
```

`rollback-version` returns to the build the last upgrade replaced, and
`rollback` is the other complete removal action. See
[the lifecycle](operations.md#candidate-lifecycle).
Your setup folders, saved keys and usage records stay where they are; see
[environment variables and files](environment-and-files.md#paths).

## Check the install

```sh
trestle build-info
trestle --help
```

If a command is not found or a step is refused, see
[troubleshooting](troubleshooting.md).

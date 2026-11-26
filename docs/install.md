# Install

This page shows how to install `trestle`, update it, and remove it.

## Install with one command

On Linux (amd64):

```sh
curl -fsSL https://georgejieh.dev/open-trestle/install.sh | bash
```

On Windows (amd64), in PowerShell:

```powershell
irm https://georgejieh.dev/open-trestle/install.ps1 | iex
```

Then, inside the Git repository you want reviewed, run `trestle init`. See
[getting started](getting-started.md).

The scripts install the newest release from
[GitHub Releases](https://github.com/georgejieh/open-trestle/releases),
pre-releases included, for your account only. They need no administrator
rights. Apart from the folders below, they change only your user `PATH` on
Windows.

The first releases are unsigned pre-releases. The script checks each download
against the release's `SHA256SUMS` file, which shows only that the download
matches the files of that release. It does not show who built them. To read a
script before you run it, download it first:

```sh
curl -fsSLO https://raw.githubusercontent.com/georgejieh/open-trestle/main/install.sh
less install.sh
bash install.sh
```

### What the scripts do

| | Linux | Windows |
| --- | --- | --- |
| Program folder | `~/.local/share/open-trestle/<version>/` (`$XDG_DATA_HOME/open-trestle` when set), with a `current` link to it | `%LOCALAPPDATA%\Programs\OpenTrestle\<version>\` |
| On your `PATH` | links to `trestle` and `trestled` in `~/.local/bin` | `<version>\bin` added to your user `PATH` |
| Access | not writable by group or others | only your account, SYSTEM and Administrators |

Each run:

1. finds the newest release, or the one you name;
2. downloads the archive for your system and `SHA256SUMS`, and stops if the
   SHA-256 does not match;
3. unpacks it next to the installed version, checks that the secret scan helper
   has the permissions Open Trestle requires, and runs `trestle build-info`,
   which must report the expected version;
4. switches to the new version, then removes the previous one.

Running the script again with the same version keeps the installed files. If a
check fails before the switch, the version you had stays in place; if the new
version does not start after the switch, the script switches back to it. If `~/.local/bin` is not on your
`PATH`, the Linux script prints the line to add. Each run writes its log to
`install.log` beside the version folders.

### Options

| Linux | Windows | Effect |
| --- | --- | --- |
| `--version 0.1.0-alpha.1` or `OPEN_TRESTLE_VERSION` | `-Version 0.1.0-alpha.1` or `OPEN_TRESTLE_VERSION` | Install this release instead of the newest. |
| `--uninstall` | `-Uninstall` or `OPEN_TRESTLE_UNINSTALL=1` | Remove what the script installed. |
| `OPEN_TRESTLE_INSTALL_ROOT`, `OPEN_TRESTLE_BIN_DIR` | `OPEN_TRESTLE_INSTALL_ROOT` | Use other folders. |
| | `-NoModifyPath` or `OPEN_TRESTLE_NO_MODIFY_PATH=1` | Show the `PATH` change without making it. |

Options go after `bash -s --` when you pipe the script, for example
`curl -fsSL https://georgejieh.dev/open-trestle/install.sh | bash -s -- --uninstall`.
Under `irm | iex`, set the environment variable first, for example
`$env:OPEN_TRESTLE_VERSION = '0.1.0-alpha.1'`. `NO_COLOR` turns off colour.

macOS is not supported. Releases are built for amd64 only; on arm64, build from
source. See [platforms](platforms.md).

## Build from source

You need a clone of this repository, Go 1.26.11 and Python 3, on Linux or
Windows.

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
helper, so the program it makes refuses every review.

## The packaged Linux amd64 install

The package places `trestle`, `trestled` and the secret scan helper under
`/usr/local`, owned by root, and is the install that `trestle update` updates.
Each release includes it as `open-trestle-linux-amd64.pyz` with a `.sha256`
file. To build it yourself from a clean committed checkout, see
[operations](operations.md#build-and-inspect-the-unsigned-linux-amd64-candidate).

1. Check the digest: `sha256sum -c open-trestle-linux-amd64.pyz.sha256`. The
   archive is unsigned, and its checksum alone does not say who built it.
2. Install and verify:

   ```sh
   chmod +x open-trestle-linux-amd64.pyz
   sudo ./open-trestle-linux-amd64.pyz install
   sudo ./open-trestle-linux-amd64.pyz verify-installed
   ```

Installing needs root and writes only below `/usr/local`. It does not start a
service and creates no configuration.

## Update

For an install made by the scripts, run the same command again. It installs
the newest release and keeps your setup. `trestle update` says so too:

```text
trestle update: this is Open Trestle 0.1.0-alpha.1 from a release archive, and trestle update updates only the packaged Linux amd64 install. To update, run the installer again:
  curl -fsSL https://georgejieh.dev/open-trestle/install.sh | bash
```

On the packaged install, `trestle update` finds a newer version, shows it, asks
you to confirm, and runs that version's own `upgrade` with `sudo`. No release is
signed yet, so today it installs only an unsigned local build left in
`~/.local/share/open-trestle/updates/`, or a file named with `--from`. See
[updates](updates.md).

## Remove

For an install made by the scripts:

```sh
curl -fsSL https://georgejieh.dev/open-trestle/install.sh | bash -s -- --uninstall
```

```powershell
$env:OPEN_TRESTLE_UNINSTALL = '1'; irm https://georgejieh.dev/open-trestle/install.ps1 | iex
```

It removes the program folders, the links or the `PATH` entry, and nothing
else. On Windows, if you turned on [repository checks](repository-checks.md),
run `trestle checks off` first: it takes back the folder grants the checks
made, and the uninstall refuses while their record exists.

For the packaged install:

```sh
sudo /usr/local/libexec/open-trestle/open-trestle-distribution.pyz uninstall
```

The `rollback-version` action returns to the build that the last upgrade
replaced, and `rollback` is the other complete removal action. See
[the lifecycle](operations.md#candidate-lifecycle).

Your setup folders, saved keys and usage records stay where they are in every
case; see [environment variables and files](environment-and-files.md#paths).

## Check the install

```sh
trestle --version
trestle --help
```

`build-info` prints the version, for a release, and the source revision. If a
command is not found or a step is refused, see
[troubleshooting](troubleshooting.md).

# Updates

To update an install made by the [install scripts](install.md#install-with-one-command),
run the install command again. It replaces your version with the newest release
and keeps your setup. In such an install, `trestle update` changes nothing and
prints that command:

```text
trestle update: this is Open Trestle 0.1.0-alpha.1 from a release archive, and trestle update updates only the packaged Linux amd64 install. To update, run the installer again:
  curl -fsSL https://georgejieh.dev/open-trestle/install.sh | bash
```

On Windows it prints `irm https://georgejieh.dev/open-trestle/install.ps1 | iex`.
It exits with status 1. The rest of this page covers the packaged install.

For the packaged Linux amd64 install, `trestle update` does the whole update.
It finds the newer version, shows it, asks you to confirm, runs that build's own
upgrade with `sudo`, and reports the result:

```sh
trestle update
```

```text
Open Trestle · update
  Installed: 0.1.0, the packaged Linux amd64 install.
  ✓ Update available: 0.2.0, the signed release v0.2.0 on
    GitHub Releases.
  … Downloading 70.5 MiB and checking it.
  ✓ Verified the copy: signed with release key
    1a2b3c4d5e6f7a8b, with the signed SHA-256 and size, and
    its own verify-archive passed.
  Installing needs administrator rights. This command runs:
    /usr/bin/sudo -- /tmp/open-trestle-update-123/open-trestle-linux-amd64.pyz upgrade
  Install 0.2.0 now? (y/N): y
  ✓ Open Trestle is now 0.2.0 (source revision 1a2b3c4d5e6f).
```

On a terminal, the download and the archive check show a spinner with the elapsed
time instead of the `Downloading` line. When standard error is not a terminal,
the plain lines above are printed.

`sudo` asks for your password on the same terminal. The "Update Open Trestle"
item on the home screen (`trestle` in a terminal) runs the same command.

| Command | What it does |
| --- | --- |
| `trestle update` | Find, show, ask, install, report. |
| `trestle update --check` | Report only. Downloads nothing but the release list and the signature. |
| `trestle update --yes` | Install without asking, for scripts. |
| `trestle update --channel auto\|release\|local` | Choose where to look (default `auto`, below). |
| `trestle update --from FILE` | Install the archive `FILE`, with `FILE.sha256` beside it. |

The command updates only the packaged install, the one whose receipt is
`/usr/local/share/open-trestle/distribution/receipt.json`. Without that receipt,
or on a platform other than Linux amd64, it says so and changes nothing. To
install the package the first time, see
[operations](operations.md#candidate-lifecycle). For the exit codes of
`trestle update` and `trestle update --check`, see
[exit codes](exit-codes.md#trestle-update).

## Where it looks

The command can look in GitHub Releases, in a local update folder, or at a file
you name.

### GitHub Releases

The release channel is the default. It reads the releases of
`georgejieh/open-trestle` in one unauthenticated request,
`GET https://api.github.com/repos/georgejieh/open-trestle/releases?per_page=20`,
bounded to 4 MiB. A release qualifies only when all of these hold:

- Its tag is `v` followed by a SemVer version.
- It is not a draft.
- It has exactly one uploaded asset of each of the three names below, at this
  repository's release download address for that tag.

The three assets are:

- `open-trestle-linux-amd64.pyz`, the archive;
- `open-trestle-linux-amd64.pyz.sha256`, its SHA-256 sidecar;
- `open-trestle-linux-amd64.pyz.sig`, its signature.

Open Trestle offers the newest qualifying release that is strictly newer than
the installed version, and offers a prerelease only to a prerelease install. The API request may not be redirected away from `api.github.com`.
The asset downloads may be redirected only to GitHub's asset hosts
(`objects.githubusercontent.com`, `release-assets.githubusercontent.com`), always
over HTTPS. The requests honor `HTTPS_PROXY` and carry no credential, cookie or
identifier. GitHub sees the address they come from and a fixed
`User-Agent: open-trestle-update`.

A build verifies releases only with the Ed25519 keys pinned in it (see
[verification](#verification)). A build with no pinned key refuses the release
channel with:

```text
trestle update: this build cannot verify releases; install the packaged release. Nothing was changed.
```

### The local update folder

The local channel is a folder that only you can open:
`$XDG_DATA_HOME/open-trestle/updates/` when `XDG_DATA_HOME` is an absolute path,
otherwise `~/.local/share/open-trestle/updates/`. It holds
`open-trestle-linux-amd64.pyz` and `open-trestle-linux-amd64.pyz.sha256`, as
`tools/linux_distribution.py` writes them. A maintainer hands over a development
build by putting the pair there, and the owner then runs `trestle update`.

```sh
install -d -m 0700 ~/.local/share/open-trestle/updates
cp open-trestle-linux-amd64.pyz open-trestle-linux-amd64.pyz.sha256 ~/.local/share/open-trestle/updates/
```

The folder must be mode `0700`. It and its parents must be owned by you (or root)
and not writable by others. The two files must be regular files, not symbolic
links, owned by you or root, and not writable by group or others. Open Trestle
refuses anything else and gives the reason, for example
`must be private (mode 0700, not 0755)` or `is a symbolic link`.

The local folder is read only for a development install (a version containing
`-dev`, such as `0.1.5-dev`) or with `--channel local`. The build is shown as
unsigned and local:

```text
  … Update available: 0.1.6-dev, an unsigned local build in
    ~/.local/share/open-trestle/updates.
    It is not signed by a release key, so only its SHA-256
    sidecar and its own verify-archive are checked. Install
    it only if you built it or trust whoever put it there.
```

A local build is offered only if it is strictly newer than the installed version.
With `--channel auto` on a development install, it checks both
places, and the higher version wins. A signed release wins a tie. If the build
cannot verify releases, the release channel is skipped with a note and the local
folder still counts.

### A file you name

`--from FILE` installs one archive that you downloaded or built. The file name
may use letters, digits, dots, dashes or underscores and must end in `.pyz`.
`FILE.sha256` must sit beside it. Open Trestle treats it as a local
build. If `FILE.sig` is also beside it and this build pins a key, the signature
must verify and match the archive, or nothing is installed. Without a pinned key,
the `.sig` is reported as not checked.

## Verification

A release is signed with Ed25519 over a statement. The statement is canonical
JSON with sorted keys and no spaces, preceded by the domain prefix
`open-trestle-release-statement-v1` and a zero byte:

```json
{"archive":"open-trestle-linux-amd64.pyz","archive_sha256":"<64 hex>","archive_size":73959613,"contract":"open-trestle/release-statement","schema_version":1,"tag":"v0.2.0","target":"linux-amd64","version":"0.2.0"}
```

The signature file `open-trestle-linux-amd64.pyz.sig` is canonical JSON with one
trailing newline:

```json
{"contract":"open-trestle/release-signature","key_id":"<16 hex>","schema_version":1,"signature":"<base64 of 64 bytes>","statement":{...}}
```

`key_id` is the first 16 hexadecimal digits of the SHA-256 of the raw 32-byte
public key. Open Trestle refuses a signature file, and uses nothing in it, if
any of these is true:

- The file is not canonical.
- It names a key that this build does not pin.
- The signature does not verify.
- Its statement names another archive or target, or a tag that is not `v` plus
  the version.
- Its statement names a size over 256 MiB.

The public keys are pinned in `internal/update/release_keys.txt`, which every
build embeds, with one `ed25519 <base64>` line per key. More than one key may be
listed while a key is rotated: add the new key, sign releases with it, and remove
the old key in a later release.

## Threat model

`trestle update` is designed so that:

- A changed or substituted download is not installed. A release archive is
  installed only when its bytes match the SHA-256 and size in a statement
  signed by a pinned key, so controlling GitHub's API, an asset host, a proxy or
  the network is not enough.
- An older version cannot be pushed in. Only a strictly newer SemVer version
  qualifies, here and in the lifecycle that runs as root.
- Another version cannot be passed off as this one. The statement binds the
  version, target, tag and archive name, and the archive's own manifest must
  agree.
- Candidate code runs only after Go verification, and the root step runs a fixed
  command on the rechecked copy (see [the order of checks](#the-order-of-checks)).
- The update check sends nothing about you. The notice makes only the release list
  request.

It does not protect against the following:

- A program running as your account. It could change the private folder's copy
  after the last recheck, or change your local update folder, your shell or
  `trestle` itself. The
  [credential store](keys.md#threat-model) has the same boundary.
- An unsigned local build or `--from` file. Its sidecar detects accidental
  change, not a deliberate one, because whoever can write the archive can write
  the sidecar.
- A compromised signing key, or a malicious release signed with a pinned key.
  Rotate the key through a reviewed change to `release_keys.txt`.
- Root, or a compromised `sudo`. Root is outside the host trust model, as for the
  [lifecycle](operations.md#candidate-lifecycle).
- A withheld update. Someone who controls the network can hide a newer release,
  and the check then reports only what it could see.

### The order of checks

Open Trestle's own Go code checks a candidate completely before any of the
candidate's code runs. The steps are:

1. Read the installed version from the receipt. The receipt must be a regular
   mode-`0444` file owned by root, beneath folders that no other account can
   change.
2. Choose the candidate. For a release, use the release list above. For a local
   build, use the folder and the ownership and permission checks above. Nothing
   beyond the list is downloaded yet.
3. Find `sudo` at `/usr/bin/sudo` or `/bin/sudo`, owned by root and not writable
   by others. Your `PATH` is not searched. If you run as root, `sudo` is not
   used.
4. Make a mode `0700` private folder named `open-trestle-update-*` under `$TMPDIR`
   (default `/tmp`).
5. For a release only, verify the signature in Go before anything else is
   downloaded, by the rules under [Verification](#verification). The statement
   must name this archive, target, tag and version.
6. Copy the candidate into the private folder. Download the sidecar and the
   archive (bounded to the signed size), or copy the local pair.
7. Verify the copy in Go. Its SHA-256 must match its sidecar. For a release, its
   SHA-256 and size must equal the signed ones, and its manifest must name the
   signed version and target. The manifest version must still be strictly newer
   than the installed one.
8. Recheck that the folder is the same private folder and that the copy still has
   the verified bytes.
9. Run the copy's own `verify-archive` as you, with a fixed `PATH` and locale.
   This is the first time any code from the candidate runs.
10. Print the exact command and ask. Without a terminal and without `--yes`, the
    command stops before downloading anything.
11. Recheck the folder and the copy again, then run exactly
    `/usr/bin/sudo -- <private folder>/open-trestle-linux-amd64.pyz upgrade`
    (for `--from`, the copy keeps the file's checked name) on your terminal, with
    a fixed `PATH`, `LANG=C` and your `TERM`. Nothing from a release's name, notes,
    tag or assets, or from your environment, reaches the arguments. The lifecycle
    enforces the strictly-newer, same-target rule again as root and keeps the
    previous version for `rollback-version`.
12. Report the result. Open Trestle reads the receipt again and shows the version
    it names. It runs the new `/usr/local/bin/trestle build-info` for the source
    revision only when that file is owned by root, is not writable by others, and
    is exactly the file (SHA-256 and size) that the new receipt names. If a
    process named `trestled` is running, the report says to restart it.
13. Remove the private folder, on every path.

If `$TMPDIR` is on a `noexec` mount, the copy cannot run. Set `TMPDIR` to a
folder on an executable file system and run the command again.

## The update notice

When a newer version is available and its output is a terminal, `trestle review`
shows one line after the review:

```text
  Update available: 0.2.0 (you have 0.1.0). Run trestle update.
```

The home screen (`trestle` in a terminal) shows it as the card's last row,
`Update … available: 0.2.0 (you have 0.1.0)`, with `-> trestle update` beneath
it. `trestle status` and `trestle doctor` show the same notice from the cache and
never ask for a new one.

For a development install with a newer build in the local folder, the notice is:

```text
  Update available: 0.1.6-dev, an unsigned local build (you have 0.1.5-dev). Run trestle update.
```

The notice works as follows.

- It reads the release list at most once every 24 hours and keeps the newest
  versions in `update-check.json`, a private `0600` file in the state folder
  (`$XDG_STATE_HOME/open-trestle/`, default `~/.local/state/open-trestle/`). It
  waits at most 3 seconds and says nothing when GitHub cannot be reached. After a
  failed check, it waits a day before asking again and keeps showing what it last
  knew.
- It checks releases only when this build pins a key and the state folder is
  usable, and the local folder only for a development install. It never downloads
  an archive or a signature.
- `OPEN_TRESTLE_UPDATE_CHECK=off` turns the notice off. `trestle update` itself
  still checks when you run it.

## What is not signed yet

No release key is listed in `internal/update/release_keys.txt` yet, and the
pre-releases that the release workflow publishes are unsigned. They carry no
`.sig`, so they do not qualify for the release channel. Until the release phase
adds a key and publishes signed releases, every build refuses the release
channel, and only the local folder and `--from` work, unsigned. Release
provenance, SBOM attestation and signer identity beyond the pinned key are not
yet published.

## Signing a release

The release phase signs each archive offline with `tools/signrelease`. It uses an
Ed25519 private key in a PKCS#8 PEM file that only its owner can read, for
example one made with `openssl genpkey -algorithm ed25519`. The tool needs Go and
makes no network request:

```sh
go run ./tools/signrelease public-key --key release-key.pem      # the line for release_keys.txt
go run ./tools/signrelease sign --key release-key.pem \
  --archive dist/open-trestle-linux-amd64.pyz --tag v0.2.0      # writes dist/open-trestle-linux-amd64.pyz.sig
go run ./tools/signrelease verify --keys internal/update/release_keys.txt \
  --archive dist/open-trestle-linux-amd64.pyz
```

`sign` checks that the archive is named `open-trestle-linux-amd64.pyz`, that its
sidecar matches, and that its manifest version is the tag without the `v`. It
does not replace an existing `.sig`. A release then uploads the archive, the
sidecar and the `.sig` as three assets of the tag's release.

Adding the key to `release_keys.txt`, keeping the private key, and adding a
signing step to `.github/workflows/release.yml` are release-phase steps that
need the maintainer's approval and secrets. The workflow has no signing step yet.

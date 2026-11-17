# Updates

`trestle update` installs a newer build of the packaged Linux amd64 install in
one step. It finds the newer version, shows it to you, asks for confirmation,
runs that build's own upgrade with `sudo`, and reports the result:

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

`sudo` asks for your password on the same terminal. From the home screen
(`trestle` in a terminal), "Update Open Trestle" runs the same command, so an
update takes two steps there too.

| Command | What it does |
| --- | --- |
| `trestle update` | Find, show, ask, install, report. |
| `trestle update --check` | Report only: download nothing but the release list and the signature. |
| `trestle update --yes` | Install without asking, for scripts. |
| `trestle update --channel auto\|release\|local` | Choose where to look (default `auto`, below). |
| `trestle update --from FILE` | Install the archive `FILE`, with `FILE.sha256` beside it. |

The command updates only the packaged install, the one whose receipt is
`/usr/local/share/open-trestle/distribution/receipt.json`. Without that receipt,
or on a platform other than Linux amd64, it says so and changes nothing. To
install the package the first time, see
[operations](operations.md#candidate-lifecycle).

## Exit codes

| Code | `trestle update` | `trestle update --check` |
| --- | --- | --- |
| `0` | Updated, already up to date, or you answered no. | Nothing newer was found where it looked. |
| `10` | Not used. | A newer version is available; for a release, its signature verified. |
| `1` | Not installed as a package, a check failed, GitHub could not be read, or the upgrade failed. | Not installed as a package, a check failed, or GitHub could not be read. |
| `2` | A usage error, or no terminal to confirm and no `--yes`. | A usage error. |

## Where it looks

The command can look in three places: GitHub Releases, a local update folder, or
a file that you name.

### GitHub Releases

The release channel is the default. It reads the releases of
`georgejieh/open-trestle` with one unauthenticated request,
`GET https://api.github.com/repos/georgejieh/open-trestle/releases?per_page=20`,
bounded to 4 MiB. A release qualifies only when all of these hold:

- its tag is `v` followed by a SemVer version;
- it is not a draft;
- it has exactly one uploaded asset of each of the three names below, at this
  repository's release download address for that tag.

The three assets are:

- `open-trestle-linux-amd64.pyz`, the archive;
- `open-trestle-linux-amd64.pyz.sha256`, its SHA-256 sidecar;
- `open-trestle-linux-amd64.pyz.sig`, its signature.

Open Trestle offers the newest qualifying release that is strictly newer than
the installed version. It offers a prerelease only to an install that is itself a
prerelease. The API request may not be redirected off `api.github.com`, and the
asset downloads may be redirected only to GitHub's asset hosts
(`objects.githubusercontent.com`, `release-assets.githubusercontent.com`), always
over HTTPS. The requests honor `HTTPS_PROXY`. They carry no credential, cookie or
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
`tools/linux_distribution.py` writes them. This is how a maintainer hands over a
development build: they put the pair there, and the owner types
`trestle update`.

```sh
install -d -m 0700 ~/.local/share/open-trestle/updates
cp open-trestle-linux-amd64.pyz open-trestle-linux-amd64.pyz.sha256 ~/.local/share/open-trestle/updates/
```

The folder must be mode `0700`, and it and its parents must be owned by you (or
root) and not writable by others. The two files must be regular files, not
symbolic links, owned by you or root, and not writable by group or others. Open
Trestle refuses anything else and gives the reason, for example
`must be private (mode 0700, not 0755)` or `is a symbolic link`.

Open Trestle reads the local folder only when the installed version is a
development version (its version contains `-dev`, such as `0.1.5-dev`), or when
you pass `--channel local`. It shows the build as an unsigned local build:

```text
  … Update available: 0.1.6-dev, an unsigned local build in
    ~/.local/share/open-trestle/updates.
    It is not signed by a release key, so only its SHA-256
    sidecar and its own verify-archive are checked. Install
    it only if you built it or trust whoever put it there.
```

Open Trestle does not offer a local build that is not strictly newer than the
installed version. With `--channel auto` on a development install, it checks both
places and the higher version wins; a signed release wins a tie. If that build
cannot verify releases, the release channel is skipped with a note, and the local
folder still counts.

### A file you name

`--from FILE` installs one archive that you downloaded or built. The file name
may use letters, digits, dots, dashes or underscores and must end in `.pyz`, and
`FILE.sha256` must sit beside it. Open Trestle checks it as a local build. When
`FILE.sig` is beside it and this build pins a key, the signature must verify and
match the archive, or nothing is installed. Without a pinned key, the `.sig` is
reported as not checked.

## Verification

A release is signed with Ed25519 over a statement, which is canonical JSON with
sorted keys and no spaces, after the domain prefix
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
public key. Open Trestle refuses a signature file, and uses nothing it says, if
any of these is true:

- the file is not canonical;
- it names a key that this build does not pin;
- the signature does not verify;
- its statement names another archive or target, or a tag that is not `v` plus
  the version;
- its statement names a size over 256 MiB.

The public keys are pinned in `internal/update/release_keys.txt`, which every
build embeds, with one `ed25519 <base64>` line per key. More than one key may be
listed while a key is rotated: add the new key, sign releases with it, and remove
the old key in a later release. No key is listed yet, so every current build
refuses the release channel.

## Threat model

`trestle update` is designed so that:

- A changed or substituted download is not installed. Open Trestle installs a
  release archive only when its bytes match the SHA-256 and size in a statement
  signed by a pinned key. Control of GitHub's API, an asset host, a proxy or the
  network is not enough.
- An older version cannot be pushed in. Only a strictly newer SemVer version
  qualifies, both here and in the lifecycle that runs as root.
- Another version cannot be passed off as this one. The statement binds the
  version, the target, the tag and the archive name, and the archive's own
  manifest must agree.
- Candidate code runs only after Go verification. The root step runs a fixed
  command on the verified copy in a private folder that is rechecked just before
  it runs (see [the order of checks](#the-order-of-checks)).
- The update check sends nothing about you. The only request the notice makes is
  the release list GET.

It does not protect against the following:

- A program running as your account. It could change the private folder's copy
  between the last recheck and the moment `sudo` starts it, or change your local
  update folder, your shell or `trestle` itself. This is the same boundary as the
  [credential store](keys.md#threat-model).
- An unsigned local build or `--from` file. Its sidecar detects accidental
  change, not a deliberate one, because whoever can write the archive can write
  the sidecar. Install one only if you built it or trust whoever put it there.
- A compromised signing key, or a malicious release signed with a pinned key.
  Rotate the key through a reviewed change to `release_keys.txt`.
- Root, or a compromised `sudo`. Root is outside the host trust model, as for the
  [lifecycle](operations.md#candidate-lifecycle).
- A withheld update. Someone who controls the network can hide a newer release,
  and the check then reports what it could see.

### The order of checks

Open Trestle's own Go code checks a candidate completely before any code from the
candidate runs. The steps are:

1. Read the installed version from the receipt. The receipt must be a regular
   mode-`0444` file owned by root, beneath folders that no other account can
   change.
2. Choose the candidate. For a release, use the release list above. For a local
   build, use the folder and the file ownership and permission checks above. Nothing
   is downloaded yet beyond the list.
3. Find `sudo` at `/usr/bin/sudo` or `/bin/sudo`, owned by root and not writable
   by others. Your `PATH` is not searched. When you run as root, no `sudo` is
   used.
4. Make a private folder named `open-trestle-update-*` under `$TMPDIR` (default
   `/tmp`), with mode `0700`.
5. For a release only, verify the signature in Go before anything else is
   downloaded. The `.sig` must be canonical, name a pinned key and verify with
   it, and its statement must name this archive, target, tag and version.
6. Copy the candidate into the private folder: download the sidecar and the
   archive (bounded to the signed size), or copy the local pair.
7. Verify the copy in Go, after copying. The copy's SHA-256 must match its
   sidecar. For a release, the copy's SHA-256 and size must equal the signed
   ones, and its manifest must name the signed version and target. The copy's own
   manifest version must still be strictly newer than the installed one.
8. Recheck that the folder is the same private folder and that the copy still has
   the verified bytes.
9. Run the copy's own `verify-archive` as you, with a fixed `PATH` and locale.
   This is the first time any code from the candidate runs.
10. Print the exact command and ask. Without a terminal and without `--yes`, the
    command stops before downloading anything.
11. Recheck the folder and the copy again, then run exactly
    `/usr/bin/sudo -- <private folder>/open-trestle-linux-amd64.pyz upgrade`
    (for `--from`, the copy keeps the file's checked name) on your terminal, with
    a fixed `PATH`, `LANG=C` and your `TERM`. The arguments are fixed: nothing
    from a release's name, notes, tag or assets, or from your environment,
    reaches them. The lifecycle enforces the strictly-newer, same-target rule
    again as root and keeps the previous version for `rollback-version`.
12. Report the result. Open Trestle reads the receipt again and shows the version
    it names. The new `/usr/local/bin/trestle build-info` runs for the source
    revision only when that file is owned by root, is not writable by others, and
    is exactly the file (SHA-256 and size) that the new receipt names. If a
    process named `trestled` is running, the report says to restart it.
13. Remove the private folder, on every path.

If the copy cannot run because `$TMPDIR` is on a `noexec` mount, set `TMPDIR` to a
folder on an executable file system and run the command again.

## The update notice

The home screen (`trestle` in a terminal) shows one line when a newer version is
available, and `trestle review` shows it after the review when its output is a
terminal:

```text
  Update available: 0.2.0 (you have 0.1.0). Run trestle update.
```

For a development install with a newer build in the local folder:

```text
  Update available: 0.1.6-dev, an unsigned local build (you have 0.1.5-dev). Run trestle update.
```

The notice works as follows.

- It reads the release list at most once every 24 hours and keeps the newest
  versions in `update-check.json` in the state folder
  (`$XDG_STATE_HOME/open-trestle/`, default `~/.local/state/open-trestle/`), a
  private `0600` file. It waits at most 3 seconds and says nothing when GitHub
  cannot be reached. After a failed check, it waits a day before asking again and
  keeps showing what it last knew.
- It checks releases only when this build pins a key and the state folder is
  usable, and it checks the local folder only for a development install. It does not
  download an archive or a signature.
- `OPEN_TRESTLE_UPDATE_CHECK=off` turns the notice off. `trestle update` itself
  still checks when you run it.

## What is not signed yet

Nothing has been released, and no release key exists. Until the release phase
adds a key to `internal/update/release_keys.txt` and publishes signed releases,
every build refuses the release channel, and only the local folder and `--from`
work, unsigned. The SHA-256 sidecar alone authenticates nothing. Release
provenance, SBOM attestation and signer identity beyond the pinned key are not
yet published.

## Signing a release

The release phase signs each archive offline with `tools/signrelease`, using an
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

Adding the key to `release_keys.txt`, keeping the private key, and wiring this
into a release workflow are release-phase steps that need the maintainer's
approval and secrets. No workflow or key is part of this repository yet.

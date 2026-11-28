# Operations and recovery

This page is for operators who build, package, install and recover Open Trestle and who run the local daemon, `trestled`.

## Build

The root module and the isolated secret-scanner module both declare Go 1.25.0 and are built with Go 1.26.11. Keep the two toolchains separate, and turn off workspace discovery for both:

```sh
GOWORK=off GOTOOLCHAIN=go1.26.11 go mod verify
GOWORK=off GOTOOLCHAIN=go1.26.11 go test ./...
(
  cd workers/secret-scanner
  GOWORK=off GOTOOLCHAIN=go1.26.11 go mod verify
  GOWORK=off GOTOOLCHAIN=go1.26.11 go test ./...
)
```

### Build information

`trestle build-info` and `trestled build-info` print the same JSON about the source: the program name, `source_revision`, `source_tree` and `source_bound`. They start no daemon and read no credentials. Ordinary development builds report empty source identities and `source_bound: false`, and a release build also reports `version`.

Protected packaging requires clean, committed source. It derives the revision and tree from `HEAD`, injects them into both product binaries, then runs each `build-info` command and compares the result. `--verify` also checks the staged product against the current clean source. Root product builds ignore Go environment files, `GOFLAGS` and `GOEXPERIMENT`. The embedded identities describe a local build and are not a publisher's signature.

## Package the secret scanner

A plain root `go build` pins no scan helper, so the resulting `trestle` or `trestled` refuses every review that sends a request to a model, with `this build pins no secret scan helper; build trestle with its helper by python3 tools/package_secret_scanner.py --development DIR`. To build a working copy on Linux or Windows, which needs Go 1.26.11 and Python 3, use development mode:

```sh
python3 tools/package_secret_scanner.py --development DIR [--target GOOS/GOARCH]
```

The default target is the machine you run the tool on. The output layout is described in [build from source](install.md#build-from-source).

`--release-version VERSION` makes a release build. It requires clean committed source and embeds the source revision, tree and `VERSION`, and for the machine's own target it also runs both `build-info` commands and compares them.

### Build the release archives

`tools/release_archives.py` makes the files that the [install scripts](install.md#install-with-one-command) download. It needs clean committed source, Go 1.26.11 and Python 3:

```sh
python3 tools/release_archives.py --version 0.1.0-alpha.1 --output DIR [--target GOOS/GOARCH ...]
```

For each target (by default `linux/amd64` and `windows/amd64`), the tool makes a release build and writes `open-trestle-<version>-linux-amd64.tar.gz` or `open-trestle-<version>-windows-amd64.zip`. Each archive holds one folder, `open-trestle-<version>-<os>-<arch>/`, containing `bin/trestle`, `bin/trestled`, `libexec/open-trestle/open-trestle-scan-helper` (`.exe` names on Windows), `LICENSE`, `NOTICE`, `licenses/` and `README.txt`. Programs are mode `0555` and other files `0444`. Finally, the tool writes `SHA256SUMS` for every file in `DIR`, in the format that `sha256sum -c` reads.

`.github/workflows/release.yml` runs on a pushed `v*` tag, or by hand with a tag. It runs the tests, the staging build and the [vulnerability gate](vulnerability-gate.md), and builds the Linux package and the archives into one folder. It then checks that `install.sh` installs the Linux archive and publishes a GitHub release with every file. A tag with a `-`, such as `v0.1.0-alpha.1`, makes a pre-release. Nothing is signed.

To build the release staging tree, use the output mode:

```sh
python3 tools/package_secret_scanner.py --output .container
python3 tools/package_secret_scanner.py --verify .container
docker build --network=none -t open-trestle:local .
```

The output mode builds the helper twice and requires byte-identical results. It builds `trestle` and `trestled` with the helper's SHA-256 pinned and stages the helper at `libexec/open-trestle/open-trestle-scan-helper`. It also writes `release/secret-scanner-release.json`, which records digests, target, toolchain, build flags, linked modules and patched dependencies, and `release/secret-scanner.spdx.json`. `--verify` checks a staging tree against those files.

The `Dockerfile` copies the staging tree into a scratch image that runs `trestled` as UID and GID 65532 and declares port 8741. Because `trestled` listens on `127.0.0.1:8741` unless `--listen` names another address, the port is reachable only inside the container. A non-loopback address such as `0.0.0.0:8741` requires `--tls-cert` and `--tls-key`, and local review mode (`--local-full-review`) requires a loopback address.

Mount a writable volume at `/var/lib/open-trestle`, owned by UID 65532 with mode `0700`. The image sets `XDG_CACHE_HOME=/var/lib/open-trestle/cache`, so the scanner keeps its compile cache there. Put `--state-dir` in another folder of the volume, such as `/var/lib/open-trestle/state`. Supply the route inventory and runtime policy through read-only mounts and credentials through environment variables; do not bake them into an image. If the scanner cannot be used, `trestled` says why at startup and refuses every request to a model.

### Secret-scanner runtime boundary

The scanner is Betterleaks v1.8.1 running in a WebAssembly (wasip1) guest. The helper executes the guest with the wazero runtime and evaluates its regular expressions with RE2.

The helper's location and required ownership are listed under [paths](environment-and-files.md#paths). The Linux package installs it as a root-owned `0555` file next to `/usr/local/bin/trestle`. Before each start, the program checks the helper's ownership and write permissions and that it matches the pinned SHA-256. If the helper is missing or changed, the review is refused with a message and nothing is sent.

`trestle review` and `trestle local-git model-review` run one helper process per review run, and each specialist member of a review set has its own. `trestled` runs each sanitization in its own helper session. A sanitization scans the request and then the masked request, which must be clean. Generation and verification sanitize separately.

The scan cache holds the compiled guest and RE2 module, and its path, size and required permissions are listed under [paths](environment-and-files.md#paths). The first review fills the cache and prints `Preparing the secret scanner for first use; this can take a minute.`, and `trestled` fills it at startup.

A request frame holds 1 to 256 UTF-8 fields of at most 256 KiB each and 2 MiB in total. Request frames are capped at 3 MiB, response frames at 4 MiB, and a complete response at 8,192 findings. All matches are discarded and dispatch is blocked on a limit, timeout, cancellation or nonzero exit, on any byte on stderr, on malformed or extra output, on an incomplete scan, or on a finding left in the residual scan. A secret is masked, and if the scan cannot complete, the request is refused and nothing is sent.

The scanner keeps only closed failure classes, scanner and build-profile identities, the helper digest, durations, counts of fields, bytes and matches, receipt identities, rule IDs and zero-based half-open byte spans. The helper writes protocol data only to stdout and keeps stderr empty, and the program does not log frames, source bytes, matched values or upstream errors. Because a span still shows the location and length of a suspected secret, restrict access to receipts, audit and metrics to the review scope.

## Build and inspect the unsigned Linux amd64 candidate

The candidate is an installable package for Linux amd64: a Python zip application with a detached SHA-256 file. The builder does not sign it. Release signing is a separate offline step, and `trestle update` verifies the `.sig`; see [updates](updates.md#signing-a-release). Run the builder after `package_secret_scanner.py --verify` and the [vulnerability gate](vulnerability-gate.md) have produced the `.container` inventory, because it refuses a staging tree that lacks `release/vulnerability-scan.json`.

```sh
python3 tools/vulnerability_gate.py --staging .container
REVISION="$(git rev-parse HEAD)"
CREATED="$(date -u -d "$(git show -s --format=%cI "$REVISION")" +%Y-%m-%dT%H:%M:%SZ)"
python3 tools/linux_distribution.py \
  --staging .container \
  --version 0.1.0-dev \
  --revision "$REVISION" \
  --created "$CREATED" \
  --output open-trestle-linux-amd64.pyz
sha256sum -c open-trestle-linux-amd64.pyz.sha256
./open-trestle-linux-amd64.pyz verify-archive
```

The builder uses only the standard library. Every member uses `ZIP_STORED`, fixed Unix metadata and a fixed timestamp, and the manifest records each install path, source identity, mode, size, digest and ELF role. The builder never replaces an existing output or sidecar, so build into a directory that only you control.

The package contains `trestle`, `trestled`, the scan helper, the project LICENSE and NOTICE, the reviewed runtime license files, the three scanner release-evidence files and the model-catalog wrapper `scripts/model_catalog.py`. The wrapper is installed at `/usr/local/share/open-trestle/scripts/model_catalog.py` with mode `0444` and is run with Python. The staging tree also holds `ca-certificates.crt`, which the Dockerfile copies into the image, but the installed payload does not include it, an empty data directory, source, tests or build tools. The wrapper calls the installed CLI and does not download or run models:

```sh
python3 /usr/local/share/open-trestle/scripts/model_catalog.py \
  --trestle /usr/local/bin/trestle refresh \
  --sources /private/model-sources.json --current /private/model-catalog.json \
  --proposal /private/model-proposal.json
```

The sidecar checks integrity, not authenticity. Get the expected digest through a separate trusted channel and run `sha256sum -c` before you run the pyz, because `verify-archive` already executes the lifecycle code embedded in the archive.

## Candidate lifecycle

The lifecycle commands install, verify, upgrade, roll back, recover and remove the package. Production commands omit `--destdir`, require an effective UID of 0 and install below `/usr/local`, and they require ancestors that root owns and that group and world cannot write. CI may prefix the install paths with an absolute, existing `--destdir` that is neither a symlink nor `/`, but destdir mode is not a production installation.

```sh
# production mode, after external checksum verification
sudo ./open-trestle-linux-amd64.pyz install
sudo ./open-trestle-linux-amd64.pyz verify-installed
sudo ./open-trestle-linux-amd64.pyz smoke --output "$(pwd)/open-trestle-linux-smoke.json"

# each separately verified, strictly newer same-target candidate
sudo ./open-trestle-linux-amd64-new.pyz upgrade
sudo /usr/local/libexec/open-trestle/open-trestle-distribution.pyz verify-installed

# only to return to the generation that the latest upgrade replaced
sudo /usr/local/libexec/open-trestle/open-trestle-distribution.pyz rollback-version

# after an interruption, from a retained copy of the candidate that started the transaction
sudo ./open-trestle-linux-amd64-new.pyz recover

# remove the installed generation: roll back an install, or uninstall normally
sudo /usr/local/libexec/open-trestle/open-trestle-distribution.pyz rollback
sudo /usr/local/libexec/open-trestle/open-trestle-distribution.pyz uninstall
```

For an installed package, `trestle update` runs the `upgrade` step for you. It finds a strictly newer candidate, verifies it, copies it into a private folder and runs its `verify-archive`, then prints what it found and asks before it runs `sudo -- <copy> upgrade`. `trestle update --from FILE` does the same for a candidate you name. See [updates](updates.md).

- **install** checks the sidecar, archive structure, manifest, modes, sizes, SHA-256 values, ELF headers and inventory before it writes anything. It writes each file with `O_EXCL` and `O_NOFOLLOW`, syncs it, commits it with `renameat2(RENAME_NOREPLACE)`, and records a receipt and journal of every file the package owns. An existing target stops the operation, and there is no force option.
- **upgrade** verifies the installed generation and the complete candidate, accepts only a newer SemVer version for the same target, and stages the full replacement before it changes any live file. It keeps the archive and sidecar of the immediate predecessor, and a tampered, missing or unsafe rollback slot stops it. Before anything changes, it fails on collisions in paths that only the new version has, the same or a lower version, tampered or unowned files, unsafe ancestors, and wrong modes or ownership.
- **rollback-version** restores only the predecessor recorded for the installed generation. It consumes the slot, so it cannot run twice. Upgrade and rollback preserve operator configuration, state and files the package does not own.
- **verify-installed** checks the receipt, the journal, the trusted ancestors, production ownership, and the modes, sizes, hashes and ELF identities. **smoke** runs that check and then a probe at the CLI command boundary that changes nothing. In destdir mode, smoke does not exercise the scan helper, and its JSON output does not show that the daemon, a provider or the network is ready.
- **rollback** and **uninstall** run an ownership preflight, then remove only files that still match the receipt and only empty directories that the package created. A missing, changed or replaced file, a symlink, or a file owned by the wrong user stops removal before any owned file is deleted. Both preserve `/etc/open-trestle`, `/var/lib/open-trestle`, directories that existed before and files the package does not own. There is no purge mode, and the lifecycle does not configure, enable or start a service.

### Recover an interrupted transition

An interrupted install, upgrade or version rollback leaves one canonical transaction record at the destination root (`.open-trestle-linux-amd64.transaction.bootstrap.json`, `.pending.json` or `.committed.json`). To recover:

1. Keep the candidate that started the transaction, or a byte-identical verified copy, outside the installation root, because an interrupted transition can quarantine the installed lifecycle path.
2. Run `recover` from that copy.

`recover` first classifies the recorded state without changing anything. For a pending record, it returns to the prior generation or removes the files of an interrupted install. For a committed record, every new final file must match, and `recover` then removes only the temporary and quarantine files it lists. If it finds anything malformed, multiple, tampered, unsafe, unexpected or ambiguous, it stops and keeps every object for inspection. It unlinks only files that match the record, removes only empty recorded directories and never deletes operator configuration or state. Running it again after success does nothing. Commands that change the installation run the same gate first, and `verify-installed` reports that recovery is required.

## Generate unsigned local release evidence

Release evidence is a checksum list and an SPDX 2.3 inventory of the artifacts you built. Generate it from a clean checkout, using artifacts built from its declared revision. The tool reads the runtime Go module graph embedded in the two root binaries and the scan helper, and the non-development entries in the npm lockfiles.

```sh
test -z "$(git status --porcelain)"
python3 tools/release_evidence.py \
  --artifact container=.container \
  --artifact web=web/dist \
  --artifact vscode=extensions/vscode/dist/open-trestle.vsix \
  --artifact linux-amd64=open-trestle-linux-amd64.pyz \
  --artifact linux-amd64-sha256=open-trestle-linux-amd64.pyz.sha256 \
  --artifact linux-amd64-smoke=open-trestle-linux-smoke.json \
  --artifact linux-amd64-lifecycle=open-trestle-linux-lifecycle.json \
  --go-binary .container/trestle \
  --go-binary .container/trestled \
  --go-binary .container/libexec/open-trestle/open-trestle-scan-helper \
  --npm-lock web/package-lock.json \
  --npm-lock extensions/vscode/package-lock.json \
  --changelog CHANGELOG.md \
  --version 0.1.0-dev \
  --revision "$(git rev-parse HEAD)" \
  --created "$CREATED" \
  --output release-evidence
```

`--created` is the commit timestamp in UTC, and the inputs must stay below the working directory. The changelog must be a regular UTF-8 file of at most 1 MiB with exactly one non-empty `## Unreleased` section, made of unique categories from `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed` or `Security` with `- ` bullets. The tool copies those into `release-notes.md` with the version, revision and creation time. The `linux-amd64-lifecycle` artifact is content-free JSON that CI writes after an install, upgrade, version rollback, second upgrade, smoke test and uninstall.

The output directory holds `release-notes.md`, `SHA256SUMS` and `sbom.spdx.json`. The tool never replaces existing output, installs the directory atomically, hashes each artifact in one pass and rejects files that change while it reads them. The revision and timestamp come from the caller. The tool does not identify the container image, sign artifacts, publish an attestation, consult a vulnerability database or establish a SLSA level. CI runs the [vulnerability gate](vulnerability-gate.md) before it generates this inventory.

## Validate runtime authority

Validate the route inventory and runtime policy before the daemon starts. The command reads no provider credentials and contacts no service. It checks that each supported provider's adapter can use its endpoint: HTTPS, or HTTP on loopback only, with a canonical host, port and path and no credentials, queries or fragments in the URL.

```sh
trestle config validate \
  --route-inventory /etc/open-trestle/routes.json \
  --runtime-policy /etc/open-trestle/policy.json
```

The daemon applies [stricter file checks](configuration-validation.md#stricter-checks-at-daemon-startup) to these paths at startup.

## Backup and restore

A recovery point is a copy of a stopped local daemon's state that you compare against later. To take one:

1. Stop the daemon and every child process.
2. Copy the entire private `--state-dir` (journal, artifacts, audit ledger, diagnostics and webhook inbox) and the configured `--setup-state` file with its `.receipts` directory. Do not copy a live journal piece by piece, and do not combine files from different recovery points.
3. Keep the route inventory, the runtime policy, the source's Git object store, the setup-root identity, the binary and the scan helper, and record them with the recovery point.
4. Keep credentials separately. Protect the backup with the same private modes as the originals.

The local source-owner record binds the absolute paths and Linux directory identities of the state root, the artifact root and the Git object root. Restoring the bytes of regular files into the same retained directories preserves ownership. Recreating a directory, restoring to another path or moving to another machine is not supported, and startup refuses an owner mismatch even when the bytes are complete. Do not edit or remove the owner record to get around that. If you cannot preserve ownership, keep the backup and use a separately initialized state root for new runs.

To accept a restore, work through these checks in order:

1. Restore into an isolated environment.
2. Compare the closed backup inventory and file hashes with the restored bytes, and verify the configured setup and source identities.
3. Replay the terminal receipts and diagnostics without dispatching any work, and confirm that their identities match the recovery-point record. For the supported layout, `trestled verify-restore` (below) does this. Normal daemon startup is not a read-only verifier: it can recover stored effects and starts workers that run before the model, even with `--local-model-workers` off.
4. Enable ingress, workers and model dispatch only after those checks pass.

These steps cover recovery in place with the daemon stopped. They are not a portable backup or a protocol for filesystem snapshots.

Missing, expired, changed, extra or uncertain records, and unresolved effect markers, stop startup. Do not delete the journal, audit events, artifacts or owner record to force a restart; keep the complete recovery point. If startup refuses a history, keep the original state for review and use a separately initialized state root and a new run ID for unrelated work.

### Cancel a run the daemon cannot replay

If replay or startup reports a typed incompatibility for an old active run:

1. Halt dispatch for that run. Do not treat the journal as a completed review, and do not rewrite its plan and events.
2. Stop the daemon and take a backup of the entire `--state-dir` and the `--setup-state` file.
3. Confirm that a compatible runtime can replay the run and that cancellation is authorized for its scope. Then try to retire the run with that runtime and an authenticated `trestle runs cancel --tenant ID --repository ID --run ID --server URL`.
4. If cancellation is confirmed, start the daemon against that state and submit a new run ID. Do not reuse the old one.
5. If no compatible runtime can replay and cancel the run, leave it intact and isolated. The daemon keeps refusing that state, so use a separately initialized state root for new runs.

There is no automatic cancellation and no migration of an incompatible active run.

### Offline in-place recovery comparison

This procedure compares a stopped, restored state with a record you took earlier. It changes nothing and starts nothing.

To take the record:

1. Stop the daemon and every child process, and keep the original state, artifact, setup and Git object directories.
2. Run `trestled recovery-point`, which writes a comparison record to stdout. Save the record outside the state directory, with permissions for the operator only.
3. Keep the matching state and Git object bytes, the setup receipts, the daemon binary, the scan helper, the route inventory and the runtime policy. These offline commands never read credentials.

```sh
umask 077
trestled recovery-point --state-dir /private/state \
  --repository-authority local.example --repository-namespace team \
  --repository-name repository --binary /retained/trestled \
  --scan-helper /retained/open-trestle-scan-helper \
  --route-inventory /retained/routes.json --runtime-policy /retained/policy.json \
  > /private/recovery-point.json
```

To compare after a restore, restore the bytes of regular leaf files into the retained directories, then run `trestled verify-restore` with the same flags and `--record /private/recovery-point.json`.

The command compares the private inventory hashes, the owner and setup identities, the replayed receipts, the artifacts, the diagnostics, the audit history, the Git object bytes and the retained runtime inputs. It starts no daemon, dispatches no work, runs no scanners, calls no providers, repairs nothing and recovers no pending effects. It refuses if an existing writer holds a lock or an effect is unresolved. A non-empty webhook intake is outside this local comparison.

A `matched` result means the stopped bytes match the record, and active runs produce `matched_pending`. Both report `restart_authorized:false`, and neither shows that the backup is fresh or that uncertain history is safe to restart. Keep refused state for review, and do not edit an owner record or delete an uncertain marker to pass.

The command supports setup at `state/setup/plan.json` only. It limits the record to 4 MiB, each state and Git inventory to 30,000 entries and 256 MiB of regular file bytes at depth 8, and the runs to 500. Exceeding a limit is a refusal, not a sign of corruption.

## Shutdown and health

Use `/healthz` for liveness and `/readyz` for dependency readiness. Send `SIGTERM` to shut the daemon down; an internal runtime failure also starts a shutdown.

On shutdown, the daemon closes admission of root requests and cancels the runtime and request contexts. Before it cleans up its stores, it waits to observe the HTTP shutdown, every supervisor that started, every root handler it admitted and the drain of the repository-worker handlers. Late root requests receive `503 Service Unavailable`.

The shutdown observer waits ten seconds. If users or cleanup outlive it, the stores are not closed beneath live users, and embedded callers receive an error saying that shutdown is incomplete. That error exposes `Finish(context.Context)` for another bounded observation. The `trestled` executable reports an incomplete shutdown and exits nonzero without retrying in the background. The store closers share no time limit.

Configure the service manager with a termination grace period, and alert on an overrun or a failed shutdown. Before a backup or restart, confirm that the old process and every process it started have exited, because a closed socket or a shutdown error does not show that all work has stopped.

The health endpoints do not show that a review succeeded. For that, query the authenticated run receipt and the review diagnostics; see [daemon API](daemon-api.md). To confirm that the daemon loaded the expected route, policy and handler identities and finished reconciling its supervisors, inspect the runtime status:

```sh
OPEN_TRESTLE_API_TOKEN="$OBSERVER_TOKEN" \
  trestle admin runtime status \
  --server https://trestle.example.invalid \
  --tenant example \
  --repository example-repository
```

Use the optional `OPEN_TRESTLE_OBSERVER_TOKEN` configured on `trestled` for this command, because it has only `run_read` and `runtime_read`. The required `OPEN_TRESTLE_API_TOKEN` is the operator and worker credential with full access and does not belong in a read-only console. Compare `configuration_identity`, the route and policy identities, the handler identities and the readiness of each component with your deployment record. The command does not reveal service endpoints or credentials.

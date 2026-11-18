# Operations and recovery

This page is for operators who build, package, install and recover Open Trestle. It covers building from source, the Linux amd64 install package and its lifecycle commands, the secret-scanner sandbox, PostgreSQL setup, backup and restore, and shutdown. Most sections are numbered procedures.

## Build

The root module declares Go 1.25.0 and is built with Go 1.26.11. The isolated secret-scanner module also declares Go 1.25.0 and is built with Go 1.26.11. Keep the two toolchains separate, and turn off workspace discovery for both:

```sh
GOWORK=off GOTOOLCHAIN=go1.26.11 go mod verify
GOWORK=off GOTOOLCHAIN=go1.26.11 go test ./...
(
  cd workers/secret-scanner
  GOWORK=off GOTOOLCHAIN=go1.26.11 go mod verify
  GOWORK=off GOTOOLCHAIN=go1.26.11 go test ./...
)
```

## Local evaluation evidence boundary

`tools/local_alpha_system.py` is a driver that records the results of a local build for evaluation. It is not a deployment profile.

### What the driver accepts

The driver must run from a source checkout that is not bare. The checkout's Git top level must equal the resolved source root, and the unreplaced `HEAD` commit and tree define what the checkout contains.

The driver rejects all of these:

- Replacement refs.
- Grafts, whether common or per worktree.
- Redirected worktrees.
- Environment overrides of Git authority.
- Alternate objects.
- Symlinked Git control, object or ref storage.

The local alpha does not support reftable reference storage or split indexes. Both fail before the driver produces output or runs a candidate. A legitimate linked worktree is accepted only when its effective top level, and its per-worktree and common Git controls, validate against the source root.

Tracked paths must match the `HEAD` tree in object type, executable bit, file bytes and symlink targets. The driver reads the Git tree and index state without refreshing the index. Before it creates the evidence directory or copies a candidate, it rejects any of these:

- Staged or unresolved entries.
- Hidden index flags.
- Unsupported or sparse entries.
- Untracked paths that are not ignored.

Ignored paths may exist, but they must stay stable throughout the run.

### How the driver seals its inputs

The driver takes the browser script and the local contract from the `HEAD` blobs. It copies the pinned Playwright payload into the browser sandbox that the output owns, and it hashes the payload again before it runs anything.

It inspects the candidate manifest and the archive digest without executing anything. They must match the source revision and the detached checksum before any output is created. The driver then copies the bytes it inspected into the sandbox and validates them again before `verify-archive`.

### What the visual evidence covers

The production console recomputes the Runtime identities with browser WebCrypto before it displays them. Each visual phase receipt binds these things:

- The authenticated runtime-status response that the console displays.
- The matching values in the DOM.
- The Runtime screenshot.
- An immediate, bounded reread after the capture.

Every fetch of identity data rejects redirects, requires the canonical final endpoint, has a total deadline, and limits streamed bytes. Configuration and component semantics must survive a restart.

All of this output is unsigned and local. It does not show that the build is ready for production.

### Build information

Both `trestle build-info` and `trestled build-info` print the same version-1 JSON contract about the source: the program name, `source_revision`, `source_tree` and `source_bound`. They do not start a daemon or read route credentials. Ordinary development builds report empty source identities and `source_bound: false`.

Protected packaging requires clean, committed source. The source verifier must pass for `HEAD`, the index, the tracked bytes and modes, the index flags and the Git configuration. Packaging then does the following:

- It derives the revision and the tree from that check.
- It injects them into both product binaries.
- It runs each `build-info` command and compares the metadata.
- It checks the tracked source again before it accepts the staging tree.

`--verify` also checks the metadata of the staged product against the current clean source. Run packaging from a clean checkout and keep custom staging outputs ignored.

Root product builds ignore the Go environment files, `GOFLAGS` and `GOEXPERIMENT`, and keep the pinned toolchain and the fixed build flags.

The embedded identities describe a local build. They are not a publisher's signature or a remote attestation. In the final artifact verification, compare the revision that the archive declares with the metadata of the installed binary.

## Package the secret scanner

A normal root `go build` is useful for development, but it does not inject the digests of the scanner binaries. Such a `trestled` build refuses sanitized egress. To build the release staging tree, use the packaging tool instead:

```sh
python3 tools/package_secret_scanner.py --output .container
python3 tools/package_secret_scanner.py --verify .container
docker build --network=none -t open-trestle:local .
```

The tool checks these before it builds:

- The Go pins of the root module and the worker.
- The Betterleaks module and ruleset identities.
- The linked license inventory.
- The source of the launcher and its build contract.
- The complete pinned Zig 0.14.1 x86_64-linux-musl toolchain archive and its extracted tree.

It then builds the static launcher twice with separate Zig caches and builds the Go worker twice, and it requires both binaries to be byte-identical across the two builds. It records both SHA-256 values and writes scanner release evidence and an SPDX inventory with SHA-1 and SHA-256 file checksums. It injects both SHA-256 digests into the Go 1.26.11 `trestled` binary.

The launcher uses static-PIE flags with an empty environment. The worker uses `GOWORK=off`, Go 1.26.11, `GOOS=linux`, `GOARCH=amd64`, `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false` and an empty build ID.

The included `Dockerfile` copies that staging tree into a scratch image that has no registry base. The image runs `trestled` as UID and GID 65532. It declares port 8741, the daemon's default. `trestled` listens on `127.0.0.1:8741` unless `--listen` names another address, so the port is reachable only inside the container. A non-loopback address such as `0.0.0.0:8741` requires `--tls-cert` and `--tls-key`. Local review mode (`--local-full-review`) requires a loopback address.

Supply the route inventory and runtime policy through read-only mounts, and supply credentials through environment variables. Do not bake route inventories, policies, tokens, database URLs or key material into an image. The image includes the project license, NOTICE, the license texts of the runtime third-party components and the scanner release evidence.

## Build and inspect the unsigned Linux amd64 candidate

The candidate is an installable package for Linux amd64. It is a Python zip application with a detached SHA-256 file. It has no signature. Run the candidate builder only after `package_secret_scanner.py --verify` and the [passive vulnerability gate](vulnerability-gate.md) have produced the fixed `.container` inventory. The builder refuses a staging tree that lacks the gate's `release/vulnerability-scan.json`.

To build the candidate and check it:

1. Run the vulnerability gate on the staging tree.
2. Set the revision and the creation time from the commit.
3. Build the archive.
4. Check the archive against its sidecar and then verify its contents.

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

The builder uses only the standard library. It writes an executable Python zip application and a detached SHA-256 file. Every member uses `ZIP_STORED`, fixed Unix metadata and a fixed timestamp. The manifest records each install path, source identity, mode, size, digest and ELF role.

### What the package contains

The input inventory contains:

- `trestle` and `trestled`.
- The scanner launcher and worker.
- The manual model-catalog wrapper.
- The project LICENSE and NOTICE.
- All reviewed runtime license files.
- The three scanner release-evidence files.

Manifest version 2 requires `scripts/model_catalog.py` as data that is not executable, with mode `0444`. It is installed at `/usr/local/share/open-trestle/scripts/model_catalog.py`. Run it with Python:

```sh
python3 /usr/local/share/open-trestle/scripts/model_catalog.py \
  --trestle /usr/local/bin/trestle refresh \
  --sources /private/model-sources.json --current /private/model-catalog.json \
  --proposal /private/model-proposal.json
```

The wrapper calls the installed CLI. It does not download or run models.

The lifecycle validator still accepts manifest-version-1 archives, which have no wrapper, so a new candidate can validate its older predecessor and restore it. Use the new candidate to upgrade, because an older embedded lifecycle cannot parse version 2.

The package does not include the CA bundle, an empty data directory, source, tests, private references or build tools. The build stops on inputs that are unexpected, missing, symlinked, in the wrong mode, changing, not amd64 or dynamically linked. It never replaces an existing output or sidecar path. Build into a directory that only the invoking account controls. CI builds the pair twice in separate locations and compares both byte for byte.

### What the checksum proves

The sidecar checks integrity, not authenticity. Get the expected digest through a separate trusted channel, and run `sha256sum -c` before you run the pyz. Running `verify-archive` already executes the lifecycle code embedded in the archive. The candidate has no signature and no production support.

### Candidate lifecycle

The lifecycle commands install, verify, upgrade, roll back, recover and remove the package. Commands for production mode omit `--destdir`. They require an effective UID of 0 and install below `/usr/local`. They require ancestors that root owns and that group and world cannot write, and they preserve root:root ownership.

CI may instead prefix the install paths with an absolute, existing `--destdir` that is not a symlink and is not `/`. Destdir mode is not a production installation.

Lifecycle transactions require exclusive control of the paths they manage. In production mode, root ownership and ancestors that nobody else can write enforce that against writers that are not root.

```sh
# production mode, after external checksum verification
sudo ./open-trestle-linux-amd64.pyz install
sudo ./open-trestle-linux-amd64.pyz verify-installed
sudo ./open-trestle-linux-amd64.pyz smoke --output "$(pwd)/open-trestle-linux-smoke.json"

# each separately verified, strictly newer same-target candidate, as often as needed
sudo ./open-trestle-linux-amd64-new.pyz upgrade
sudo /usr/local/libexec/open-trestle/open-trestle-distribution.pyz verify-installed

# only to return to the generation that the latest upgrade replaced
sudo /usr/local/libexec/open-trestle/open-trestle-distribution.pyz rollback-version

# retain the transaction-starting candidate outside the install root; use it after interruption
sudo ./open-trestle-linux-amd64-new.pyz recover

# choose one complete removal action for whichever generation is installed
sudo /usr/local/libexec/open-trestle/open-trestle-distribution.pyz rollback
# or, for a normal removal
sudo /usr/local/libexec/open-trestle/open-trestle-distribution.pyz uninstall
```

For an installed package, `trestle update` runs the `upgrade` step for you. It finds a strictly newer candidate, verifies it in Go, copies it into a private folder, runs its `verify-archive`, prints what it found and asks, and then runs `sudo -- <copy> upgrade`. `trestle update --from FILE` does the same for a candidate that you name. See [updates](updates.md). The lifecycle commands on this page remain the way to install, roll back, recover and remove.

#### Install

`install` checks all of these before it writes any file: the sidecar, the archive structure, the manifest, the payload modes and sizes, the SHA-256 values, the ELF headers and the inventory. It streams members one at a time and does not call ZIP extraction APIs. It writes each file with `O_EXCL` and `O_NOFOLLOW`, calls fsync on it, and commits it with the Linux call `renameat2(RENAME_NOREPLACE)`. A receipt and a transaction journal record the installed archive and every file that the package owns. Existing targets stop the operation, and there is no force option.

#### Upgrade

`upgrade` first verifies the installed generation and the complete candidate. It accepts only a newer SemVer version for the same target. It stages and validates the full replacement before it changes any live file. It keeps the archive and sidecar of the immediate predecessor. In protected receipt and journal files, it records the old and new versions, archives and manifests, and the transaction and the action.

When the rollback slot already holds a predecessor, the same transaction moves the generation that it supersedes into the slot. It discards the older predecessor's archive, sidecar, receipt and journal copies. It first verifies them like every file that the package owns, so a slot that is tampered with, missing, a symlink, in the wrong mode or in an unsafe parent directory stops the upgrade. The transaction plan names the discarded generation and all four copies before anything moves. They are quarantined like any replaced file and removed only after the commit.

These conditions fail before anything changes:

- Collisions in paths that only the new version has.
- The same or a lower version.
- Tampered controls or owned files.
- Unsafe ancestors.
- Wrong modes or ownership.
- Inconsistencies in the rollback slot.

#### Roll back to the previous version

`rollback-version` runs only from the installed generation. It restores only the predecessor that is recorded for that generation, and it consumes the slot. It cannot select an older archive and cannot run twice. Upgrade and version rollback preserve operator configuration, state and all files that the package does not own.

A predecessor that was installed, or reached by `rollback-version`, gets its original receipt and journal back. A predecessor that was itself an upgrade names its own predecessor, which was discarded, so it gets a new `rollback-version` receipt and journal with no predecessor. Every earlier lifecycle that can upgrade accepts that receipt.

#### Transaction records and recovery

The candidate reserves three canonical records at the destination root. At most one of them exists at a time:

- `.open-trestle-linux-amd64.transaction.bootstrap.json`
- `.open-trestle-linux-amd64.transaction.pending.json`
- `.open-trestle-linux-amd64.transaction.committed.json`

Each record has a specific meaning:

- The bootstrap record contains the plan, but it permits no change to managed files. `recover` removes only a valid bootstrap record.
- A pending record always selects a rollback to the prior generation, or removal of the files for an install that was interrupted.
- A committed record requires every new final file to match. `recover` then removes only the temporary and quarantine files that the record lists. It does not reconstruct a committed file that is missing.

The rename from pending to committed, followed by an fsync of the destination root, is the only decision to commit.

Plans record the old and new generations, the control digests, the names for staging and quarantine, and the directory inventories. Transaction records are version 2. Version 2 adds the discarded predecessor, and only an upgrade may name one. The slot that the upgrade frees must hold that generation, which is older than the one being superseded. The slot that it refills must hold the superseded generation and its controls.

This candidate still recovers version 1 records that an earlier lifecycle left behind. A lifecycle that reads only version 1 records refuses a version 2 record without changing anything. In that case, recover with the candidate that started the transaction.

After a restart, Open Trestle classifies state by path, file type, mode, size, SHA-256 and the applicable ownership policy. Saved inode and device numbers are used only for live race checks.

To recover from an interrupted transition:

1. Keep the candidate that started the transaction, or another verified rescue pyz that is byte-identical to it, outside the installation root. An interrupted transition can quarantine the installed lifecycle path.
2. Run `recover` from that copy.

`recover` first classifies the recorded state without changing anything. If it finds anything malformed, multiple, tampered, unsafe, unexpected or ambiguous, it stops and keeps every object for you to inspect. Its cleanup unlinks only a file that matches the record, and it calls `rmdir` only on a recorded directory that is empty. It does not recurse, and it does not delete operator configuration, state, adjacent files or a directory that is not empty. Running recovery again after it succeeds does nothing. Commands that change the installation run the same recovery gate first. `verify-installed` instead reports that explicit recovery is required.

#### Crash tests

On Ubuntu 24.04, an opt-in destdir test matrix sends SIGKILL immediately after each of these points:

- Every successful file or directory fsync.
- Every successful `renameat2` boundary.

It does so for install, for upgrade into an empty rollback slot and into an occupied one, for `rollback-version` before and after such a slot replacement, and for recovery itself.

Every case converges to the generation from before the commit, or to the verified generation from after it. The slot holds the matching rollback archive, and no bytes of a discarded generation remain. Operator sentinels survive and recorded debris is removed.

The tests depend on atomic rename and on file and directory fsync that succeed. They do not cover any of the following:

- Loss of unflushed writes.
- Torn writes.
- Kernel panic.
- Controller caches.
- Reboot.
- Production `/`.
- Enforcement of root ownership.
- Any declared filesystem or mount profile.
- Network or overlay filesystems.
- A hostile root.

They make no claim about power loss or a supported deployment.

#### Verify and smoke test

`verify-installed` checks the receipt and the journal, the trusted ancestors, ownership in production, and the modes, sizes, hashes and ELF identities. `smoke` first runs that check. It then runs a probe at the CLI command boundary that changes nothing, with a minimal environment.

In destdir mode, the smoke test does not exercise the scanner launcher, because that launcher opens its worker at the fixed production path. The container sandbox test covers running the scanner. Smoke output is JSON with no content, and it does not show that the daemon, a provider, a database or the network is ready.

#### Roll back an install and uninstall

`rollback` reverses the install transaction that the receipt records. `uninstall` runs the same ownership preflight before it deletes anything. Both remove only files that still match the receipt, and only directories that the package created and that are empty.

If the preflight sees a file that is missing, changed, replaced, a symlink or owned by the wrong user, removal stops before any owned file is deleted.

Both commands preserve the application configuration under `/etc/open-trestle`, the application state under `/var/lib/open-trestle`, directories that existed before, and files that the package does not own. There is no purge mode. The lifecycle does not configure, enable or start a service, and it does not create application configuration or state.

### Secret-scanner runtime boundary

The scanner runs in a sandbox. The root client invokes `/usr/local/libexec/open-trestle/open-trestle-secret-scanner --stdio-v1`. That launcher is static and single-threaded. It applies `NO_NEW_PRIVS`, core, CPU and file-descriptor limits, and a Landlock domain. It then executes only `/usr/local/libexec/open-trestle/open-trestle-secret-scanner-worker --sandboxed-stdio-v1`.

The Go worker installs a seccomp filter that covers the whole process (TSYNC) before Betterleaks initializes. The launcher and worker receive anonymous pipes, `/` as the working directory and an empty environment. The worker cannot open network sockets, change the filesystem, create namespaces, mount filesystems, trace another process or execute another program. A failure of the sandbox or of the identity check happens before any source input is accepted.

Both files must be owned by root, with group `root` and mode `0555`. They must sit beneath directories that root owns and nobody else can write, and they must match the digests compiled into `trestled`. This trust check protects against replacement by the service account that has no privileges. It does not protect a host after the compromise of root or the kernel.

Each scan runs in one child process. That process starts as the launcher and replaces itself with the worker. There is no process pool and no sidecar. A successful sanitization normally starts two child processes: one initial scan and one fresh scan of what remains. Generation and verification sanitize their requests separately. Plan capacity for that start-up cost, and do not assume one scanner that lives for a whole review.

The framed request accepts 1 to 256 fields of valid UTF-8, with at most 256 KiB each and 2 MiB decoded in total. Request frames are capped at 3 MiB, response frames at 4 MiB, and a complete response at 8,192 findings. The worker's deadline is five seconds after the frame is decoded. The parent's hard watchdog is six seconds from the start of the process, or an earlier deadline from the caller.

Any of these discards all matches and blocks dispatch: a limit, a timeout, a cancellation, a nonzero exit, a byte on stderr, malformed or extra output, an incomplete scan or a finding that remains in the residual scan. Open Trestle does not accept a partial scan result.

### Scanner observability and privacy

The records that the scanner keeps are limited to these things:

- Closed classes of failure.
- Scanner and build-profile identities.
- Launcher and worker digests.
- Duration.
- Counts of fields, bytes and matches.
- Receipt identities.
- Rule IDs.
- Byte spans that are zero-based and half-open.

The child writes protocol data only to stdout and must keep stderr empty. The parent does not log request or response frames, source bytes, matched values, upstream errors or the text of process errors. The initial receipt and the residual receipt contain no field content, paths, snippets, matches, source digests or Betterleaks fingerprints.

A record with no content can still reveal sensitive information. A span shows the field ordinal, the location and the length of a suspected secret. Restrict access to receipts, audit and metrics to the review scope, and do not attach span or rule data to general metrics. The provider receives sanitized request text; keep content logging by the provider disabled under the approved route.

### Scanner upgrade and requalification

Treat any change as a new build profile that needs review. This covers changes to the Betterleaks version or commit, the embedded config, the rule inventory, the regexp engine, the adapter behavior, the launcher or Go toolchain, the target, the CGO setting, the sandbox, the timeouts and the build flags. Before you adopt the new profile:

1. Compare the upstream public API and detection behavior with the current version. Review the embedded config, the sorted rule IDs, and every linked module and license.
2. Regenerate the ruleset identity, the allowlist, the deterministic launcher and worker, the binary digests, the release evidence, the SPDX inventory and the injection of the root digest.
3. Run all public tests of the protocol, the exact spans, repeats, cancellation, resources, the sandbox, leakage and the residual scan.
4. Run three canonical passes of the unchanged private corpus. The current gate is exactly 11/14 expected occurrences, 10/11 positive files, 2/2 repeated locations and 11/11 exact spans. The gate also expects the three misses that are named (the bearer token, the AWS secret key and the AWS session token) and one `generic-api-key` near miss at `[7,51)`. A loss, a changed span, or an additional or changed near miss blocks adoption until someone has reviewed it.
5. Run five direct-adapter passes with a warm cache and 16 MiB, and five end-to-end child-process passes at the maximum legal size of 2 MiB. Each gate requires a median wall time of at most two seconds and a maximum RSS of at most 256 MiB.
6. Rerun the root and worker tests, the race tests, vet, the deterministic packaging, the staging inventory, the release evidence, the container sandbox and the security review of the frozen diff.

The private corpus and the raw scanner output stay outside tracked release material. The baseline measures one fixed corpus. The scanner misses some credential formats, including the ones named above.

## Generate unsigned local release evidence

Release evidence is a checksum list and an SPDX 2.3 inventory of the artifacts you built. Generate it from a clean checkout and from the artifacts that were built from its declared revision. The tool reads the runtime Go module graph that is embedded in the two root binaries and the scanner worker, and the non-development dependency entries in the npm lockfiles. The scanner staging evidence covers the static launcher, which is not a Go binary.

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
  --go-binary .container/libexec/open-trestle/open-trestle-secret-scanner-worker \
  --npm-lock web/package-lock.json \
  --npm-lock extensions/vscode/package-lock.json \
  --changelog CHANGELOG.md \
  --version 0.1.0-dev \
  --revision "$(git rev-parse HEAD)" \
  --created "$CREATED" \
  --output release-evidence
```

The `linux-amd64-lifecycle` artifact is JSON with no content. CI writes it after it has completed these steps in order: a v1 install, a v2 upgrade and verification, a v1 `rollback-version` and verification, a second v2 upgrade, a smoke test and an uninstall. It records the action names, the target, the versions, the archive digests and the pass status.

Use the commit timestamp, normalized to UTC, for `--created`. The inputs for artifacts, Go binaries, npm lockfiles and the changelog must stay below the working directory. The required changelog must be a regular UTF-8 file that is not a symlink, of at most 1 MiB. It must contain exactly one `## Unreleased` section that is not empty. That section is made of unique categories from `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed` or `Security`, with bullets that start `- ` and are not empty. The tool preserves those authored categories, bullets and indented continuation lines in `release-notes.md`. Beside them it writes the bound version, the revision, the creation time and a fixed warning that this is a candidate and is not supported.

The output directory contains `release-notes.md`, `SHA256SUMS` and `sbom.spdx.json`. The tool never replaces existing output. It installs the complete directory atomically, so a failure does not leave partial output at the requested path. It hashes each artifact in one streaming pass that computes SHA-1 and SHA-256, and it rejects files that change while it reads them. `SHA256SUMS` contains SHA-256 only. Inputs that are missing, empty, duplicated, malformed, sensitive, escaping or symlinks fail.

This is an unsigned local inventory. The declared revision and timestamp come from the caller. CI also validates both generated SBOMs with the SPDX Workgroup `spdx-tools` 0.8.5 validator, from a test-only lock that is pinned and checked by hash.

The release-evidence tool does none of the following:

- It does not identify the built container image.
- It does not sign artifacts.
- It does not publish an attestation.
- It does not consult a vulnerability database.
- It does not establish a SLSA level.
- It does not make the current experimental release suitable for production.

CI separately runs the [passive vulnerability gate](vulnerability-gate.md) before it generates this inventory.

## Validate runtime authority

Validate the route inventory and runtime policy before the daemon starts. The command reads no provider credentials and contacts no service. It checks that the adapter of each supported provider can use the provider's endpoint: HTTPS or HTTP on loopback only, a canonical host, port and path, and no credentials, queries or fragments in the URL.

```sh
trestle config validate \
  --route-inventory /etc/open-trestle/routes.json \
  --runtime-policy /etc/open-trestle/policy.json
```

The daemon applies stricter file checks at startup. Each of these paths must be a regular file that is not a symlink and has no group or world write permission.

## Initialize PostgreSQL

Use a migration role only for schema changes. `trestle admin postgres migrate` reads `OPEN_TRESTLE_POSTGRES_MIGRATION_URL`, applies migrations whose checksums it verifies under the migration lock, and creates the database namespace. Use `trestle admin postgres initialize` only when you intend to use required-mode publication. It does the same work and also creates the publication authority row once.

To apply migrations:

```sh
OPEN_TRESTLE_POSTGRES_MIGRATION_URL="$MIGRATION_URL" \
  trestle admin postgres migrate
```

For required-mode publication, initialize instead:

```sh
OPEN_TRESTLE_POSTGRES_MIGRATION_URL="$MIGRATION_URL" \
  trestle admin postgres initialize \
  --authority-identity "$OPERATOR_AUTHORITY_DIGEST"
```

The authority argument is a nonzero lowercase SHA-256 digest of a stable identifier for your deployment. It is not secret, and it is not a password. Save the `publication_authority_receipt_identity` that the command returns in the protected recovery records of your deployment. Do not rerun initialization to repair a restored identity that you did not expect.

Normal application credentials must use a separate connection URL in `OPEN_TRESTLE_POSTGRES_URL`. To read the database authority of the runtime role, which is not secret, run `trestle admin postgres identity`. Then verify the migrations and, when publication is enabled, the fence namespace that the database owns, before you start the daemon:

```sh
OPEN_TRESTLE_POSTGRES_URL="$APPLICATION_URL" \
  trestle admin postgres verify \
  --authority-identity "$OPERATOR_AUTHORITY_DIGEST" \
  --expected-receipt-identity "$EXPECTED_RECEIPT_IDENTITY"
```

These commands print no connection string and no operator digest. Pass the identity from `trestle admin postgres identity` to every PostgreSQL daemon as `--postgres-database-authority-identity`. Startup fails if the runtime database identity differs.

## Local full-review recovery point

A recovery point is a copy of a stopped local daemon's state that you can compare with later.

To take a recovery point:

1. Stop the daemon.
2. Copy its private `--state-dir`, the configured `--setup-state` file and its `.receipts` directory.
3. Keep the route inventory, the runtime policy, the Git object store of the source, the setup-root identity, the binary version and the scanner digests, and record them with the recovery point.
4. Keep credentials separately.

Do not copy a live journal, and do not combine files from different recovery points. Protect the backup bytes with the same private modes and access controls as the originals.

The local source-owner record binds the absolute paths and the Linux directory identities of the state root, the artifact root and the Git object root. If you restore the bytes of regular files into those same retained directories, the ownership can be preserved. Recreating a directory, restoring to another path or moving to another machine is not supported. Startup refuses an owner mismatch even when the copied bytes are otherwise complete. Do not edit or remove the owner record to get around that refusal. If you cannot preserve the original ownership, keep the backup and use a separately initialized state root for a new run.

Before you restart workers:

1. Compare the closed backup inventory and the file hashes with the restored bytes.
2. Verify the configured setup and source identities.
3. Replay the terminal receipts and the diagnostics without dispatching any work.
4. Confirm that their identities match the recovery-point record.

The `trestled verify-restore` command in [Offline in-place recovery comparison](#offline-in-place-recovery-comparison) does this for the supported layout. Do not start the daemon in place of this replay-only check. Normal daemon startup is not a read-only verifier: it can recover stored effects, and it starts workers that run before the model, even when `--local-model-workers` is disabled. If you cannot perform the check, keep the stopped state and the recovery point, and do not treat the restore as qualified.

These steps cover recovery in place with the daemon stopped. They are not a portable backup or a protocol for filesystem snapshots.

A terminal internal failure alone does not permit a restart. Consider an initial generation attempt that was rejected only because of the shape of the candidate document. Startup can accept the retained failed run, but only after fresh checks all succeed: the journal, the five-event audit, the artifacts, the current route, the handler, the scanner and the full catalog of the pipeline. The failed run remains inconclusive and has no candidate output. A restart does not dispatch that history again.

Missing, expired, changed, extra or uncertain records still stop startup, and so do unresolved effect markers. This path does not recover model effects that failed or are partial. Do not delete the journal, the audit events, the artifacts or the owner record to force a restart. Stop the daemon and keep the complete recovery point. If startup refuses that history, use a separately initialized state root and a new run ID for unrelated work, and keep the original state for review. This isolates the old history. It is not a recovery in place.

This evaluation profile is not yet a supported v1 installation.

## Backup and restore

A complete backup must preserve all of these:

- PostgreSQL metadata.
- Publication attempts.
- The publication authority singleton.
- Protected artifact objects.
- Envelope metadata.
- The keys needed to decrypt the objects that are retained.

Database snapshots and object-store snapshots must represent one documented recovery point. A database snapshot without its matching protected objects is incomplete, and so is a restored set of objects without the matching metadata.

To accept a restore, work through these checks in order:

1. Restore into an isolated environment with external publication disabled.
2. Verify the PostgreSQL migration checksums.
3. Verify the expected receipt identity of the publication authority.
4. Confirm that the restored history of publication attempts covers the declared recovery point.
5. Verify protected artifact retrieval and access to the envelope key, using conformance objects that are not sensitive.
6. Run a review that only replays, and compare the terminal state that it derives from the journal with the recorded receipt.
7. Enable ingress, workers, model dispatch and publication only after those checks pass.

The authority receipt detects a database that is fresh or was initialized separately. It cannot show that a copy that carries the same authority row contains every later transaction. To rule out stale restores, rely on the consistency of your database backups, your records of the recovery point and the check of publication attempts.

## Retire an old active review plan after a typed incompatibility

Some changes make an old review plan impossible to replay. This section describes how to deal with such a plan without rewriting its history.

In the local full-review evaluation profile, a context abstention first appends a bounded v3 prepare event, which has no content, to the private file journal. Only then does the daemon store the scoped deterministic artifact and append the result of the failed task. On restart, before any supervisor or listener can settle an expired context lease, the daemon replays an unresolved prepare event. It validates the plan, task, scope, provenance and artifact bytes, restores a missing artifact from the journaled envelope, and writes one linked result for the failed task.

If a prepared artifact is corrupt, expired, ambiguous or unavailable, startup stops. It never becomes a success with empty output or a task that is ready for the model. This path applies to the local FileRunJournal and the local artifact store. The full local daemon rejects stores that are not local.

If replay or startup reports a typed incompatibility for an old active review plan, follow these steps:

1. Halt dispatch and publication for that plan. Do not treat an incompatible journal as a completed review, and do not rewrite its immutable plan and events.
2. For the local single-node profile, stop the daemon and take a consistent backup of the entire private `--state-dir` (journal, artifacts and diagnostics) together with the configured `--setup-state` file, before you decide anything else. For PostgreSQL and S3 profiles, use their procedure for a consistent backup of metadata, objects and envelope keys instead. Do not copy a live file journal piece by piece.
3. Record the recovery point and confirm that you can read the backup.
4. Try to retire the plan. An operator may use a compatible runtime and an authenticated `trestle runs cancel --tenant ID --repository ID --run ID --server URL`. First verify that the runtime can replay the plan and that cancellation is authorized for that scope.
5. If a compatible runtime cannot safely replay and cancel the plan, leave the old plan intact and isolated for the operator to review later. There is no automatic cancellation and no migration of an incompatible active plan.
6. If the cancellation is confirmed, start the newer daemon against that state and submit a new review run ID.
7. If the old active plan stays intact, the newer daemon will still refuse that state. Isolate and keep its backup, and use a separately initialized state root for any new run.

Do not reuse the old run ID.

## Shutdown and health

Use `/healthz` for liveness of the process and `/readyz` for readiness of its dependencies. Send `SIGTERM` to shut the daemon down. An internal failure of the runtime also starts a shutdown.

On shutdown, the daemon closes admission of root requests and cancels the contexts of the runtime and of requests. Before it starts to clean up its stores, it waits to observe all of these:

- The HTTP shutdown.
- Every supervisor that started.
- Every root handler that it admitted.
- The drain of the repository-worker handlers.

Late root requests receive `503 Service Unavailable`. A written response, a returned supervisor or a closed listener does not alone show that the handlers stopped.

The shutdown observer waits ten seconds. If users or cleanup outlive it, the stores are not closed beneath users that are still live. Embedded callers receive an error that shutdown is incomplete. The error keeps the daemon and exposes `Finish(context.Context)` for another bounded observation. Every observation refers to the same stopped runtime and the same ordered chain of closers, each of which runs once. The daemon does not retry a closer that was partly attempted. Cleanup errors remain failures even after the call to the closer returns.

The `trestled` executable reports an incomplete shutdown and exits with a nonzero status. It does not wait indefinitely or retry in the background. The HTTP shutdown phase has a grace period of ten seconds, while the closers of the stores have no shared time limit. An embedded caller must keep an incomplete error until it finishes observing the shutdown or ends its process.

Configure the service manager with a grace period for termination, and alert on an overrun or on a failed shutdown. Before a backup or restart, confirm that the old daemon process and every process it started have exited. A closed socket or a shutdown error does not show that all work has stopped.

The health endpoints do not show that a review or a publication succeeded. Query the authenticated run receipt and the review diagnostics instead. Versions 1 through 5 contain the state of verified findings. Version 6 contains scripted observations that remain unverified and need their own disposition in a review.

To confirm that the daemon loaded the expected database, rate limit, route, policy and handler identities and completed the reconciliation of its supervisors, inspect the runtime of the repository:

```sh
OPEN_TRESTLE_API_TOKEN="$OBSERVER_TOKEN" \
  trestle admin runtime status \
  --server https://trestle.example.invalid \
  --tenant example \
  --repository example-repository
```

The optional `OPEN_TRESTLE_OBSERVER_TOKEN` that is configured on `trestled` has `run_read` and `runtime_read` only. Use it for this command. The required `OPEN_TRESTLE_API_TOKEN` is the credential of the operator and the worker, with full access, so do not put it in a read-only console.

Compare these values with the record of your deployment:

- `configuration_identity`.
- The route and policy identities.
- The storage posture.
- The state of the publication fence.
- The handler identities.
- The readiness of each component.

The command does not reveal service endpoints or credentials.

## Offline in-place recovery comparison

This procedure compares a stopped, restored daemon state with a record you took earlier. It changes nothing and starts nothing.

To take the record:

1. Stop the daemon and every child process before you take a consistent copy.
2. Keep the original state, artifact, setup and Git object directories. The owner record binds the Linux directory identity and the absolute paths, so recreating those directories is not supported, even if the file bytes match.
3. Run `trestled recovery-point`. It writes a comparison record to stdout. Save that record outside the state directory, with permissions for the operator only.
4. Keep the matching state and Git object bytes, the ledger of setup receipts, the daemon binary, the scanner and scanner-worker binaries, the route inventory and the runtime policy. Credentials are separate, and these offline commands never read them.

```
umask 077
trestled recovery-point --state-dir /private/state \
  --repository-authority local.example --repository-namespace team \
  --repository-name repository --binary /retained/trestled \
  --scanner /retained/scanner --scanner-worker /retained/scanner-worker \
  --route-inventory /retained/routes.json --runtime-policy /retained/policy.json \
  > /private/recovery-point.json
```

To compare after a restore:

1. Restore the bytes of regular leaf files into the retained directories.
2. Run `trestled verify-restore` with the same flags and `--record /private/recovery-point.json`.

The command compares the private inventory hashes, the owner and setup identities, the replayed receipts, the artifact and deletion records, the diagnostics, the audit history, the Git object bytes and the retained runtime inputs. It does not start a daemon, dispatch work, run scanners, call providers, repair files or recover pending effects. A lock that an existing writer still holds, or an unresolved effect, makes it refuse the comparison. Intake of webhooks that is not empty is outside this local comparison, in which publication is disabled.

A `matched` result means that the stopped bytes you observed match the record. Active runs produce `matched_pending`. Both report `restart_authorized:false`. Neither shows that the backup is fresh or that uncertain history is safe to restart. Keep refused state so that you can review it. Do not edit an owner record or delete an uncertain marker to make the command pass.

The command currently supports setup at `state/setup/plan.json` only. It bounds the record at 4 MiB. It bounds each inventory of state and of Git at 30,000 entries and 256 MiB of regular file bytes, at depth 8, and at 500 runs. Exceeding a bound is a refusal, not a sign of corruption. The bounds of the stores and the parsers also apply.

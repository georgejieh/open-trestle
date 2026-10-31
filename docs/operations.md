# Operations and recovery

## Build

The root module declares Go 1.25.0 and is built with Go 1.26.10. The isolated secret-scanner module declares Go 1.25.0 and is built with Go 1.26.10. Keep the toolchains separate and disable workspace discovery for both:

```sh
GOWORK=off GOTOOLCHAIN=go1.26.10 go mod verify
GOWORK=off GOTOOLCHAIN=go1.26.10 go test ./...
(
  cd workers/secret-scanner
  GOWORK=off GOTOOLCHAIN=go1.26.10 go mod verify
  GOWORK=off GOTOOLCHAIN=go1.26.10 go test ./...
)
```

## Local evaluation evidence boundary

`tools/local_alpha_system.py` is a bounded evidence driver, not a deployment profile. It
must run from a non-bare source checkout whose effective absolute Git top level equals the
resolved source root. The literal unreplaced `HEAD` commit and tree are the authority.
Replacement refs, common or per-worktree grafts, redirected worktrees, Git authority
environment overrides, alternate objects and symlinked Git control/object/ref storage are
rejected. Reftable reference storage and split indexes are not supported by the local alpha
and fail before output or candidate execution. A legitimate linked worktree is accepted
only when its effective top level and per-worktree/common Git controls validate against
that source root.

Tracked paths must exactly match the literal tree in object type, Git executable semantics,
regular-file bytes and symlink targets. The driver reads Git tree and index state without
refreshing the index. It rejects staged or unresolved entries, hidden index flags,
unsupported or sparse entries and nonignored untracked paths before it creates the evidence
directory or copies a candidate.

Ignored paths have a separate bounded identity and may exist, but they must remain stable
through the run. That identity does not establish committed provenance. The browser script
and local contract are sealed from exact `HEAD` blobs. The pinned Playwright payload is
copied into the output-owned browser sandbox and rehashed before execution. The original
candidate manifest and archive digest are inspected without execution and must match the
source revision and detached checksum before output is created. The exact inspected bytes
are then copied into the sandbox and revalidated before `verify-archive`; the manifest does
not prove the worktree by itself.

The production console recomputes Go-compatible Runtime identities with browser WebCrypto
before it renders or exposes them. Visual phase receipts bind the authenticated
runtime-status response displayed by the console, the corresponding DOM values and Runtime
screenshot, and an immediate bounded post-capture reread. All identity-bearing evidence
fetches reject redirects, require their exact canonical final endpoint, have total
deadlines and enforce streaming byte limits. Configuration and component semantics must
survive restart. Runtime status identities and observation times are observation-specific
and need not be equal.
All evidence remains unsigned local output and does not establish publisher authenticity,
production readiness or support.

A normal root `go build` is useful for development, but it does not inject the trusted scanner binary digests. Such a `trestled` build fails closed when sanitized egress is requested. Build the release staging tree with the reviewed packaging tool instead:

```sh
python3 tools/package_secret_scanner.py --output .container
python3 tools/package_secret_scanner.py --verify .container
docker build --network=none -t open-trestle:local .
```

The tool verifies the root and worker Go pins, Betterleaks module and ruleset identities, linked license inventory, launcher source and build contract, and the complete pinned Zig 0.14.1 x86_64-linux-musl toolchain archive and extracted tree. It builds the static launcher twice with separate Zig caches, builds the Go worker twice, and requires byte-identical outputs for both binaries. It then records both SHA-256 values, emits scanner release evidence and SPDX with SHA-1 and SHA-256 file checksums, injects both SHA-256 digests into the Go 1.26.10 `trestled` binary, and admits only the fixed staging inventory. The launcher uses empty-environment static-PIE flags. The worker uses `GOWORK=off`, Go 1.26.10, `GOOS=linux`, `GOARCH=amd64`, `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`, and an empty build ID.

The included `Dockerfile` copies that staging tree into a scratch image with no registry base. The image runs `trestled` as UID and GID 65532. Supply runtime authority files through read-only mounts and credentials through the documented environment variables. Do not bake route inventories, policies, tokens, database URLs, or key material into an image. The image includes the project license, NOTICE, exact runtime third-party license texts, and scanner release evidence.

## Build and inspect the unsigned Linux amd64 candidate

Run the Linux candidate builder only after `package_secret_scanner.py --verify` and the
passive vulnerability gate have produced the fixed `.container` inventory:

```sh
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

The stdlib-only builder emits an executable Python zip application plus a detached
SHA-256 file. Every member uses `ZIP_STORED`, fixed Unix metadata and a fixed timestamp.
The canonical manifest binds each install path, source identity, mode, size, digest and
ELF role. The input inventory is exact: `trestle`, `trestled`, the scanner launcher and
worker, the manual model-catalog wrapper, project LICENSE and NOTICE, all reviewed
runtime license files, and the three scanner release-evidence files. Manifest version 2
requires `scripts/model_catalog.py` as non-executable mode `0444` data, installed at
`/usr/local/share/open-trestle/scripts/model_catalog.py`. Invoke it with Python:

```sh
python3 /usr/local/share/open-trestle/scripts/model_catalog.py \
  --trestle /usr/local/bin/trestle refresh \
  --sources /private/model-sources.json --current /private/model-catalog.json \
  --proposal /private/model-proposal.json
```

The wrapper delegates to the explicit installed CLI and does not download or run models.
The current lifecycle validator still accepts exact manifest-version-1 archives without
the wrapper, so a new candidate can validate and restore its older predecessor. Use the
new candidate for upgrade; an older embedded lifecycle cannot parse version 2. Receipt,
transaction and smoke schemas are unchanged. The CA bundle, empty data directory, source, tests,
private references and build tools are not included. Unexpected, missing, symlinked,
wrong-mode, changing, non-amd64 or dynamically linked inputs stop the build. Existing
output or sidecar paths are never replaced. Build into a directory under the exclusive
control of the invoking account; concurrent mutation by another process with the same
account authority is outside this local build boundary. CI builds the pair twice in
separate locations and compares both byte for byte.

The sidecar provides integrity, not authenticity. Obtain the expected digest through a
separate trusted channel and run `sha256sum -c` before the pyz. Invoking
`verify-archive` already runs its embedded lifecycle code. The candidate has no
signature, signer identity, published provenance, SLSA claim or production support.

### Candidate lifecycle

Production-mode commands omit `--destdir`, require effective UID 0, install below
`/usr/local`, require root-owned non-group/world-writable ancestors and preserve
root:root ownership. CI may prefix the fixed logical paths with an absolute, existing,
non-symlink `--destdir` other than `/`. Destdir mode is not a production installation
or a security boundary against a concurrent process running as the same account.
Lifecycle transactions require exclusive control of their managed paths. Production
mode enforces that boundary against non-root writers through root ownership and
non-writable ancestors; a concurrent root process is outside the host trust model.

```sh
# production mode, after external checksum verification
sudo ./open-trestle-linux-amd64.pyz install
sudo ./open-trestle-linux-amd64.pyz verify-installed
sudo ./open-trestle-linux-amd64.pyz smoke --output "$(pwd)/open-trestle-linux-smoke.json"

# a separately verified, strictly newer same-target candidate
sudo ./open-trestle-linux-amd64-new.pyz upgrade
sudo /usr/local/libexec/open-trestle/open-trestle-distribution.pyz verify-installed
# consume the one immediate-predecessor rollback slot, if needed
sudo /usr/local/libexec/open-trestle/open-trestle-distribution.pyz rollback-version

# retain the transaction-starting candidate outside the install root; use it after interruption
sudo ./open-trestle-linux-amd64-new.pyz recover

# choose one complete removal action for whichever generation is installed
sudo /usr/local/libexec/open-trestle/open-trestle-distribution.pyz rollback
# or, for a normal removal
sudo /usr/local/libexec/open-trestle/open-trestle-distribution.pyz uninstall
```

`install` validates the sidecar, complete archive grammar, canonical manifest, payload
modes, sizes, SHA-256 values, ELF headers and closed inventory before it publishes a
file. It streams members individually and does not call ZIP extraction APIs. Each file
is written through `O_EXCL` and `O_NOFOLLOW`, fsynced, and committed with Linux
`renameat2(RENAME_NOREPLACE)`. A receipt and transaction journal bind the installed
archive and every owned file. Existing targets stop the operation; there is no force or
unbounded replacement option.

`upgrade` first verifies the exact installed generation and the complete candidate. It
accepts only a strictly newer SemVer generation for the same fixed target. It stages and
validates the full replacement before changing live files, retains exactly the immediate
predecessor archive and sidecar, and binds the old and new versions, archives, manifests,
transaction and action in protected canonical receipt and journal files. New-only path
collisions, same or lower versions, tampered controls or owned files, unsafe ancestors,
wrong modes or ownership, and rollback-slot inconsistencies fail before mutation.
`rollback-version` runs only from the exact installed generation, restores only that
bound predecessor and its exact protected receipt and journal bytes, and consumes the slot. It cannot select an arbitrary older archive or
run twice. A second upgrade is refused while the rollback slot is pending. Upgrade and
version rollback preserve operator configuration, state and all unowned files.

The candidate reserves three mutually exclusive canonical records at the destination
root:

- `.open-trestle-linux-amd64.transaction.bootstrap.json`
- `.open-trestle-linux-amd64.transaction.pending.json`
- `.open-trestle-linux-amd64.transaction.committed.json`

The bootstrap record contains the exact canonical plan but admits no managed mutation.
`recover` removes only a valid bootstrap. A pending record always selects rollback to the
exact prior generation, or clean absence for an interrupted install. A committed record
requires every new final file to match before it removes only recorded temporary and
quarantine files. It never reconstructs a missing committed file. The pending-to-committed
rename followed by destination-root fsync is the sole commit decision. Generation and plan
identities use separate SHA-256 domains. Plans bind exact old and new descriptors, control
digests, deterministic staging and quarantine names, and bounded directory inventories.
Persisted inode or device numbers are not restart authority; those values are used only for
live race checks. Restart classification uses safe paths, regular-file type, mode, size,
SHA-256 and the applicable ownership policy.

`recover` first classifies the complete recorded state without mutation. Malformed,
noncanonical, multiple, tampered, unsafe, unexpected or ambiguous objects stop recovery
and preserve every object for operator inspection. Cleanup unlinks only a matching
recorded file and calls `rmdir` only on a recorded empty directory. It never recurses and
never deletes operator configuration, state, adjacent files or a nonempty directory.
Running recovery again after success is a no-op. Mutating lifecycle commands run the same
recovery gate first; `verify-installed` instead reports that explicit recovery is required.
Retain the transaction-starting candidate or another byte-identical verified rescue pyz
outside the installation root because the installed lifecycle path can be quarantined by
an interrupted transition.

On Ubuntu 24.04, a separate opt-in destdir matrix sends SIGKILL immediately after every
successful file or directory fsync and every successful `renameat2` boundary for install,
upgrade, `rollback-version`, and recovery itself. Every case converges to the exact
pre-commit generation or verified post-commit generation, preserves operator sentinels,
removes recorded debris, and remains idempotent. This evidence is conditional on atomic
rename plus successful file-fsync and directory-fsync semantics. It does not test loss of
unflushed writes, torn writes, kernel panic, controller caches, reboot, production `/`,
root ownership enforcement, any declared filesystem or mount profile, network or overlay
filesystems, or hostile root. It is not a power-loss or supported deployment claim.

`verify-installed` checks the receipt and journal, trusted ancestors, exact ownership in
production, modes, sizes, hashes and ELF identities. `smoke` first performs that check,
then runs a bounded, non-mutating CLI command-boundary probe with a fixed minimal
environment. In destdir mode it does not claim to exercise the scanner launcher,
because that launcher intentionally opens its worker at the fixed production path.
The container sandbox test remains the scanner execution gate. Smoke output is
canonical, content-free JSON and does not claim daemon, provider, database or network
readiness.

`rollback` reverses the receipt-bound install transaction. `uninstall` performs the
same full ownership preflight before deleting anything. Both quarantine and remove
only files that still match the receipt and remove only package-created directories
that are empty. A missing, changed, replaced, symlinked or
wrong-owner file observed during the complete preflight stops removal before any owned
file is deleted. Each later removal uses a same-directory atomic quarantine and
identity check. The exclusive-control boundary above excludes concurrent same-authority
mutation during that transaction. Application configuration under `/etc/open-trestle`, application state under
`/var/lib/open-trestle`, pre-existing directories and unowned files are preserved.
There is no purge mode. The lifecycle does not configure, enable or start a service and
does not create application configuration or state.

### Secret-scanner runtime boundary

The root client invokes only `/usr/local/libexec/open-trestle/open-trestle-secret-scanner --stdio-v1`. That static, single-threaded launcher applies `NO_NEW_PRIVS`, core, CPU, and file-descriptor limits plus a Landlock domain, then executes only `/usr/local/libexec/open-trestle/open-trestle-secret-scanner-worker --sandboxed-stdio-v1`. The Go worker installs a process-wide TSYNC seccomp filter before Betterleaks initialization. The pair receives anonymous pipes, cwd `/`, and an empty environment. The worker cannot open network sockets, mutate the filesystem, create namespaces, mount filesystems, trace another process, or execute another program. A sandbox or identity failure occurs before source input is accepted.

Both files must be root-owned, group `root`, mode `0555`, beneath root-owned non-writable directories, and must match the digests compiled into `trestled`. This trust check protects against replacement by the unprivileged service account. It does not protect a host after root or kernel compromise. Host-root control can replace code, inspect process memory, or change enforcement and is outside this boundary's threat model. Keep host administration, image admission, kernel patching, and runtime isolation as separate controls.

The cost model is one child process per scan. That process starts as the launcher and replaces itself with the worker through the fixed exec boundary; there is no process pool or sidecar. A successful sanitization normally pays for two child processes: one initial scan and one fresh residual scan. Generation and independent verification sanitize their requests separately. Capacity planning must include that cold-start cost rather than assuming one long-lived scanner per review.

The framed request accepts 1 to 256 valid-UTF-8 fields, at most 256 KiB each and 2 MiB decoded in aggregate. Request and response frames are capped at 3 MiB and 4 MiB, respectively, and a complete response is capped at 8,192 findings. The worker deadline is five seconds after the frame is decoded; the parent hard watchdog is six seconds from process start or an earlier caller deadline. A limit, timeout, cancellation, nonzero exit, stderr byte, malformed or extra output, incomplete scan, or residual finding discards all matches and blocks dispatch. No partial scan result is accepted.

### Scanner observability and privacy

Operational records are limited to closed failure classes, scanner and build-profile identities, launcher and worker digests, duration, field and byte counts, match counts, receipt identities, rule IDs, and zero-based half-open byte spans. The child writes protocol data only to stdout and must keep stderr empty. The parent does not log request or response frames, source bytes, matched values, upstream errors, or process error text. Initial and residual receipts contain no field content, paths, snippets, matches, source digests, or Betterleaks fingerprints.

Content-free does not mean sensitivity-free. A span reveals the field ordinal, location, and length of a suspected secret. Restrict receipt, audit, and metric access to the review scope, and do not attach high-cardinality span or rule data to general metrics. Remote-provider telemetry is a separate boundary: the provider receives sanitized request text, and operators must keep provider content logging disabled under the approved route.

### Scanner upgrade and requalification

Treat any Betterleaks version, commit, embedded config, rule inventory, regexp engine, adapter behavior, launcher or Go toolchain, target, CGO setting, sandbox, timeout, or build-flag change as a new reviewed build profile. Before adopting it:

1. Diff the upstream public API and detection behavior, review the embedded config and sorted rule IDs, and review every linked module and license.
2. Regenerate the ruleset identity, allowlist, deterministic launcher and worker, binary digests, release evidence, SPDX, and root digest injection.
3. Run all public protocol, exact-span, repeat, cancellation, resource, sandbox, leakage, and residual-scan tests.
4. Run three canonical passes of the unchanged private corpus. The current gate is exactly 11/14 expected occurrences, 10/11 positive files, 2/2 repeated locations, 11/11 exact spans, the named bearer, AWS secret key, and AWS session token misses, and one `generic-api-key` near miss at `[7,51)`. A loss, changed span, or additional or changed near miss blocks adoption until reviewed.
5. Run five warm-cache 16 MiB direct-adapter passes and five maximum-legal 2 MiB end-to-end child-process passes. Each gate requires median wall time at most two seconds and maximum RSS at most 256 MiB.
6. Rerun root and worker tests, race tests, vet, deterministic packaging, staging inventory, release evidence, container sandbox, and the frozen-diff security review.

The private corpus and raw scanner output stay outside tracked release material. The baseline measures one fixed corpus and does not establish comprehensive secret detection.

## Generate unsigned local release evidence

Generate a deterministic checksum list and SPDX 2.3 inventory only from a clean checkout and the exact artifacts built from its declared revision. The tool reads the runtime Go module graph embedded in the two root binaries and the scanner worker, plus the non-development dependency entries in the npm lockfiles. The scanner-specific staging evidence separately binds the static launcher because it is not a Go binary.

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
  --created 2026-08-30T22:46:23Z \
  --output release-evidence
```

The `linux-amd64-lifecycle` artifact is canonical content-free JSON emitted only after
CI completes v1 install, v2 upgrade and verification, v1 `rollback-version` and
verification, a second v2 upgrade, smoke, and uninstall. It records only the ordered
action names, target, versions, archive digests and pass status. The release evidence
binds its exact bytes like every other artifact.

Use the commit timestamp normalized to UTC for `--created`. Artifact, Go binary, npm lockfile, and changelog inputs must remain below the working directory. The required changelog must be a regular, non-symlinked UTF-8 file of at most 1 MiB. It must contain exactly one nonempty `## Unreleased` section made from unique `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, or `Security` categories and nonempty `- ` bullets. The tool preserves those authored categories, bullets, and indented continuation lines in `release-notes.md`, alongside the bound version, revision, creation time, and a fixed candidate-status and non-support warning.

The output directory contains `release-notes.md`, `SHA256SUMS`, and `sbom.spdx.json`. Existing output is never replaced. The complete directory is installed atomically, so validation or write failure does not leave partial evidence at the requested output path. Artifact hashing streams SHA-1 and SHA-256 in one pass and rejects files that change during the read. `SHA256SUMS` remains SHA-256-only. Missing, empty, duplicate, malformed, sensitive, escaping, or symlinked inputs fail without creating a partial evidence directory.

This is an unsigned local inventory. The declared revision and timestamp are caller inputs, not independently verified provenance. The project-owned tests validate the exact SPDX fields emitted by the tool. CI also installs the official SPDX Workgroup `spdx-tools` 0.8.5 semantic validator from a fully pinned, hash-checked test-only lock and validates both generated SBOMs. The release-evidence tool does not identify the built container image, sign artifacts, publish an attestation, consult a vulnerability database, establish a SLSA level, or make the current experimental release suitable for production. CI separately runs the [passive vulnerability gate](vulnerability-gate.md) before generating this inventory. Preserve the distinction between that point-in-time advisory check and the missing signing, provenance, active validation, and deployment evidence.

## Validate runtime authority

Validate the exact route inventory and runtime policy before daemon startup. This command does not read provider credentials or contact a service. It does validate that each supported provider endpoint is usable by its adapter, including HTTPS or loopback-only HTTP, canonical host, port, and path rules, and absence of URL credentials, queries, or fragments.

```sh
trestle config validate \
  --route-inventory /etc/open-trestle/routes.json \
  --runtime-policy /etc/open-trestle/policy.json
```

The daemon applies stricter file checks at startup. Each authority path must be a regular, non-symlinked file with no group or world write permission.

## Initialize PostgreSQL

Use a migration role only for explicit schema changes. `trestle admin postgres migrate` reads `OPEN_TRESTLE_POSTGRES_MIGRATION_URL`, applies checksum-verified migrations under the migration lock, and creates the database namespace without granting publication authority. Use `trestle admin postgres initialize` only when required-mode publication is intended; it also creates the publication authority row once.

```sh
OPEN_TRESTLE_POSTGRES_MIGRATION_URL="$MIGRATION_URL" \
  trestle admin postgres migrate
```

For required-mode publication:

```sh
OPEN_TRESTLE_POSTGRES_MIGRATION_URL="$MIGRATION_URL" \
  trestle admin postgres initialize \
  --authority-identity "$OPERATOR_AUTHORITY_DIGEST"
```

The authority argument is a nonzero lowercase SHA-256 digest of a stable, non-secret operator deployment identifier. It is not a password. Capture the returned `publication_authority_receipt_identity` in the deployment's protected recovery records. Do not rerun initialization to repair an unexpected restore identity.

Normal application credentials must use a separate connection URL in `OPEN_TRESTLE_POSTGRES_URL`. Read the non-secret runtime-role database authority with `trestle admin postgres identity`. Then verify migrations and, when publication is enabled, the database-owned fence namespace before starting the daemon:

```sh
OPEN_TRESTLE_POSTGRES_URL="$APPLICATION_URL" \
  trestle admin postgres verify \
  --authority-identity "$OPERATOR_AUTHORITY_DIGEST" \
  --expected-receipt-identity "$EXPECTED_RECEIPT_IDENTITY"
```

The commands print no connection string or operator digest. Failure output is content-free. Pass the identity from `trestle admin postgres identity` to every PostgreSQL daemon as `--postgres-database-authority-identity`; startup fails before serving if the exact runtime database authority differs.

## Local full-review recovery point

Stop the daemon before copying its private `--state-dir`, the configured
`--setup-state` file and its `.receipts` directory. Retain the exact route inventory,
runtime policy, source Git object store, setup-root identity, binary version and
scanner digests with the recovery-point record. Keep credentials separate. Do not
copy a live journal or combine files from different recovery points. Protect backup
bytes with the same private modes and access controls as the originals.

The local source-owner record binds the absolute paths and Linux directory
identities of the state root, artifact root and Git object root. Restoring regular
file bytes into those same retained directories can preserve that ownership.
Recreating a directory, restoring to another path or moving to another machine is
not a supported re-enrollment: startup refuses an owner mismatch even when the
copied bytes are otherwise complete. Do not edit or remove the owner record to
bypass that refusal. Retain the backup and use a separately initialized state root
for a new run if the original ownership cannot be preserved.

Before restarting workers, compare the closed backup inventory and file hashes
with the restored bytes, verify the configured setup and source identities, and
replay terminal receipts and diagnostics without dispatch. Confirm their exact
identities match the recovery-point record. This guide does not yet provide an
executable replay-only procedure for that check. Normal daemon startup is not a
read-only verifier: it can recover stored effects and starts pre-model workers
even when `--local-model-workers` is disabled. Do not start the daemon as a
substitute for the replay-only check. If that check cannot be performed, retain
the stopped state and recovery point; do not treat the restore as qualified.
These are in-place, stopped-daemon recovery requirements, not portable backup
qualification, a filesystem snapshot protocol, or proof of power-loss durability.

A terminal internal failure alone does not permit restart. For an initial generation
attempt rejected only for candidate-document shape, startup can admit the retained
failed run only after fresh journal, five-event audit, exact artifact, current
route, handler, scanner, and full pipeline-catalog checks succeed. The failed run
remains inconclusive with no candidate output. Restart does not dispatch that
history again. The rejection witness retains no response text.

Missing, expired, changed, extra, uncertain, or unsupported evidence, and unresolved
effect markers, still stop startup. This path does not recover arbitrary failed
or partial model effects. Do not delete the journal, audit events, artifacts or
owner record to force a restart. Stop the daemon and retain the complete recovery
point. If startup refuses that history, use a separately initialized state root
and a new run ID for unrelated work, preserving the original state for review.
This is isolation of unproven history, not successful in-place recovery.

This evaluation profile is not yet qualified as a supported v1 installation.

## Backup and restore

A complete backup must preserve PostgreSQL metadata, publication attempts, the publication authority singleton, protected artifact objects, envelope metadata, and the keys needed to decrypt retained objects. Database and object-store snapshots must represent one documented recovery point. A database snapshot without its corresponding protected objects is incomplete. A restored object set without the matching metadata is also incomplete.

Before accepting a restore:

1. Restore into an isolated environment with external publication disabled.
2. Verify PostgreSQL migration checksums.
3. Verify the expected publication authority receipt identity.
4. Confirm the restored publication-attempt history covers the declared recovery point.
5. Verify protected artifact retrieval and envelope-key access using non-sensitive conformance objects.
6. Run a replay-only review and compare its journal-derived terminal state with the recorded receipt.
7. Enable ingress, workers, model dispatch, and publication only after those checks pass.

The authority receipt detects a fresh or independently initialized database. It cannot prove that a copy carrying the same authority row contains every later transaction. Operators must use database backup consistency, recovery-point records, and publication-attempt verification to rule out stale restores.

## Retire an old active review plan after a typed incompatibility

For the local full-review evaluation profile, a context abstention first appends a bounded, content-free v3 prepare event to the private file journal. Only then does the daemon put the scoped deterministic artifact and append the failed-task result. On restart, before any supervisor or listener can settle an expired context lease, the daemon replays an unresolved prepare, validates its exact plan/task/scope/provenance and artifact bytes, restores a missing artifact from the journaled envelope, and writes one linked failed-task result. A corrupt, expired, ambiguous, or unavailable prepared artifact stops startup; it never becomes an empty-output success or model-ready task. This is a local FileRunJournal and local artifact-store path, not a qualified PostgreSQL/S3 full-review migration. The existing full-local daemon configuration rejects those nonlocal stores; their current event storage bound is not a v3 conformance claim.

If replay or startup reports a typed incompatibility for an old active review plan, halt dispatch and publication for that plan. Do not treat an incompatible journal as a completed review or silently rewrite its immutable plan and events. For the local single-node profile, stop the daemon and take a consistent backup of the entire private `--state-dir` (journal, artifacts, and diagnostics) together with the configured `--setup-state` file, before any disposition. Record the recovery point and confirm the backup can be read. For PostgreSQL/S3 profiles, use their consistent metadata/object/envelope-key backup procedure instead. Do not copy a live file journal piecemeal.

An operator may use a compatible stage-2 runtime and authenticated `trestle runs cancel --tenant ID --repository ID --run ID --server URL` to retire the old plan. First verify that the runtime can replay the plan and that cancellation is authorized for that exact scope. If a compatible runtime cannot safely replay and cancel it, leave the old plan intact and isolated for later operator review. There is no automatic cancellation or supported migration of an incompatible active plan. If cancellation is confirmed, start the newer daemon against that state and submit a fresh review run ID. If the old active plan remains intact, the newer daemon will still refuse that state: isolate and retain its backup, and use a separately initialized state root for any fresh run. Never reuse the old run ID or claim this is an in-place migration.

## Shutdown and health

Use `/healthz` for process liveness and `/readyz` for dependency readiness. Both responses are content-free. Send `SIGTERM` for shutdown. Internal runtime failure also starts shutdown. The daemon seals root request admission, cancels runtime and request contexts, and observes HTTP shutdown, every started supervisor, every admitted root handler, and repository-worker handler drain before starting store cleanup. Late root requests receive a content-free `503 Service Unavailable`. A response write, supervisor return, or closed listener alone is not proof that handlers stopped.

The shutdown observer has a ten-second budget. If users or cleanup outlive it, stores are not closed beneath live users. Embedded callers receive an incomplete-shutdown error that retains the daemon and exposes `Finish(context.Context)` for another bounded observation. Every observation refers to the same stopped runtime and the same ordered, exactly-once closer chain. It does not retry a partially attempted closer. Cleanup errors remain failures even after the closer call returns.

The `trestled` executable reports incomplete shutdown and exits nonzero rather than waiting indefinitely or running a background retry. This is process containment, not successful cleanup, confirmed flush, or eligible recovery. The HTTP shutdown phase has its existing ten-second grace period; concrete store closers have no universal context bound. An embedded caller must retain an incomplete error until it finishes observing shutdown or explicitly terminates its process.

Configure the service manager with an explicit termination grace period and alert on an overrun or failed shutdown. Before backup or restart, confirm that the old daemon process and any processes it started have exited. A closed socket or shutdown error is not proof that all work stopped. This limitation is not a supported interrupted-recovery guarantee.

Do not infer review or publication success from health endpoints. Query the authenticated run receipt and canonical review diagnostics instead. Versions 1 through 5 contain independently verified finding state; version 6 contains deterministic observations that remain unverified and require their own review disposition.

Use repository-scoped runtime inspection to confirm the daemon loaded the expected non-secret database, rate-limit, route, policy, and handler authorities and completed supervisor reconciliation:

```sh
OPEN_TRESTLE_API_TOKEN="$OBSERVER_TOKEN" \
  trestle admin runtime status \
  --server https://trestle.example.invalid \
  --tenant example \
  --repository example-repository
```

The optional `OPEN_TRESTLE_OBSERVER_TOKEN` configured on `trestled` has `run_read` and `runtime_read` only. Use it for this command. The required `OPEN_TRESTLE_API_TOKEN` is the full-authority operator and worker credential and should not be placed in a read-only console. Compare `configuration_identity`, route and policy identities, storage posture, publication-fence state, handler identities, and component readiness with the deployment record. The command does not reveal service endpoints or credentials. A ready runtime still does not imply that a review succeeded or publication is safe.

## Offline in-place recovery comparison

Stop the daemon and every child process before taking a consistent copy. Keep the
original state, artifact, setup and Git object directories. The owner record binds
Linux directory identity and absolute paths. Recreating those directories is not
supported re-enrollment, even if file bytes match.

The `trestled recovery-point` command emits a private canonical comparison record
on stdout. Save it outside the state directory under operator-only permissions.
Retain the matching state and Git object bytes, setup receipt ledger, daemon binary,
scanner and scanner-worker binaries, route inventory and runtime policy. Credentials
are separate and are never read by these offline commands.

```
umask 077
trestled recovery-point --state-dir /private/state \
  --repository-authority local.example --repository-namespace team \
  --repository-name repository --binary /retained/trestled \
  --scanner /retained/scanner --scanner-worker /retained/scanner-worker \
  --route-inventory /retained/routes.json --runtime-policy /retained/policy.json \
  > /private/recovery-point.json
```

After restoring regular leaf bytes into the retained directories, run
`trestled verify-restore` with the same flags and
`--record /private/recovery-point.json`. It compares private inventory hashes,
owner/setup identities, replayed receipts, artifact/deletion records, diagnostics,
audit history, Git object bytes and retained runtime inputs. It does not construct
a daemon, dispatch work, run scanners, call providers, repair files or recover
pending effects. A held existing writer lock or unresolved effect refuses the
comparison. Completed deletions remain observations; they do not authorize erasure.
Nonempty webhook intake is outside this publication-disabled local comparison.

A `matched` result means the observed stopped bytes match the record. Active runs
produce `matched_pending`. Both report `restart_authorized:false`. Neither proves
backup freshness, authenticates the recovery record, or decides that uncertain
history is safe to restart. Preserve refused state for operator review. Never edit
an owner record or delete an uncertain marker to make the command pass.

The command currently supports setup at `state/setup/plan.json` only. It bounds the
record at 4 MiB, each state/Git inventory at 30,000 entries and 256 MiB of regular
file bytes, depth 8, and 500 runs. Exceeding a bound is refusal, not corruption or
proof of absence. Existing canonical store/parser bounds also apply. This is not
a filesystem snapshot protocol, portable restore, supported installed profile,
physical power-loss test, or v1 acceptance claim.

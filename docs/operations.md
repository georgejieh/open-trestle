# Operations and recovery

## Build

The root module declares Go 1.25.0 and is built with Go 1.26.8. The isolated secret-scanner module declares Go 1.25.0 and is built with Go 1.25.12. Keep the toolchains separate and disable workspace discovery for both:

```sh
GOWORK=off GOTOOLCHAIN=go1.26.8 go mod verify
GOWORK=off GOTOOLCHAIN=go1.26.8 go test ./...
(
  cd workers/secret-scanner
  GOWORK=off GOTOOLCHAIN=go1.25.12 go mod verify
  GOWORK=off GOTOOLCHAIN=go1.25.12 go test ./...
)
```

A normal root `go build` is useful for development, but it does not inject the trusted scanner binary digests. Such a `trestled` build fails closed when sanitized egress is requested. Build the release staging tree with the reviewed packaging tool instead:

```sh
python3 tools/package_secret_scanner.py --output .container
python3 tools/package_secret_scanner.py --verify .container
docker build --network=none -t open-trestle:local .
```

The tool verifies the root and worker Go pins, Betterleaks module and ruleset identities, linked license inventory, launcher source and build contract, and the complete pinned Zig 0.14.1 x86_64-linux-musl toolchain archive and extracted tree. It builds the static launcher twice with separate Zig caches, builds the Go worker twice, and requires byte-identical outputs for both binaries. It then records both SHA-256 values, emits scanner release evidence and SPDX with SHA-1 and SHA-256 file checksums, injects both SHA-256 digests into the Go 1.26.8 `trestled` binary, and admits only the fixed staging inventory. The launcher uses empty-environment static-PIE flags. The worker uses `GOWORK=off`, Go 1.25.12, `GOOS=linux`, `GOARCH=amd64`, `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`, and an empty build ID.

The included `Dockerfile` copies that staging tree into a scratch image with no registry base. The image runs `trestled` as UID and GID 65532. Supply runtime authority files through read-only mounts and credentials through the documented environment variables. Do not bake route inventories, policies, tokens, database URLs, or key material into an image. The image includes the project license, NOTICE, exact runtime third-party license texts, and scanner release evidence.

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
  --go-binary .container/trestle \
  --go-binary .container/trestled \
  --go-binary .container/libexec/open-trestle/open-trestle-secret-scanner-worker \
  --npm-lock web/package-lock.json \
  --npm-lock extensions/vscode/package-lock.json \
  --version 0.1.0-dev \
  --revision "$(git rev-parse HEAD)" \
  --created 2026-08-30T22:46:23Z \
  --output release-evidence
```

Use the commit timestamp normalized to UTC for `--created`. Artifact, Go binary, and npm lockfile inputs must remain below the working directory. The output directory contains `SHA256SUMS` and `sbom.spdx.json`. Existing output is never replaced. Artifact hashing streams SHA-1 and SHA-256 in one pass and rejects files that change during the read. `SHA256SUMS` remains SHA-256-only. Missing, empty, duplicate, sensitive, escaping, or symlinked inputs fail without creating a partial evidence directory.

This is an unsigned local inventory. The declared revision and timestamp are caller inputs, not independently verified provenance. The project-owned tests validate the exact SPDX fields emitted by the tool. CI also installs the official SPDX Workgroup `spdx-tools` 0.8.5 semantic validator from a fully pinned, hash-checked test-only lock and validates both generated SBOMs. The tool does not identify the built container image, sign artifacts, publish an attestation, consult a vulnerability database, establish a SLSA level, or make the current experimental release suitable for production. Preserve those distinctions until separately authorized release infrastructure produces and verifies the missing evidence.

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

## Shutdown and health

Use `/healthz` for process liveness and `/readyz` for dependency readiness. Both responses are content-free. Send `SIGTERM` for shutdown. The daemon applies a ten-second bound to HTTP listener shutdown, cancels supervisor contexts, then waits for supervisors to return before closing durable stores. The supervisor join is intentionally not a hard timeout because closing storage beneath active work would be unsafe. Handlers are required to honor cancellation, but a defective handler can delay process exit. Configure the service manager with an explicit termination grace period and alert on an overrun.

Do not infer review or publication success from health endpoints. Query the authenticated run receipt and verified diagnostics instead.

Use repository-scoped runtime inspection to confirm the daemon loaded the expected non-secret database, rate-limit, route, policy, and handler authorities and completed supervisor reconciliation:

```sh
OPEN_TRESTLE_API_TOKEN="$OBSERVER_TOKEN" \
  trestle admin runtime status \
  --server https://trestle.example.invalid \
  --tenant example \
  --repository example-repository
```

The optional `OPEN_TRESTLE_OBSERVER_TOKEN` configured on `trestled` has `run_read` and `runtime_read` only. Use it for this command. The required `OPEN_TRESTLE_API_TOKEN` is the full-authority operator and worker credential and should not be placed in a read-only console. Compare `configuration_identity`, route and policy identities, storage posture, publication-fence state, handler identities, and component readiness with the deployment record. The command does not reveal service endpoints or credentials. A ready runtime still does not imply that a review succeeded or publication is safe.

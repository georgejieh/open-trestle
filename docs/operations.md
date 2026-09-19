# Operations and recovery

## Build

Open Trestle requires Go 1.24 or newer.

```sh
go test ./...
go build -trimpath -o bin/trestle ./cmd/trestle
go build -trimpath -o bin/trestled ./cmd/trestled
```

The included `Dockerfile` packages prebuilt static binaries into a scratch image and has no registry base. Prepare its deliberately narrow build context first:

```sh
mkdir -p .container/data
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o .container/trestle ./cmd/trestle
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o .container/trestled ./cmd/trestled
cp /etc/ssl/certs/ca-certificates.crt .container/ca-certificates.crt
cp LICENSE .container/LICENSE
cp NOTICE .container/NOTICE
cp -R THIRD_PARTY_LICENSES .container/licenses
docker build --network=none -t open-trestle:local .
```

The image runs `trestled` as UID and GID 65532. Supply runtime authority files through read-only mounts and credentials through the documented environment variables. Do not bake route inventories, policies, tokens, database URLs, or key material into an image. Record the binary and CA-bundle digests as release inputs. The image includes the project license, NOTICE, and runtime third-party license texts.

## Generate unsigned local release evidence

Generate a deterministic checksum list and SPDX 2.3 inventory only from a clean checkout and the exact artifacts built from its declared revision. The tool reads the runtime Go module graph embedded in both binaries and the non-development dependency entries in the npm lockfiles.

```sh
test -z "$(git status --porcelain)"
python3 tools/release_evidence.py \
  --artifact container=.container \
  --artifact web=web/dist \
  --artifact vscode=extensions/vscode/dist/open-trestle.vsix \
  --go-binary .container/trestle \
  --go-binary .container/trestled \
  --npm-lock web/package-lock.json \
  --npm-lock extensions/vscode/package-lock.json \
  --version 0.1.0-dev \
  --revision "$(git rev-parse HEAD)" \
  --created 2026-08-30T22:46:23Z \
  --output release-evidence
```

Use the commit timestamp normalized to UTC for `--created`. Artifact, Go binary, and npm lockfile inputs must remain below the working directory. The output directory contains `SHA256SUMS` and `sbom.spdx.json`. Existing output is never replaced. Artifact hashing is streaming and rejects files that change during the read. Missing, empty, duplicate, sensitive, escaping, or symlinked inputs fail without creating a partial evidence directory.

This is an unsigned local inventory. The declared revision and timestamp are caller inputs, not independently verified provenance. The project-owned tests validate the exact SPDX fields emitted by the tool, but release acceptance must also validate the output against an independently pinned official SPDX 2.3 schema. The current CI does not fetch or vendor that external schema. The tool does not identify the built container image, sign artifacts, publish an attestation, consult a vulnerability database, establish a SLSA level, or make the current experimental release suitable for production. Preserve those distinctions until separately authorized release infrastructure produces and verifies the missing evidence.

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

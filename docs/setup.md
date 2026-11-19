# Setup planning

A setup plan is a record of a deployment's posture and of the checks that still block readiness. It contains no secrets, and it is content-addressed, meaning that its identity is a hash of its contents. Creating a plan does not contact a provider, connect a forge or enable publication.

This page is for operators who run `trestled` and need a deployment plan. To set up a review of one repository on your own machine, run `trestle init` instead. It asks a few questions and writes the setup folder and its plan for you, and `trestle review` then reviews the latest change. See [getting started](getting-started.md), and [local-first bootstrap](local-first-bootstrap.md) for the commands that `trestle init` runs.

## Create a protected plan

Create a private directory and initialize one deployment profile:

```sh
install -d -m 0700 "$HOME/.local/state/open-trestle/setup"
trestle setup init \
  --profile local_single_node \
  --tenant example \
  --repository example-repository \
  --recovery-owner platform-owner \
  --state "$HOME/.local/state/open-trestle/setup/plan.json"
```

The state path must not exist. Its parent must be a directory that is not a symlink and has no group or other write permission. The CLI creates the plan with mode `0600`, synchronizes the file and its parent directory, and never overwrites an existing plan.

Only `Runner.Run` creates later revisions. It executes an approved checker and applies that checker's receipt for the current plan through the protected state writer. Each revision increments the revision number and binds the previous identity and the checker-catalog identity. It is written by an atomic replacement, and the receipt and parent directories are synchronized.

If a stop occurs after the receipt is durable but before the plan head changes, `StateFile.PendingReceipt` exposes that one fenced receipt. The same transition can then finish without rerunning the check.

Inspect and validate the canonical state with:

```sh
trestle setup inspect \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --expected-root-identity "$RECORDED_INITIAL_PLAN_IDENTITY"
```

Initialization also creates a private, append-only receipt ledger beside the plan, at `plan.json.receipts`. Back up, restore and transfer the plan and the receipt ledger together. A plan that is copied without its ledger is rejected once it contains a closed check.

For a daemon that uses local metadata, keep `--setup-state` either under the private `--state-dir/setup/plan.json` directory or outside `--state-dir` (such as the sibling of a `runs` state root). Do not use a direct child such as `--state-dir/plan.json` or `--state-dir/setup.json`. Daemon startup rejects this layout, including its `.lock`, `.receipts` and possible `.next` siblings. See [daemon root inventory](daemon-api.md#start-a-local-daemon).

### Offline move of a direct-root setup plan

Use this procedure to move a plan that sits directly under `--state-dir` to a layout that daemon startup accepts.

1. Stop the daemon and all setup writers.
2. Inspect the original state, and record its exact initial root identity and its current plan identity.
3. Create a protected backup snapshot at a new path that does not exist, outside the live setup directory: `trestle setup backup create --state "$OLD_DIRECT_PLAN" --destination "$NEW_PROTECTED_BACKUP" --expected-plan-identity "$CURRENT_PLAN_IDENTITY"`. The snapshot contains the complete, verified receipt ledger, not only `plan.json`.
4. Restore the snapshot with the backup and restore commands below, to a new protected `--state-dir/setup/plan.json` or to a path outside the root. Pass both `--expected-root-identity "$RECORDED_INITIAL_PLAN_IDENTITY"` and `--expected-plan-identity "$BACKED_UP_PLAN_IDENTITY"`. The destination plan path must not exist, and its private, trusted parent directory must already exist. Restore never overwrites.
5. Inspect the restored path with `trestle setup inspect --state "$NEW_PLAN" --expected-root-identity "$RECORDED_INITIAL_PLAN_IDENTITY"`, and verify its exact plan identity and its full receipt history. Keep the verified external backup.
6. While both writers are still stopped, move the original direct-root plan, lock, receipt ledger and staging entries to a protected location outside `--state-dir`. Do this through an offline transfer that an operator has reviewed. Do not leave direct-root copies in place.
7. Only after those entries are gone, update `--setup-state` and check that the daemon starts. Keep the original protected copy until you have verified the restored path and the startup.

An unknown direct entry continues to block startup. Open Trestle does not move or delete these files itself.

### How receipts are written

Receipt writes require a filesystem that supports hard links within one directory and file and directory synchronization. Open Trestle writes each receipt to its canonical receipt filename plus `.next`, synchronizes it and closes it. A hard link then installs the immutable final name without overwriting anything. The ledger directory is synchronized before and after the staging file is removed. If the filesystem does not support hard links or synchronization, the write fails. There is no fallback that overwrites.

When a writer reopens the ledger, it can reclaim one protected staging file, either for the next revision or for a receipt that is already installed and verified. Read-only inspection leaves that staging file unchanged. A complete staging file without a final name is uncommitted, and Open Trestle discards it. Only a complete final receipt can resume a transition without rerunning its check. Unknown names, unsafe staging files and malformed committed receipts remain errors.

During restore, staging recovery is limited to the next receipt after a valid, contiguous installed prefix. Restore checks the snapshot and root identities before it opens the destination, and checks all installed receipts against the snapshot before it installs the plan.

The initial and restored plan files are written and synchronized under the protected `<state>.next` name. A hard link then installs the complete final plan without overwriting anything. When a writer reopens, it can discard the uncommitted plan staging file. A partially written final plan remains an error and is not overwritten automatically.

Inspection rejects symlinks, broad file permissions, replacement races, unknown fields, noncanonical JSON, invalid identities, unsafe profile combinations and inconsistent readiness.

## Offline posture checks

Five built-in checks can advance the protected plan without network access:

```sh
trestle setup check storage \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --storage-root "$HOME/.local/state/open-trestle"

OPEN_TRESTLE_API_TOKEN="$OPERATOR_TOKEN" \
OPEN_TRESTLE_OBSERVER_TOKEN="$OBSERVER_TOKEN" \
  trestle setup check observer \
  --state "$HOME/.local/state/open-trestle/setup/plan.json"


trestle setup check administrator \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --approved-by platform-owner

# For an air-gapped plan, derive the authority as documented below, then run:
trestle setup check bundle \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --approve-signed-bundle-authority-identity "$SIGNED_BUNDLE_AUTHORITY_IDENTITY" \
  --bundle "$ABSOLUTE_BUNDLE_PATH" \
  --bundle-sha256 "$BUNDLE_SHA256" \
  --bundle-bytes "$BUNDLE_BYTES" \
  --public-key "$ED25519_PUBLIC_KEY_HEX" \
  --signature "$ED25519_SIGNATURE_HEX" \
  --approved-by platform-owner
```

### Storage and observer checks

The storage posture check opens one directory that the current user owns, with mode `0700`, and rechecks every ancestor up to the filesystem root. Each ancestor must be owned by the current user or by root. An ancestor with group or other write access must also be sticky and protect a child entry that the current user owns. Symlinked or replaceable path components are rejected.

Several checks depend on file ownership: administrator, backup, storage and protected runtime files. On Windows they read each file's and folder's owner and access control list instead of its mode (see [platforms](platforms.md#protected-files-on-windows)). They return `unavailable` on platforms where ownership authority is not implemented, and protected setup state refuses to open or inspect there. The mutable state, lock and receipt files must be owned by the user of the setup process. Their parent chain must prevent another local principal from replacing them before the check creates a lock, changes a mode, cleans up or reads. The storage check does not claim that backup, capacity or crash recovery was tested.

The observer credential posture check validates that both values are safe in a header and that the credentials differ. It does not store either credential, and it does not check that a daemon accepts the observer credential.

### Administrator check

The administrator check binds the setup root, tenant, repository, named recovery owner, and the effective operating-system user and group of the current process. `--approved-by` must match the plan's recovery owner. It does not create an account or grant operating-system privileges.

### Backups

Record the current plan identity, then create a protected backup snapshot:

```sh
trestle setup backup create \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --destination "$HOME/backups/open-trestle/plan.snapshot.json" \
  --expected-plan-identity "$CURRENT_PLAN_IDENTITY"

trestle setup check backup \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --backup-snapshot "$HOME/backups/open-trestle/plan.snapshot.json"
```

The destination directory must already exist with mode `0700`, have a stable, trusted chain of ancestors, differ from the live state directory, and not be nested beneath it. Snapshot creation never overwrites a path. The file has mode `0600` and contains the plan and its complete receipt history.

The checker requires that the current process owns the file and that its plan and root identities equal the live plan's. A stale snapshot cannot pass a later check after another receipt changes the plan.

Restore only to a new protected state path, and fence both recorded identities:

```sh
trestle setup backup restore \
  --snapshot "$HOME/backups/open-trestle/plan.snapshot.json" \
  --destination "$HOME/.local/state/open-trestle-restored/plan.json" \
  --expected-root-identity "$RECORDED_INITIAL_PLAN_IDENTITY" \
  --expected-plan-identity "$BACKED_UP_PLAN_IDENTITY"
```

Restore rebuilds the append-only receipt ledger and validates the restored state before it returns. It never overwrites state, and it can resume an interrupted rebuild of the ledger. A passing backup check confirms that one separate, protected copy of the setup state is complete. It does not cover independent media, off-site retention, application artifacts or database backups, which remain your responsibility.

### Exit codes

A passed check exits with code `0`. A `blocked` or `unavailable` check that completed writes its canonical receipt and exits with code `3`. Malformed arguments, invalid setup identifiers and unsupported profiles print usage and exit with code `2`. An identity mismatch, stale state, checker failure or persistence failure exits with code `1`.

Offline checks write only the protected plan and the receipt ledger. Backup creation writes only its new snapshot, and restore writes only its new state path, lock and receipt ledger. None of these contacts a provider, forge, database, object store or model.

## PostgreSQL storage authority

Controlled-hybrid and Kubernetes profiles use a database-native namespace rather than a hash of connection credentials. A migration administrator creates or upgrades the schema:

```sh
OPEN_TRESTLE_POSTGRES_MIGRATION_URL="$MIGRATION_DSN" \
  trestle admin postgres migrate
```

The command applies the embedded migration set and creates the durable database namespace. Next, use the separately scoped runtime credential to derive the identity of the runtime role. This changes nothing:

```sh
OPEN_TRESTLE_POSTGRES_URL="$RUNTIME_DSN" \
  trestle admin postgres identity
```

After you record that non-secret identity, run the confirmed setup check:

```sh
OPEN_TRESTLE_POSTGRES_URL="$RUNTIME_DSN" \
  trestle setup check postgres \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --approve-postgres-authority-identity "$DATABASE_AUTHORITY_IDENTITY" \
  --approved-by platform-owner
```

The checker verifies the setup scope, recovery owner and approvals before it reads `OPEN_TRESTLE_POSTGRES_URL`. It opens one connection. In one repeatable-read transaction, it verifies every migration checksum, the database name, the active schema, the runtime role and the durable namespace.

The DSN, password and SQL errors do not enter setup state. A connection failure or timeout is `unavailable`. A migration conflict, a substituted role or schema, or an identity mismatch is `blocked`.

The check confirms the identity of the metadata store and the compatibility of its schema at one point in time. Artifact encryption, backup recovery, replica reconciliation and the other requirements are separate checks.

Budgeted artifact erasure requires the PostgreSQL schema to include the full embedded migration registry, including `0012_artifact_erasure.sql` and `0013_artifact_erasure_resume.sql`. Apply that schema only through an explicitly authorized migration administrator, before you start the daemon in budgeted mode. In budgeted mode the daemon verifies the runtime database identity, the migration checksums, the artifact erasure schema and the resume schema in read-only snapshots. It applies no migration, and it rejects `--apply-migrations` and `OPEN_TRESTLE_POSTGRES_MIGRATION_URL`.

## Shared API rate limiting

Kubernetes HA plans require `shared_rate_limit_validated` after PostgreSQL storage authority passes. Migration 9 adds one shared fixed-window table that holds no content. Derive the setup and runtime identities offline, from the verified database identity and the root identity that `trestle setup inspect` shows:

```sh
RATE_LIMIT_AUTHORITY_IDENTITY="$(
  trestle admin postgres rate-limit identity \
    --database-authority-identity "$POSTGRES_DATABASE_AUTHORITY_IDENTITY" \
    --setup-root-identity "$SETUP_ROOT_IDENTITY" |
  jq -r .shared_rate_limit_authority_identity
)"
```

### How the limiter works

The runtime uses two fixed PostgreSQL namespaces:

- Requests before authentication: at most 120 requests per database-clock minute, across 10,000 active key digests.
- Authenticated principals: at most 600 requests per database-clock minute, across 1,024 active key digests.

Raw network addresses, tenant IDs, principal IDs and bearer tokens are not stored. Requests before authentication are keyed by the IP address of the direct TCP peer, and a forwarded-address header is ignored. If you need a limit for each client at the ingress, a reverse proxy needs its own client-aware limit. A conflicting live configuration fails.

The limits use PostgreSQL `transaction_timestamp()`, so clock skew on a replica host cannot create extra permits.

A database error, a live configuration conflict or an exhausted number of keys in a namespace returns 503 `rate_limit_unavailable` and grants no request. When an established key's request quota is exhausted, the server returns 429. Local metadata mode keeps its own in-memory limiter, which is local to one process and does not satisfy this HA requirement.

### The conformance check

Run the explicit database conformance check:

```sh
trestle setup check rate-limit \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --approve-shared-rate-limit-authority-identity "$RATE_LIMIT_AUTHORITY_IDENTITY" \
  --postgres-database-authority-identity "$POSTGRES_DATABASE_AUTHORITY_IDENTITY" \
  --approved-by platform-owner
```

After it verifies the PostgreSQL receipt, scope, actor and plan, the probe reads `OPEN_TRESTLE_POSTGRES_URL` and revalidates every migration and the database identity. It requires that:

- Two limiter instances share one quota of two requests and reject the third request.
- The two instances share a bound of two keys and reject a third key.
- The quota resets only after the expiry measured by the database clock.
- Of two concurrent attempts for the final permit, exactly one succeeds.
- The table contains only the two expected key digests and configuration identities.

A pass deletes the conformance rows and verifies that none remain.

A process stop can leave conformance rows that hold only digests, counts and times. Their admission expires after one minute. A retry for the same setup root removes expired rows before it proceeds. Without a retry, they remain until operator maintenance.

The check covers the application-level shared limiting against the configured primary database. Load balancer behavior, PostgreSQL replication health and provider quotas are outside it.

## Replica reconciliation

Kubernetes HA plans also require `replica_reconciliation_validated`. This check is separate from PostgreSQL identity and shared rate limiting. It checks that the journal, notification queue, task leases and terminal reconciliation converge through the configured database. Derive the authority identity offline:

```sh
REPLICA_RECONCILIATION_AUTHORITY_IDENTITY="$(
  trestle admin postgres reconciliation identity \
    --database-authority-identity "$POSTGRES_DATABASE_AUTHORITY_IDENTITY" \
    --setup-root-identity "$SETUP_ROOT_IDENTITY" |
  jq -r .replica_reconciliation_authority_identity
)"
```

Run the confirmed conformance check only after the PostgreSQL storage receipt passes:

```sh
trestle setup check reconciliation \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --approve-replica-reconciliation-authority-identity "$REPLICA_RECONCILIATION_AUTHORITY_IDENTITY" \
  --postgres-database-authority-identity "$POSTGRES_DATABASE_AUTHORITY_IDENTITY" \
  --approved-by platform-owner
```

Before the probe reads `OPEN_TRESTLE_POSTGRES_URL`, the checker verifies the Kubernetes HA posture, the setup scope, the recovery owner, the PostgreSQL receipt and the current plan identity. The probe revalidates every migration and the database identity, holds one session advisory lock, and uses two runtime stores over that database.

### What the probe does

The first instance opens one disposable plan that holds no content. The second instance must reconstruct the same plan and state. Then the probe requires that:

- Two schedulers converge on one notification.
- Two notification claims and two task claims each grant exactly one current lease.
- The other instance completes the task, and two concurrent finalizers converge on one terminal run of five events with the exact fixture output.

For database-unavailable outcomes of a recognized type, concurrent operations make at most three attempts in total, with a fixed delay of ten milliseconds between attempts. Corruption and contradictory state are not retried. The probe uses PostgreSQL time as the operation clock and makes no request except to the database.

### Cleanup

Before and after the cycle, one serializable transaction inspects every table that can reference the disposable scope. Cleanup proceeds only when the stored rows are the expected fixture and all unrelated scope tables are empty. It deletes the fixture in foreign-key order, then checks that no rows remain. Unknown or corrupt rows block cleanup and prevent a passing receipt.

A process stop can leave the fixture rows, which hold no content. A retry validates the partial fixture before it deletes it, and it never deletes a scope that it does not recognize. Without a retry, the rows remain for you to investigate.

This check does not contact the Kubernetes API or test PostgreSQL replication, failover or load balancing.

## Envelope-storage authority

Controlled-hybrid and Kubernetes HA plans keep `envelope_storage_validated` separate from `secret_backend_validated`. The KMS receipt does not cover S3. Derive the combined authority identity offline:

```sh
ENVELOPE_STORAGE_AUTHORITY_IDENTITY="$(
  trestle admin envelope identity \
    --tenant tenant-a \
    --s3-endpoint https://s3.example \
    --s3-region us-east-1 \
    --s3-bucket open-trestle-artifacts \
    --s3-prefix reviews \
    --kms-region us-east-1 \
    --kms-key-arn arn:aws:kms:us-east-1:123456789012:key/KEY-ID |
  jq -r .envelope_storage_authority_identity
)"
```

The authority binds these values:

- the tenant
- the canonical S3 endpoint, region, bucket and prefix
- the exact KMS tenant-key registry
- the optional KMS endpoint
- the direct, no-proxy transport posture
- the attempt bounds
- these distinct credential references, used when a request is made:
  - `OPEN_TRESTLE_S3_ACCESS_KEY_ID`, `OPEN_TRESTLE_S3_SECRET_ACCESS_KEY`, and optional `OPEN_TRESTLE_S3_SESSION_TOKEN` for the bucket prefix
  - `OPEN_TRESTLE_AWS_ACCESS_KEY_ID`, `OPEN_TRESTLE_AWS_SECRET_ACCESS_KEY`, and optional `OPEN_TRESTLE_AWS_SESSION_TOKEN` for the KMS key

The check rejects the same access-key ID in both roles. It does not inspect IAM policies, so you must scope the bucket prefix and the KMS key in AWS policy.

After you set those environments on the setup service, run the check. It makes requests to S3 and KMS:

```sh
trestle setup check envelope \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --approve-envelope-storage-authority-identity "$ENVELOPE_STORAGE_AUTHORITY_IDENTITY" \
  --s3-endpoint https://s3.example \
  --s3-region us-east-1 \
  --s3-bucket open-trestle-artifacts \
  --s3-prefix reviews \
  --kms-region us-east-1 \
  --kms-key-arn arn:aws:kms:us-east-1:123456789012:key/KEY-ID \
  --approved-by platform-owner
```

Add the same optional `--kms-endpoint URL` to both the admin command and the check command when you intend to use a custom KMS endpoint. The checker rejects a different identity, scope or actor before it reads any credential or contacts either service.

### What the check does

After confirmation, the checker builds the production S3 backend, the AWS KMS tenant-key provider and `artifact.EnvelopeStore`. It then runs these steps:

1. It creates one fixed, public conformance artifact at a fixed key.
2. It verifies that the raw stored object contains neither the literal payload nor its base64 form.
3. It retrieves the artifact and validates it through client-side AES-256-GCM envelope decryption.
4. It deletes only the exact immutable S3 version that the read returned.
5. It requires a final not-found response.

A successful run makes at most eight S3 requests and three KMS operations. S3 requests are not retried. Each KMS operation permits at most three attempts. The whole check has one 90-second deadline. Redirects and proxies are disabled, and HTTPS requires TLS 1.2 or newer.

The conformance artifact bypasses the runtime retention intents. It contains only the fixed public payload, and the check can delete only that key and the version it has just verified.

### Failures and cleanup

A failure before the deletion can leave one envelope-encrypted object at the conformance key. A later run with the same setup root and authority identity can verify and remove a valid object. A corrupt or conflicting object needs your own procedure for recovering a bucket version. Changing the authority changes the conformance key, so first retry the old authority or remove its version.

A passing receipt requires verified absence. Setup state stores only identities, and no endpoint, bucket, prefix, key ARN, credential or key material.

Only an S3 `NoSuchKey` error counts as absence. `NoSuchBucket`, a generic 404 from the endpoint, malformed error XML, a missing version identifier, a changed object and malformed KMS output do not produce a passing receipt. A missing or unreachable service is `unavailable`. Conflicts in the version, the integrity, the tenant key or the authority are `blocked`.

The final not-found check confirms that the current key is absent. It does not list historical versions or override the bucket's retention and delete-marker policy. Bucket policy must deny any unversioned or unrelated change to the conformance prefix.

A pass covers one round trip through envelope storage at that time. Backup, replication and lifecycle policy are outside it.

## Budgeted artifact erasure startup

Budgeted artifact erasure is an opt-in storage mode of the daemon. It is not a setup check or a deletion API. Select it with `--artifact-erasure-mode budgeted`. The default is `--artifact-erasure-mode legacy`.

Budgeted startup requires all of the following:

- PostgreSQL metadata storage with the runtime-role `--postgres-database-authority-identity`.
- S3 artifact storage with the existing endpoint, region, bucket, prefix and separate S3 credential environments.
- The existing KMS region and key ARN, an optional secure KMS endpoint, and separate KMS credential environments.
- An explicit protected erasure policy from `--erasure-policy`.
- An explicit protected S3 erasure CA from `--s3-erasure-trusted-ca`.

`--erasure-policy` and `--s3-erasure-trusted-ca` are invalid in legacy mode. Budgeted mode rejects local metadata, local artifacts, a missing policy or CA, `--apply-migrations`, and any `OPEN_TRESTLE_POSTGRES_MIGRATION_URL`. It uses the existing credential names for the database, S3 and KMS.

The protected policy must be valid at the UTC time the daemon samples at startup. It must bind the configured database identity, the S3 backend configuration identity, the S3 prefix and the storage namespace. The CA file must be an absolute, protected path to a regular, non-empty file owned by a trusted owner, no larger than 256 KiB. The budgeted S3 erasure backend requires HTTPS and accepts only the CA roots you name. It does not fall back to the system trust roots.

Startup constructs the protected policy, the S3 erasure backend, the KMS provider, the PostgreSQL artifact index, the budgeted erasure witness and the indexed, budgeted envelope store. Construction makes no S3 or KMS requests. The PostgreSQL verification contacts the configured database.

A `RuntimeStatus` v1 component named `artifact_erasure_budgeted` with state `ready` means that construction completed. It does not monitor policy freshness or provider health.

Budgeted store instances enable the budgeted resume and readback protocol. The daemon does not add an admin erasure endpoint, an operator Prepare or Resume command, or an automatic loop for erasure recovery.

Setup receipts are separate from this mode. Each of the following needs its own check or your own confirmation:

- PostgreSQL storage authority
- shared rate limiting
- replica reconciliation
- envelope storage
- the secret backend
- provider authorization
- webhook conformance
- policy dry runs
- backups
- media recovery

## Secret-backend authority

Controlled-hybrid and Kubernetes HA plans require a separate `secret_backend_validated` receipt. First derive the identity of the region and the registry of one key for each tenant. This command runs offline, reads no credentials and does not contact AWS:

```sh
KMS_AUTHORITY_IDENTITY="$(
  trestle admin kms identity \
    --tenant tenant-a \
    --region us-east-1 \
    --key-arn arn:aws:kms:us-east-1:123456789012:key/KEY-ID |
  jq -r .kms_authority_identity
)"
```

Configure the AWS credentials in the environment of the setup service. Then run the check:

```sh
export OPEN_TRESTLE_AWS_ACCESS_KEY_ID='...'
export OPEN_TRESTLE_AWS_SECRET_ACCESS_KEY='...'
export OPEN_TRESTLE_AWS_SESSION_TOKEN='...'

trestle setup check secret \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --approve-kms-authority-identity "$KMS_AUTHORITY_IDENTITY" \
  --kms-region us-east-1 \
  --kms-key-arn arn:aws:kms:us-east-1:123456789012:key/KEY-ID \
  --approved-by platform-owner
```

Use `--kms-endpoint URL` only for a custom, approved service endpoint.

After the state and approvals check out, the checker reads the three AWS credential environments. It then runs these steps:

1. It asks the tenant key to generate one AES-256 data key.
2. It unwraps the returned ciphertext with the same key ARN and the hashed tenant encryption context.
3. It requires that the key ARN, the algorithm and the sizes in the response match.
4. It compares the two plaintext keys and clears all plaintext copies.

The two KMS operations each permit at most three attempts, under one 60-second check deadline. Responses are capped at 1 MiB, redirects and proxies are disabled, and HTTPS requires TLS 1.2 or newer. The IAM principal needs only `kms:GenerateDataKey` and `kms:Decrypt` for the approved key and tenant encryption context.

A passing receipt stores only identities, and no AWS credential, endpoint, key ARN or key material. Missing or malformed credentials, a crossed tenant and key in the response, or a different approved identity blocks the check. A transport failure, a timeout, throttling or a KMS service failure records `unavailable`.

This check covers one round trip through the key provider at that time and makes no S3 request. `envelope_storage_validated` remains a separate requirement.

## Remote-provider authorization

Controlled-hybrid and Kubernetes HA plans require an explicit `remote_provider_authorized` receipt before they are ready. Validate the protected route inventory and runtime policy to get their identities. Then approve the review-policy identity and the named recovery owner:

```sh
trestle setup check provider \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --route-inventory /etc/open-trestle/routes.json \
  --runtime-policy /etc/open-trestle/runtime-policy.json \
  --approve-inventory-identity "$INVENTORY_IDENTITY" \
  --approve-runtime-policy-identity "$RUNTIME_POLICY_IDENTITY" \
  --approve-review-policy-identity "$REVIEW_POLICY_IDENTITY" \
  --approved-by platform-owner
```

### What the authorization requires

The authorization reopens the protected files under the same ownership checks as policy validation. It requires all of the following:

- A controlled remote-inference posture.
- At least one canonical, non-loopback HTTPS `private_remote` connection.
- Provider content logging disabled across the inventory.
- A known cost that is inside the profile cap.
- Unpinned ranking.
- Publication blocking when the result is inconclusive.
- A pair of generation and verification routes with distinct provider IDs, connection IDs, canonical endpoint origins (with default ports normalized) and credential-environment identities. The immutable registry records of both routes must be approved, and their health and quota observations must be ready.

Other inventory records stay visible to gateway filtering, but being present does not authorize them. Every adapter's provider, connection, zone, logging, endpoint and credential-environment identity must match the inventory namespace.

### What the receipt does not enable

This setup receipt alone does not enable sending repository content to a remote provider. In the standard generation flow, the sanitized request and the Betterleaks egress receipt are created and stored before the generation handler runs. The verification handler creates its own pair. Raw requests, investigation requests, legacy callers and generic adapter dispatch are denied before any credential is retrieved. Sanitization fails in these cases:

- more than 256 fields
- more than 256 KiB in one field
- more than 2 MiB decoded in total
- scanner or residual findings that cannot be completed
- a deadline or fault of the secret scan helper

A plain `go build` from the root pins no secret scan helper, so it cannot enable this path. Build with `tools/package_secret_scanner.py` instead.

### Credentials and DNS

Credential environment names use the `OPEN_TRESTLE_PROVIDER_*` namespace. The authorization does not read the corresponding values. Distinct environment names show that the configuration references are separate, not that the secrets or the provider-side privileges differ. Open Trestle does not resolve DNS names, so make sure that two approved names do not point to the same provider account.

The authorization makes no DNS lookup, network request or model call. Setup state stores only identities, and no paths, endpoints, environment names, provider declarations or prices.

### What a pass proves

A pass means that the named recovery owner authorized one remote-provider configuration, and that its protected snapshot satisfied the declared policy constraints. Credential availability, provider connectivity and the scan helper are not checked. The separate policy receipt, the scan helper release evidence and the dry run remain required.

The pinned Betterleaks v1.8.1 profile detected 11 of 14 expected occurrences in its reviewed corpus. It missed bearer credentials, AWS secret keys and AWS session tokens, and it redacted one near miss as a `generic-api-key` at `[7,51)`. See the [secret scanner section](operations.md#secret-scanner-runtime-boundary) for the scanner's limits. Changing either protected file, or any approved identity, invalidates the authorization.

## GitHub integration permissions

Controlled-hybrid and Kubernetes HA plans require a current `integration_permissions_validated` receipt. This check creates a GitHub installation token through the native broker. It is not a read-only inspection. Set `OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG` to the absolute path of the protected [source-broker descriptor](../schemas/runtime/github-source-broker-v1.schema.json). The host captures that configuration once. Requests cannot supply a descriptor path, a raw configuration, an App key, or the legacy overrides for endpoint, version, installation or repository.

Derive the identities that depend only on the configuration. This does not open a broker or read credentials:

```sh
trestle admin github permissions identity \
  --broker-config "$OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG"
```

### The identity result

The result has seven fields:

- `contract: open-trestle/github-permission-admin-result`
- `schema_version: 2`
- `status: configuration_only`
- `operation: identity`
- `broker_authority_identity`
- `setup_issuance_authority_identity`
- `permission_authority_identity`

Record the three native identities. They are not grants. The legacy admin quartet (`--api-endpoint`, `--api-version`, `--installation-id`, `--repository-full-name`) still returns the unchanged schema 1 result, which contains only identities. It cannot be combined with `--broker-config`, even with empty values, and it cannot run the current setup check.

### The broker descriptor

The descriptor has 20 fields: `contract`, `schema_version`, `tenant_id`, `repository_id`, `repository_full_name`, `github_repository_id`, `installation_id`, `app_id`, `repository_authority`, `api_endpoint`, `api_version`, `archive_authorities`, `app_key_version`, `app_public_key_sha256`, `credential_environment`, `authorization_generation`, `ownership_mode`, `attempt_state_directory`, `allow_token_creation` and `allow_demand_renewal`.

Its contract is `open-trestle/github-source-broker`, schema version 1. The repository authority is `github.com`, the credential environment is `OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY`, the ownership mode is `single_host_exclusive`, and both effect booleans must be true. Setup and admin require an API year of 2000 or later. The date pattern in the descriptor schema checks only the shape.

### Running the check

Keep the dedicated, short-lived GitHub App user access token in `OPEN_TRESTLE_GITHUB_SETUP_TOKEN`, and the pinned App private key in `OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY`, on the host. In broker mode, do not configure the static `OPEN_TRESTLE_GITHUB_API_TOKEN`. Approve both identities and the creation of a token:

```sh
trestle setup check integration \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --approve-github-source-broker-authority-identity "$GITHUB_BROKER_AUTHORITY_IDENTITY" \
  --allow-github-installation-token-creation \
  --approve-integration-permission-authority-identity "$GITHUB_PERMISSION_AUTHORITY_IDENTITY" \
  --approved-by platform-owner
```

The broker approval, the permission approval, the actor, the scope, the probe configuration, the catalog and the expected plan must all agree before the check runs. The probe reads the dedicated user token and compares it with the runtime GitHub, setup-service, daemon operator, observer and webhook environments. A missing, reused or mixed static credential is rejected before the App key is read or any request is made. No secret value enters the setup identity or state.

The permission inspector then checks which installations the user can see, through `GET /user/installations`. Native issuance authenticates the installation using the pinned App signer, and requests one narrow installation token. A static token or signed metadata that the caller supplies cannot take its place. The only permissions admitted are `metadata: read`, `contents: read` and `pull_requests: read`, and the only event is `pull_request`. An actual grant that equals the user token is rejected.

None of these produces a pass: extra permissions, write access, extra events or repositories, a selection of all repositories, suspension, duplicate critical JSON members, wrong pins, crossed scope, redirects, unknown issuance outcomes, or cancellation. Discovery of the user's installations is limited to ten pages of 100 installations and responses of 1 MiB. The setup check has a 60-second deadline around inspector requests of 30 seconds each. Proxies and redirects are disabled, and remote requests require TLS 1.2 or newer. See [GitHub integration permission evidence](github-integration-permissions.md) for the native protocol and its limits.

### Sessions and owners

One standalone command owns one lazy session. An interactive TUI or web handler owns one session for its foreground lifetime, and it can reuse a valid cached token. Renewal occurs only on foreground demand. Records of the owner and of the issuance attempt hold no content, and they remain after success, failure, an unknown issuance and Close. Tokens are not stored.

A restarted process cannot recover a token by reusing that generation or by deleting its owner marker. A new generation and new approvals require a change to your configuration. There is no automatic retry, no recovery at restart, no owner on a shared volume and no HA credential ownership. This `single_host_exclusive` limit applies even to the `kubernetes_ha` setup profile.

A pass means that the user can see the installation and that one native grant for the setup purpose was accepted at that time. The daemon needs its own approval and an owner for the runtime purpose. State stores only identities, and no tokens, PEM data, endpoints, provider responses or owner paths.

If the cleanup of credentials is incomplete, the command reports `setup credential cleanup failed` and exits nonzero, even if a receipt was already stored. The receipt and the accepted provider effect are not rolled back. Do not replay issuance to repair the storage of a receipt. A durable, current, pending receipt can recover without opening credentials.

### Current authority migration

Old plans, catalogs, receipts and Ready states remain readable. They are historical and do not count for integration or webhooks. The Runner rejects both operations under an old integration binding, before it recovers a pending receipt or runs a checker.

Initialize a fresh protected state path with a current plan, and rerun every check that contacts a service. Do not overwrite the old plan, relabel its catalog or import old receipts. Replacing a current integration receipt resets webhook to pending, so rerun webhook against the new permission receipt.

## GitHub webhook conformance

Controlled-hybrid and Kubernetes HA plans require `webhook_validated` after the integration-permission receipt. Derive the authority identity, which needs no credentials. Use the plan scope and the non-secret webhook key ID that `trestled` uses:

```sh
GITHUB_WEBHOOK_AUTHORITY_IDENTITY="$(
  trestle admin github webhook identity \
    --tenant tenant-a \
    --repository repository-a \
    --key-id primary-2026 |
  jq -r .webhook_authority_identity
)"
```

The authority binds all of these:

- the tenant and repository scope
- the key ID
- the `OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET` reference
- the configuration identity of the verifier
- HMAC-SHA-256
- `POST /webhooks/github`
- the exact request headers
- the bounds of a 1 MiB payload and 256-byte headers
- one request at a time
- the exact `pull_request` actions
- five fixed requests and their expected statuses
- the digests and delivery IDs of the public fixtures
- the response contract and the security headers
- one private, disposable `FileStore` record
- durability before acknowledgment
- a required, bounded, non-recursive cleanup of at most the lock and one delivery record
- zero listener or network requests

### The secret

Generate a 32-byte secret with a cryptographically secure random generator, and encode it as 64 lowercase hexadecimal characters. The validator rejects other encodings, zero or low-diversity values, and repeated patterns of up to 32 characters. It cannot check how the secret was generated.

The secret must differ from the GitHub setup, runtime and publication tokens, and from the setup-service, daemon operator and observer tokens. Then run the confirmed check:

```sh
export OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET="$(openssl rand -hex 32)"

trestle setup check webhook \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --approve-webhook-authority-identity "$GITHUB_WEBHOOK_AUTHORITY_IDENTITY" \
  --github-webhook-key-id primary-2026 \
  --approved-by platform-owner
```

### What the check does

The Runner first rejects historical integration catalogs. The checker rejects a stale plan, a missing current integration-permission receipt, a changed scope, a wrong actor or a mismatched authority before it reads the secret. It then calls the production verifier and HTTP handler in process. It requires these results:

- A bad signature receives 401 and nothing is stored.
- A correctly signed `pull_request/opened` fixture reaches a private file before the handler returns 202.
- A replay of that fixture returns 200 with the original acceptance identity, and no second record.
- The same delivery ID with a different, correctly signed, allowed body returns 409 and does not change the record.
- A correctly signed, disallowed action returns 202 as ignored, and nothing is stored.

The verifier clears the secret byte slice that it owns when it is closed. Go environment values are immutable strings, so their storage is not erased: keep the process environment private and rotate the secret when required. The disposable directory must close successfully, be removed and be absent before the check can pass.

At daemon startup, the runtime applies the same secret format. It rejects a secret that equals any configured operator, observer, runtime GitHub, GitHub setup or setup-service token. The publication token is compared with the webhook secret when it is requested, not at startup.

### What the check does not cover

This check opens no listener and makes no GitHub, DNS, model or source request. The payload is public, synthetic data. The disposable local `FileStore` exercises the handler, the verifier, admission, persistence before acknowledgment, deduplication, conflict handling, filtering and cleanup. It does not check that GitHub can reach your network or that a shared production inbox store works.

Setup state retains only identities, and never the secret, the signature, the payload, the key ID or the temporary path. See [Verified webhook ingress](webhook-ingress.md) for the runtime boundary and the GitHub references.

## Runtime policy approval and dry run

For a new runtime policy, first compute the route inventory identity and bind it into the policy document:

```sh
trestle config inventory-identity \
  --route-inventory /etc/open-trestle/routes.json
```

For a v1 policy, copy the reported `inventory_identity` into the runtime policy, and optionally add preferences from the reported `route_record_identities`. Setup rejects generation pins in v1 policies. For a local generation route and an explicit verifier route, bind a v2 policy instead:

```sh
trestle config bind \
  --route-inventory /etc/open-trestle/routes.json \
  --runtime-policy-template /etc/open-trestle/runtime-policy.template.json \
  --generation-adapter local-generation \
  --verification-adapter local-verification
```

Save its stdout as a new protected runtime-policy file before you validate. The adapters must identify different local records that satisfy the independence requirement of the policy. Binding does not approve routes, read credentials, contact providers or change setup state. See [local configuration bootstrap](local-model-review.md#local-responses-configuration-bootstrap).

Next, validate the protected route inventory and the bound runtime policy:

```sh
trestle config validate \
  --route-inventory /etc/open-trestle/routes.json \
  --runtime-policy /etc/open-trestle/runtime-policy.json
```

Record the reported `inventory_identity`, `runtime_policy_identity` and `review_policy_identity`. When you advance the setup plan, the named recovery owner must then approve those identities:

```sh
trestle setup check policy \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --route-inventory /etc/open-trestle/routes.json \
  --runtime-policy /etc/open-trestle/runtime-policy.json \
  --approve-inventory-identity "$INVENTORY_IDENTITY" \
  --approve-runtime-policy-identity "$RUNTIME_POLICY_IDENTITY" \
  --approve-review-policy-identity "$REVIEW_POLICY_IDENTITY" \
  --approved-by platform-owner
```

The files and their ancestors must be owned by the current user or by root. Configuration files cannot be writable by the group or by others. Shared writable ancestors need the same sticky-directory protections as the local storage checks. The checker does not resolve a credential reference or connect to an endpoint.

### What a passing policy must satisfy

A passing policy must match the selected setup posture. It must meet all of these conditions:

- It uses only declared privacy zones.
- It binds every adapter to one unambiguous zone, provider, connection, logging, endpoint and credential authority.
- It disables content logging.
- It stays within the cost cap of the profile.
- It provides at least two routes that are currently approved and usable, at the required independence level.
- It uses canonical endpoints. Local and air-gapped profiles accept only numeric loopback endpoints and local routes. Remote routes reject conventional localhost names and non-unicast numeric addresses, and the offline check does not resolve DNS names.
- It blocks publication on inconclusive verification, and its publication independence floor is not weaker than its verification floor.

Local v2 policies must bind a generation pin and an explicit verifier record. Both records must be eligible and must satisfy the required independence level. Another usable pair in the inventory cannot substitute for them. v1 policies are unpinned. Remote setup postures do not accept local v2 policies.

### Local inference check

For `local_single_node` and `air_gapped`, validate actual local inference after the exact policy receipt is durable:

```sh
trestle setup check inference \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --route-inventory /etc/open-trestle/routes.json \
  --runtime-policy /etc/open-trestle/runtime-policy.json \
  --approve-inventory-identity "$INVENTORY_IDENTITY" \
  --approve-runtime-policy-identity "$RUNTIME_POLICY_IDENTITY" \
  --approve-review-policy-identity "$REVIEW_POLICY_IDENTITY" \
  --approved-by platform-owner
```

This is a functional probe, not an offline validation. It reads each selected credential environment only when it sends a request. It sends at most two fixed prompts that contain no secrets, to two models from the approved local inventory, and stops after the first failed step. A pass requires one generation response and one verification response. Both adapters must return the empty candidate and verification contracts through the normal path for admitting responses.

Each request reserves a byte-based input estimate, as review planning does. The estimate is the request payload plus the trusted system channel plus 256 framing bytes, and on a [local structured-output](local-model-review.md#chat-completions-transport) connection it also includes the serialized `response_format`. A route must therefore declare enough context for it. Each request permits at most 256 output tokens, reported input above the reservation is rejected, and the check has one total deadline of 90 seconds.

For v2, generation uses the pinned record, and verification uses only the explicit verifier record, ranked without the generation pin. For v1, verification keeps the ordered preferences after excluding routes that are not independent. The probe does not retry or fall back. Its HTTP transport disables proxies and connection reuse, accepts only numeric-loopback dial targets, and does not resolve DNS. The policy must disable content logging.

The plan stores only identities, and not the credential, the prompt, the model text, the endpoint, the model name or the token counts. A pass means that the approved local generation and verification paths completed the fixed contract at that time. It says nothing about review quality. Authentication, malformed output or a policy mismatch blocks the check. A transient connection failure, a timeout, a rate limit or a server failure records `unavailable`.

### Dry run

After the policy receipt is stored, run the review dry run with the same approval:

```sh
trestle setup check dry-run \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --route-inventory /etc/open-trestle/routes.json \
  --runtime-policy /etc/open-trestle/runtime-policy.json \
  --approve-inventory-identity "$INVENTORY_IDENTITY" \
  --approve-runtime-policy-identity "$RUNTIME_POLICY_IDENTITY" \
  --approve-review-policy-identity "$REVIEW_POLICY_IDENTITY" \
  --approved-by platform-owner
```

The dry run uses fixed content and local dispatchers. It selects the generation and verifier records in the same way as the inference check. It exercises these parts of the pipeline:

- the configured eligibility filter and ranking
- generation authorization and verification authorization
- the provider-neutral dispatch contract
- admission of candidate and verifier output
- terminal attempt records
- cost reconciliation
- output lineage
- the independence receipt

It has a limit of five seconds. It has no publisher, source writer, validation process, network client or credential resolver, so it cannot publish, change source or contact a model endpoint. A policy file that changed or is missing produces a blocked or unavailable receipt.

## Signed offline bundle validation

Air-gapped plans require `signed_bundle_validated`. The check validates one opaque file. It does not extract, import, execute or scan it. Open Trestle never receives a private signing key.

First compute the byte count and SHA-256 digest of the file. Then ask Open Trestle to print the statement bytes as base64:

```sh
STATEMENT_BASE64="$(
  trestle admin bundle statement \
    --bundle-sha256 "$BUNDLE_SHA256" \
    --bundle-bytes "$BUNDLE_BYTES" |
  jq -r .statement_base64
)"
printf '%s' "$STATEMENT_BASE64" | base64 -d > offline-bundle-statement.json
```

Sign the decoded statement file with the approved offline Ed25519 private key, using signing tools that are governed separately. Encode the raw 32-byte public key as 64 lowercase hexadecimal characters, and the raw 64-byte signature as 128 lowercase hexadecimal characters. Then derive the setup authority identity:

```sh
SIGNED_BUNDLE_AUTHORITY_IDENTITY="$(
  trestle admin bundle identity \
    --bundle-sha256 "$BUNDLE_SHA256" \
    --bundle-bytes "$BUNDLE_BYTES" \
    --public-key "$ED25519_PUBLIC_KEY_HEX" \
    --signature "$ED25519_SIGNATURE_HEX" |
  jq -r .signed_bundle_authority_identity
)"
```

The signed statement is canonical JSON with the contract `open-trestle/offline-bundle-signature-statement`, schema version 1, `bundle_sha256` and `bundle_bytes`. The authority binds all of these:

- the identity of the statement
- the SHA-256 and Ed25519 algorithms
- the exact digest and byte count
- the identities of the public key and the signature
- a file limit of one GiB
- a streaming buffer of 64 KiB
- the rules for canonical absolute paths
- the requirement of a regular file
- same-file checks before and after streaming
- cancellation checks
- a closed error posture
- zero extraction, import, execution or network requests

Run the explicit local verification:

```sh
trestle setup check bundle \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --approve-signed-bundle-authority-identity "$SIGNED_BUNDLE_AUTHORITY_IDENTITY" \
  --bundle "$ABSOLUTE_BUNDLE_PATH" \
  --bundle-sha256 "$BUNDLE_SHA256" \
  --bundle-bytes "$BUNDLE_BYTES" \
  --public-key "$ED25519_PUBLIC_KEY_HEX" \
  --signature "$ED25519_SIGNATURE_HEX" \
  --approved-by platform-owner
```

The checker accepts only the air-gapped posture of local storage, local inference, denied egress and an offline bundle. It checks the setup scope, the recovery owner, the approved authority and the current plan identity before it opens the file. The verifier rejects all of these:

- empty or oversized files
- noncanonical or all-zero key material
- malformed signatures
- symlinks
- files that are not regular files
- replacement of the path
- changes of size
- a digest mismatch
- a signature mismatch
- a read failure
- cancellation

An I/O failure is unavailable. A malformed or mismatched bundle is blocked. Setup state keeps no path, bundle bytes, key, signature or filesystem error.

You must establish trust in the public key, its rotation and revocation, the custody of signing and the delivery of the statement through a separate process. A passing receipt means that the file matched the approved size, digest, public key and Ed25519 signature at the time of the check. It does not look inside the file.

## Guided local web setup

Start the setup service on a numeric loopback address, with a dedicated random token:

```sh
export OPEN_TRESTLE_SETUP_TOKEN='replace-with-a-distinct-long-random-token'
trestle setup web \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --listen 127.0.0.1:8742
```

Open the `/console/setup` address that the command prints, and enter the setup token. The service does not print the token. It accepts only a numeric loopback listener and checks the Host header to prevent DNS rebinding. It rejects a token that equals the daemon's operator or observer token. The browser keeps the token and all form values only in memory, and sends the token only in an authorization header.

When no plan exists, the guided surface shows the four safe profiles, the scope and the recovery owner. Creating a plan needs a separate confirmation. An existing plan opens at its first pending requirement, and shows its readiness, effect posture, recovery action, evidence identity and receipt history. Each check requires an inline confirmation that is bound to the displayed plan identity and requirement key. Stale plans are rejected.

### Checks the web setup can run

The local setup API can initialize a plan and run these built-in checkers:

- local administrator
- backup snapshot
- local and PostgreSQL storage
- envelope-storage conformance
- KMS secret backend
- remote-provider authorization
- GitHub integration-permission inspection
- local GitHub webhook conformance
- PostgreSQL shared rate limiting
- replica reconciliation
- signed offline bundle
- observer credential posture
- runtime policy
- explicit local inference
- non-publishing dry run

Creating and restoring a backup snapshot stay explicit CLI operations. Other requirements remain visibly pending, and the console says that no built-in web checker is available for them.

The API requires valid UTF-8 JSON and rejects duplicate keys, unknown or case-folded member names, and forbidden fields even when they are empty. Inspecting missing state changes nothing. Starting the service does not run a check or create setup state.

### GitHub integration checks in the web setup

For integration checks, configure `OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG` on the host, and start `trestle setup web` with `--approve-github-source-broker-authority-identity "$GITHUB_BROKER_AUTHORITY_IDENTITY"`. A descriptor without that startup approval is rejected, and no startup flag replaces consent in the request.

In the existing integration form, supply both the broker identity and the permission identity, the recovery owner, and consent to create a token. Confirm `create GitHub installation token and run integration_permissions_validated`. The request has only the nine schema 2 fields documented in [Daemon API and client](daemon-api.md#local-setup-api). Unrelated check requests stay at schema 1. A setup bearer token alone cannot approve issuance, and the server checks every approval and the expected plan.

### Shutdown

On shutdown, the service cancels the credential owner first and allows five seconds for the HTTP shutdown. If that fails, it forces the server to close. It then closes the credential session, with a separate five-second drain for the broker and for opening. Cleanup failures are reported without provider details. An incomplete close of the credential session stays cached, and it cannot roll back a stored receipt.

## Keyboard-first setup

After initialization, you can inspect and advance the same protected plan in a foreground terminal:

```sh
trestle setup tui \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --storage-root "$HOME/.local/state/open-trestle" \
  --backup-snapshot "$HOME/backups/open-trestle/plan.snapshot.json" \
  --administrator-approved-by platform-owner
```

Use `j` and `k` to select a requirement. Press `x`, then type the displayed `run REQUIREMENT_KEY` command to confirm one receipt write. Use `r` to reload and `q` to quit. The interface shows the states pending, passed, blocked and unavailable, plus the recovery action and the recent receipt history.

The interface executes only the checker configurations that were supplied when it started. Unsupported requirements remain pending, and the interface says that no checker is configured. The flags for policy approval and local inference are the same as those of the non-interactive commands. Local inference stays disabled until the policy check passes, and it still needs the `x` key plus the `run local_inference_validated` confirmation. See [Foreground terminal interface](tui.md#setup-terminal-interface).

Interactive integration setup uses the same descriptor, and the startup flags `--approve-github-source-broker-authority-identity`, `--allow-github-installation-token-creation` and `--approve-integration-permission-authority-identity`, plus `--integration-approved-by platform-owner`. The `x` key and then `run integration_permissions_validated` confirm the effect that you approved in advance. Overrides from the legacy quartet cannot run it. `--once` only inspects, and creates no broker owner and no credential session.

## Profiles

| Profile | Storage default | Inference default | Network and integration default |
|---|---|---|---|
| `local_single_node` | private local metadata and artifacts | local only | egress denied, local integration |
| `controlled_hybrid` | PostgreSQL plus envelope-encrypted S3 | explicitly approved remote route | allowlisted egress, least-privilege SCM |
| `kubernetes_ha` | PostgreSQL plus envelope-encrypted S3 | explicitly approved remote route | allowlisted egress, least-privilege SCM and shared coordination checks |
| `air_gapped` | private local metadata and artifacts | local only | egress denied, signed offline bundles |

Every profile starts with 30-day retention, provider content logging disabled, provider fallback disabled, publication disabled and dynamic validation disabled. The controlled-hybrid and Kubernetes baselines cap each model request at 100,000 micro-USD. The local and air-gapped baselines permit no remote model spend. Choosing a profile does not create infrastructure or connect an external service.

## Readiness checks

The plan contains an ordered set of requirements. Each is a scripted check, a probe, an authorization or a dry run. Facts that need no environment are recorded when the plan is created. All requirements that depend on the environment start as `pending`. A plan becomes `ready` only when every required check has a receipt from an approved checker.

Each plan embeds one checker catalog and the ordered history of check receipts. When Open Trestle decodes a plan, it replays that history from the initial plan. Every plan identity, checker identity, receipt identity, revision, timestamp, latest result for a requirement, and the final readiness value must match. Editing the plan alone cannot create readiness, and swapping the catalog is rejected.

A check receipt binds the current plan identity, the requirement key, the approved checker identity, an outcome, the evidence identity, the recovery action and a UTC timestamp. Stale receipts, and checkers that are not in the catalog, are rejected. `blocked` and `unavailable` checks keep the plan unready and name one recovery action. A later check must bind the newer plan identity.

### Replacing a prerequisite receipt

Replacing an existing prerequisite receipt resets its dependent requirements to `pending` and clears their current evidence fields:

- Replacing the policy receipt resets the local-inference and dry-run checks.
- Replacing the PostgreSQL receipt resets the shared rate-limit and replica-reconciliation checks.
- Replacing the integration-permission receipt resets the webhook check.

This applies to replacement outcomes of passed, blocked and unavailable, even when the evidence digest is unchanged. Historical receipts remain immutable, and unrelated requirements keep their state. Run the dependent checks again against the new plan before you rely on readiness.

A history that kept a dependent result after its prerequisite was replaced fails validation, and Open Trestle does not rewrite or migrate it. Preserve the original state and ledger. Then either restore a verified, compatible backup with its expected root identity, or initialize a separate protected state path and repeat the approvals and checks. Do not edit receipts or overwrite the old ledger.

Older binaries cannot replay histories that contain these resets, so do not mix setup writers across versions.

### What setup state holds

Setup state contains no tokens, passwords, provider endpoints, source, prompts, model responses or secret values. Setup receipts carry only identities and outcomes.

`trestle setup inspect` reports `ready` only after the embedded chain of approved receipts replays successfully, and every receipt has an identical record in the protected ledger. Record the initial plan identity that `setup init` returns. After an import or restore, require it with `--expected-root-identity` to detect that the root was substituted.

### The trust boundary

The local state owner, and the process that runs the approved checkers, form the setup trust boundary. They can authorize state transitions. File permissions and the append-only ledger protect against other local users, accidental edits, incomplete copies, stale writes and interrupted replacement. They do not protect against a malicious owner of the operating system.

### Published contracts

The published contracts are:

- `schemas/setup/setup-command-result-v1.schema.json`
- `schemas/setup/setup-plan-v1.schema.json`
- `schemas/setup/setup-check-receipt-v1.schema.json`
- `schemas/setup/setup-init-request-v1.schema.json`
- `schemas/setup/setup-check-request-v1.schema.json`
- `schemas/setup/setup-check-request-v2.schema.json`
- `schemas/setup/offline-bundle-signature-statement-v1.schema.json`
- `schemas/setup/setup-session-v1.schema.json`
- `schemas/setup/setup-check-result-v1.schema.json`
- `schemas/setup/setup-error-v1.schema.json`

The runtime parsers also rebuild identities, enforce the order and sources of the profile requirements, check the ordering of timestamps, and require canonical encoding.

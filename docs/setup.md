# Setup planning

A setup plan is a record of a deployment's posture and of the checks that still block readiness. It contains no secrets, and it is content-addressed, meaning that its identity is a hash of its contents. Open Trestle uses one versioned setup-plan contract across all operator surfaces. Creating a plan cannot contact a provider, connect a forge, create an identity, enable publication, or enable dynamic validation.

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

The state path must not exist. Its parent must be a directory that is not a symlink and has no group or other write permission. The CLI creates the plan with mode `0600`, synchronizes the file and its parent directory, and never overwrites an existing plan. The shared state-file implementation uses an exclusive writer lock.

Only `Runner.Run` creates later revisions. It executes an approved checker and applies that checker's receipt for the current plan through the protected state writer. Each revision increments the revision number and binds the previous identity and the checker-catalog identity. It is written by an atomic replacement, and the receipt and parent directories are synchronized.

If a stop occurs after the receipt is durable but before the plan head changes, `StateFile.PendingReceipt` exposes that one fenced receipt. The same transition can then finish without rerunning the check.

Inspect and validate the canonical state with:

```sh
trestle setup inspect \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --expected-root-identity "$RECORDED_INITIAL_PLAN_IDENTITY"
```

Initialization also creates a private, append-only receipt ledger beside the plan, at `plan.json.receipts`. Back up, restore and transfer the plan and the receipt ledger together. A plan that is copied without its ledger is rejected once it contains a closed check.

For a daemon that uses local metadata, keep `--setup-state` either under the private `--state-dir/setup/plan.json` directory or outside `--state-dir` (such as the sibling of a `runs` state root). Do not use a direct child such as `--state-dir/plan.json` or `--state-dir/setup.json`. Daemon startup now rejects this previously accepted layout, including its `.lock`, `.receipts` and possible `.next` siblings. This is an explicit availability change. It is not evidence that an old plan is corrupt or contains v4 events. See [daemon root inventory](daemon-api.md#start-a-local-daemon).

### Offline move of a direct-root setup plan

Use this procedure to move a plan that sits directly under `--state-dir` to a layout that daemon startup accepts.

1. Stop the daemon and all setup writers.
2. Inspect the original state, and record its exact initial root identity and its current plan identity.
3. Create a protected backup snapshot at a new path that does not exist, outside the live setup directory: `trestle setup backup create --state "$OLD_DIRECT_PLAN" --destination "$NEW_PROTECTED_BACKUP" --expected-plan-identity "$CURRENT_PLAN_IDENTITY"`. The snapshot contains the complete, verified receipt ledger, not only `plan.json`.
4. Restore the snapshot with the backup and restore commands below, to a new protected `--state-dir/setup/plan.json` or to a path outside the root. Pass both `--expected-root-identity "$RECORDED_INITIAL_PLAN_IDENTITY"` and `--expected-plan-identity "$BACKED_UP_PLAN_IDENTITY"`. The destination plan path must not exist, and its private, trusted parent directory must already exist. Restore never overwrites.
5. Inspect the restored path with `trestle setup inspect --state "$NEW_PLAN" --expected-root-identity "$RECORDED_INITIAL_PLAN_IDENTITY"`, and verify its exact plan identity and its full receipt history. Keep the verified external backup.
6. While both writers are still stopped, move the original direct-root plan, lock, receipt ledger and staging entries to a protected location outside `--state-dir`. Do this through an offline transfer that an operator has reviewed. Do not leave direct-root copies in place.
7. Only after those entries are gone, update `--setup-state` and check that the daemon starts. Keep the original protected copy until you have verified the restored path and the startup.

An unknown direct entry continues to block startup. Open Trestle performs no daemon migration, no silent move and no deletion.

### How receipts are written

Receipt writes require a filesystem that supports hard links within one directory and file and directory synchronization. Open Trestle writes each receipt to its canonical receipt filename plus `.next`, synchronizes it and closes it. A hard link then installs the immutable final name without overwriting anything. The ledger directory is synchronized before and after the staging file is removed. If the filesystem does not support hard links or synchronization, the write fails closed. There is no fallback that overwrites.

When a writer reopens the ledger, it can reclaim one protected staging file, either for the next revision or for a receipt that is already installed and verified. Read-only inspection leaves that staging file unchanged and never treats its bytes as passed evidence. A complete staging file without a final name is still uncommitted, and Open Trestle discards it. Only a complete final receipt can resume a transition without rerunning its check. Unknown names, unsafe staging files and malformed committed receipts remain errors and are not discarded as temporary files. This includes partial final receipt files that older versions left behind.

During restore, before a destination plan exists, staging recovery is limited to the next receipt after a valid, contiguous installed prefix, or to a receipt that is already in that prefix. Restore still verifies the exact snapshot and root identities before it opens the destination. It also checks all installed receipts against that snapshot before it installs the plan.

The initial and restored plan files are written and synchronized under the protected `<state>.next` name. A hard link then installs the complete final plan without overwriting anything. When a writer reopens, it can discard the protected, uncommitted plan staging file, and inspection never promotes it. A final plan that an older implementation left partially written remains an error and is not overwritten automatically.

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

The storage posture check opens and pins one exact directory that the current user owns, with mode `0700`. It pins and rechecks every ancestor up to the filesystem root. Each ancestor must be owned by the current user or by root. An ancestor with group or other write access must also be sticky and protect a child entry that the current user owns. Symlinked or replaceable path components are rejected.

Several checks depend on file ownership: administrator, backup, storage and protected runtime files. On Windows they read each file's and folder's owner and access control list instead of its mode (see [platforms](platforms.md#protected-files-on-windows)). They return `unavailable` on platforms where ownership authority is not implemented, and protected setup state refuses to open or inspect there. The mutable state, lock and receipt files must be owned by the user of the setup process. Their parent chain must prevent another local principal from replacing them before the check creates a lock, changes a mode, cleans up or reads. The storage check does not claim that backup, capacity or crash recovery was tested.

The observer credential posture check validates bounded values that are safe in a header, and checks that the credentials are unequal in constant time. It never stores either credential, and never puts a hash of one into evidence. It does not claim that a daemon accepted the observer. A later functional check has to establish that separately.

### Administrator check

The administrator check binds the exact setup root, tenant, repository, named recovery owner, and the effective operating-system user and group identity of the current process. `--approved-by` must exactly match the plan's recovery owner. The check records consent for the identity of the current process. It does not create an account, grant operating-system privileges, or prove control of an external identity provider.

### Backups

Record the current plan identity, then create an exact protected backup snapshot:

```sh
trestle setup backup create \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --destination "$HOME/backups/open-trestle/plan.snapshot.json" \
  --expected-plan-identity "$CURRENT_PLAN_IDENTITY"

trestle setup check backup \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --backup-snapshot "$HOME/backups/open-trestle/plan.snapshot.json"
```

The destination directory must already exist with mode `0700`, have a stable, trusted chain of ancestors, differ from the live state directory, and not be nested beneath it. Snapshot creation never overwrites a path. The file is canonical mode `0600` plan data that contains the complete, verified receipt history.

The checker reads the file twice and pins it. It requires that the current process owns the file, and that its plan and root identities exactly equal the live plan's. The receipt identifies the exact plan that the snapshot represents. A stale snapshot cannot pass a later check after another receipt changes the plan.

Restore only to a new protected state path, and fence both recorded identities:

```sh
trestle setup backup restore \
  --snapshot "$HOME/backups/open-trestle/plan.snapshot.json" \
  --destination "$HOME/.local/state/open-trestle-restored/plan.json" \
  --expected-root-identity "$RECORDED_INITIAL_PLAN_IDENTITY" \
  --expected-plan-identity "$BACKED_UP_PLAN_IDENTITY"
```

Restore rebuilds the append-only receipt ledger and validates the restored state before it returns. It never overwrites state, and it can resume an interrupted rebuild of the ledger, provided the partial ledger is an exact match. A passing backup check establishes that there is one separate, protected copy of the setup state that is complete byte for byte. It does not establish independent media, isolation from storage failure, off-site retention, application artifacts, database backups or a successful disaster-recovery exercise. Those remain recovery obligations of your deployment.

### Exit codes

A passed check exits with code `0`. A `blocked` or `unavailable` check that completed writes its canonical receipt and exits with code `3`. Malformed arguments, invalid setup identifiers and unsupported profiles print usage and exit with code `2`. An authority mismatch, stale state, checker failure or persistence failure exits with code `1` and prints no content from the failing operation.

Check execution writes only the protected plan and the append-only receipt ledger. Explicit backup creation writes only its new snapshot, and restore writes only its new state path, lock and receipt ledger. None of these operations contacts a provider, forge, database, object store or model.

## PostgreSQL storage authority

Controlled-hybrid and Kubernetes profiles use a database-native namespace rather than a hash of connection credentials. A migration administrator creates or upgrades the schema explicitly:

```sh
OPEN_TRESTLE_POSTGRES_MIGRATION_URL="$MIGRATION_DSN" \
  trestle admin postgres migrate
```

The command applies the exact embedded migration set and creates the durable database namespace. It reports no authority identity and does not initialize publication authority. Next, use the separately scoped runtime credential to derive the identity of the runtime role. This does not change anything:

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

The checker binds the setup root, tenant, repository, recovery owner, approving actor, expected database authority and probe implementation before it reads `OPEN_TRESTLE_POSTGRES_URL`. It opens a pool with one connection. In one repeatable-read transaction, it verifies every migration checksum, the database name, the active schema, the runtime role and the durable namespace.

Only the expected authority identity and a closed outcome influence the setup receipt. The DSN, password, certificate private material, SQL errors, database details and authority components never enter setup state or general errors. A connection failure or timeout is `unavailable`. A migration conflict, a malformed authority, a substituted role or schema, or an identity mismatch is `blocked`.

This establishes the identity of the metadata store and the compatibility of its schema at one point in time. It does not validate artifact encryption, backup recovery, replica reconciliation, publication authority, capacity, latency or future availability. Those remain separate requirements.

Budgeted artifact erasure requires the PostgreSQL schema to include the full embedded migration registry, which includes `0012_artifact_erasure.sql` and `0013_artifact_erasure_resume.sql`. Apply that schema only through an explicitly authorized migration administrator, before you start the daemon in budgeted mode. The budgeted daemon branch verifies the runtime database authority, the migration checksums, the artifact erasure schema and the resume schema in read-only snapshots. It does not apply migration 0013 or any other migration. In budgeted mode it rejects `--apply-migrations` and `OPEN_TRESTLE_POSTGRES_MIGRATION_URL`.

## Shared API rate limiting

Kubernetes HA plans require `shared_rate_limit_validated` after PostgreSQL storage authority passes. Migration 9 adds one shared fixed-window table that holds no content. Derive the exact setup and runtime authorities offline, from the verified database identity and the root identity that `trestle setup inspect` shows:

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

Raw network addresses, tenant IDs, principal IDs and bearer tokens are not stored. The authority for requests before authentication uses the canonical unmapped IP address of the direct TCP peer, and never trusts a forwarded-address header. If you need fairness for each client at the ingress, a reverse proxy therefore needs its own authenticated, client-aware limit. Each namespace and each raw authority key are domain-separated before the SHA-256 value is stored. Every row also binds the complete limiter configuration identity, and a conflicting live configuration fails closed.

Existing keys use row locks. A new key uses a transaction-scoped advisory lock for its namespace, removes expired rows, checks the exact number of keys, and inserts one window. The limits use PostgreSQL `transaction_timestamp()`, so clock skew on a replica host cannot create extra permits.

A database error, a live configuration conflict or an exhausted number of keys in a namespace returns 503 `rate_limit_unavailable` and grants no request. When an established key's request quota is exhausted, the server returns 429. The composite authority also binds the canonical key sources, the operation deadline, the status and error codes, and the retry headers that the HTTP server uses. Local metadata mode keeps its own explicit in-memory limiter, which is local to one process, and it does not satisfy this HA requirement.

### The conformance check

Run the explicit database conformance check:

```sh
trestle setup check rate-limit \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --approve-shared-rate-limit-authority-identity "$RATE_LIMIT_AUTHORITY_IDENTITY" \
  --postgres-database-authority-identity "$POSTGRES_DATABASE_AUTHORITY_IDENTITY" \
  --approved-by platform-owner
```

After the fences for the PostgreSQL receipt, scope, actor, authority and stale plan, the probe reads `OPEN_TRESTLE_POSTGRES_URL`. It revalidates every migration and the exact database authority. A session advisory lock isolates a deterministic setup-root namespace. The probe requires that:

- Two independent limiter instances share one quota of two requests and reject the third request.
- The two instances share a bound of two keys and reject a third key.
- The quota resets only after the expiry measured by the database clock.
- Of two concurrent attempts for the final permit, exactly one succeeds.
- The table contains exactly the two expected key digests and configuration identities.

A pass deletes only the exact conformance namespace and verifies that zero rows remain before it releases its session lock.

A process stop can leave conformance rows that hold no content. Their admission expires after one minute. A retry for the same setup root removes expired rows before it proceeds. Without a retry, expired rows of digests, counts and times can remain until operator maintenance. No DSN, credential, raw key, IP address, tenant, principal, payload or source content enters the row, the observation, the receipt, an API error or the setup state.

This proof validates the application-level shared limiting against the configured primary database. It does not prove how a load balancer behaves, whether PostgreSQL replication is healthy, provider-specific quotas, token budgets, webhook throttling or Kubernetes network policy.

## Replica reconciliation

Kubernetes HA plans also require `replica_reconciliation_validated`. This check is separate from PostgreSQL identity and shared rate limiting. It proves that the application-level journal, notification queue, task leases and terminal reconciliation converge through the configured database. Derive the exact authority offline. It contains no content:

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

Before the probe reads `OPEN_TRESTLE_POSTGRES_URL`, the checker verifies the Kubernetes HA posture, the setup scope, the recovery owner, the PostgreSQL receipt, the expected authority, the immutable probe configuration and the current plan identity. The probe revalidates every migration and the exact database authority. It holds one session advisory lock that is derived from the setup root and the database. It then uses two independently built runtime stores over that database.

### What the probe does

The first instance opens one deterministic, disposable plan that holds no content. The second instance must reconstruct the same plan and state. Then the probe requires that:

- Two schedulers converge on one notification.
- Two notification claims and two task claims each grant exactly one current lease.
- The other instance completes the task, and two concurrent finalizers converge on one terminal run of five events with the exact fixture output.

For database-unavailable outcomes of a recognized type, concurrent operations make at most three attempts in total, with a fixed delay of ten milliseconds between attempts. Corruption and contradictory state are not retried. The probe uses PostgreSQL time as the operation clock. It makes no provider, forge, Kubernetes, source, model, publication or non-database network request.

### Cleanup

Before and after the cycle, one serializable transaction that is scoped to the tenant inspects every table that can reference the disposable scope. Cleanup proceeds only when the stored plan, the canonical event prefix, the notification, and the pending, active or acknowledged delivery state are exactly the expected fixture, and all unrelated scope tables are empty. It deletes the notifications, the run events, the plan and the scope in foreign-key order, then proves that no rows remain. Unknown or corrupt rows block cleanup and prevent a passing receipt.

A process stop can leave the fixture plan, the run events, the notification, the worker labels, the timestamps and the lease authority that holds only digests. None of these hold content. A retry under the same session lock validates that exact partial fixture before it deletes it. It never deletes a preexisting scope that it does not recognize. Without a retry, the disposable rows remain for the operator to investigate.

This bounded proof does not contact the Kubernetes API. It does not prove PostgreSQL physical replication, failover, load-balancer behavior, capacity, latency, disaster recovery or future availability.

## Envelope-storage authority

Controlled-hybrid and Kubernetes HA plans keep `envelope_storage_validated` separate from `secret_backend_validated`. The receipt that covers KMS only does not prove S3 persistence, integrity, versioning or deletion. Derive the exact combined authority offline. It contains no secrets:

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

The check rejects the same access-key ID in both roles. That detects direct reuse of a credential. It does not inspect IAM policies on its own, and it does not prove that two different access keys cannot reach overlapping resources. Operators must enforce the scopes of the bucket prefix and of the KMS key in AWS policy.

After you set those environments on the setup service, run the check that has effects, explicitly:

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

Add the same optional `--kms-endpoint URL` to both the admin command and the check command when you intend to use a custom KMS endpoint. The checker rejects a different authority, scope or actor before it reads any credential or contacts either service.

### What the check does

After confirmation, the checker builds the production S3 backend, the AWS KMS tenant-key provider and `artifact.EnvelopeStore`. It then runs these steps:

1. It creates one fixed, public conformance artifact at a deterministic key.
2. It verifies that the raw stored object contains neither the literal payload nor its base64 form.
3. It retrieves the artifact and validates it through client-side AES-256-GCM envelope decryption.
4. It deletes only the exact immutable S3 version that the read returned.
5. It requires a final not-found response.

A fresh, successful run makes at most eight S3 requests and three KMS operations. S3 requests have no automatic retry and no reused connection. Each KMS operation permits at most three attempts. The whole check has one 90-second deadline. Redirects and proxies are disabled, responses are bounded, and HTTPS requires TLS 1.2 or newer.

This conformance artifact deliberately bypasses the runtime retention intents, because it contains only the fixed public payload and exists solely for the confirmed create, read and delete check. The bypass is private to the conformance implementation. It can delete only the deterministic key and the exact version that it has just verified, and it cannot accept a runtime artifact, a user payload, a prefix or an arbitrary version for deletion.

### Failures and cleanup

A failure before the exact deletion can leave one envelope-encrypted object at the deterministic conformance key. A later confirmed run with the same setup root and the exact same authority can verify and remove a valid object. A corrupt or conflicting object requires the operator's own procedure for recovering an exact bucket version. Changing the authority changes the conformance key. Operators must first retry the old authority or remove its exact version under that procedure.

A passing receipt requires verified absence. Setup state stores only identities derived from content: the authority, the conformance, the evidence, the checker and the receipt. It stores no endpoint, bucket, prefix, key ARN, credential, payload, ciphertext, wrapped key, plaintext key or S3 version.

Only a bounded S3 `NoSuchKey` error counts as absence. None of these can produce a passing receipt: `NoSuchBucket`, a generic 404 from the endpoint, malformed error XML, a missing version identifier, a changed object, or malformed KMS output. Missing or unreachable service state is `unavailable`. Deterministic conflicts in the version, the integrity, the tenant key or the authority are `blocked`.

The final not-found check proves that the current key is absent through the configured backend. It does not list hidden historical versions, and it does not override the bucket's retention and delete-marker policy. Bucket policy must deny any unversioned or unrelated change to the conformance prefix.

A pass proves one bounded round trip through envelope storage at that time. It does not prove backup, replication, lifecycle, disaster recovery, future availability, deletion of application retention, publication authority, model authority, webhook authority or source-mutation authority.

## Budgeted artifact erasure startup

Budgeted artifact erasure is an opt-in storage mode of the daemon. It is not a setup check, and it is not an operator deletion API. Select it with `--artifact-erasure-mode budgeted`. The default remains `--artifact-erasure-mode legacy`, and existing local and legacy S3 behavior is unchanged.

Budgeted startup requires all of the following:

- PostgreSQL metadata storage with the exact runtime-role `--postgres-database-authority-identity`.
- S3 artifact storage with the existing endpoint, region, bucket, prefix and separate S3 credential environments.
- The existing KMS region and key ARN, an optional secure KMS endpoint, and separate KMS credential environments.
- An explicit protected erasure policy from `--erasure-policy`.
- An explicit protected S3 erasure CA from `--s3-erasure-trusted-ca`.

`--erasure-policy` and `--s3-erasure-trusted-ca` are invalid in legacy mode. Budgeted mode rejects local metadata, local artifacts, a missing policy or CA, `--apply-migrations`, and any `OPEN_TRESTLE_POSTGRES_MIGRATION_URL`. It uses the existing credential names for the database, S3 and KMS. It adds no new credential environment variable and no hidden trust source.

The protected policy must be valid at the UTC millisecond startup sample that the daemon takes itself. It must bind the configured database authority, the S3 backend configuration identity, the S3 prefix and the storage namespace. The CA file must be an absolute, clean, protected path to a regular file owned by a trusted owner. It must be non-empty, stable across two reads, and no larger than 256 KiB. The budgeted S3 erasure backend requires HTTPS and accepts only the CA roots you name explicitly. It does not fall back to the ambient S3 trust roots.

Startup constructs the protected policy, the S3 erasure backend, the KMS provider, the PostgreSQL artifact index, the budgeted erasure witness and the indexed, budgeted envelope store. These are checks of the startup configuration, and they make zero S3 or KMS requests. The PostgreSQL verification still contacts the configured database.

A `RuntimeStatus` v1 component named `artifact_erasure_budgeted` with state `ready` means that construction completed. It does not prove ongoing freshness of the policy, provider health, bucket versioning, physical erasure, authorization of erasure, media backup, disaster recovery or future availability.

Budgeted store instances enable the budgeted resume and readback protocol. The daemon wires up artifact storage and the callers that put or get artifacts. It does not add an admin erasure endpoint, an operator Prepare or Resume command, or an automatic loop for erasure recovery. Direct library callers must supply valid timestamps. The daemon normalizes only the times of its own artifact callers.

Existing setup receipts remain separate evidence. Before a deployment treats any of the following as satisfied, each needs its own documented check or operator proof:

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

Controlled-hybrid and Kubernetes HA plans require a separate `secret_backend_validated` receipt. First derive the identity of the exact region and the registry of one key for each tenant. The identity holds no secrets. This command runs offline, reads no credentials and does not contact AWS:

```sh
KMS_AUTHORITY_IDENTITY="$(
  trestle admin kms identity \
    --tenant tenant-a \
    --region us-east-1 \
    --key-arn arn:aws:kms:us-east-1:123456789012:key/KEY-ID |
  jq -r .kms_authority_identity
)"
```

Configure the AWS credentials, which are used when a request is made, in the environment of the setup service. Then run the check explicitly:

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

Use `--kms-endpoint URL` only when you intend to bind a custom, approved service endpoint. The endpoint is part of the checker configuration identity. It does not change the identity of the logical tenant-key registry.

After the state and approval fences pass, the checker reads the three AWS credential environments. It then runs these steps:

1. It asks the exact tenant key to generate one AES-256 data key.
2. It unwraps the returned ciphertext with the same key ARN and the hashed tenant encryption context.
3. It requires that the key ARN, the algorithm and the sizes in the response match.
4. It compares the two plaintext keys in constant time, and clears all plaintext copies.

The two KMS operations each permit at most three attempts, under one 60-second check deadline. Responses are capped at 1 MiB, redirects and proxies are disabled, and HTTPS connections require TLS 1.2 or newer. The IAM principal needs only `kms:GenerateDataKey` and `kms:Decrypt` for the approved key and tenant encryption context.

A passing receipt stores only identities of the authority, checker, evidence and outcome, all without content. It stores no AWS credential, endpoint, key ARN, wrapped key, plaintext key, response or provider error. Missing or malformed credentials, a crossed tenant and key in the response, or a different approved identity blocks the check. A transport failure, a timeout, throttling or a KMS service failure records `unavailable`.

This check proves one bounded round trip through the key provider at that time. It makes no S3 request. It does not prove persistence of envelope objects, retention, deletion, recovery, future availability, publication authority, model authority or source-mutation authority. `envelope_storage_validated` remains a separate requirement.

## Remote-provider authorization

Controlled-hybrid and Kubernetes HA plans require an explicit `remote_provider_authorized` receipt before they are ready. Validate the protected route inventory and runtime policy to get their exact identities. Then approve the same review-policy identity and the named recovery owner:

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

The authorization reopens the protected files and reads them twice, under the same ownership and replacement fences over the full ancestry as policy validation. It requires all of the following:

- An exact controlled remote-inference posture.
- At least one canonical, non-loopback HTTPS `private_remote` connection.
- Provider content logging disabled across the inventory.
- A known cost that is inside the profile cap.
- Unpinned ranking.
- Publication blocking when the result is inconclusive.
- A pair of generation and verification routes with distinct provider IDs, connection IDs, canonical endpoint origins (with default ports normalized) and credential-environment identities. The immutable registry records of both routes must be approved, and their health and quota observations must be ready.

Other inventory records stay visible to the deterministic gateway filtering. They do not become authorized attempts merely because they are present. Every adapter's provider, connection, zone, logging, endpoint and credential-environment identity must match the inventory namespace exactly.

### What the receipt does not enable

This setup receipt alone does not enable the dispatch of repository content to a remote provider. In the standard generation flow, the sanitized request and the Betterleaks egress receipt are created and persisted before the generation handler runs. The verification handler creates its own pair. Each model handler reloads its exact artifacts, including the digests of the compiled launcher and worker, and validates them jointly. Only those handlers can seal the opaque proof that the OpenAI adapter accepts for the authorized `private_remote` request and review scope.

Raw requests, investigation requests, legacy callers and generic adapter dispatch remain denied before any credential is retrieved. Sanitization fails closed in these cases:

- more than 256 fields
- more than 256 KiB in one field
- more than 2 MiB decoded in total
- scanner or residual findings that cannot be completed
- a timeout of five seconds for the worker, or six seconds for the parent

A normal development build from the root has no injected scanner digests, so it cannot enable this path.

### Credentials and DNS

Credential environment names use the `OPEN_TRESTLE_PROVIDER_*` namespace, and the identities derived from those references are configuration authority. The authorization never resolves or reads the corresponding values. Distinct environment identities prove that the configuration references are separate. They do not prove that the secret bytes differ or that the privileges on the provider side are disjoint. Open Trestle does not resolve DNS names, so operators must prevent two approved names from aliasing the same provider authority.

The authorization makes no DNS lookup, network request, model call, retry, fallback, publication, source change, webhook action or dynamic-validation request. Setup state stores only identities derived from content: the approval, the checker, the evidence and the receipt. It does not store paths, endpoints, environment names, provider declarations, prices or route observations.

### What a pass proves

A pass proves that the named recovery owner authorized one exact remote-provider configuration, and that its protected snapshot satisfied the declared policy constraints. It does not prove credential availability, provider connectivity, scanner packaging or coverage, current service health, review quality, future cost or permission to publish. The separate policy receipt, the packaged scanner evidence and the non-publishing dry run remain required.

The pinned Betterleaks v1.8.1 profile detected 11 of 14 expected occurrences in its reviewed corpus. It missed bearer credentials, AWS secret keys and AWS session tokens, and it redacted one near miss as a `generic-api-key` at `[7,51)`. That evidence is not a claim that every secret is detected. Changing either protected file, or any approved identity, invalidates the authorization.

## GitHub integration permissions

Controlled-hybrid and Kubernetes HA plans require a current `integration_permissions_validated` receipt. This is an explicitly effectful check by the native broker. It is not a GET-only inspection and it is not permission to publish. Set `OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG` to the absolute path of the protected [source-broker descriptor](../schemas/runtime/github-source-broker-v1.schema.json). The host captures that configuration once. Requests cannot supply a descriptor path, a raw configuration, an App key, or the legacy overrides for endpoint, version, installation or repository.

Derive the identities that depend only on the configuration. This does not open a broker, read credentials, allocate an owner or create a generation:

```sh
trestle admin github permissions identity \
  --broker-config "$OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG"
```

### The identity result

The result has exactly seven fields:

- `contract: open-trestle/github-permission-admin-result`
- `schema_version: 2`
- `status: configuration_only`
- `operation: identity`
- `broker_authority_identity`
- `setup_issuance_authority_identity`
- `permission_authority_identity`

Record the three native identities. None of them is a grant that was observed or an approval. The legacy admin quartet (`--api-endpoint`, `--api-version`, `--installation-id`, `--repository-full-name`) still returns the unchanged schema 1 result, which contains only identities. It is mutually exclusive with `--broker-config` by flag presence, even for empty values, and it cannot execute the current setup check.

### The broker descriptor

The unchanged descriptor has exactly 20 fields: `contract`, `schema_version`, `tenant_id`, `repository_id`, `repository_full_name`, `github_repository_id`, `installation_id`, `app_id`, `repository_authority`, `api_endpoint`, `api_version`, `archive_authorities`, `app_key_version`, `app_public_key_sha256`, `credential_environment`, `authorization_generation`, `ownership_mode`, `attempt_state_directory`, `allow_token_creation` and `allow_demand_renewal`.

Its contract is `open-trestle/github-source-broker`, schema version 1. The repository authority is `github.com`, the credential environment is `OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY`, the ownership mode is `single_host_exclusive`, and both effect booleans must be true. The native checks of protected files, key pins, paths, endpoints, dates, scopes and directories remain authoritative. Setup and admin additionally require an API year of 2000 or later. The date pattern in the generic descriptor schema checks only the shape.

### Running the check

Keep the dedicated, short-lived GitHub App user access token in `OPEN_TRESTLE_GITHUB_SETUP_TOKEN`, and the pinned App private key in `OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY`, on the host. In broker mode, do not configure the static `OPEN_TRESTLE_GITHUB_API_TOKEN`. Explicitly approve both authorities and the creation of a token:

```sh
trestle setup check integration \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --approve-github-source-broker-authority-identity "$GITHUB_BROKER_AUTHORITY_IDENTITY" \
  --allow-github-installation-token-creation \
  --approve-integration-permission-authority-identity "$GITHUB_PERMISSION_AUTHORITY_IDENTITY" \
  --approved-by platform-owner
```

The common broker approval, the permission approval, the actor, the scope, the immutable probe configuration, the current catalog and the expected plan must all agree before dispatch. The probe reads the dedicated user token and compares it with the runtime GitHub, setup-service, daemon operator, observer and webhook environments, in that order. A missing, reused or mixed static credential is rejected before any owner is allocated, the App key is read, or an HTTP request is made. No secret value and no hash of a secret enters the setup identity or state.

Only then may the lazy setup-purpose session open its retained owner. The real permission inspector first checks which installations the user can see, through the bounded `GET /user/installations`. Native issuance then authenticates the exact installation using the pinned App signer, and requests one narrow installation token.

The accepted native grant binds the installation, the numeric repository, the selected single-repository scope, the expiry, the common authority, the setup issuance lane and the durable attempt. Neither an opaque static token nor signed metadata that the caller supplies can take its place. The only permissions admitted are `metadata: read`, `contents: read` and `pull_requests: read`, and the only event is `pull_request`. An actual grant that equals the user token is rejected.

None of these can produce a pass: extra permissions, write access, extra events or repositories, a selection of all repositories, suspension, duplicate critical JSON members, wrong pins, crossed scope, redirects, unknown issuance outcomes, or cancellation. Discovery of the user's installations is limited to ten pages of 100 installations and responses of 1 MiB. The setup check has a 60-second deadline around inspector requests of 30 seconds each. Direct transports disable proxies and redirects, and remote requests require TLS 1.2 or newer. See [GitHub integration permission evidence](github-integration-permissions.md) for the native protocol and its limits.

### Sessions and owners

One standalone command owns one lazy session. An interactive TUI or web handler owns one session for its foreground lifetime, and it can reuse a valid cached token. Renewal occurs only on foreground demand. Records of the owner and of the issuance attempt hold no content, and they remain after success, failure, an unknown issuance and Close. Tokens are not persisted.

A restarted process cannot recover a token by reusing that generation or by deleting its owner marker. A fresh generation and fresh approvals require an explicit change of the operator's configuration. There is no automatic retry owner, no recovery at restart, no owner on a shared volume and no HA credential ownership. This `single_host_exclusive` limit applies even to the `kubernetes_ha` setup profile.

A pass proves that the user can see the installation and that one native grant for the setup purpose was accepted at that time. It does not grant the daemon any runtime authority, which needs its own independent common approval and an owner for the runtime purpose. It does not change installation access, revoke a token, validate webhook delivery, execute a review, modify source or grant publication. State stores only identities of the authority, observation, evidence, checker and receipt, all without content. It never stores tokens, PEM data, endpoints, provider responses or owner paths.

If the cleanup of credentials is incomplete, the command reports `setup credential cleanup failed` and exits nonzero, even if a receipt was already persisted. The receipt and the provider effect that was accepted are not rolled back. A stable, incomplete Close result stays incomplete when Close is repeated. Logical closure is not physical quiescence. Never replay issuance to repair the persistence of a receipt. A durable, current, pending receipt can recover without opening credentials.

### Current authority migration

Old plans, catalogs, receipts and Ready states remain readable with their original bytes. They are historical, and they are not the current authority for integration or webhooks. The Runner rejects both operations under an old integration binding, before it recovers a pending receipt or runs a checker. The browser marker is only a diagnostic and a gate for actions. It is never authority for the server or for issuing tokens.

Initialize a fresh protected state path with a current plan, and rerun every nondeterministic check. Do not overwrite the old plan, relabel its catalog, import old receipts or upcast Ready automatically. Replacing a current integration receipt resets webhook to pending under the existing dependency rules, so rerun webhook against the new, exact permission receipt. Inspecting history is not migration.

## GitHub webhook conformance

Controlled-hybrid and Kubernetes HA plans require `webhook_validated` after the integration-permission receipt. Derive the authority that needs no credentials. Use the exact plan scope and the non-secret webhook key ID that `trestled` uses:

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

Generate a 32-byte secret with a cryptographically secure random generator, and encode it as exactly 64 lowercase hexadecimal characters. The validator rejects other encodings, zero or low-diversity values, and repeated patterns of up to 32 characters. These structural checks establish a capacity of 256 bits, but they cannot prove the entropy of the generator. How the secret was generated remains the operator's responsibility.

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

The Runner first rejects historical integration catalogs, before it recovers a pending receipt or runs anything. The checker rejects a stale plan, a missing current integration-permission receipt, a changed scope, a wrong actor, a changed probe or a mismatched authority, all before it reads the secret. It then calls the production verifier and HTTP handler directly, in process. It requires these results:

- A bad signature receives 401 and nothing is stored.
- A correctly signed `pull_request/opened` fixture reaches a private, crash-safe file before the handler returns 202.
- An exact replay of that fixture returns 200 with the original acceptance identity, and no second record.
- The same delivery ID with a different, correctly signed, allowed body returns 409 and does not change the record.
- A correctly signed, disallowed action returns 202 as ignored, and nothing is stored.

The verifier clears the secret byte slice that it owns when it is closed, and the executor also clears the input byte slices that it owns. Go environment values start out as immutable strings, so the check does not claim that their backing storage is erased. Operators must keep the process environment private and rotate the external secret when required. The disposable directory must still be the private directory that was originally created. It must close successfully, be removed and be absent before the check can pass.

At daemon startup, the runtime applies the same secret format. It rejects a secret that equals any configured operator, observer, runtime GitHub, GitHub setup or setup-service token. The publication token remains a capability that exists only at request time. Its provider compares a digest only after publication is authorized, and it rejects equality before it returns the token. Startup does not read the publication value.

### What the check does not cover

This cycle opens no listener and makes no GitHub, DNS, model, source, review-run or publication request. The fixed payload is public, synthetic data. The disposable local `FileStore` proves the semantics of the handler, the verifier, admission, persistence before acknowledgment, deduplication, conflict handling, filtering and cleanup. It does not prove that GitHub can reach the network, or that a shared production inbox store works. The receipts for PostgreSQL metadata and envelope storage remain separate.

Setup state retains only identities of the authority, observation, dependency receipt, evidence, checker and receipt. It never retains the secret, the signature, the payload, the key ID or the temporary path.

GitHub documents `X-Hub-Signature-256` as an HMAC-SHA-256 over the unchanged payload, and recommends a high-entropy secret and a constant-time comparison. GitHub also documents `X-GitHub-Delivery` as the delivery identifier, and recommends a fast 2xx response with asynchronous work. See [Verified webhook ingress](webhook-ingress.md) for the runtime boundary and the official references.

## Runtime policy approval and dry run

For a new runtime policy, first compute the route inventory identity and bind it into the policy document:

```sh
trestle config inventory-identity \
  --route-inventory /etc/open-trestle/routes.json
```

For a historical v1 policy, copy the reported `inventory_identity` into the runtime policy, and optionally add preferences from the reported `route_record_identities`. Setup continues to reject generation pins in v1 policies. For a local generation route and an explicit verifier route, bind a v2 policy instead:

```sh
trestle config bind \
  --route-inventory /etc/open-trestle/routes.json \
  --runtime-policy-template /etc/open-trestle/runtime-policy.template.json \
  --generation-adapter local-generation \
  --verification-adapter local-verification
```

Save its stdout as a new protected runtime-policy file before you validate. The adapters must identify different local records that satisfy the independence requirement of the policy. Binding does not approve routes, establish readiness, read credentials, contact providers or change setup state. See [local configuration bootstrap](local-model-review.md#local-responses-configuration-bootstrap). Likewise, decoding the inventory identity does not prove that the policy is bound, nor reachability, health, quality or live conformance.

Next, validate the protected route inventory and the bound runtime policy:

```sh
trestle config validate \
  --route-inventory /etc/open-trestle/routes.json \
  --runtime-policy /etc/open-trestle/runtime-policy.json
```

Record the reported `inventory_identity`, `runtime_policy_identity` and `review_policy_identity`. When you advance the setup plan, the named recovery owner must then approve those exact identities:

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

The checker reads the protected regular files twice and pins their full path ancestry. The files and their ancestors must be owned by the current user or by root. Configuration files cannot be writable by the group or by others. Shared writable ancestors need the same sticky-directory protections as the local storage checks. The checker does not resolve a credential reference or connect to an endpoint.

### What a passing policy must satisfy

A passing policy must match the selected setup posture. It must meet all of these conditions:

- It uses only declared privacy zones.
- It binds every adapter to one unambiguous zone, provider, connection, logging, endpoint and credential authority.
- It disables content logging.
- It stays within the cost cap of the profile.
- It provides at least two routes that are currently approved and usable, at the required independence level.
- It uses canonical endpoint locality. Local and air-gapped profiles accept only numeric loopback endpoints and local routes. Remote routes reject conventional localhost names and non-unicast numeric addresses, and the offline check does not resolve approved DNS names.
- It blocks publication on inconclusive verification, and its publication independence floor is not weaker than its verification floor.

Local v2 policies must bind an exact generation pin and an explicit verifier record. Both selected records must be eligible and must satisfy the required independence level. Another usable pair in the inventory cannot substitute for them. Historical v1 policies remain unpinned. Remote setup postures do not accept the local v2 pair contract.

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

This is an explicit functional probe, not an offline validation. It reads each selected credential environment only at dispatch time. It sends at most two fixed prompts that contain no secrets, to independently routed models from the approved local inventory. It stops after the first failed step. A pass requires exactly one generation response and one independent-verification response. Both adapters must return the exact empty candidate and verification contracts through the normal, strict path for admitting responses.

Each request reserves its own byte-based input estimate, as review planning does. The estimate is the request payload plus the trusted system channel plus 256 framing bytes, and on a [local structured-output](local-model-review.md#chat-completions-transport) connection it also includes the serialized `response_format`. A route must therefore declare enough context for it. Each request permits at most 256 output tokens, reported input above the reservation is rejected, and the check has one total deadline of 90 seconds.

For v2, generation uses the pinned record, and verification uses only the explicit verifier record, ranked without the generation pin. For v1, verification keeps the ordered preferences after excluding routes that are not independent. The probe performs no retry and no fallback. Its HTTP transport disables proxies and connection reuse, accepts only canonical numeric-loopback dial targets, and never performs DNS resolution. Provider storage is disabled, the policy must disable content logging, and the checker has no publisher, no source writer and no authority for dynamic validation.

The plan stores only identities of the configuration, the execution and the receipt, all derived from content. It does not store the credential, the prompt, the model text, the endpoint, the model name, the token counts or the body of a failure. A passing result proves that the exact approved local generation and independent-verification paths completed the fixed contract at that time. It does not establish review quality, throughput, future availability, remote fallback or permission to publish. Authentication, malformed output or a policy mismatch blocks the check. A transient connection failure, a timeout, a rate limit or a server failure records `unavailable`.

### Dry run

After the policy receipt is durable, run the bounded review dry run with the same approval:

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

The dry run uses fixed content and local, deterministic dispatchers. It selects the generation and verifier records in the same way as the inference check, including the explicit v2 verifier and the pin that applies to generation only. It exercises these parts of the pipeline:

- the configured eligibility filter and ranking
- generation authorization and independent verification authorization
- the provider-neutral dispatch contract
- strict admission of candidate and verifier output
- terminal attempt records
- cost reconciliation
- output lineage
- the independence receipt

It has a bound of five seconds. It is constructed without a publisher, source writer, validation process, network client or credential resolver, so it cannot publish, change source, invoke dynamic validation or contact a configured model endpoint. A policy file that changed or is missing produces a blocked or unavailable receipt, instead of reusing older evidence.

## Signed offline bundle validation

Air-gapped plans require `signed_bundle_validated`. The check validates one exact, opaque file. It does not extract, import, execute, scan or interpret it. Open Trestle never receives a private signing key.

First compute the exact byte count and SHA-256 digest of the file. Then ask Open Trestle to print the canonical statement bytes as base64:

```sh
STATEMENT_BASE64="$(
  trestle admin bundle statement \
    --bundle-sha256 "$BUNDLE_SHA256" \
    --bundle-bytes "$BUNDLE_BYTES" |
  jq -r .statement_base64
)"
printf '%s' "$STATEMENT_BASE64" | base64 -d > offline-bundle-statement.json
```

Sign the decoded statement file with the approved offline Ed25519 private key, using signing tools that are governed separately. Encode the raw 32-byte public key as 64 lowercase hexadecimal characters, and the raw 64-byte signature as 128 lowercase hexadecimal characters. Then derive the exact setup authority, which holds no content:

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

The checker accepts only the air-gapped posture of local storage, local inference, denied egress and an offline bundle. It checks the setup scope, the recovery owner, the approved authority, the immutable probe configuration and the current plan identity before it opens the file. The verifier rejects all of these:

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

An I/O failure is unavailable. A malformed or mismatched bundle is blocked. Setup state and general errors keep no path, bundle bytes, key, signature or filesystem error.

The public key and the signature are public inputs for verification, but their raw values are not written to setup state. Operators must establish trust in the public key, its rotation, its revocation, the custody of signing and the delivery of the statement through a separate process. A passing receipt proves only that the one local, opaque file matched the approved size, digest, public key and Ed25519 signature at the time of the check. It does not validate the structure of an archive, its contained artifacts, an SBOM, provenance, transparency logs, timestamps, release policy, malware, compatibility, import behavior, execution safety or enforcement that nothing leaves the host.

## Guided local web setup

Start the setup service on a numeric loopback address, with a dedicated random token:

```sh
export OPEN_TRESTLE_SETUP_TOKEN='replace-with-a-distinct-long-random-token'
trestle setup web \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --listen 127.0.0.1:8742
```

Open the `/console/setup` address that the command prints, and enter the setup token. The service never prints the token. It accepts no non-loopback listener and pins the exact numeric Host authority to prevent DNS rebinding. It rejects a token that equals the daemon's operator or observer token. The browser keeps the token and all form values only in React memory. It sends the token only in an authorization header, and omits ambient credentials.

When no plan exists, the guided surface shows the four safe profiles, the exact scope and the recovery owner. Creating a plan needs a separate confirmation. An existing plan opens at its first pending requirement, and shows its exact readiness, effect posture, recovery, evidence identity and receipt lineage. Each check requires an inline confirmation that is bound to the displayed plan identity and requirement key. Stale plans are rejected.

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

The API uses strict JSON that must be valid UTF-8 and rejects duplicate keys. It rejects unknown or case-folded request member names before Go decodes them. It validates forbidden fields by presence even when they are empty. It also uses bounded request and response bodies, inspection of missing state that changes nothing, protected state writers, no-store responses and errors that carry no content. Starting the service does not run a check or create setup state.

### GitHub integration checks in the web setup

For integration checks, configure `OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG` on the host, and start `trestle setup web` with `--approve-github-source-broker-authority-identity "$GITHUB_BROKER_AUTHORITY_IDENTITY"`. A descriptor without the exact startup cap is rejected. No startup allow flag takes the place of consent in the request.

In the existing integration form, supply both the common broker identity and the permission identity, the exact recovery owner, and explicit consent to create a token. Confirm `create GitHub installation token and run integration_permissions_validated`. The request has only the nine schema 2 fields documented in [Daemon API and client](daemon-api.md#local-setup-api). Unrelated check requests stay at schema 1. A setup bearer token alone cannot approve issuance, and the server independently checks every approval and the current expected plan.

### Shutdown

On shutdown, the service cancels the credential owner first and allows five seconds for the HTTP Shutdown. If the HTTP shutdown fails, it forces the server's Close. It then closes the credential session, with a separate, bounded five-second drain for the broker and for opening. Both cleanup failures are reported without provider details. These are separate, sequential budgets, not one aggregate of five seconds, and not a hard guarantee of ten seconds for kernel quiescence. A Close of the credential session that is incomplete stays cached, and it cannot roll back a durable receipt.

## Keyboard-first setup

After initialization, you can inspect and advance the same protected plan in a foreground terminal:

```sh
trestle setup tui \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --storage-root "$HOME/.local/state/open-trestle" \
  --backup-snapshot "$HOME/backups/open-trestle/plan.snapshot.json" \
  --administrator-approved-by platform-owner
```

Use `j` and `k` to select a requirement. Press `x`, then type the displayed `run REQUIREMENT_KEY` command to confirm one receipt write. Use `r` to reload and `q` to quit. The interface shows the exact states pending, passed, blocked and unavailable, plus the closed recovery action and the recent receipt lineage.

The interface executes only the checker configurations that were supplied when it started. Unsupported requirements remain pending, and the interface says that no checker is configured. The flags for policy approval and local inference are identical to those of the non-interactive commands. Local inference remains disabled until the exact policy check passes, and it still needs the `x` key plus the `run local_inference_validated` confirmation. See [Foreground terminal interface](tui.md#setup-terminal-interface).

Interactive integration setup uses the same descriptor, and the startup flags `--approve-github-source-broker-authority-identity`, `--allow-github-installation-token-creation` and `--approve-integration-permission-authority-identity`, plus `--integration-approved-by platform-owner`. The existing `x` key and then `run integration_permissions_validated` confirm the effect that you approved in advance. Overrides from the legacy quartet cannot execute it. The guidance discloses the creation of an installation token, the retained owner records and renewal on foreground demand. `--once` remains inspection only, and creates no broker owner and no credential session.

## Profiles

| Profile | Storage default | Inference default | Network and integration default |
|---|---|---|---|
| `local_single_node` | private local metadata and artifacts | local only | egress denied, local integration |
| `controlled_hybrid` | PostgreSQL plus envelope-encrypted S3 | explicitly approved remote route | allowlisted egress, least-privilege SCM |
| `kubernetes_ha` | PostgreSQL plus envelope-encrypted S3 | explicitly approved remote route | allowlisted egress, least-privilege SCM and shared coordination checks |
| `air_gapped` | private local metadata and artifacts | local only | egress denied, signed offline bundles |

Every profile starts with 30-day retention, provider content logging disabled, provider fallback disabled, publication disabled and dynamic validation disabled. The controlled-hybrid and Kubernetes baselines cap each model request at 100,000 micro-USD. The local and air-gapped baselines permit no remote model spend. Choosing a profile is not authority to create infrastructure or to connect an external service.

## Readiness checks

The plan contains an ordered set of requirements. Each is a deterministic check, a probe, an authorization or a dry run. Deterministic setup facts are recorded when the plan is created. All requirements that depend on the environment start as `pending`. A plan becomes `ready` only when every required check has an exact receipt from an approved checker.

Each plan embeds and binds one immutable checker catalog and the ordered history of check receipts. When Open Trestle decodes a plan, it replays that history from the initial, incomplete plan. Every previous plan identity, checker identity, receipt identity, revision, timestamp, latest result for a requirement, and the final readiness value must match. A plan-only edit cannot create readiness, and swapping the catalog is rejected.

A check receipt binds the current plan identity, the requirement key, the approved checker identity, a closed outcome, the evidence identity, the recovery action and a UTC timestamp. Stale receipts, and checkers that are not in the immutable catalog, are rejected. `blocked` and `unavailable` checks keep the plan unready and name one closed recovery action. A later check must bind the newer plan identity.

### Replacing a prerequisite receipt

Replacing an existing prerequisite receipt resets its dependent requirements to `pending` and clears their current evidence fields:

- Replacing the policy receipt resets the local-inference and dry-run checks.
- Replacing the PostgreSQL receipt resets the shared rate-limit and replica-reconciliation checks.
- Replacing the integration-permission receipt resets the webhook check.

This applies to replacement outcomes of passed, blocked and unavailable, even when the evidence digest is unchanged. Historical receipts remain immutable, and unrelated requirements keep their state. Run the dependent checks again against the new plan before you rely on readiness.

The Go replay and the console enforce the same rules for replacing a prerequisite. Histories without invalidated dependent results keep their existing identities. Older histories that kept a dependent result after its prerequisite was replaced now fail validation, even if their plan identity, which has no key, is recomputed. Open Trestle does not silently rewrite or migrate them. Preserve the original state and ledger for investigation. Then either restore a verified, compatible backup with its expected root identity, or explicitly initialize a separate protected state path and repeat the approvals and checks. Do not edit receipts or overwrite the old ledger.

Older binaries cannot replay newly written histories that contain these resets, so do not mix setup writers across this upgrade. These rules cover the prerequisite relationships listed above. They do not continuously validate every external service or credential.

### What setup state holds

Setup state never contains tokens, passwords, provider endpoints, source, prompts, model responses, bearer leases or secret values. Credential entry and external authorization belong to provider, identity or integration interfaces that are protected separately. Their setup receipts carry only identities that hold no secrets, and outcomes.

`trestle setup inspect` reports `ready` only after the embedded chain of approved receipts replays successfully, and every receipt has an identical record in the protected ledger. Record the initial plan identity that `setup init` returns. After an import or restore, require it with `--expected-root-identity` to detect that the root was substituted.

### The trust boundary

The local state owner, and the process that composes the approved checker implementations, form the setup trust boundary. They can authorize state transitions. File permissions and the append-only ledger protect against other local users, accidental edits, incomplete copies, stale writes and interrupted replacement. They do not protect against a malicious owner of the operating system. A deployment that does not trust that boundary needs an external signing or attestation service before it treats setup state as portable evidence.

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

The runtime parsers also rebuild identities, enforce the exact order and sources of the profile requirements, check the ordering of timestamps, and require canonical encoding.

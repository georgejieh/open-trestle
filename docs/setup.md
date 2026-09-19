# Setup planning

Open Trestle uses one versioned setup-plan contract across operator surfaces. A setup plan is a secret-free, content-addressed record of deployment posture and the checks that still block readiness. Creating a plan cannot contact a provider, connect a forge, create an identity, enable publication, or enable dynamic validation.

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

The state path must not exist. Its parent must be a non-symlinked directory without group or other write permission. The CLI creates the plan with mode `0600`, synchronizes the file and parent directory, and never overwrites an existing plan. The shared state-file implementation uses an exclusive writer lock. Later revisions are created only by `Runner.Run`, which executes an approved checker and applies its current-plan receipt through the protected state writer. They increment the revision, bind the previous identity and checker-catalog identity, use an atomic replacement, and synchronize the receipt and parent directories. If a stop occurs after the receipt is durable but before the plan head changes, `StateFile.PendingReceipt` exposes that one fenced receipt so the same transition can finish without rerunning the check. Inspect and validate the canonical state with:

```sh
trestle setup inspect \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --expected-root-identity "$RECORDED_INITIAL_PLAN_IDENTITY"
```

Initialization also creates a private append-only receipt ledger beside the plan at `plan.json.receipts`. Back up, restore, and transfer the plan and receipt ledger together. A plan copied without its ledger is rejected once it contains a closed check.

Receipt writes require a filesystem that supports same-directory hard links and file and directory synchronization. Each receipt is written to its canonical receipt filename plus `.next`, synchronized, and closed before a hard link installs the immutable final name without overwriting it. The ledger directory is synchronized before and after staging removal. Unsupported hard-link or synchronization operations fail closed; there is no overwrite fallback.

On writer reopen, one protected staging file can be reclaimed for the next revision or an already verified installed receipt. Read-only inspection leaves that staging file unchanged and never treats its bytes as passed evidence. A complete staging file without a final name is still uncommitted and is discarded. Only a complete final receipt can resume a transition without rerunning its check. Unknown names, unsafe staging files, and malformed committed receipts remain errors and are not discarded as temporary files. This includes partial final receipt files left by older versions.

During restore, before a destination plan exists, staging recovery is limited to the next receipt after a valid contiguous installed prefix, or a receipt already in that prefix. Restore still verifies the exact snapshot and root identities before opening the destination and checks all installed receipts against that snapshot before installing its plan. Initial and restored plan files are also written and synchronized under the protected `<state>.next` name before a hard link installs the complete final plan without overwriting it. Writer reopen can discard the protected uncommitted plan staging file; inspection never promotes it. A final plan left partially written by an older implementation remains an error and is not overwritten automatically.

Inspection rejects symlinks, broad file permissions, replacement races, unknown fields, noncanonical JSON, invalid identities, unsafe profile combinations, and inconsistent readiness.

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

The storage posture check opens and pins one exact current-user-owned `0700` directory. It pins and rechecks every ancestor to the filesystem root. Every ancestor must be owned by the current user or root. An ancestor with group or other write access must additionally be sticky and protect a child entry owned by the current user. Symlinked or replaceable path components are rejected. Ownership-dependent administrator, backup, storage, and protected runtime-file checks return `unavailable` on platforms where ownership authority is not implemented, including Windows in this release. Protected setup state also refuses open or inspection on those platforms. Mutable state, lock, and receipt files must be owned by the setup process user; their parent chain must prevent replacement by another local principal before any lock creation, chmod, cleanup, or read. It does not claim that backup, capacity, or crash recovery was tested. The observer credential posture check validates bounded header-safe values and constant-time inequality. It never stores or hashes either credential into evidence. It does not claim that a daemon accepted the observer; a later functional check must establish that separately.

The administrator check binds the exact setup root, tenant, repository, named recovery owner, and current effective operating-system user and group identity. `--approved-by` must exactly match the plan's recovery owner. It records consent for the current process identity. It does not create an account, grant operating-system privileges, or prove control of an external identity provider.

Create an exact protected backup snapshot after recording the current plan identity:

```sh
trestle setup backup create \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --destination "$HOME/backups/open-trestle/plan.snapshot.json" \
  --expected-plan-identity "$CURRENT_PLAN_IDENTITY"

trestle setup check backup \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --backup-snapshot "$HOME/backups/open-trestle/plan.snapshot.json"
```

The destination directory must already exist with mode `0700`, have stable trusted ancestry, differ from the live state directory, and not be nested beneath that directory. Snapshot creation never overwrites a path. The file is canonical mode `0600` plan data containing the complete verified receipt history. The checker double-reads and pins that file, requires current-process ownership, and requires its plan and root identities to exactly equal the live plan. The receipt identifies the exact plan represented by the snapshot. A stale snapshot cannot pass a later check after another receipt changes the plan.

Restore only to a new protected state path and fence both recorded identities:

```sh
trestle setup backup restore \
  --snapshot "$HOME/backups/open-trestle/plan.snapshot.json" \
  --destination "$HOME/.local/state/open-trestle-restored/plan.json" \
  --expected-root-identity "$RECORDED_INITIAL_PLAN_IDENTITY" \
  --expected-plan-identity "$BACKED_UP_PLAN_IDENTITY"
```

Restore reconstructs the append-only receipt ledger and validates the restored state before returning. It never overwrites state and can resume an exact interrupted ledger materialization. A passing backup check establishes one separate protected byte-complete setup-state copy. It does not establish independent media, storage failure isolation, off-site retention, application artifacts, database backups, or a successful disaster-recovery exercise. Those remain deployment-specific recovery obligations.

A passed check exits `0`. A completed `blocked` or `unavailable` check writes its canonical receipt and exits `3`. Malformed arguments, invalid setup identifiers, and unsupported profiles print usage and exit `2`. Authority mismatch, stale state, checker failure, or persistence failure exits `1` with content-free output. Check execution writes only the protected plan and append-only receipt ledger. Explicit backup creation writes only its new snapshot, and restore writes only its new state path, lock, and receipt ledger. None of these operations contacts a provider, forge, database, object store, or model.

## PostgreSQL storage authority

Controlled-hybrid and Kubernetes profiles use a database-native namespace rather than a hash of connection credentials. A migration administrator creates or upgrades the schema explicitly:

```sh
OPEN_TRESTLE_POSTGRES_MIGRATION_URL="$MIGRATION_DSN" \
  trestle admin postgres migrate
```

The command applies the exact embedded migration set and creates the durable database namespace. It reports no authority identity and does not initialize publication authority. With the separately scoped runtime credential, derive the runtime role's identity without mutation:

```sh
OPEN_TRESTLE_POSTGRES_URL="$RUNTIME_DSN" \
  trestle admin postgres identity
```

After recording that non-secret identity, run the confirmed setup check:

```sh
OPEN_TRESTLE_POSTGRES_URL="$RUNTIME_DSN" \
  trestle setup check postgres \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --approve-postgres-authority-identity "$DATABASE_AUTHORITY_IDENTITY" \
  --approved-by platform-owner
```

The checker binds the setup root, tenant, repository, recovery owner, approving actor, expected database authority, and probe implementation before reading `OPEN_TRESTLE_POSTGRES_URL`. It opens a pool with one connection, verifies every migration checksum plus the database name, active schema, runtime role, and durable namespace in one repeatable-read transaction. Only the expected authority identity and a closed outcome influence the setup receipt. The DSN, password, certificate private material, SQL errors, database details, and authority components do not enter setup state or general errors. A connection failure or timeout is `unavailable`; a migration conflict, malformed authority, role or schema substitution, or identity mismatch is `blocked`.

This establishes metadata-store identity and schema compatibility at one point in time. It does not validate artifact encryption, backup recovery, replica reconciliation, publication authority, capacity, latency, or future availability. Those remain separate requirements.

Budgeted artifact erasure requires the PostgreSQL schema to include the normal thirteen-migration registry through `0013_artifact_erasure_resume.sql`. Apply that schema only through an explicitly authorized migration administrator before budgeted daemon startup. The budgeted daemon branch verifies the runtime database authority, migration checksums, artifact erasure schema, and resume schema in read-only snapshots. It does not apply migration 0013 or any other migration, and it rejects `--apply-migrations` and `OPEN_TRESTLE_POSTGRES_MIGRATION_URL` in budgeted mode.

## Shared API rate limiting

Kubernetes HA plans require `shared_rate_limit_validated` after PostgreSQL storage authority passes. Migration 9 adds one content-free shared fixed-window table. Derive the exact setup and runtime authorities offline from the verified database identity and the root identity shown by `trestle setup inspect`:

```sh
RATE_LIMIT_AUTHORITY_IDENTITY="$(
  trestle admin postgres rate-limit identity \
    --database-authority-identity "$POSTGRES_DATABASE_AUTHORITY_IDENTITY" \
    --setup-root-identity "$SETUP_ROOT_IDENTITY" |
  jq -r .shared_rate_limit_authority_identity
)"
```

The runtime uses two fixed PostgreSQL namespaces. Pre-authentication request authorities admit at most 120 requests per database-clock minute across 10,000 active key digests. Authenticated principals admit at most 600 requests per database-clock minute across 1,024 active key digests. Raw network addresses, tenant IDs, principal IDs, and bearer tokens are not stored. Pre-authentication authority uses the canonical unmapped IP of the direct TCP peer and never trusts a forwarded-address header. A reverse proxy therefore needs its own authenticated client-aware limit if per-client ingress fairness is required. Each namespace and raw authority key are domain-separated before SHA-256 storage. Every row also binds the complete limiter configuration identity. A conflicting live configuration fails closed.

Existing keys use row locks. A new key uses a transaction-scoped advisory lock for its namespace, removes expired rows, checks exact cardinality, and inserts one window. Limits use PostgreSQL `transaction_timestamp()`, so replica host clock skew cannot create extra permits. Database errors, a live configuration conflict, or namespace-cardinality exhaustion return 503 `rate_limit_unavailable` and grant no request. Exhaustion of an established key's request quota returns 429. The composite authority also binds the canonical key sources, operation deadline, status and error codes, and retry headers used by the HTTP server. Local metadata mode keeps its explicitly process-local in-memory limiter and does not satisfy this HA requirement.

Run the explicit database conformance check:

```sh
trestle setup check rate-limit \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --approve-shared-rate-limit-authority-identity "$RATE_LIMIT_AUTHORITY_IDENTITY" \
  --postgres-database-authority-identity "$POSTGRES_DATABASE_AUTHORITY_IDENTITY" \
  --approved-by platform-owner
```

After the PostgreSQL receipt, scope, actor, authority, and stale-plan fences, the probe reads `OPEN_TRESTLE_POSTGRES_URL`. It revalidates every migration and the exact database authority. A session advisory lock isolates a deterministic setup-root namespace. Two independent limiter instances must share one two-request quota, reject the third request, share a two-key cardinality bound, reject a third key, reset only after database-time expiry, and admit exactly one of two concurrent attempts for the final permit. The table must contain exactly the two expected key digests and configuration identities. A pass deletes only the exact conformance namespace and verifies zero rows before releasing its session lock.

A process stop can leave content-free conformance rows. Their admission expires after one minute. A retry for the same setup root removes expired rows before proceeding; without a retry, expired digest/count/time rows can remain until operator maintenance. No DSN, credential, raw key, IP address, tenant, principal, payload, or source content enters the row, observation, receipt, API error, or setup state. This proof validates application-level shared limiting against the configured primary database. It does not prove load-balancer behavior, PostgreSQL replication health, provider-specific quotas, token budgets, webhook throttling, or Kubernetes network policy.

## Replica reconciliation

Kubernetes HA plans also require `replica_reconciliation_validated`. This check is separate from PostgreSQL identity and shared rate limiting. It proves that the application-level journal, notification queue, task leases, and terminal reconciliation converge through the configured database. Derive the exact content-free authority offline:

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

The checker verifies the Kubernetes HA posture, setup scope, recovery owner, PostgreSQL receipt, expected authority, immutable probe configuration, and current plan identity before the probe reads `OPEN_TRESTLE_POSTGRES_URL`. The probe revalidates every migration and the exact database authority. It holds one setup-root and database-derived session advisory lock, then uses two independently constructed runtime stores over that database.

The first instance opens one deterministic, content-free disposable plan. The second must reconstruct the same plan and state. Two schedulers must converge on one notification. Two notification claims and two task claims must each grant exactly one current lease. The other instance completes the task, and two concurrent finalizers must converge on one five-event terminal run with the exact fixture output. Concurrent operations make at most three total attempts for typed database-unavailable outcomes, with a fixed ten-millisecond delay between attempts; corruption and contradictory state do not retry. The probe uses PostgreSQL time as the operation clock. It makes no provider, forge, Kubernetes, source, model, publication, or non-database network request.

Before and after the cycle, one tenant-scoped serializable transaction inspects every table that can reference the disposable scope. Cleanup proceeds only when the stored plan, canonical event prefix, notification, and pending, active, or acknowledged delivery state are the exact expected fixture and all unrelated scope tables are empty. It deletes notifications, run events, the plan, and the scope in foreign-key order, then proves that no rows remain. Unknown or corrupt rows block cleanup and prevent a passing receipt.

A process stop can leave the content-free fixture plan, run events, notification, worker labels, timestamps, and digest-only lease authority. A retry under the same session lock validates that exact partial fixture before deleting it. It never deletes an unknown preexisting scope. Without a retry, the disposable rows remain for operator investigation. This bounded proof does not contact the Kubernetes API and does not prove PostgreSQL physical replication, failover, load-balancer behavior, capacity, latency, disaster recovery, or future availability.

## Envelope-storage authority

Controlled-hybrid and Kubernetes HA plans keep `envelope_storage_validated` separate from `secret_backend_validated`. The KMS-only receipt does not prove S3 persistence, integrity, versioning, or deletion. Derive the exact non-secret combined authority offline:

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

The authority binds the tenant, canonical S3 endpoint, region, bucket, prefix, exact KMS tenant-key registry, optional KMS endpoint, direct no-proxy transport posture, attempt bounds, and these distinct request-time credential references:

- `OPEN_TRESTLE_S3_ACCESS_KEY_ID`, `OPEN_TRESTLE_S3_SECRET_ACCESS_KEY`, and optional `OPEN_TRESTLE_S3_SESSION_TOKEN` for the bucket prefix;
- `OPEN_TRESTLE_AWS_ACCESS_KEY_ID`, `OPEN_TRESTLE_AWS_SECRET_ACCESS_KEY`, and optional `OPEN_TRESTLE_AWS_SESSION_TOKEN` for the KMS key.

The check rejects the same access-key ID in both roles. That detects direct credential reuse; it does not independently inspect IAM policies or prove that two different access keys cannot reach overlapping resources. Operators must enforce the bucket-prefix and KMS-key scopes in AWS policy.

After setting those environments on the setup service, run the effectful check explicitly:

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

Add the same optional `--kms-endpoint URL` to the admin and check commands when a custom KMS endpoint is intended. The checker rejects a different authority, scope, or actor before reading any credential or contacting either service.

After confirmation, the checker constructs the production S3 backend, AWS KMS tenant-key provider, and `artifact.EnvelopeStore`. It creates one fixed public conformance artifact at a deterministic key. It verifies that the raw stored object contains neither the literal payload nor its base64 representation, retrieves and validates the artifact through client-side AES-256-GCM envelope decryption, deletes only the exact immutable S3 version returned by the read, and requires a final not-found response. A fresh successful run performs at most eight S3 requests and three KMS operations. S3 requests have no automatic retry or reused connection. Each KMS operation permits at most three attempts. The whole check has one 90-second deadline. Redirects and proxies are disabled, responses are bounded, and HTTPS requires TLS 1.2 or newer.

This conformance artifact deliberately bypasses runtime retention intents because it contains only the fixed public payload and exists solely for the confirmed create-read-delete check. The bypass is private to the conformance implementation and can delete only the deterministic key and exact version it just verified. It cannot accept a runtime artifact, user payload, prefix, or arbitrary version for deletion.

A failure before exact deletion can leave one envelope-encrypted object at the deterministic conformance key. A later confirmed run with the same setup root and exact authority can verify and remove a valid object. A corrupt or conflicting object requires the operator's exact-version bucket recovery procedure. Changing the authority changes the conformance key; operators must first retry the old authority or remove its exact version under that procedure. A passing receipt requires verified absence. Setup state stores only content-derived authority, conformance, evidence, checker, and receipt identities. It stores no endpoint, bucket, prefix, key ARN, credential, payload, ciphertext, wrapped key, plaintext key, or S3 version.

Only a bounded S3 `NoSuchKey` error is admitted as absence. `NoSuchBucket`, a generic endpoint 404, malformed error XML, a missing version identifier, a changed object, or malformed KMS output cannot produce a passing receipt. Missing or unreachable service state is `unavailable`; deterministic version, integrity, tenant-key, and authority conflicts are `blocked`.

The final not-found check proves current-key absence through the configured backend. It does not enumerate hidden historical versions or override bucket retention and delete-marker policy. Bucket policy must deny unversioned or unrelated mutation of the conformance prefix.

A pass proves one bounded envelope-storage round trip at that time. It does not prove backup, replication, lifecycle, disaster recovery, future availability, application retention deletion, publication authority, model authority, webhook authority, or source-mutation authority.

## Budgeted artifact erasure startup

Budgeted artifact erasure is an opt-in daemon storage mode, not a setup check and not an operator deletion API. Select it with `--artifact-erasure-mode budgeted`. The default remains `--artifact-erasure-mode legacy`, and existing local and legacy S3 behavior is unchanged.

Budgeted startup requires all of the following:

- PostgreSQL metadata storage with the exact runtime-role `--postgres-database-authority-identity`;
- S3 artifact storage with the existing endpoint, region, bucket, prefix, and separate S3 credential environments;
- the existing KMS region, key ARN, optional secure KMS endpoint, and separate KMS credential environments;
- an explicit protected erasure policy from `--erasure-policy`; and
- an explicit protected S3 erasure CA from `--s3-erasure-trusted-ca`.

`--erasure-policy` and `--s3-erasure-trusted-ca` are invalid in legacy mode. Budgeted mode rejects local metadata, local artifacts, missing policy or CA, `--apply-migrations`, and any `OPEN_TRESTLE_POSTGRES_MIGRATION_URL`. It uses the existing database, S3, and KMS credential names. It adds no new credential environment variable and no hidden trust source.

The protected policy must be valid for the daemon-owned UTC millisecond startup sample. It must bind the configured database authority, S3 backend configuration identity, S3 prefix, and storage namespace. The CA file must be an absolute clean protected path to a trusted-owner regular file, non-empty, stable across two reads, and no larger than 256 KiB. The budgeted S3 erasure backend requires HTTPS and accepts explicit CA roots only; it does not fall back to ambient S3 trust roots.

Startup constructs the protected policy, S3 erasure backend, KMS provider, PostgreSQL artifact index, budgeted erasure witness, and indexed budgeted envelope store. These are startup configuration checks. They make zero S3 or KMS requests. The PostgreSQL verification still contacts the configured database. A `RuntimeStatus` v1 component named `artifact_erasure_budgeted` with state `ready` means that construction completed. It does not prove ongoing policy freshness, provider health, bucket versioning, physical erasure, erasure authorization, media backup, disaster recovery, or future availability.

Budgeted store instances enable the budgeted resume and readback protocol. The daemon wires artifact storage and its callers that put or get artifacts. It does not add an admin erasure endpoint, an operator Prepare/Resume command, or an automatic erasure recovery loop. Direct library callers must supply valid timestamps; the daemon normalizes only its own artifact caller times.

Existing setup receipts remain separate evidence. PostgreSQL storage authority, shared rate limiting, replica reconciliation, envelope storage, secret backend, provider authorization, webhook conformance, policy dry runs, backups, and media recovery each need their own documented checks or operator proof before a deployment treats them as satisfied.

## Secret-backend authority

Controlled-hybrid and Kubernetes HA plans require a separate `secret_backend_validated` receipt. First derive the non-secret identity of the exact region and one-key-per-tenant registry. This command is offline and does not read credentials or contact AWS:

```sh
KMS_AUTHORITY_IDENTITY="$(
  trestle admin kms identity \
    --tenant tenant-a \
    --region us-east-1 \
    --key-arn arn:aws:kms:us-east-1:123456789012:key/KEY-ID |
  jq -r .kms_authority_identity
)"
```

Configure request-time AWS credentials in the setup service environment, then explicitly run the check:

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

Use `--kms-endpoint URL` only when the operator intends to bind a custom approved service endpoint. The endpoint participates in the checker configuration identity. It does not alter the logical tenant-key registry identity.

After the state and approval fences pass, the checker reads the three AWS credential environments. It asks the exact tenant key to generate one AES-256 data key and unwraps the returned ciphertext with the same key ARN and hashed tenant encryption context. It requires the response key ARN, algorithm, and sizes to match, compares the two plaintext keys in constant time, and clears all plaintext copies. The two KMS operations each permit at most three attempts under one 60-second check deadline. Responses are capped at 1 MiB, redirects and proxies are disabled, and HTTPS connections require TLS 1.2 or newer. The IAM principal needs only `kms:GenerateDataKey` and `kms:Decrypt` for the approved key and tenant encryption context.

A passing receipt stores only content-free authority, checker, evidence, and outcome identities. It stores no AWS credential, endpoint, key ARN, wrapped key, plaintext key, response, or provider error. Missing or malformed credentials, a crossed tenant/key response, or a different approved identity blocks the check. A transport, timeout, throttling, or KMS service failure records `unavailable`.

This check proves one bounded key-provider round trip at that time. It performs no S3 request. It does not prove envelope object persistence, retention, deletion, recovery, future availability, publication authority, model authority, or source-mutation authority. `envelope_storage_validated` remains a separate requirement.

## Remote-provider authorization

Controlled-hybrid and Kubernetes HA plans require an explicit `remote_provider_authorized` receipt before readiness. Validate the protected route inventory and runtime policy to obtain their exact identities, then approve the same review-policy identity and named recovery owner:

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

The authorization reopens and double-reads the protected files under the same full-ancestry ownership and replacement fences as policy validation. It requires an exact controlled remote-inference posture, at least one canonical non-loopback HTTPS `private_remote` connection, disabled provider content logging across the inventory, known cost inside the profile cap, unpinned ranking, publication blocking on inconclusive results, and a generation/verification pair with distinct provider IDs, connection IDs, canonical endpoint origins with default ports normalized, and credential-environment identities whose immutable registry records are approved and whose health and quota observations are ready. Other inventory records remain visible to deterministic gateway filtering and do not become authorized attempts merely because they are present. Every adapter's provider, connection, zone, logging, endpoint, and credential-environment identity must match the inventory namespace exactly.

Credential environment names use the `OPEN_TRESTLE_PROVIDER_*` namespace and their reference-derived identities are configuration authority. The authorization never resolves or reads the corresponding values. Distinct environment identities prove separate configuration references, not different secret bytes or disjoint provider-side privileges. DNS names are not resolved, so operators must prevent two approved names from aliasing the same provider authority. It makes no DNS lookup, network request, model call, retry, fallback, publication, source change, webhook action, or dynamic-validation request. Setup state stores only content-derived approval, checker, evidence, and receipt identities, not paths, endpoints, environment names, provider declarations, prices, or route observations.

A pass proves that the named recovery owner authorized one exact remote-provider configuration and that its protected snapshot satisfied the declared policy constraints. It does not prove credential availability, provider connectivity, current service health, review quality, future cost, or permission to publish. The separate policy receipt and non-publishing dry run remain required. Changing either protected file or any approved identity invalidates the authorization.

## GitHub integration permissions

Controlled-hybrid and Kubernetes HA plans require a current `integration_permissions_validated` receipt. This is an explicitly effectful native broker check, not a GET-only inspection or permission to publish. Set `OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG` to the absolute path of the protected [source-broker descriptor](../schemas/runtime/github-source-broker-v1.schema.json). The host captures that configuration once. Requests cannot supply a descriptor path, raw configuration, App key, or legacy endpoint/version/installation/repository overrides.

Derive the configuration-only identities without opening a broker, reading credentials, allocating an owner, or creating a generation:

```sh
trestle admin github permissions identity \
  --broker-config "$OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG"
```

The result has exactly seven fields: `contract: open-trestle/github-permission-admin-result`, `schema_version: 2`, `status: configuration_only`, `operation: identity`, `broker_authority_identity`, `setup_issuance_authority_identity`, and `permission_authority_identity`. Record the three native identities. None is an observed grant or approval. The legacy admin quartet (`--api-endpoint`, `--api-version`, `--installation-id`, `--repository-full-name`) still returns the unchanged schema 1 identity-only result. It is mutually exclusive with `--broker-config` by flag presence, even for empty values, and cannot execute the current setup check.

The unchanged descriptor has exactly 20 fields: `contract`, `schema_version`, `tenant_id`, `repository_id`, `repository_full_name`, `github_repository_id`, `installation_id`, `app_id`, `repository_authority`, `api_endpoint`, `api_version`, `archive_authorities`, `app_key_version`, `app_public_key_sha256`, `credential_environment`, `authorization_generation`, `ownership_mode`, `attempt_state_directory`, `allow_token_creation`, and `allow_demand_renewal`. Its contract is `open-trestle/github-source-broker`, schema version 1. Repository authority is `github.com`, credential environment is `OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY`, ownership is `single_host_exclusive`, and both effect booleans must be true. Native protected-file, key-pin, path, endpoint, date, scope, and directory checks remain authoritative. Setup and admin additionally require API year >=2000; the generic descriptor date schema is only a shape check.

Keep the dedicated short-lived GitHub App user access token in `OPEN_TRESTLE_GITHUB_SETUP_TOKEN` and the pinned App private key in `OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY` on the host. Do not configure static `OPEN_TRESTLE_GITHUB_API_TOKEN` in broker mode. Explicitly approve both authorities and token creation:

```sh
trestle setup check integration \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --approve-github-source-broker-authority-identity "$GITHUB_BROKER_AUTHORITY_IDENTITY" \
  --allow-github-installation-token-creation \
  --approve-integration-permission-authority-identity "$GITHUB_PERMISSION_AUTHORITY_IDENTITY" \
  --approved-by platform-owner
```

The common broker approval, permission approval, actor, scope, immutable probe configuration, current catalog, and expected plan must agree before dispatch. The probe reads the dedicated user token and compares it with the runtime GitHub, setup-service, daemon operator, observer, and webhook environments in that order. Missing, reused, or mixed static credentials reject before owner allocation, App key access, or HTTP. No secret value or secret hash enters setup identity or state.

Only then may the lazy setup-purpose session open its retained owner. The real permission inspector first checks user installation visibility through bounded `GET /user/installations`. Native issuance then authenticates the exact installation using the pinned App signer and requests one narrow installation token. The accepted native grant, not an opaque static token or caller-supplied signed metadata, binds the installation, numeric repository, selected single-repository scope, expiry, common authority, setup issuance lane, and durable attempt. The only admitted permissions are `metadata: read`, `contents: read`, and `pull_requests: read`; the only event is `pull_request`. An actual grant equal to the user token is rejected.

Extra permissions, write access, extra events or repositories, all-repositories selection, suspension, duplicate critical JSON members, wrong pins, crossed scope, redirects, unknown issuance outcomes, or cancellation cannot produce a pass. User discovery remains limited to ten pages of 100 installations and 1 MiB responses. The setup check has a 60-second deadline around 30-second inspector requests. Direct transports disable proxies and redirects; remote requests require TLS 1.2 or newer. See [GitHub integration permission evidence](github-integration-permissions.md) for the native protocol and limits.

One standalone command owns one lazy session. An interactive TUI or web handler owns one session for its foreground lifetime and can reuse a valid cached token. Renewal occurs only on foreground demand. Content-free owner and issuance-attempt records remain after success, failure, unknown issuance, and Close. Tokens are not persisted. A restarted process cannot recover a token by reusing that generation or deleting its owner marker. A fresh generation and fresh approvals require an explicit operator configuration change; there is no automatic retry owner, restart recovery, shared-volume owner, or HA credential ownership. This `single_host_exclusive` limit applies even to the `kubernetes_ha` setup profile.

A pass proves user visibility and one accepted native setup-purpose grant at that time. It does not grant daemon runtime authority, which needs its independent common approval and runtime-purpose owner. It does not change installation access, revoke a token, validate webhook delivery, execute a review, modify source, or grant publication. State stores only content-free authority, observation, evidence, checker, and receipt identities, never tokens, PEM, endpoint, provider response, or owner path.

If credential cleanup is incomplete, the command reports `setup credential cleanup failed` and exits nonzero even if a receipt was already persisted. The receipt and accepted provider effect are not rolled back. A stable incomplete Close result stays incomplete on repeated Close; logical closure is not physical quiescence. Never replay issuance to repair receipt persistence. A durable current pending receipt can recover without opening credentials.

### Current authority migration

Old plans, catalogs, receipts, and Ready remain readable with their original bytes. They are historical, not current integration or webhook authority. The Runner rejects both operations under an old integration binding before pending-receipt recovery or checker execution. The browser marker is only a diagnostic and action gate, never server or mint authority.

Initialize a fresh protected state path with a current plan and rerun every nondeterministic check. Do not overwrite the old plan, relabel its catalog, import old receipts, or auto-upcast Ready. Replacing a current integration receipt resets webhook to pending under the existing dependency rules; rerun webhook against the new exact permission receipt. Historical inspection is not migration.

## GitHub webhook conformance

Controlled-hybrid and Kubernetes HA plans require `webhook_validated` after the integration-permission receipt. Derive the credential-free authority with the exact plan scope and the non-secret webhook key ID used by `trestled`:

```sh
GITHUB_WEBHOOK_AUTHORITY_IDENTITY="$(
  trestle admin github webhook identity \
    --tenant tenant-a \
    --repository repository-a \
    --key-id primary-2026 |
  jq -r .webhook_authority_identity
)"
```

The authority binds the tenant and repository scope, key ID, `OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET` reference, verifier configuration identity, HMAC-SHA-256, `POST /webhooks/github`, exact request headers, 1 MiB payload and 256-byte header bounds, one-request concurrency, exact `pull_request` actions, five fixed requests and expected statuses, public fixture digests and delivery IDs, response contract and security headers, one private disposable `FileStore` record, durable-before-acknowledgment behavior, required bounded nonrecursive cleanup of at most the lock and one delivery record, and zero listener or network requests.

Generate a 32-byte secret with a cryptographically secure random generator and encode it as exactly 64 lowercase hexadecimal characters. The validator rejects other encodings, zero or low-diversity values, and repeated patterns up to 32 characters. These structural checks establish 256-bit capacity but cannot prove the generator's entropy; generation provenance remains an operator responsibility. The secret must differ from the GitHub setup, runtime, and publication tokens and from the setup-service, daemon operator, and observer tokens. Then run the confirmed check:

```sh
export OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET="$(openssl rand -hex 32)"

trestle setup check webhook \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --approve-webhook-authority-identity "$GITHUB_WEBHOOK_AUTHORITY_IDENTITY" \
  --github-webhook-key-id primary-2026 \
  --approved-by platform-owner
```

The Runner first rejects historical integration catalogs, before pending recovery or execution. The checker rejects a stale plan, missing current integration-permission receipt, changed scope, wrong actor, changed probe, or mismatched authority before reading the secret. It then calls the production verifier and HTTP handler directly in process. A bad signature must receive 401 without storage. A correctly signed `pull_request/opened` fixture must reach a private crash-safe file before the handler returns 202. Its exact replay must return 200 with the original acceptance identity and no second record. The same delivery ID with a different correctly signed allowed body must return 409 without changing the record. A correctly signed disallowed action must return 202 as ignored without storage. The verifier clears its owned secret byte slice when closed. The executor also clears its owned input byte slices. Go environment values originate as immutable strings, so the check does not claim that their backing storage is erased; operators must keep the process environment private and rotate the external secret when required. The disposable directory must still be the originally created private directory, close successfully, be removed, and be absent before the check can pass.

At daemon startup, the runtime applies the same secret format and rejects equality with any configured operator, observer, runtime GitHub, GitHub setup, or setup-service token. The publication token remains a request-time capability: its provider compares a digest only after publication authorization and rejects equality before returning the token. The publication value is not read during startup.

This cycle opens no listener and makes no GitHub, DNS, model, source, review-run, or publication request. The fixed payload is public synthetic data. The disposable local `FileStore` proves handler, verifier, admission, persistence-before-acknowledgment, deduplication, conflict, filtering, and cleanup semantics. It does not prove network reachability from GitHub or shared production inbox storage. PostgreSQL metadata and envelope-storage receipts remain separate. Setup state retains only authority, observation, dependency-receipt, evidence, checker, and receipt identities. It never retains the secret, signature, payload, key ID, or temporary path.

GitHub documents `X-Hub-Signature-256` as an HMAC-SHA-256 over the unchanged payload and recommends a high-entropy secret and constant-time comparison. GitHub also documents `X-GitHub-Delivery` as the delivery identifier and recommends a fast 2xx response with asynchronous work. See [Verified webhook ingress](webhook-ingress.md) for the runtime boundary and official references.

## Runtime policy approval and dry run

For a new runtime policy, first compute the route inventory identity and bind it
into the policy document:

```sh
trestle config inventory-identity \
  --route-inventory /etc/open-trestle/routes.json
```

Copy the reported `inventory_identity` into the runtime policy, and optionally add
route pins or preferences from the reported `route_record_identities`. This command
decodes only protected local configuration. It does not contact providers and does
not prove policy binding, reachability, health, quality, or live conformance.

Validate the protected route inventory and bound runtime policy next:

```sh
trestle config validate \
  --route-inventory /etc/open-trestle/routes.json \
  --runtime-policy /etc/open-trestle/runtime-policy.json
```

Record the reported `inventory_identity`, `runtime_policy_identity`, and `review_policy_identity`. The named recovery owner must then approve those exact identities when advancing the setup plan:

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

The checker double-reads protected regular files and pins their full path ancestry. Files and ancestors must be owned by the current user or root. Configuration files cannot be group or other writable. Shared writable ancestors require the same sticky-directory protections as local storage checks. The checker does not resolve a credential reference or connect to an endpoint.

A passing policy must match the selected setup posture. It uses only declared privacy zones, binds every adapter to one unambiguous zone, provider, connection, logging, endpoint, and credential authority, disables content logging, stays within the profile cost cap, provides at least two currently approved and usable routes at the required independence level, and uses canonical endpoint locality. Local and air-gapped profiles accept only numeric loopback endpoints and local routes. Remote routes reject conventional localhost names and non-unicast numeric addresses; the offline check does not resolve approved DNS names. The policy must block publication on inconclusive verification, and its publication independence floor cannot be weaker than its verification floor. Exact route pins are rejected because removing the generation route for independent verification would make the pin unavailable.

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

This is an explicit functional probe, not an offline validation. It reads each selected credential environment only at dispatch time and attempts at most two fixed, secret-free prompts against independently routed models from the approved local inventory. It stops after the first failed step; a pass requires exactly one generation response and one independent-verification response. Both adapters must return the exact empty candidate and verification contracts through the normal strict response admission path. Each request permits at most 256 output tokens, reported input above 1,024 tokens is rejected, and the check has one 90-second total deadline. It performs no retry or fallback. Its HTTP transport disables proxies and connection reuse, accepts only canonical numeric-loopback dial targets, and never performs DNS resolution. Provider storage is disabled, content logging must be disabled by policy, and the checker has no publisher, source writer, or dynamic-validation authority.

The plan stores only content-derived configuration, execution, and receipt identities. It does not store the credential, prompt, model text, endpoint, model name, token counts, or failure body. A passing result proves that the exact approved local generation and independent-verification paths completed the fixed contract at that time. It does not establish review quality, throughput, future availability, remote fallback, or permission to publish. Authentication, malformed output, or policy mismatch blocks the check. A transient connection, timeout, rate-limit, or server failure records `unavailable`.

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

The dry run uses fixed content and local deterministic dispatchers. It exercises the configured eligibility filter, ranking, generation authorization, independent verification authorization, provider-neutral dispatch contract, strict candidate and verifier output admission, terminal attempt records, cost reconciliation, output lineage, and independence receipt. It has a five-second bound and is constructed without a publisher, source writer, validation process, network client, or credential resolver. It cannot publish, mutate source, invoke dynamic validation, or contact a configured model endpoint. A changed or missing policy file produces a blocked or unavailable receipt instead of reusing older evidence.

## Signed offline bundle validation

Air-gapped plans require `signed_bundle_validated`. The check validates one exact opaque file without extracting, importing, executing, scanning, or interpreting it. Open Trestle never receives a private signing key.

First compute the exact file byte count and SHA-256 digest. Ask Open Trestle to emit the canonical statement bytes as base64:

```sh
STATEMENT_BASE64="$(
  trestle admin bundle statement \
    --bundle-sha256 "$BUNDLE_SHA256" \
    --bundle-bytes "$BUNDLE_BYTES" |
  jq -r .statement_base64
)"
printf '%s' "$STATEMENT_BASE64" | base64 -d > offline-bundle-statement.json
```

Sign the decoded statement file with the approved offline Ed25519 private key using separately governed signing tooling. Encode the raw 32-byte public key as 64 lowercase hexadecimal characters and the raw 64-byte signature as 128 lowercase hexadecimal characters. Then derive the exact content-free setup authority:

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

The signed statement is canonical JSON with contract `open-trestle/offline-bundle-signature-statement`, schema version 1, `bundle_sha256`, and `bundle_bytes`. The authority binds the statement identity, SHA-256 and Ed25519 algorithms, exact digest and byte count, public-key and signature identities, one GiB file limit, 64 KiB streaming buffer, canonical absolute-path rules, regular-file requirement, same-file checks before and after streaming, cancellation checks, closed error posture, and zero extraction, import, execution, or network requests.

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

The checker admits only the air-gapped local-storage, local-inference, denied-egress, offline-bundle posture. Setup scope, recovery owner, approved authority, immutable probe configuration, and current plan identity are checked before the file is opened. The verifier rejects empty or oversized files, noncanonical or all-zero key material, malformed signatures, symlinks, non-regular files, path replacement, size changes, digest mismatch, signature mismatch, read failure, and cancellation. I/O failure is unavailable. A malformed or mismatched bundle is blocked. Setup state and general errors retain no path, bundle bytes, key, signature, or file-system error.

The public key and signature are public verification inputs, but their raw values are not written to setup state. Operators must establish public-key trust, rotation, revocation, signing custody, and statement delivery through a separate process. A passing receipt proves only that the one local opaque file matched the approved size, digest, public key, and Ed25519 signature at check time. It does not validate archive structure, contained artifacts, SBOM, provenance, transparency logs, timestamps, release policy, malware, compatibility, import behavior, execution safety, or no-egress enforcement.

## Guided local web setup

Start the setup service on a numeric loopback address with a dedicated random token:

```sh
export OPEN_TRESTLE_SETUP_TOKEN='replace-with-a-distinct-long-random-token'
trestle setup web \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --listen 127.0.0.1:8742
```

Open the printed `/console/setup` address and enter the setup token. The service never prints the token, accepts no non-loopback listener, pins the exact numeric Host authority to prevent DNS rebinding, and rejects a token equal to the daemon operator or observer token. The browser keeps the token and all form values only in React memory. It sends the token only in an authorization header and omits ambient credentials.

When no plan exists, the guided surface presents the four safe profiles, exact scope, and recovery owner. Plan creation needs a separate confirmation. An existing plan opens at its first pending requirement and shows exact readiness, effect posture, recovery, evidence identity, and receipt lineage. Each check requires an inline confirmation bound to the displayed plan identity and requirement key. Stale plans are rejected.

The local setup API can initialize a plan and run the built-in local-administrator, backup-snapshot, local and PostgreSQL storage, envelope-storage conformance, KMS secret-backend, remote-provider authorization, GitHub integration-permission inspection, local GitHub webhook conformance, PostgreSQL shared rate limiting, replica reconciliation, signed offline bundle, observer credential posture, runtime policy, explicit local-inference, and non-publishing dry-run checkers. Backup snapshot creation and restore stay explicit CLI operations. Other requirements remain visibly pending and say that no built-in web checker is available. The API uses strict valid-UTF-8 and duplicate-key-rejecting JSON, rejects unknown or case-folded request member names before Go decoding, and validates forbidden fields by presence even when empty, uses bounded request and response bodies, mutation-free missing-state inspection, protected state writers, no-store responses, and content-free errors. Starting the service does not run a check or create setup state.


For integration checks, configure `OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG` on the host and start `trestle setup web` with `--approve-github-source-broker-authority-identity "$GITHUB_BROKER_AUTHORITY_IDENTITY"`. A descriptor without the exact startup cap is rejected. No startup allow flag substitutes for request consent. In the existing integration form, supply both common broker and permission identities, the exact recovery owner, and explicit token-creation consent. Confirm `create GitHub installation token and run integration_permissions_validated`. The request has only the nine schema 2 fields documented in [Daemon API and client](daemon-api.md#local-setup-api); unrelated check requests stay schema 1. A setup bearer token alone cannot approve issuance. The server independently checks every approval and the current expected plan.

Shutdown cancels the credential owner first, allows five seconds for HTTP Shutdown, and forces server Close on HTTP failure. It then closes the credential session with a separate bounded five-second broker/open drain. Both cleanup failures are reported without provider details. These are separate sequential budgets, not one five-second aggregate or a hard ten-second kernel-quiescence guarantee. An incomplete credential Close remains cached and cannot roll back a durable receipt.

## Keyboard-first setup

After initialization, the same protected plan can be inspected and advanced in a foreground terminal:

```sh
trestle setup tui \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --storage-root "$HOME/.local/state/open-trestle" \
  --backup-snapshot "$HOME/backups/open-trestle/plan.snapshot.json" \
  --administrator-approved-by platform-owner
```

Use `j` and `k` to select a requirement. Press `x`, then type the displayed `run REQUIREMENT_KEY` command to confirm one receipt write. Use `r` to reload and `q` to quit. The interface shows exact pending, passed, blocked, and unavailable states plus the closed recovery action and recent receipt lineage. It executes only the checker configurations supplied when it starts. Unsupported requirements remain pending and say that no checker is configured. Policy approval and local-inference flags are identical to the non-interactive commands. Local inference remains disabled until the exact policy check passes and still needs the `x` plus `run local_inference_validated` confirmation. See [Foreground terminal interface](tui.md#setup-terminal-interface).


Interactive integration setup uses the same descriptor and `--approve-github-source-broker-authority-identity`, `--allow-github-installation-token-creation`, and `--approve-integration-permission-authority-identity` startup flags, plus `--integration-approved-by platform-owner`. The existing `x` then `run integration_permissions_validated` command confirms the explicitly preapproved effect. Legacy quartet overrides cannot execute it. Guidance discloses installation token creation, retained owner records, and foreground demand renewal. `--once` remains inspection only and creates no broker owner or credential session.

## Profiles

| Profile | Storage default | Inference default | Network and integration default |
|---|---|---|---|
| `local_single_node` | private local metadata and artifacts | local only | egress denied, local integration |
| `controlled_hybrid` | PostgreSQL plus envelope-encrypted S3 | explicitly approved remote route | allowlisted egress, least-privilege SCM |
| `kubernetes_ha` | PostgreSQL plus envelope-encrypted S3 | explicitly approved remote route | allowlisted egress, least-privilege SCM and shared coordination checks |
| `air_gapped` | private local metadata and artifacts | local only | egress denied, signed offline bundles |

Every profile starts with 30-day retention, provider content logging disabled, provider fallback disabled, publication disabled, and dynamic validation disabled. Controlled-hybrid and Kubernetes baselines cap each model request at 100,000 micro-USD. Local and air-gapped baselines permit no remote model spend. Choosing a profile is not authority to create infrastructure or connect an external service.

## Readiness checks

The plan contains an ordered set of deterministic, probe, authorization, and dry-run requirements. Deterministic setup facts are recorded at creation. All environment-dependent requirements start as `pending`. A plan becomes `ready` only when every required check has an exact approved checker receipt.

Each plan embeds and binds one immutable checker catalog plus the ordered check-receipt history. Decoding replays that history from the initial incomplete plan and requires every previous plan identity, checker identity, receipt identity, revision, timestamp, latest requirement result, and final readiness value to match. A plan-only edit cannot create readiness. Swapping the catalog is rejected. A check receipt binds the current plan identity, requirement key, approved checker identity, closed outcome, evidence identity, recovery action, and UTC timestamp. Stale receipts and checkers outside the immutable catalog are rejected. `blocked` and `unavailable` checks keep the plan unready and name one closed recovery action. A later check must bind the newer plan identity.

Replacing an existing prerequisite receipt resets its dependent requirements to `pending` and clears their current evidence fields. Policy replacement resets local-inference and dry-run checks; PostgreSQL replacement resets shared rate-limit and replica-reconciliation checks; integration-permission replacement resets the webhook check. This applies to passed, blocked, and unavailable replacement outcomes, even when the evidence digest is unchanged. Historical receipts remain immutable. Unrelated requirements retain their state. Run the dependent checks again against the new plan before relying on readiness.

Go replay and the console enforce the same prerequisite replacement rules. Histories without invalidated dependent results keep their existing identities. Older histories that retained a dependent result after replacing its prerequisite now fail validation, even if their unkeyed plan identity is recomputed. They are not silently rewritten or migrated. Preserve the original state and ledger for investigation. Restore a verified compatible backup with its expected root identity, or explicitly initialize a separate protected state path and repeat the approvals and checks. Do not edit receipts or overwrite the old ledger. Older binaries cannot replay newly written histories containing these resets; do not mix setup writers across this upgrade. These rules cover the listed prerequisite relationships, not continuous validation of every external service or credential.

Setup state never contains tokens, passwords, provider endpoints, source, prompts, model responses, bearer leases, or secret values. Credential entry and external authorization belong to separately protected provider, identity, or integration interfaces. Their setup receipts carry only non-secret identities and outcomes. `trestle setup inspect` reports `ready` only after the embedded approved receipt chain replays successfully and every receipt has an identical protected ledger record. Record the initial plan identity returned by `setup init`. Require it with `--expected-root-identity` after import or restore to detect root substitution.

The local state owner and the process that composes approved checker implementations are the setup trust boundary. They can authorize state transitions. File permissions and the append-only ledger protect against other local users, accidental edits, incomplete copies, stale writes, and interrupted replacement, not a malicious operating-system owner. Deployments that do not trust that boundary need an external signing or attestation service before treating setup state as portable evidence.

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

Runtime parsers additionally reconstruct identities, enforce exact profile requirement order and sources, check timestamp ordering, and require canonical encoding.

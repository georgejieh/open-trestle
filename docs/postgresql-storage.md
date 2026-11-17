# PostgreSQL canonical ledgers

The PostgreSQL adapter stores Open Trestle's review-run journal and audit ledger in a database, for deployments that need shared, durable state. This page is for operators who run that database and for contributors who work on the adapter.

`adapters/storage/postgres` implements the canonical review-run journal and the content-free audit ledger on PostgreSQL 17-compatible semantics. It stores the canonical JSON contracts as they are and keeps no separate run-state model. Callers rebuild state through `controlplane.ReplayReviewRun`.

## What the database stores

The database migrations cover these areas:

- review scopes, run plans, run events and audit events;
- diagnostic-to-artifact mappings;
- content-free task notifications;
- publication-attempt guards;
- webhook deliveries, refusals and retries;
- shared rate limits;
- artifact metadata and erasure progress.

Diagnostic text, webhook bodies, source content and artifact payloads are not placed in these tables. The adapter has several stores for the data that points at protected artifacts.

- `DiagnosticStore` keeps one canonical diagnostic set in the configured protected artifact store. PostgreSQL records only its set identity, artifact identity, scope and expiry. Versions 1 through 5 and 8 use the `verified_finding_set` artifact kind and `independent_verifier` origin. Version 6 uses `deterministic_evidence` and `deterministic_tool` with set, snapshot and analysis-result lineage. Version 7 is the final full-review result. The host assembles it and stores it as a `run_export` artifact with `host` origin. Its lineage names the set, the snapshot, the review snapshot, and the analysis and verified-set identities that it carries.
- `WebhookStore` does the same for a canonical verified delivery and its acceptance receipt. It binds the protected artifact to the delivery's review-run scope. It stores only the repository scope, the source, the delivery and artifact identities, the acceptance time and the expiry.
- `ArtifactIndex` records payload-free artifact metadata, short-lived deletion authority (including the legal-hold clearance identity) and completed physical-deletion receipts. It also provides stable expiry scans that exclude completed deletions.
- `IndexedArtifactStore` combines that index with any artifact store that supports retention, so a failed index write can be retried without repeating a physical effect.

### Migrations 0010 and 0011

Migration `0010_artifact_kinds_and_origins.sql` extends the artifact metadata constraints for source-file payloads, publication receipts and memory-origin results. Apply this migration through an authorized migration administrator before you start the updated indexed runtime. A database that lacks it fails verification.

Migration `0011_investigation_artifact_kinds.sql` extends the artifact-kind constraint for `investigation_turn` and `investigation_tool_result`. A runtime that requires version 0011 fails migration verification until an authorized administrator applies it. The migration registers the kinds. It does not validate investigation payloads or change storage limits.

### Expired webhook mappings

Webhook reconciliation and live-inbox capacity count only mappings whose body retention has not expired. Expired mappings remain as content-free deduplication history, but Open Trestle does not load or replay their bodies. A direct lookup or an authenticated redelivery of a retired ID returns an expired-delivery outcome. Storage corruption and I/O failures remain errors. Expiry does not delete the metadata or physically erase the artifact.

## Concurrency

Every mutation of the runtime ledger or metadata starts a transaction and sets `open_trestle.tenant_id` locally. Writes of run plans, the journal and the audit take transaction-scoped advisory locks. Other metadata writers use advisory locks specific to the operation, or row locks and conditional-update checks.

Run and audit appends then do the following in order: read and validate the canonical head, compare the caller's expected head, enforce the next sequence and predecessor, enforce the 10,000-event stream bound, insert once and commit. Serializable transactions protect plan and event writes from concurrent forks. A repeated identical run event is idempotent, with the same semantics as the in-memory journal.

### Retry policy

`Store.SavePlan`, `Store.Append` and `AuditLedger.Append` retry PostgreSQL serialization failures (`40001`) and deadlocks (`40P01`), for at most three transaction attempts in total. Each attempt starts a fresh SERIALIZABLE transaction, sets the tenant again, takes the advisory lock, and rechecks the current scope, plan and head. A transaction whose statement failed is rolled back before the retry. A commit error with either SQLSTATE also permits a fresh attempt. A failed rollback stops the retry.

A competing run head returns the normal head conflict, and an identical run event remains idempotent. `Store.Append` applies the same public-writer guards as the memory and file journals:

- It rejects a `context_input_settled` event with `controlplane.ErrPreparedContextInput`.
- It rejects a public `task_succeeded` for a lease that already recorded a prepared context packet, with `controlplane.ErrPreparedContextPacket`. It checks this against the stored history before the duplicate-head shortcut.

`ArtifactIndex.RegisterArtifact`, `ArtifactIndex.RecordDeletionAuthorization` and `ArtifactIndex.RecordDeletionReceipt` use the same retry policy for metadata writes that touch only the database. Each fresh transaction rechecks the canonical metadata and the applicable deletion authorization and receipt. An identical existing record is idempotent, and conflicting metadata or deletion records are a conflict. The inserted result is reset on each attempt and returned as true only after a successful commit.

`Store.EnqueueTaskNotification`, `Store.ClaimTaskNotification` and `Store.AcknowledgeTaskNotification` use the same retry policy.

- Enqueue rechecks the notice and stays idempotent.
- Claim selects an eligible row again and rebuilds its lease from the fresh notification and delivery count. A retry can therefore select a different notification.
- One delivery token is generated lazily for each public claim and kept only across attempts that are confirmed aborted. Empty selections do not need entropy.
- Candidate results are reset on each attempt and returned only after a successful commit.
- Acknowledgement keeps the caller's lease and checks all lease fences again.
- Entropy failures and RowsAffected errors are terminal, even if they carry a retryable SQLSTATE.

`Store.ClaimPublicationAttempt` and `Store.CompletePublicationAttempt` use the same retry policy for writes to the publication guard that touch only the database. Claim rechecks the operation's attempt, request and status. An identical claimed or completed row returns false, and only an insert known to be committed grants permission to dispatch. Completion rereads the status, the result and the claimed time, keeps an identical completed result and retains the update fences. Claim results and row state are reset on each attempt, and RowsAffected errors are terminal. Failures return the publication guard conflict or unavailable error, not internal database errors.

`DiagnosticStore.PutDiagnosticSet` and `WebhookStore.Put` use the same retry policy only for their SERIALIZABLE metadata phase. Their first READ COMMITTED mapping lookup is separate and is not retried. If that lookup finds no mapping, the public operation creates one artifact value and calls `Artifact.Put` once before it enters the metadata retries. Each metadata attempt rechecks the scope and the mapping state. Webhook insertion also rechecks the live capacity using the current expiry time. Inserted results and captured mappings are reset on each attempt and used only after a successful commit.

A concurrent duplicate captures its original mapping and completes the metadata transaction before it loads the protected artifact. This frees the connection for an artifact index that uses the same pool. Diagnostic duplicates validate the original artifact, not just the set identity. A webhook redelivery compares content and returns the original delivery and receipt, including its original receive time. Changed content is a conflict. Expired webhook mappings return the expired-delivery error without loading retired bodies.

A webhook whose signed content (scope, source, event type, action, body digest) was already accepted under a different delivery ID returns `webhook.ErrDeliveryReplayed`. The initial lookup checks this before any protected body is written. A unique partial index on `replay_key` (migration `0016`) decides concurrent acceptances. Expired rows keep their key, and rows from before the migration have none.

Artifact-store errors are not retried, even if they look like a PostgreSQL error. A failed metadata phase can leave an artifact unmapped, and this policy does not reclaim it.

### Limits of the retry policy

Only these eleven database-only operations and the two metadata phases use the retry policy. Cancellation or expiry of the context stops further attempts.

- Initial context validation for diagnostics and webhooks returns each store's context errors.
- Cancellation after a successful artifact write but before the metadata begins returns the invalid-database error.
- Cancellation after a SQL abort returns the unavailable error.
- Running out of attempts returns the unavailable error.
- Network failures, commits with an ambiguous outcome, other SQLSTATEs and domain conflicts are not retried.
- An unknown metadata commit returns no accepted result.

The retry loop does not run task handlers, publish reviews, perform physical artifact writes or deletions, retry whole `IndexedArtifactStore` operations, or regenerate delivery capabilities.

Erasure resume treats an unknown outcome at the time boundary according to the operation that crossed the deadline, not the version list alone. If an external request was dispatched, an unavailable or malformed response and its linked unknown record must share one durable commit, and no later request is sent under that invocation. When expiry is detected before dispatch, the pending progress is kept and no external attempt is recorded. Later authorized invocations keep the prior usage and unknown history and converge when the external state permits it.

Authority initialization and migrations do not use this retry policy and can still fail on transaction conflicts. Shared rate limiting uses READ COMMITTED and is also outside this policy.

### Reading and error mapping

Head reads use a window count and reject a stream whose row count differs from its final sequence. Page reads require contiguous sequence values. Every JSON value that is returned is parsed through its public canonical decoder and checked against the indexed tenant, repository, run, scope, sequence, plan and event identities. Database errors are mapped to public errors that do not include SQL, connection strings or server messages.

## Distributed task notifications

`Store` implements `controlplane.TaskNotificationQueue`. Enqueue is idempotent. Claim uses a tenant, repository and run predicate plus `FOR UPDATE SKIP LOCKED`. It then issues a random delivery token and stores only the digest. Acknowledgement checks the notification, worker, digest, delivery number, lease time and expiry in one update. Expired deliveries can be claimed again, up to the ten-delivery limit.

Migration `0005_task_notifications.sql` adds an empty-payload PostgreSQL `NOTIFY` trigger to committed run-event and notification inserts. `WaitForTaskNotification` uses a dedicated pgx connection with `LISTEN`. The empty shared signal discloses no tenant, repository, run or content. Missed or duplicate signals are harmless, because the queue row and the replayed run journal decide what runs. The daemon also reconciles every configured repository periodically.

## Publication attempt guard

`Store` also implements `review.PublicationAttemptGuard`. Migration `0006_publication_attempts.sql` records the scope, the operation key, the attempt identity, the request digest, the state and the identity of the terminal result. It stores no review text and no credentials. A serializable claim, locked by operation key, permits one external dispatch across all attempt identities. Repeated identical claims do nothing, and a later attempt for the same operation key conflicts. This guard lets forge adapters avoid a duplicate write across a process stop, even when the remote create endpoint has no idempotency key.

## Tenant isolation

Every tenant-owned primary key starts with `tenant_id`. A scope registry binds each tenant, repository and run tuple to one scope identity, and ledger rows have composite foreign keys to that registry. Each tenant table enables and forces row-level security. The policy compares `tenant_id` with the transaction-local `open_trestle.tenant_id` setting. The adapter also includes the tenant and repository predicate in every query.

The application role must not be a PostgreSQL superuser and must not have `BYPASSRLS`. Use a separate migration role.

`trestled --metadata-store postgres` requires `--postgres-database-authority-identity`. It verifies the migration checksums and the authority of the database, schema, runtime role and namespace in one repeatable-read snapshot with the application role. It applies migrations only when both `--apply-migrations` and the separate `OPEN_TRESTLE_POSTGRES_MIGRATION_URL` are present.

Grant the application role only the table and sequence access that it needs. Do not grant update, truncate or delete on the immutable ledger tables. The opt-in integration test rejects a database role that can see another tenant after it changes its local tenant setting.

## Migrations

`ApplyMigrations` takes a transaction-scoped advisory lock, creates the migration ledger, verifies the SHA-256 checksum of any version that is already applied, and applies the embedded SQL atomically. Changing an applied file produces `ErrMigrationConflict`.

Schema changes need a new numbered migration. Do not edit a migration that an installation already uses.

## Connections

`postgres.Open` uses pgx, limits the pool size, sets `application_name=open-trestle` and confirms connectivity. Remote TCP connections require verified TLS with a server name. Plaintext is accepted only for an IP-literal loopback address or a local Unix socket. Connection strings that contain a newline or NUL are rejected. Connection and query failures do not include the data source in the errors they return.

A deployment should get the data source from its secret provider. Do not place database passwords in repository configuration, run plans, events, traces, exports or support bundles.

## Webhook replay-key upgrades

Pause ingress before you apply `0016_webhook_replay_key.sql`. The migration keeps existing rows, whose replay keys are unknown. A constraint that is not yet validated requires non-NULL keys on every new insert or update. Old binaries therefore cannot keep creating unprotected rows after the migration.

The updated store rejects new-ID admissions for a repository and source while any legacy row there has a NULL replay key, including expired rows. The response is storage-unavailable. The response does not say that the body was replayed. Redelivery under the same ID and its expiry rules are unchanged. Fresh repositories without legacy rows operate normally.

An authorized backfill must do the following for each retained canonical `StoredDelivery`: load and validate it through its protected artifact store, derive `Delivery().ReplayKey()`, and update only that scoped metadata mapping. Do not invent keys from delivery identities, delete the deduplication history or bypass the fence.

If a required protected artifact is unavailable or expired, keep ingress paused and arrange an authorized database recovery. Rotating the webhook secret does not update NULL replay keys and does not lift this fence. Intake stays unavailable until every legacy key is backfilled, or an authorized database recovery establishes replacement history. After every historical row is backfilled, the migration administrator can validate `open_trestle_webhook_deliveries_replay_key_required`. A complete operator backfill command is not provided yet.

## Verification

Unit tests use an SQL mock to exercise persistence, tenant transaction setup, advisory locking, migration checksums, the forced row-level security declarations, corruption detection and error mapping. Live integration tests and pgx simple-protocol injection canary tests are available when an operator supplies an isolated PostgreSQL database:

```sh
OPEN_TRESTLE_TEST_POSTGRES_URL='postgres://...?...' \
  GOWORK=off GOTOOLCHAIN=go1.26.11 go test ./adapters/storage/postgres \
  -run 'Test(PostgresIntegration|PgxSimpleProtocolKeepsPlaceholdersInsideDollarQuotesLiteral)$' -count=1
```

The live database role must not be a superuser and must be suitable for destructive test data. The integration test uses unique run identities and does not remove ledger rows. The pgx canary uses a temporary table and rolls back its transaction.

`TestWebhookReplayUpgradeIntegration` separately uses `OPEN_TRESTLE_TEST_POSTGRES_UPGRADE_URL` with an isolated test database. It creates and removes its own schema, applies versions 1 through 15, inserts two legacy protected deliveries and applies version 16. It then checks the upgrade fence, same-ID redelivery, partial and complete trusted key backfill, fresh intake, replay refusal, and rejection of new NULL keys.

## Publication fence authority

Migration `0008_database_authority.sql` creates one database-native namespace row. Apply storage migrations explicitly with `OPEN_TRESTLE_POSTGRES_MIGRATION_URL` and `trestle admin postgres migrate`. The command creates or keeps the namespace but reports no database or publication authority identity. The runtime role derives its non-secret authority identity through the read-only identity command. Without the migration option, startup of the runtime and of setup does not create or change this row.

Use `OPEN_TRESTLE_POSTGRES_URL` with `trestle admin postgres identity` to reread the migrations and database authority through the runtime role without changing the database. Keep the reported identity outside setup state, then approve it with `trestle setup check postgres`. Neither command derives an identity from the DSN or password.

A PostgreSQL store takes part in external publication only when it is constructed with `NewWithPublicationAuthority` and a database-verified deployment authority. Migration `0007_publication_guard_authority.sql` stores an operator digest beside a database-generated namespace UUID. `VerifyPublicationAuthority` reads the database name, the active schema, the namespace UUID and the operator digest from the connected database. The attempt-guard identity binds the resulting receipt. `New` is enough for journals and metadata, but it exposes no publication guard.

`trestled` requires `--postgres-authority-identity` for required-mode publication. Provision a new database explicitly with `trestle admin postgres initialize` and migration credentials. The administration command returns the receipt that you must keep. Daemon startup does not initialize or change publication authority. Before you accept a restored database, run `trestle admin postgres verify` with a receipt identity that you kept outside the database. See [Operations and recovery](operations.md).

A missing or mismatched row fails startup. A fresh database generates a different namespace UUID even when an operator reuses the same digest, so the publisher and handler identities change. Keep the complete authority row only when your backup, restore and operational policy establish that the restored database holds the same canonical publication-attempt history.

The PostgreSQL administration JSON result is defined by `schemas/runtime/postgres-admin-result-v1.schema.json`.

## Shared API rate limits

Migration `0009_shared_rate_limits.sql` adds the global fixed-window table that the daemon uses when it selects PostgreSQL metadata. Rows contain a namespace, a domain-separated SHA-256 key digest, the limiter configuration identity, database timestamps, a count and an expiry. They contain no bearer token, principal, tenant, repository, network address or request payload. Existing keys serialize with row locks. New-key cardinality uses a transaction-scoped namespace advisory lock. Expired rows are removed before a new key is admitted.

The daemon publishes the composite shared rate-limit authority in its authenticated runtime status. A local metadata daemon publishes `process_local` and no authority. PostgreSQL mode publishes `postgres` and requires the authority. Database errors, live configuration conflicts and exhaustion of namespace cardinality return service unavailable, and the request is not granted. When an established key exhausts its request quota, the response is 429.

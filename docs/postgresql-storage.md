# PostgreSQL canonical ledgers

The PostgreSQL adapter stores Open Trestle's review-run journal and audit ledger in a database, for deployments that need shared, durable state. This page is for operators who run that database and for contributors who work on the adapter.

`adapters/storage/postgres` implements the canonical review-run journal and the content-free audit ledger on PostgreSQL 17-compatible semantics. It stores the existing canonical JSON contracts unchanged. The adapter does not reinterpret events and does not keep a second mutable run-state model. Callers rebuild state through `controlplane.ReplayReviewRun`.

## What the database stores

The database migrations cover these areas:

- review scopes, immutable run plans, run events and audit events;
- diagnostic-to-artifact mappings;
- content-free task notifications;
- publication-attempt guards;
- webhook deliveries, refusals and retries;
- shared rate limits;
- artifact metadata and erasure progress.

Diagnostic text, webhook bodies, source content and artifact payloads are not placed in these tables. The adapter has several stores for the data that points at protected artifacts.

- `DiagnosticStore` keeps one canonical diagnostic set in the configured protected artifact store. PostgreSQL records only its set identity, artifact identity, scope and expiry. Versions 1 through 5 and 8 keep `verified_finding_set` and `independent_verifier` artifact authority. Version 6 uses `deterministic_evidence` and `deterministic_tool` authority with set, snapshot and analysis-result lineage, and is not relabeled as verified. Version 7 is the final full-review result. The host assembles it from independent evidence and stores it as a `run_export` artifact with `host` origin. Its lineage names the set, the snapshot, the review snapshot, and the analysis and verified-set identities that it carries.
- `WebhookStore` does the same for a canonical verified delivery and its acceptance receipt. It binds the protected artifact to the delivery's deterministic review-run scope. It stores only the repository scope, the source, the delivery and artifact identities, the acceptance time and the expiry.
- `ArtifactIndex` records payload-free artifact metadata, short-lived deletion authority (including the legal-hold clearance identity) and completed physical-deletion receipts. It also provides bounded, stable expiry scans that exclude completed deletions.
- `IndexedArtifactStore` combines that index with any artifact store that supports retention, so a failed index write can be retried without repeating a physical effect.

### Migrations 0010 and 0011

Migration `0010_artifact_kinds_and_origins.sql` extends the artifact metadata constraints for source-file payloads, publication receipts and memory-origin results. Earlier migration files and checksums remain unchanged. Apply this additive migration through an explicitly authorized migration administrator before you start the updated indexed runtime. A database that lacks the required migration fails verification.

Additive migration `0011_investigation_artifact_kinds.sql` extends only the artifact-kind constraint, for `investigation_turn` and `investigation_tool_result`. Prior migrations and checksums remain unchanged. A runtime that requires version 0011 fails migration verification until an authorized administrator applies it. Recognizing a kind and registering its metadata do not validate investigation payloads, tool authority, operation-claim deduplication or protected custody. This migration does not change storage limits and does not supply controller persistence admission.

### Expired webhook mappings

Webhook reconciliation and live-inbox capacity count only mappings whose body retention has not expired. Expired mappings remain as content-free deduplication history, but Open Trestle does not load or replay their bodies. A direct lookup or an authenticated redelivery of a retired ID returns an explicit expired-delivery outcome. Ordinary storage corruption and I/O failures remain errors and are not silently skipped. This does not delete historical metadata and does not claim physical artifact erasure.

## Concurrency

Every mutation of the runtime ledger or metadata starts a transaction and sets `open_trestle.tenant_id` locally. Writes of run plans, the journal and the audit take transaction-scoped advisory locks. Other metadata writers use advisory locks specific to the operation, or row locks and conditional-update checks.

Run and audit appends then do the following in order: read and validate the canonical head, compare the caller's expected head, enforce the next sequence and predecessor, enforce the 10,000-event stream bound, insert once and commit. Serializable transactions protect plan and event writes from concurrent forks. A repeated exact run event is idempotent, with the same semantics as the in-memory journal.

### Retry policy

`Store.SavePlan`, `Store.Append` and `AuditLedger.Append` retry PostgreSQL serialization failures (`40001`) and deadlocks (`40P01`), for at most three transaction attempts in total. Each attempt starts a fresh SERIALIZABLE transaction, sets the tenant again, takes the advisory lock, and rechecks the current scope, plan and head. A transaction whose statement failed is rolled back before the retry. A commit error with either SQLSTATE also permits a fresh attempt. A failed rollback stops the retry. The canonical inputs and insert arguments do not change between attempts.

A competing run head returns the normal head conflict, and an identical run event remains idempotent. `Store.Append` applies the same public-writer guards as the memory and file journals:

- It refuses a `context_input_settled` event with `controlplane.ErrPreparedContextInput`.
- It refuses a public `task_succeeded` for a lease that already recorded a prepared context packet, with `controlplane.ErrPreparedContextPacket`. It checks this against the stored history before the duplicate-head shortcut.

`ArtifactIndex.RegisterArtifact`, `ArtifactIndex.RecordDeletionAuthorization` and `ArtifactIndex.RecordDeletionReceipt` use the same retry policy for metadata writes that touch only the database. Each fresh transaction rechecks the canonical metadata and the applicable deletion authorization and receipt. An identical existing record remains idempotent, and conflicting metadata or deletion evidence remains a conflict. The inserted result is reset on each attempt and returned as true only after a successful commit.

`Store.EnqueueTaskNotification`, `Store.ClaimTaskNotification` and `Store.AcknowledgeTaskNotification` use the same retry policy.

- Enqueue rechecks the immutable canonical notice and stays idempotent.
- Claim selects an eligible row again and rebuilds its lease from the fresh notification and delivery count. A retry can therefore select a different notification.
- One delivery token is generated lazily for each public claim and kept only across attempts that are confirmed aborted. Empty selections do not need entropy.
- Candidate results are reset on each attempt and returned only after a successful commit.
- Acknowledgement keeps the exact caller lease and checks all lease fences again.
- Entropy failures and RowsAffected errors are terminal, even if they carry a retryable SQLSTATE.

`Store.ClaimPublicationAttempt` and `Store.CompletePublicationAttempt` use the same retry policy for writes to the publication guard that touch only the database. Claim rechecks the operation's attempt, request and status. An identical claimed or completed row returns false, and only an insert known to be committed grants permission to dispatch. Completion rereads the status, the result and the claimed time, keeps an identical completed result and retains the exact update fences. Claim results and row state are reset on each attempt, and RowsAffected errors are terminal. The guard keeps its database-bound identity and its exact-operation-key guarantee. Failures return the existing publication guard conflict or unavailable error, not internal database errors.

`DiagnosticStore.PutDiagnosticSet` and `WebhookStore.Put` use the same retry policy only for their SERIALIZABLE metadata phase. Their first READ COMMITTED mapping lookup is separate and is not retried. If that lookup finds no mapping, the public operation creates one immutable artifact value and calls `Artifact.Put` once before it enters the metadata retries. Each metadata attempt rechecks the scope and the mapping state. Webhook insertion also rechecks the live capacity using the current expiry time. The artifact identity, the canonical bytes, the creation and acceptance times and the retention do not change between attempts. Inserted results and captured mappings are reset on each attempt and used only after a successful commit.

A concurrent duplicate captures its original mapping and completes the metadata transaction before it loads the protected artifact. This frees the connection for an artifact index that uses the same pool. Diagnostic duplicates validate the original artifact, not just the set identity. A webhook redelivery compares content and returns the original immutable delivery and receipt, including its original receive time. Changed content is a conflict. Expired webhook mappings return the expired-delivery error without loading retired bodies.

A webhook whose signed content (scope, source, event type, action, body digest) was already accepted under a different delivery ID returns `webhook.ErrDeliveryReplayed`. The initial lookup checks this before any protected body is written. A unique partial index on `replay_key` (migration `0016`) decides concurrent acceptances. Expired rows keep their key, and rows from before the migration have none.

Artifact-store errors are not changed and not retried, even if they look like a PostgreSQL error. A failed metadata phase can leave a speculative artifact unmapped. This policy does not reclaim such artifacts, and it does not prove how many physical I/O operations an artifact backend performs internally.

### Limits of the retry policy

Only these eleven database-only operations and the two metadata phases use the retry policy. Cancellation or expiry of the context prevents another attempt.

- Initial context validation for diagnostics and webhooks keeps each store's context errors.
- Cancellation after a successful artifact write but before the metadata begins keeps the invalid-database error.
- Cancellation after a SQL abort keeps the unavailable error.
- Running out of attempts returns the existing unavailable error.
- Network failures, commits with an ambiguous outcome, other SQLSTATEs and domain conflicts are not retried.
- Driver causes and server details from database operations are not exposed.
- An unknown metadata commit returns no accepted result.

The retry loop does not run task handlers, publish reviews, perform physical artifact writes or deletions, retry whole `IndexedArtifactStore` operations, or regenerate delivery capabilities between attempts.

Erasure resume treats an unknown outcome at the time boundary according to the operation that actually crossed the deadline. It is not treated as a condition of the version list alone. If an external request was dispatched, an unavailable or malformed response and its exact linked unknown evidence must share one known durable commit. No later request may be sent under that invocation. When expiry is detected before dispatch, the pending progress is kept and no external attempt is invented. Later invocations that are explicitly authorized must keep the prior usage and unknown history, and must converge when the external state permits it.

Authority initialization and migrations do not use this retry policy and can still fail on transaction conflicts. Shared rate limiting uses READ COMMITTED and is also outside this policy. This bounded database recovery does not establish availability of workers across replicas, complete erasure or exactly-once external effects.

### Reading and error mapping

Head reads use a window count and reject a stream whose row count differs from its final sequence. Page reads require contiguous sequence values. Every JSON value that is returned is parsed through its public canonical decoder and checked against the indexed tenant, repository, run, scope, sequence, plan and event identities. Database errors are mapped to bounded public errors, so SQL, connection strings and server messages are never exposed.

## Distributed task notifications

`Store` implements `controlplane.TaskNotificationQueue`. Enqueue is immutable and idempotent. Claim uses an exact tenant, repository and run predicate plus `FOR UPDATE SKIP LOCKED`. It then issues a random delivery token and stores only the digest. Acknowledgement checks the notification, worker, digest, delivery number, lease time and expiry in one update. Expired deliveries can be claimed again, up to the fixed ten-delivery bound.

Migration `0005_task_notifications.sql` adds an empty-payload PostgreSQL `NOTIFY` trigger to committed run-event and notification inserts. `WaitForTaskNotification` uses a dedicated pgx connection with `LISTEN`. The empty shared signal discloses no tenant, repository, run or content. Missed or duplicate signals are harmless, because the queue row and the replayed run journal are authoritative. The daemon also runs bounded periodic reconciliation for every configured repository.

## Publication attempt guard

`Store` also implements `review.PublicationAttemptGuard`. Migration `0006_publication_attempts.sql` records the exact scope, the operation key, the attempt identity, the request digest, the state and the identity of the terminal result. It stores no review text and no credentials. A serializable claim, locked by operation key, permits one external dispatch across all attempt identities. Repeated exact claims do nothing, and a later attempt for the same operation key conflicts. This guard lets forge adapters fail closed across a process stop, even when the remote create endpoint has no native idempotency key.

## Tenant isolation

Every tenant-owned primary key starts with `tenant_id`. A scope registry binds each tenant, repository and run tuple to one scope identity, and ledger rows have composite foreign keys to that registry. Each tenant table enables and forces row-level security. The policy compares `tenant_id` with the transaction-local `open_trestle.tenant_id` setting. The adapter still includes the tenant and repository predicate in every query. Row-level security is a second boundary, not a replacement for scoped queries.

The application role must not be a PostgreSQL superuser and must not have `BYPASSRLS`. Use a separate migration role.

`trestled --metadata-store postgres` requires `--postgres-database-authority-identity`. It verifies the migration checksums and the authority of the database, schema, runtime role and namespace in one repeatable-read snapshot with the application role. It applies migrations only when both `--apply-migrations` and the separate `OPEN_TRESTLE_POSTGRES_MIGRATION_URL` are present.

Grant the application role only the table and sequence access that it needs. Do not grant update, truncate or delete on the immutable ledger tables. The opt-in integration test rejects a database role that can see another tenant after it changes its local tenant setting.

## Migrations

`ApplyMigrations` takes a fixed, transaction-scoped advisory lock, creates the migration ledger, verifies the SHA-256 checksum of any version that is already applied, and applies the embedded SQL atomically. A migration version is immutable. Changing an applied file produces `ErrMigrationConflict` rather than silently rewriting history.

Schema changes need a new numbered migration. Do not edit a migration that an installation already uses.

## Connections

`postgres.Open` uses pgx, bounds the pool, sets `application_name=open-trestle` and confirms connectivity. Remote TCP connections require verified TLS with a server name. Plaintext is accepted only for an IP-literal loopback address or a local Unix socket. Connection strings that contain a newline or NUL are rejected. Connection and query failures do not include the data source in the errors they return.

A deployment should get the data source from its secret provider. Never place database passwords in repository configuration, run plans, events, traces, exports or support bundles.

## Webhook replay-key upgrades

Pause ingress before you apply `0016_webhook_replay_key.sql`. The migration keeps existing rows, whose replay keys are unknown. A constraint that is not yet validated requires non-NULL keys on every new insert or update. Old binaries therefore cannot keep creating unprotected rows after the migration.

The updated store refuses new-ID admissions for a repository and source while any legacy row there has a NULL replay key, including expired rows. The response is storage-unavailable. It does not assert that a new body was definitely replayed. Redelivery under the same ID and its existing expiry rules remain unchanged. Fresh repositories without legacy rows operate normally.

An authorized backfill must do the following for each retained canonical `StoredDelivery`: load and validate it through its protected artifact store, derive `Delivery().ReplayKey()`, and update only that exact scoped metadata mapping. Do not invent keys from delivery identities, delete the immutable deduplication history or bypass the fence.

If a required protected artifact is unavailable or expired, keep ingress paused and arrange a database recovery that is explicitly authorized. Rotating the webhook secret may be part of a broader recovery decision, but it does not update NULL replay keys and does not lift this PostgreSQL fence. Intake stays unavailable until every legacy key is safely backfilled, or an explicitly authorized database recovery establishes trusted replacement history. There is no automatic unsafe fallback. After every historical row is backfilled, the migration administrator can validate `open_trestle_webhook_deliveries_replay_key_required`. A complete operator backfill command is not provided yet.

## Verification

Unit tests use a strict SQL mock to exercise canonical persistence, tenant transaction setup, advisory locking, migration checksums, the declarations of forced row-level security, corruption detection and error mapping. Live integration tests and pgx simple-protocol injection canary tests are available when an operator supplies an isolated PostgreSQL database:

```sh
OPEN_TRESTLE_TEST_POSTGRES_URL='postgres://...?...' \
  GOWORK=off GOTOOLCHAIN=go1.26.11 go test ./adapters/storage/postgres \
  -run 'Test(PostgresIntegration|PgxSimpleProtocolKeepsPlaceholdersInsideDollarQuotesLiteral)$' -count=1
```

The live database role must not be a superuser and must be suitable for destructive test data. The integration test uses unique run identities but does not remove immutable ledger rows. The pgx canary uses a temporary table and rolls back its transaction.

`TestWebhookReplayUpgradeIntegration` separately uses `OPEN_TRESTLE_TEST_POSTGRES_UPGRADE_URL` with an isolated test database. It creates and removes its own schema, applies versions 1 through 15, inserts two legacy protected deliveries and applies version 16. It then checks the upgrade fence, same-ID redelivery, partial and complete trusted key backfill, fresh intake, replay refusal, and rejection of new NULL keys. It does not backfill an operator's database.

## Publication fence authority

Migration `0008_database_authority.sql` creates one database-native namespace row, independently of publication authority. Apply storage migrations explicitly with `OPEN_TRESTLE_POSTGRES_MIGRATION_URL` and `trestle admin postgres migrate`. The command creates or keeps the namespace but reports no database or publication authority identity. The runtime role derives its separate, non-secret authority identity through the read-only identity command. Without the explicit migration option, startup of the runtime and of setup never creates or changes this row.

Use `OPEN_TRESTLE_POSTGRES_URL` with `trestle admin postgres identity` to reread the exact migrations and database authority through the runtime role without changing the database. Keep the reported identity outside setup state, then approve it with `trestle setup check postgres`. Neither command prints an identity or derives one from the DSN or password.

A PostgreSQL store takes part in external publication only when it is constructed with `NewWithPublicationAuthority` and a database-verified deployment authority. Migration `0007_publication_guard_authority.sql` stores an operator digest beside a database-generated namespace UUID. `VerifyPublicationAuthority` reads the database name, the active schema, the namespace UUID and the operator digest from the connected database. The attempt-guard identity binds the resulting receipt. `New` is still enough for journals and metadata, but it exposes no publication guard or idempotency guarantee.

`trestled` requires `--postgres-authority-identity` for required-mode publication. Provision a new database explicitly with `trestle admin postgres initialize` and migration credentials. The administration command returns the receipt that you must keep. Daemon startup never initializes publication authority, and normal startup never creates or changes this row. Before you accept a restored database, run `trestle admin postgres verify` with a receipt identity that you kept outside the database. See [Operations and recovery](operations.md).

A missing or mismatched row fails startup. A fresh database generates a different namespace UUID even when an operator reuses the same digest, so the publisher and handler identities change. Keep the complete authority row only when your backup, restore and operational policy establish that the restored database holds the same canonical publication-attempt history.

The PostgreSQL administration JSON result is defined by `schemas/runtime/postgres-admin-result-v1.schema.json`.

## Shared API rate limits

Migration `0009_shared_rate_limits.sql` adds the global, content-free fixed-window table that the daemon uses when it selects PostgreSQL metadata. Rows contain only a bounded namespace, a domain-separated SHA-256 key digest, the exact limiter configuration identity, database timestamps, a bounded count and an expiry. They contain no bearer token, principal, tenant, repository, network address or request payload. Existing keys serialize with row locks. New-key cardinality uses a transaction-scoped namespace advisory lock. Expired rows are removed before a new key is admitted.

The daemon publishes the composite shared rate-limit authority in its authenticated runtime status. A local metadata daemon publishes `process_local` and no authority. PostgreSQL mode publishes `postgres` and requires the exact authority. Database errors, live configuration conflicts and exhaustion of namespace cardinality fail closed as service unavailable. They never silently grant a request, and they never report a false quota exhaustion for a single key. When an established key exhausts its request quota, the response is 429.

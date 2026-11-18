# Runtime artifact exchange

Runtime artifacts are the records that review-run tasks pass to each other. This page is for contributors. It describes what an artifact contains, how the local store keeps it and how it is deleted.

Each artifact records the following:

- its tenant, repository and run scope;
- a kind and a canonical media type;
- a data classification and a producer origin;
- its declared storage protection;
- ordered provenance identities;
- the payload digest;
- the creation time and the expiry.

The artifact's identity covers all of that metadata. The payload is copied when the artifact is built and verified again when it is decoded.

The public wire contract is `schemas/artifact/runtime-artifact-v1.schema.json`. Encoded payloads are capped at 16 MiB before base64 encoding. Open Trestle rejects unknown fields, noncanonical JSON, duplicate provenance, altered payloads, expired timestamps and identity mismatches. Artifact formatting is redacted.

The artifact kinds include `investigation_turn` and `investigation_tool_result`. These are record labels only. They do not validate a turn or tool-result payload, and the payload codec and the expected identity, scope and origin must be checked separately. The limits are 16 MiB for the payload and 22 MiB for the encoded envelope. The snapshot investigation controller checks that a turn's record fits both limits before paid dispatch, and checks the encoded record again afterward.

## Local store

The daemon opens a private local artifact store under its state root. The store provides:

- partitioning by review scope;
- lookup by content address;
- handling of duplicates;
- advisory writer locking that can be reclaimed after a process dies;
- checks that each object is a regular file and keeps the same inode;
- `0600` permissions on objects and locks;
- atomic rename plus file and directory synchronization;
- limits on object count and object size;
- corruption detection;
- denial of expired artifacts at read time and at write time.

The local file adapter declares `process_private` protection and refuses artifacts marked `envelope_encrypted`.

Artifacts must not contain credentials or raw worker lease capabilities. Secrets stay in the configured secret provider.

## Handler boundary

`ValidatedTaskHandler` wraps an approved task handler. Before it invokes the handler, the wrapper resolves the input. For a root task, that is the task's input artifact. For a downstream task, it is every available output from the declared dependencies. The wrapper checks the run scope, the retention and the allowed input kinds.

A successful result is accepted only when its output resolves to an allowed kind in the same scope, and its provenance contains the identity of every resolved input artifact. A terminal optional dependency has no output artifact. A missing, corrupt, expired or cross-wired artifact fails before the task completion is recorded.

Workers can restart, and downstream tasks can revalidate every input from its content-addressed provenance.

## Retention deletion

Physical deletion requires a short-lived, content-addressed authorization. The authorization is bound to the scope, the artifact, the retention policy, the principal, the reason and a legal-hold clearance receipt. Deleting an artifact because it expired is rejected before the artifact's expiry time. Tenant erasure and repository erasure use separate reasons. The clearance identity records the policy decision, and the store does not infer clearance from missing data.

The file store writes and synchronizes a payload-free deletion intent before it removes the artifact bytes. It then synchronizes the directory and converts the intent into a completed tombstone. Startup recovery finishes any prepared intent and verifies the payload digest before removal.

While a prepared intent exists, reads treat the artifact as deleted, even if an interrupted deletion left its bytes in place. A completed tombstone prevents reintroduction under the same artifact identity, and it makes an identical deletion retry idempotent.

The public contracts are `schemas/artifact/artifact-deletion-authorization-v1.schema.json` and `schemas/artifact/artifact-deletion-receipt-v1.schema.json`. Tombstones contain no payload. They remain as deduplication and compliance records, and they need their own ledger compaction policy later.

The local adapter accepts only `process_private`. `artifact.EnvelopeStore` provides envelope-encrypted remote storage through the conditional object backend contract. The included path-style S3 adapter requires versioned objects and single-part requests. A deployment must supply a tenant-aware envelope key provider. See [Envelope-encrypted object storage](remote-artifact-storage.md). Remote artifact upload is not exposed as a general client API.

## Canonical metadata index

The PostgreSQL `ArtifactIndex` stores no artifact payload. It keeps the scope, the artifact and payload identities, metadata labels, the retention time, the lineage of the deletion authorization and the physical deletion receipts.

`IndexedArtifactStore` writes the physical data before it registers the metadata, and records the deletion authority before the physical removal. Each step is idempotent. A crash can therefore leave an expiring orphan or an unindexed completed deletion, but a retry converges without bringing data back or repeating an external effect. Expiry scans return only artifacts without a completed deletion receipt. Policy and legal-hold evaluation are separate prerequisites before an authorization can be created.

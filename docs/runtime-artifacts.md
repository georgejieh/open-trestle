# Runtime artifact exchange

Review-run tasks exchange immutable artifacts rather than conversational summaries or process-local pointers. Each artifact binds its exact tenant, repository, and run scope; closed kind; canonical media type; data classification; producer origin; declared storage protection; ordered provenance identities; payload digest; creation time; and expiry. Its identity covers all of that metadata. The payload is copied on construction and verified again when decoded.

The public wire contract is `schemas/artifact/runtime-artifact-v1.schema.json`. Encoded payloads are capped at 16 MiB before base64 encoding. Unknown fields, noncanonical JSON, duplicate provenance, altered payloads, expired timestamps, and identity mismatches fail closed. Artifact formatting is redacted.

The closed artifact kinds include `investigation_turn` and `investigation_tool_result`. These are inert record labels, not validation of a turn or tool-result payload, proof of issuer or protected origin, or permission to run a tool. Payload codecs and trusted expected identities, scope and origin must be checked separately. The existing 16 MiB payload and 22 MiB encoded envelope limits remain unchanged. A future investigation controller must admit persistable record sizes before paid dispatch and check the actual framing afterward.

## Local store

The daemon opens a private local artifact store under its state root. It provides:

- exact review-scope partitioning;
- content-addressed lookup;
- immutable duplicate handling;
- exclusive advisory writer locking that is reclaimable after process death;
- regular-file and same-inode checks;
- `0600` object and lock permissions;
- atomic rename plus file and directory synchronization;
- bounded object count and object size;
- corruption detection; and
- expiry denial at read and write time.

The local file adapter declares only `process_private` protection and refuses artifacts marked `envelope_encrypted`. A future S3-compatible adapter must perform and attest tenant envelope encryption before accepting that protection value. Classification is policy input, not proof that encryption occurred.

Artifacts must never contain credentials or raw worker lease capabilities. Secrets remain in the configured secret provider. Source, model output, and external material remain untrusted even when their transport digest is valid.

## Handler boundary

`ValidatedTaskHandler` wraps an exact approved task handler. Before invoking it, the wrapper resolves a root task's immutable input artifact or every available output from the downstream task's declared dependencies. It checks exact run scope, retention, and allowed input kinds. A successful result is accepted only when its output resolves to an allowed kind in the same scope and its provenance contains every resolved input artifact identity. Terminal optional dependencies are represented explicitly and do not invent an output artifact. Missing, corrupt, expired, or cross-wired artifacts fail before task completion is recorded.

This turns the run journal into a restartable control plane while the artifact store carries bounded data-plane objects. Workers can restart without relying on chat history, and downstream tasks can revalidate every input from content-addressed provenance.

## Retention deletion

Physical deletion requires a short-lived content-addressed authorization bound to the exact scope, artifact, retention policy, principal, reason, and a legal-hold clearance receipt. Expiry deletion is rejected before the artifact expiry time. Tenant and repository erasure use separate closed reasons. The clearance identity provides immutable lineage to the policy decision; the store never infers clearance from missing data.

The file store writes and synchronizes a payload-free deletion intent before removing artifact bytes. It then synchronizes the directory and converts the intent to a completed tombstone. Startup recovery finishes any prepared intent and verifies the payload digest before removal. This closes the crash window between physical deletion and durable receipt creation. A completed tombstone prevents reintroduction under the same artifact identity and makes an identical deletion retry idempotent.

Public contracts are `schemas/artifact/artifact-deletion-authorization-v1.schema.json` and `schemas/artifact/artifact-deletion-receipt-v1.schema.json`. Tombstones contain no payload. They remain bounded deduplication and compliance evidence and require their own later ledger compaction policy.

The local adapter still accepts only `process_private`. `artifact.EnvelopeStore` provides envelope-encrypted remote storage through the conditional object backend contract. The included path-style S3 adapter requires versioned objects and bounded single-part requests. A deployment must supply an approved tenant-aware envelope key provider. See [Envelope-encrypted object storage](remote-artifact-storage.md). Remote artifact upload is not exposed as a general client API.

## Canonical metadata index

The PostgreSQL `ArtifactIndex` stores no artifact payload. It retains exact scope, artifact and payload identities, closed metadata labels, retention time, deletion authorization lineage, and physical deletion receipts. `IndexedArtifactStore` writes physical data before registering metadata and records deletion authority before physical removal. Each step is idempotent, so a crash can leave an expiring orphan or an unindexed completed deletion, but a retry converges without reintroducing data or repeating an external effect. Bounded expiry scans return only artifacts without a completed deletion receipt; policy and legal-hold evaluation remain separate prerequisites before an authorization can be created.

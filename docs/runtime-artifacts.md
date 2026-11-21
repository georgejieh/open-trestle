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

The local adapter accepts only `process_private`. Remote artifact upload is not exposed as a general client API.

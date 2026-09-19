# Envelope-encrypted object storage

Open Trestle can place runtime artifacts behind `artifact.EnvelopeStore`. The store encrypts the complete canonical artifact before it reaches an object backend. `adapters/storage/s3` implements the backend contract for path-style, S3-compatible endpoints.

A deployment must supply an `artifact.EnvelopeKeyProvider` backed by an approved KMS or secret service. `adapters/keys/awskms` implements that boundary with the official AWS SDK. `trestled --artifact-store s3 --metadata-store postgres` exposes the combined KMS, S3, and PostgreSQL profile for one configured tenant. The daemon takes separate `--s3-region` and `--kms-region` values and reads separately named S3 and KMS credential environments so one credential is not silently reused across both services. Production operators must choose workload identity, independently scope S3 and KMS credentials, and retain HA operational evidence outside the artifact payload path.

## Encryption boundary

Each object uses a fresh 256-bit data key and a 96-bit random nonce with AES-256-GCM. The tenant key provider wraps the data key and returns an opaque key reference. Authenticated additional data binds the format version, review-scope identity, artifact identity, key reference, and wrapped-key digest. The encrypted body also carries a SHA-256 digest. Reads verify the object checksum, canonical envelope, authenticated metadata, decrypted canonical artifact, exact scope, artifact identity, protection claim, and payload digest.

The object key contains only the configured prefix, hashed review-scope identity, and artifact identity. Tenant and repository names are inside the encrypted artifact. Data keys are requested and unwrapped with the exact tenant identifier and are cleared from the store's local working copy after use. Key providers must enforce that tenant binding and must never return a plaintext key as its wrapped representation.

## AWS KMS tenant keys

The AWS KMS provider uses an immutable registry with one exact symmetric key ARN per tenant. Aliases, bare key IDs, duplicate tenants, shared key ARNs, malformed ARNs, and keys outside the configured region are rejected. This prevents a configuration declaration from silently moving a tenant to another key or making two tenants share one wrapping boundary.

`GenerateDataKey` requests `AES_256`. `Decrypt` supplies the exact key ARN and `SYMMETRIC_DEFAULT`. Both operations use the same SHA-256 tenant binding as KMS encryption context; the tenant name itself is not placed in the context or ordinary provider formatting. Returned key ARN, algorithm, plaintext length, and ciphertext bounds are verified. Plaintext returned by the SDK is cleared after it is copied into the bounded envelope-key value. Provider errors are mapped to closed errors without retaining AWS messages or request data.

The caller constructs the AWS KMS client and therefore owns its credential source, endpoint, retry, FIPS, and region configuration. Use workload identity or a secret provider rather than static repository configuration. The KMS policy must restrict `kms:GenerateDataKey` and `kms:Decrypt` to the registered key and should require the Open Trestle encryption-context key.

Before treating KMS as setup-ready, derive the exact tenant-region-key identity with `trestle admin kms identity` and run the explicitly confirmed `trestle setup check secret` operation described in [Setup planning](setup.md#secret-backend-authority). That bounded check performs one generate and unwrap sequence and stores only content-free evidence. It makes no S3 request. Separately derive the combined authority with `trestle admin envelope identity` and run `trestle setup check envelope`. That explicit check writes one fixed public artifact through the production envelope path, rejects visible plaintext in the raw object, retrieves and verifies it, deletes only its exact returned S3 version, and verifies absence. Its deterministic residue and recovery limits are documented in [Setup planning](setup.md#envelope-storage-authority).

## Backend contract

The remote backend has three narrow operations:

- atomic create-if-absent with a caller-supplied content digest;
- bounded read with an immutable object-version token;
- delete of that exact version only.

A backend must not emulate these operations with an unconditional overwrite or deletion. The envelope store verifies successful creates by reading and decrypting the stored object. Conflicts, cross-wired objects, checksum changes, invalid encryption metadata, and scope changes fail closed.

The S3 adapter:

- requires HTTPS except for an IP-literal loopback endpoint;
- rejects redirects;
- signs every request with AWS Signature Version 4;
- retrieves credentials for every request so a provider can rotate them without restart;
- uses `If-None-Match: *` for immutable creates;
- sends and verifies SHA-256 checksum metadata;
- requires a non-null `x-amz-version-id` on reads;
- deletes only with that exact `versionId`; and
- limits every object operation to 32 MiB.

Runtime artifacts encode to at most 22 MiB, so the adapter deliberately uses one bounded `PutObject` request. It does not start multipart uploads and cannot leave abandoned multipart parts. Larger export formats require a separate contract with explicit part count, part size, abort, checksum, and recovery bounds.

## Retention deletion

Remote deletion uses immutable intent and completion objects. The store first creates and verifies a payload-free intent, then decrypts and verifies the exact artifact version, deletes that version, and creates and verifies a completion receipt. An interrupted operation can resume with `RecoverDeletion` after the caller obtains the known scope and artifact identity from its canonical metadata ledger. Reads and writes reject an identity as soon as an intent exists, so a crash cannot make prepared data live again.

Application legal-hold clearance remains bound into the deletion authorization. An S3 Object Lock or bucket retention rule is an additional infrastructure control; a refusal from that layer leaves the intent recoverable and does not create a false completion receipt. Intent and completion objects must not be removed by a broad artifact lifecycle rule. Their later compaction needs a separate compliance policy and durable audit binding.

## Operator requirements

Use a versioned bucket and a credential limited to the configured bucket prefix. Deny public access, insecure transport, unversioned deletion, and unrelated bucket actions. Keep raw S3 and KMS credentials outside run journals, artifacts, traces, exports, and support bundles. Configure bucket replication, lifecycle, backup, and disaster-recovery behavior to preserve tenant deletion and legal-hold policy. Verify the target S3-compatible implementation with the backend conformance tests before use.

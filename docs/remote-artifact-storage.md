# Envelope-encrypted object storage

Envelope encryption is a scheme in which each object is encrypted with its own data key, and a separate key service protects that data key. Open Trestle can keep runtime artifacts in S3-compatible storage this way. This page is for operators who set up that storage and for contributors who work on it.

Open Trestle places runtime artifacts behind `artifact.EnvelopeStore`. The store encrypts the complete canonical artifact before it reaches an object backend. `adapters/storage/s3` implements the backend contract for path-style, S3-compatible endpoints.

A deployment must supply an `artifact.EnvelopeKeyProvider` backed by an approved KMS or secret service. `adapters/keys/awskms` implements that boundary with the official AWS SDK. `trestled --artifact-store s3 --metadata-store postgres` exposes the combined KMS, S3 and PostgreSQL profile for one configured tenant. The daemon takes separate `--s3-region` and `--kms-region` values. It reads separately named S3 and KMS credential environments, so one credential is not silently reused across both services. Production operators must choose workload identity, scope the S3 and KMS credentials independently, and keep HA operational evidence outside the artifact payload path.

## Encryption boundary

Each object uses a fresh 256-bit data key and a 96-bit random nonce with AES-256-GCM. The tenant key provider wraps the data key and returns an opaque key reference. The authenticated additional data binds the format version, the review-scope identity, the artifact identity, the key reference and the digest of the wrapped key. The encrypted body also carries a SHA-256 digest.

A read verifies all of the following: the object checksum, the canonical envelope, the authenticated metadata, the decrypted canonical artifact, the exact scope, the artifact identity, the protection claim and the payload digest.

The object key contains only the configured prefix, the hashed review-scope identity and the artifact identity. Tenant and repository names are inside the encrypted artifact. Data keys are requested and unwrapped with the exact tenant identifier, and the store clears them from its local working copy after use. Key providers must enforce that tenant binding, and must never return a plaintext key as its wrapped form.

## AWS KMS tenant keys

The AWS KMS provider uses an immutable registry with one exact symmetric key ARN per tenant. It rejects aliases, bare key IDs, duplicate tenants, shared key ARNs, malformed ARNs and keys outside the configured region. This prevents a configuration declaration from silently moving a tenant to another key, or from making two tenants share one wrapping boundary.

`GenerateDataKey` requests `AES_256`. `Decrypt` supplies the exact key ARN and `SYMMETRIC_DEFAULT`. Both operations use the same SHA-256 tenant binding as the KMS encryption context. The tenant name itself is not placed in the context or in ordinary provider formatting. Open Trestle verifies the returned key ARN, algorithm, plaintext length and ciphertext bounds. It clears the plaintext that the SDK returns after copying it into the bounded envelope-key value. Provider errors are mapped to closed errors, without keeping AWS messages or request data.

The caller constructs the AWS KMS client, so the caller owns its credential source, endpoint, retry, FIPS and region configuration. Use workload identity or a secret provider rather than static repository configuration. The KMS policy must limit `kms:GenerateDataKey` and `kms:Decrypt` to the registered key, and should require the Open Trestle encryption-context key.

Before you treat KMS as ready in setup, do the following:

1. Derive the exact tenant-region-key identity with `trestle admin kms identity`.
2. Run the explicitly confirmed `trestle setup check secret` operation described in [Setup planning](setup.md#secret-backend-authority). This bounded check performs one generate and unwrap sequence and stores only content-free evidence. It makes no S3 request.
3. Derive the combined authority with `trestle admin envelope identity`.
4. Run `trestle setup check envelope`. This explicit check writes one fixed public artifact through the production envelope path and rejects visible plaintext in the raw object. It then retrieves and verifies the artifact, deletes only the exact S3 version that was returned, and verifies that the artifact is gone.

The deterministic residue and recovery limits of the last check are documented in [Setup planning](setup.md#envelope-storage-authority).

## Backend contract

The remote backend has three narrow operations:

- atomic create-if-absent with a caller-supplied content digest;
- bounded read with an immutable object-version token;
- delete of that exact version only.

A backend must not emulate these operations with an unconditional overwrite or deletion. The envelope store verifies each successful create by reading and decrypting the stored object. Conflicts, cross-wired objects, checksum changes, invalid encryption metadata and scope changes fail closed.

The S3 adapter does the following:

- requires HTTPS, except for an IP-literal loopback endpoint;
- rejects redirects;
- signs every request with AWS Signature Version 4;
- retrieves credentials for every request, so a provider can rotate them without a restart;
- uses `If-None-Match: *` for immutable creates;
- sends and verifies SHA-256 checksum metadata;
- requires a non-null `x-amz-version-id` on reads;
- deletes only with that exact `versionId`;
- limits every object operation to 32 MiB.

Runtime artifacts encode to at most 22 MiB, so the adapter deliberately uses one bounded `PutObject` request. It does not start multipart uploads, and so it cannot leave abandoned multipart parts. Larger export formats need a separate contract with explicit bounds on part count and part size, and rules for abort, checksum and recovery.

## Retention deletion

Remote deletion uses immutable intent and completion objects. The store takes these steps:

1. It creates and verifies a payload-free intent.
2. It decrypts and verifies the exact artifact version.
3. It deletes that version.
4. It creates and verifies a completion receipt.

An interrupted operation can resume with `RecoverDeletion`, after the caller gets the known scope and artifact identity from its canonical metadata ledger. Reads and writes reject an identity as soon as an intent exists, so a crash cannot make prepared data live again.

The application's legal-hold clearance stays bound into the deletion authorization. An S3 Object Lock or bucket retention rule is an additional infrastructure control. If that layer refuses a deletion, the intent stays recoverable and no false completion receipt is created. A broad artifact lifecycle rule must not remove intent and completion objects. Compacting them later needs a separate compliance policy and a durable audit binding.

## Operator requirements

Use a versioned bucket and a credential limited to the configured bucket prefix. Deny public access, insecure transport, unversioned deletion and unrelated bucket actions. Keep raw S3 and KMS credentials out of run journals, artifacts, traces, exports and support bundles. Configure bucket replication, lifecycle, backup and disaster-recovery behavior so that they keep the tenant deletion and legal-hold policy. Verify the target S3-compatible implementation with the backend conformance tests before you use it.

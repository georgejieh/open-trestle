# Refresh model availability metadata

Model catalog refresh is a manual staging command. It lists availability metadata,
not approved inference routes. It does not activate models, change selectors,
load or download weights, make inference requests, approve routes or privacy
claims, or rewrite old run identities. Runtime configuration and route inventory
remain separate authorities. Loopback alone does not prove local inference:
a local runtime can expose cloud-backed model aliases.

## Source manifest

Create a protected JSON manifest in an owned directory. Source IDs are stable
operator-selected identities, not provider display names. Changing the kind or
URL of an existing source ID is refused while it exists in the current catalog.
To change connection identity, choose a new source ID and review the old source's
removal. Removing a source from the manifest explicitly proposes removing its
entries.

```json
{
  "schema_version": 1,
  "sources": [
    {
      "id": "workstation-runtime",
      "kind": "ollama_tags",
      "url": "http://127.0.0.1:11434/api/tags"
    }
  ]
}
```

Supported kinds:

- `openai_models`: an explicit URL ending in `/models`, such as `/v1/models`.
  Reads `data[].id` without changing case, separators, or tags.
- `ollama_tags`: an explicit `/api/tags` URL. Reads `models[].name` exactly.

The rest of each model object is preserved as metadata. `digest`, capabilities,
costs, and other returned fields are observations, not verified commitments,
privacy evidence, readiness, entitlement, or approval. A moving alias remains a
moving alias; refresh does not resolve it to immutable weights or rebind any
approved route. Stable identity is `(source_id, exact selector)`.

Schema version 1 remains unauthenticated: it never reads a credential or sends
an auth header. For a metadata endpoint that requires bearer authentication,
use schema version 2 with an explicit environment reference:

```json
{
  "schema_version": 2,
  "sources": [
    {
      "id": "authenticated-metadata",
      "kind": "openai_models",
      "url": "https://openrouter.ai/api/v1/models",
      "credential_environment": "OPEN_TRESTLE_PROVIDER_CATALOG"
    }
  ]
}
```

Provision that variable through your secure credential interface before refresh.
The manifest stores its name, never its value. Only `OPEN_TRESTLE_PROVIDER_`
references using uppercase letters, digits and underscores are accepted. Literal
keys, empty references, nulls and alternate field spellings are refused. Changing
a source's credential reference requires a new source ID, like changing its URL.
A version 2 source without the field remains unauthenticated. No login cache is read.

Refresh validates the complete manifest and remote opt-in before resolving any
credential. It retrieves a referenced key only for that source's bounded GET.
A missing or header-unsafe key records `metadata_unavailable` without making an
unauthenticated request. Redirects do not forward credentials. Apply reads no
credentials and makes no requests. Proposals and catalogs retain only the reference.
A version 2 manifest produces a version 2 catalog; the proposal envelope remains
version 1. Existing version 1 catalogs and proposals keep their wire format.

URLs must not contain credentials, query strings, or fragments. The endpoint is
explicit operator authority, not a URL discovered in model metadata. Choose a
reference dedicated to that endpoint. An authenticated numeric-loopback HTTP source
sends the bearer in plaintext to whichever process listens on that port; verify
that listener before refresh. A manifest cannot reuse one reference across distinct
origins. Authenticated discovery does not prove
retention, model eligibility, account privacy or permission to run inference.
OpenRouter documents bearer authentication for its model catalog; check each
service's current discovery contract before choosing a URL. This command does
not turn an inference endpoint into a discovery API.

Numeric loopback HTTP/HTTPS endpoints are accepted without remote permission.
Hostnames such as `localhost` are not local authority. Other endpoints require
HTTPS and the explicit `--allow-remote` flag. Proxy environment variables are
ignored. Remote DNS answers must all be public, and dialing uses one checked
numeric address. Private, loopback, and link-local remote addresses are refused.
Redirects are never followed. Refresh sends GET only to the supplied metadata
URLs, and does not discover other URLs in response metadata.

## Review and apply

Protect the manifest and its directory before running either command. Files and
all ancestors must pass the same ownership, symlink, and write-authority checks
as protected runtime configuration. Paths must be distinct, including writer
lock paths. Catalogs and proposals are written mode `0600`; locks are cooperative
exclusive locks held only during the write. Do not remove lock files while any
writer might be active.

```sh
trestle config models refresh \
  --sources /private/model-sources.json \
  --current /private/model-catalog.json \
  --proposal /private/model-proposal-1.json
```

The proposal path must be new. Refresh never overwrites a proposal or writes the
current catalog. JSON stdout gives `proposal_digest`, `current_digest`, an
`added`/`removed`/`changed` diff, and source failures. Changes include before/after
metadata with the same exact selector. Inspect stdout and the protected proposal
file. For explicit public HTTPS sources, add `--allow-remote` to refresh.

Apply requires the exact two digests from that review:

```sh
trestle config models apply \
  --sources /private/model-sources.json \
  --current /private/model-catalog.json \
  --proposal /private/model-proposal-1.json \
  --expected-proposal REVIEWED_PROPOSAL_SHA256 \
  --expected-current REVIEWED_CURRENT_SHA256_OR_absent
```

The first catalog uses the literal `absent` current digest. Digests cover exact
file bytes, including whitespace. Apply checks proposal bytes, manifest bytes,
source bindings and current bytes, then checks them again before replacement.
It performs no network calls. A stale digest, changed manifest, corrupt input,
untrusted path, or held writer lock refuses application. Generate a fresh proposal
at a new path rather than overwriting the reviewed file.

Each failed source retains its previous successful snapshot and records
`metadata_unavailable`. A failed new source has an empty snapshot and that failure.
Successful sources still contribute changes. Thus even an all-failed refresh can
be reviewed and applied to record failures without erasing last-known-good model
entries. No provider error bodies are copied into failures. Source failure is a
reviewable result (exit 0), not a hidden global success claim. Inspect `failures`.
Malformed inputs or persistence errors return a nonzero exit and no replacement.

Writes use a same-directory temporary file, file sync, atomic replacement, and
parent-directory sync. Initial installation uses a no-clobber hard link of the
complete staged inode; existing catalogs use rename under the exclusive writer
lock. Metadata, parsing, digest, and pre-commit persistence failures leave the
current catalog unchanged. As with any atomic file replacement, a parent sync
failure occurs **after** visibility changed: the command reports `replaced;
directory durability unconfirmed`. Inspect the actual current digest before
retrying. Do not assume a nonzero exit in that case proves rollback. Filesystem
power-loss guarantees depend on the host filesystem.

Limits are 32 sources, 10,000 models per source, 1 MiB per HTTP body, 16 KiB response
headers, 8 MiB per protected file, 5 seconds per source, and a 60-second aggregate
network budget. HTTP is sequential and retries are not performed. Duplicate JSON
keys, duplicate selectors, invalid selectors, malformed documents, and unexpected
shapes fail the affected source. No scheduler, route approval or activation hook
is installed.

The optional wrapper executes this same product command and does not build or
fetch anything itself:

```sh
python3 tools/model_catalog.py --trestle /opt/trestle/bin/trestle refresh \
  --sources /private/model-sources.json --current /private/model-catalog.json \
  --proposal /private/model-proposal-2.json
```

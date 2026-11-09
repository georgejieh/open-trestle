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

The rest of each model object is preserved as metadata, with its members and
their encoding unchanged; the selector is stored once, beside it. `digest`, capabilities,
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

## Named local runtime catalogs

The URLs below use the ports in [the named local runtime recipes](named-local-runtimes.md).
Use them only for your explicitly configured listeners. These mappings were checked
against official documentation on November 1, 2026, not against installed servers.
Check your runtime version and listener before refresh.

| Runtime | Metadata source | Scope and selector |
| --- | --- | --- |
| llama.cpp, direct single-model server | `openai_models`, `http://127.0.0.1:8080/v1/models` for generation and port `8081` for verification | The documented `data[].id` list has one loaded-model entry. `--alias` sets its ID; without an alias, the ID is the model-file path. It is not a disk inventory. |
| Ollama local | `ollama_tags`, `http://127.0.0.1:11434/api/tags` | Read `models[].name` exactly. This available-model list is not the running-model list at `/api/ps`. A selector or loopback address does not prove local weights or local execution. |
| vLLM | `openai_models`, `http://127.0.0.1:8000/v1/models` for generation and port `8001` for verification | At retrieved upstream tree `3a90cc6fd0504b52bf47d58e8d70cff4b03f2c19`, GET `/v1/models` serializes `data[].id`: configured served names (or the model argument), plus registered LoRA names. The recipes use one served name per process. This is static source evidence, not a commit/release pin or installed-server result; verify the selected version and list authentication before refresh. |
| LM Studio on Mac | `/v1/models` is documented; catalog kind not established here | The list contains models visible to the server and may include downloaded models with Just-In-Time loading. Confirm the response envelope and how loaded `--identifier` values appear before choosing a catalog kind. |

These are metadata mappings, not service conformance or route approval. Aliases
are API selectors, not immutable weight identities. The existing manual selector
recipes do not prove that a runtime lacks a discovery API.

Ollama's local API does not require authentication. The llama.cpp recipes do not
set a key; its documented optional key settings do not establish list-endpoint
authentication behavior here. For an explicitly authenticated listener, verify its
list contract and use the schema-2 credential reference above. Never add a dummy
key or read a runtime's login cache.

Official sources:

- [llama.cpp server](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md), direct `GET /v1/models` and `--alias`.
- [Ollama list models](https://docs.ollama.com/api/tags) and [local API authentication](https://docs.ollama.com/api/authentication).
- [vLLM serve options](https://docs.vllm.ai/en/stable/cli/serve), `--served-model-name`.
  Retrieved tree evidence (not a commit/release pin):
  [vLLM list router](https://raw.githubusercontent.com/vllm-project/vllm/3a90cc6fd0504b52bf47d58e8d70cff4b03f2c19/vllm/entrypoints/openai/models/api_router.py),
  [vLLM list handler](https://raw.githubusercontent.com/vllm-project/vllm/3a90cc6fd0504b52bf47d58e8d70cff4b03f2c19/vllm/entrypoints/openai/models/serving.py),
  [vLLM response classes](https://raw.githubusercontent.com/vllm-project/vllm/3a90cc6fd0504b52bf47d58e8d70cff4b03f2c19/vllm/entrypoints/serve/engine/protocol.py), and
  [vLLM served-name initialization](https://raw.githubusercontent.com/vllm-project/vllm/3a90cc6fd0504b52bf47d58e8d70cff4b03f2c19/vllm/entrypoints/launchers/api_server/app_state.py).
- [LM Studio model listing](https://lmstudio.ai/docs/developer/openai-compat/models) and [loaded identifiers](https://lmstudio.ai/docs/cli/local-models/load).

## OpenCode Go and Ollama Cloud metadata examples

These named services publish metadata endpoints compatible with the existing
source kinds. The examples below select metadata sources only. They do not
configure inference or establish route support, account entitlement, privacy
approval or permission to send repository content.

```json
{
  "schema_version": 1,
  "sources": [
    {
      "id": "my-opencode-go-catalog",
      "kind": "openai_models",
      "url": "https://opencode.ai/inference/go/v1/models"
    },
    {
      "id": "my-ollama-cloud-catalog",
      "kind": "ollama_tags",
      "url": "https://ollama.com/api/tags"
    }
  ]
}
```

Save the manifest in an owned protected directory. Use the existing manual
`trestle config models refresh` command with `--allow-remote` and a new proposal
path. Review exact IDs, metadata, source failures and the two digests before
running `trestle config models apply`. Apply does not fetch or activate anything.
Source IDs above are examples; choose stable IDs for your configuration.

Both documented endpoints returned public metadata without a key on October 30,
2026. Schema version 1 never reads credentials. Do not put inference keys into
these URLs or assume every metadata endpoint is permanently unauthenticated.
If the service later documents authenticated discovery, review that contract and
use the existing schema version 2 credential-reference mechanism where supported.
Do not scrape login caches or add literal keys.

OpenCode Go reads `data[].id` exactly, such as `glm-5.3-flash`. Do not prepend
OpenCode's client configuration namespace `opencode-go/` to direct API IDs.
Ollama Cloud reads `models[].name` exactly, such as `gemma4:31b`; do not replace it
with the CLI alias `gemma4:cloud`. These are examples observed in metadata, not
recommended defaults or model approvals. Model availability and aliases can move.

Pricing, model limits, reasoning fields, capabilities and API base URLs remain
untrusted observations. They cannot change connection authority, approve
retention, download weights or enable inference. OpenCode Go privacy differs by
model. Ollama on loopback can expose cloud-backed models; an address alone does
not prove local execution. Named inference profiles need separate qualification.

A 403 or malformed response is reported as `metadata_unavailable`, not an empty
successful catalog. Previous successful entries are retained for that source;
review `failures` even if refresh exits successfully. Do not infer that a failed
metadata refresh means a model was removed or that a successful one allows use.

Official documentation (retrieved October 30, 2026):

- [OpenCode Go](https://opencode.ai/v2/docs/console/go), Models and API sections.
- [Ollama Cloud](https://docs.ollama.com/cloud), direct API and model catalog.
- [Ollama list models API](https://docs.ollama.com/api/tags).

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

Limits are 32 sources, 10,000 models per source, 4 MiB per HTTP body, 16 KiB response
headers, 8 MiB per protected file, 5 seconds per source, and a 60-second aggregate
network budget. The body limit admits a fetch only; it is not part of any stored
catalog, digest or identity. Proposals and catalogs are written as compact JSON
with a trailing newline and without HTML escaping, so each stored model is at
most 20 bytes longer than its object in the list: any one list the fetch accepts
fits the 8 MiB file limit. Several large sources together can still exceed it,
which fails closed before anything is written. Catalogs and proposals written
earlier, indented and with the selector also inside each model's metadata, still
read back and apply, and diff against new metadata without reporting unchanged
models. HTTP is sequential and retries are not performed. Duplicate JSON
keys, duplicate selectors, invalid selectors, malformed documents, and unexpected
shapes fail the affected source. No scheduler, route approval or activation hook
is installed.

The installed wrapper at `/usr/local/share/open-trestle/scripts/model_catalog.py`
and the source-tree wrapper execute this same product command. Neither builds or
fetches anything itself:

```sh
python3 tools/model_catalog.py --trestle /opt/trestle/bin/trestle refresh \
  --sources /private/model-sources.json --current /private/model-catalog.json \
  --proposal /private/model-proposal-2.json
```

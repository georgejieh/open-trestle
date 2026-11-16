# Refresh model availability metadata

`trestle config models refresh` is a manual command that stages a list of the models your providers and local servers report as available. Operators use it to review that list before storing it as a catalog. The list is availability metadata, not a set of approved inference routes.

The command does not activate models, change selectors, load or download weights, make inference requests, approve routes or privacy claims, or rewrite old run identities. The runtime configuration and the route inventory remain separate authorities. Loopback alone does not prove that inference is local, because a local runtime can expose cloud-backed model aliases.

`trestle init` does not use this command or a catalog file. In an interactive run, when you did not give a model by flag, it reads one list from the provider you chose. It uses the same list reader and no key. The list kinds are:

- `openai_models` for OpenCode Go and for a local server's `/v1/models`
- `ollama_tags` for Ollama Cloud
- for OpenRouter, its public model list and its zero-data-retention endpoint list (see [OpenRouter zero data retention](openrouter-zdr-profile.md))

Open Trestle reads the list fresh on each run, shows it for that run only, and never saves it as a catalog. When it cannot read the list, the wizard asks you to type the model ID.

## Source manifest

Create a protected JSON manifest in a directory that you own. Source IDs are stable identities that the operator selects, not provider display names. While a source ID exists in the current catalog, changing its kind or URL is refused. To change a connection identity, choose a new source ID and review the removal of the old source. Removing a source from the manifest explicitly proposes removing its entries.

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

Two kinds are supported:

- `openai_models`: an explicit URL ending in `/models`, such as `/v1/models`. It reads `data[].id` without changing case, separators or tags.
- `ollama_tags`: an explicit `/api/tags` URL. It reads `models[].name` exactly.

The rest of each model object is kept as metadata, with its members and their encoding unchanged, and the selector is stored once beside it. Fields such as `digest`, capabilities and costs are observations. They are not verified commitments, privacy evidence, readiness, entitlement or approval. A moving alias stays a moving alias: refresh does not resolve it to immutable weights and does not rebind any approved route. The stable identity is `(source_id, exact selector)`.

### Authenticated sources

Schema version 1 stays unauthenticated. It never reads a credential or sends an auth header. For a metadata endpoint that requires bearer authentication, use schema version 2 with an explicit environment reference:

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

Provision that variable through your secure credential interface before you refresh. The manifest stores its name and never its value. Only `OPEN_TRESTLE_PROVIDER_` references that use uppercase letters, digits and underscores are accepted. Literal keys, empty references, nulls and alternate field spellings are refused. Changing a source's credential reference requires a new source ID, as changing its URL does. A version 2 source without the field stays unauthenticated. No login cache is read.

Refresh validates the complete manifest and the remote opt-in before it resolves any credential. It retrieves a referenced key only for that source's bounded GET request. If a key is missing or unsafe for a header, the source records `metadata_unavailable` and no unauthenticated request is made. Redirects do not forward credentials. Apply reads no credentials and makes no requests. Proposals and catalogs keep only the reference. A version 2 manifest produces a version 2 catalog, and the proposal envelope stays at version 1. Existing version 1 catalogs and proposals keep their wire format.

### URL rules

URLs must not contain credentials, query strings or fragments. The endpoint is explicit authority from the operator, not a URL discovered in model metadata. Choose a credential reference that is dedicated to that endpoint, and note that a manifest cannot reuse one reference across distinct origins.

An authenticated source on numeric-loopback HTTP sends the bearer token in plaintext to whichever process listens on that port, so verify that listener before you refresh. Authenticated discovery does not prove retention, model eligibility, account privacy or permission to run inference. OpenRouter documents bearer authentication for its model catalog. Check each service's current discovery contract before you choose a URL. This command does not turn an inference endpoint into a discovery API.

Numeric loopback HTTP and HTTPS endpoints are accepted without remote permission. Hostnames such as `localhost` do not count as local authority. Every other endpoint requires HTTPS and the explicit `--allow-remote` flag. Proxy environment variables are ignored. For a remote endpoint, every DNS answer must be public, and the connection uses one checked numeric address. Private, loopback and link-local remote addresses are refused. Redirects are never followed. Refresh sends GET only to the metadata URLs you supply, and it does not discover other URLs in response metadata.

## Named local runtime catalogs

The URLs below use the ports from [the named local runtime recipes](named-local-runtimes.md). Use them only for listeners that you configured explicitly. These mappings were checked against official documentation on November 1, 2026, not against installed servers. Check your runtime version and listener before you refresh.

| Runtime | Metadata source | Scope and selector |
| --- | --- | --- |
| llama.cpp, direct single-model server | `openai_models`, `http://127.0.0.1:8080/v1/models` for generation and port `8081` for verification | The documented `data[].id` list has one loaded-model entry. `--alias` sets its ID; without an alias, the ID is the model-file path. It is not a disk inventory. |
| Ollama local | `ollama_tags`, `http://127.0.0.1:11434/api/tags` | Read `models[].name` exactly. This available-model list is not the running-model list at `/api/ps`. A selector or loopback address does not prove local weights or local execution. |
| vLLM | `openai_models`, `http://127.0.0.1:8000/v1/models` for generation and port `8001` for verification | At retrieved upstream tree `3a90cc6fd0504b52bf47d58e8d70cff4b03f2c19`, GET `/v1/models` serializes `data[].id`: configured served names (or the model argument), plus registered LoRA names. The recipes use one served name per process. This is static source evidence, not a commit/release pin or installed-server result; verify the selected version and list authentication before refresh. |
| LM Studio on Mac | `/v1/models` is documented; catalog kind not established here | The list contains models visible to the server and may include downloaded models with Just-In-Time loading. Confirm the response envelope and how loaded `--identifier` values appear before choosing a catalog kind. |

These are metadata mappings, not proof that a service conforms and not route approval. Aliases are API selectors, not immutable weight identities. The existing manual selector recipes do not prove that a runtime lacks a discovery API.

Ollama's local API does not require authentication. The llama.cpp recipes do not set a key, and its documented optional key settings do not establish how the list endpoint behaves under authentication. For a listener that you have explicitly set up with authentication, verify its list contract and use the schema version 2 credential reference described above. Never add a dummy key, and never read a runtime's login cache.

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

These two services publish metadata endpoints that work with the existing source kinds. The example below selects metadata sources only. It does not configure inference, and it does not establish route support, account entitlement, privacy approval or permission to send repository content.

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

Save the manifest in a protected directory that you own. Run the manual `trestle config models refresh` command with `--allow-remote` and a new proposal path. Review the exact IDs, the metadata, the source failures and the two digests, and only then run `trestle config models apply`. Apply does not fetch or activate anything. The source IDs above are examples, so choose stable IDs for your own configuration.

When last checked (see the retrieval date below), both documented endpoints returned public metadata without a key. Schema version 1 never reads credentials. Do not put inference keys into these URLs, and do not assume that every metadata endpoint will stay unauthenticated. If a service later documents authenticated discovery, review that contract and use the existing schema version 2 credential-reference mechanism where it is supported. Do not scrape login caches or add literal keys.

OpenCode Go reads `data[].id` exactly, such as `glm-5.3-flash`. Do not prepend OpenCode's client configuration namespace `opencode-go/` to direct API IDs. Ollama Cloud reads `models[].name` exactly, such as `gemma4:31b`. Do not replace it with the CLI alias `gemma4:cloud`. These are examples seen in metadata, not recommended defaults or model approvals. Model availability and aliases can change.

Pricing, model limits, reasoning fields, capabilities and API base URLs stay untrusted observations. They cannot change connection authority, approve retention, download weights or enable inference. OpenCode Go privacy differs by model. Ollama on loopback can expose cloud-backed models, and an address alone does not prove local execution. Named inference profiles need separate qualification.

A 403 or a malformed response is reported as `metadata_unavailable`, not as an empty, successful catalog. The previous successful entries for that source are kept. Review `failures` even if refresh exits successfully. A failed metadata refresh does not mean that a model was removed, and a successful one does not allow its use.

Official documentation (retrieved October 30, 2026):

- [OpenCode Go](https://opencode.ai/v2/docs/console/go), Models and API sections.
- [Ollama Cloud](https://docs.ollama.com/cloud), direct API and model catalog.
- [Ollama list models API](https://docs.ollama.com/api/tags).

## Review and apply

Protect the manifest and its directory before you run either command. The files and all their ancestors must pass the same checks for ownership, symlinks and write authority as protected runtime configuration. All paths must be distinct, including the paths of the writer locks. Catalogs and proposals are written with mode `0600`. Locks are cooperative, exclusive locks held only during the write. Do not remove lock files while any writer might be active.

```sh
trestle config models refresh \
  --sources /private/model-sources.json \
  --current /private/model-catalog.json \
  --proposal /private/model-proposal-1.json
```

The proposal path must be new. Refresh never overwrites a proposal and never writes the current catalog. Its JSON output on stdout gives `proposal_digest`, `current_digest`, a diff of `added`, `removed` and `changed` models, and source failures. A change includes the before and after metadata for the same exact selector. Inspect stdout and the protected proposal file. For explicit public HTTPS sources, add `--allow-remote` to refresh.

Apply requires the exact two digests from that review:

```sh
trestle config models apply \
  --sources /private/model-sources.json \
  --current /private/model-catalog.json \
  --proposal /private/model-proposal-1.json \
  --expected-proposal REVIEWED_PROPOSAL_SHA256 \
  --expected-current REVIEWED_CURRENT_SHA256_OR_absent
```

For the first catalog, use the literal `absent` as the current digest. Digests cover the exact file bytes, including whitespace. Apply checks the proposal bytes, the manifest bytes, the source bindings and the current bytes, then checks them again before it replaces anything. It makes no network calls. A stale digest, a changed manifest, corrupt input, an untrusted path or a held writer lock refuses application. Generate a fresh proposal at a new path rather than overwriting the reviewed file.

### How failures are recorded

Each failed source keeps its previous successful snapshot and records `metadata_unavailable`. A failed new source has an empty snapshot and that failure. Successful sources still contribute their changes. So even a refresh in which every source failed can be reviewed and applied to record the failures, without erasing the last-known-good model entries. No provider error bodies are copied into failures.

A source failure is a reviewable result with exit code 0. It is not a hidden claim that everything succeeded, so inspect `failures`. Malformed inputs and persistence errors return a nonzero exit code and replace nothing.

### How files are written

Writes use a temporary file in the same directory, a file sync, an atomic replacement and a parent-directory sync. The first installation uses a no-clobber hard link of the complete staged inode. Existing catalogs are replaced with a rename under the exclusive writer lock. Failures in metadata, parsing, digests or persistence before the commit leave the current catalog unchanged.

As with any atomic file replacement, a parent sync failure happens **after** the new file became visible. In that case the command reports `replaced; directory durability unconfirmed`. Inspect the actual current digest before you retry, and do not assume that a nonzero exit proves a rollback. How well data survives a power loss depends on the host filesystem.

### Limits

The limits are 32 sources, 10,000 models per source, 4 MiB per HTTP body, 16 KiB of response headers, 8 MiB per protected file, 5 seconds per source and a 60-second aggregate network budget. HTTP requests run one after another, and Open Trestle does not retry them. Duplicate JSON keys, duplicate selectors, invalid selectors, malformed documents and unexpected shapes fail the affected source. Open Trestle installs no scheduler, route approval or activation hook.

The body limit only controls whether a fetch is accepted. It is not part of any stored catalog, digest or identity. Proposals and catalogs are written as compact JSON with a trailing newline and without HTML escaping. As a result, each stored model is at most 20 bytes longer than its object in the list, so any one list that the fetch accepts fits the 8 MiB file limit.

A stored proposal nests each model object four levels deeper than its list. The fetch therefore refuses a model object that is nested more than 58 levels deep, counting its own members as level 1. That source is recorded as `metadata_unavailable`, and the other sources still refresh. Every list that the fetch accepts therefore also fits the 64-level document depth bound once stored. Several large sources together can still exceed the 8 MiB limit, which fails closed before anything is written.

Catalogs and proposals written earlier, which were indented and had the selector also inside each model's metadata, still read back and apply. They also diff against new metadata without reporting unchanged models.

### Wrapper script

The installed wrapper at `/usr/local/share/open-trestle/scripts/model_catalog.py` and the wrapper in the source tree both run this same product command. Neither builds or fetches anything itself:

```sh
python3 tools/model_catalog.py --trestle /opt/trestle/bin/trestle refresh \
  --sources /private/model-sources.json --current /private/model-catalog.json \
  --proposal /private/model-proposal-2.json
```

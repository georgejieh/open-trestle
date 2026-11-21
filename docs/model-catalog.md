# Refresh model availability metadata

`trestle config models refresh` is a manual command that stages a list of the models your providers and local servers report as available. You review that list before storing it as a catalog. The list is availability metadata, not a set of approved inference routes.

The command does not activate models, change selectors, load or download weights, make inference requests or approve routes. The runtime configuration and the route inventory are separate. A local runtime can expose cloud-backed model aliases, so a loopback address does not mean that inference is local.

`trestle init` does not use this command or a catalog file. In an interactive run, when you did not give a model by flag, it reads one list from the provider you chose. It uses the same list reader and no key. The list kinds are:

- `openai_models` for OpenCode Go and for a local server's `/v1/models`
- `ollama_tags` for Ollama Cloud
- for OpenRouter, its public model list and its zero-data-retention endpoint list (see [OpenRouter zero data retention](openrouter-zdr-profile.md))

Open Trestle reads the list on each run, shows it for that run only, and does not save it as a catalog. When it cannot read the list, the wizard asks you to type the model ID.

## Source manifest

Create a protected JSON manifest in a directory that you own. Source IDs are stable identities that you choose, not provider display names. While a source ID exists in the current catalog, changing its kind or URL is refused. To change a connection identity, choose a new source ID and review the removal of the old source. Removing a source from the manifest proposes removing its entries.

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

- `openai_models`: an explicit URL ending in `/models`, such as `/v1/models`. It reads `data[].id` as is, without changing case, separators or tags.
- `ollama_tags`: an explicit `/api/tags` URL. It reads `models[].name` as is.

The rest of each model object is kept as metadata, with its members and their encoding unchanged, and the selector is stored once beside it. Fields such as `digest`, capabilities and costs are what the source reported. A moving alias stays a moving alias: refresh does not resolve it to fixed weights or rebind an approved route. The stable identity is `(source_id, exact selector)`.

### Authenticated sources

Schema version 1 is unauthenticated. It does not read a credential or send an auth header. For a metadata endpoint that requires bearer authentication, use schema version 2 with an explicit environment reference:

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

Provision that variable through your secure credential interface before you refresh. The manifest stores its name, not its value. Only `OPEN_TRESTLE_PROVIDER_` references that use uppercase letters, digits and underscores are accepted. Literal keys, empty references, nulls and alternate field spellings are refused. Changing a source's credential reference requires a new source ID, as changing its URL does. A version 2 source without the field stays unauthenticated. No login cache is read.

Refresh validates the manifest and the remote opt-in before it resolves any credential. It retrieves a referenced key only for that source's GET request. If a key is missing or unsafe for a header, the source records `metadata_unavailable` and no unauthenticated request is made. Redirects do not forward credentials. Apply reads no credentials and makes no requests. Proposals and catalogs keep only the reference. A version 2 manifest produces a version 2 catalog, and the proposal envelope stays at version 1. Existing version 1 catalogs and proposals keep their wire format.

### URL rules

URLs must not contain credentials, query strings or fragments. The endpoint is the URL you supply, not one discovered in model metadata. Choose a credential reference that is dedicated to that endpoint. A manifest cannot reuse one reference across origins.

An authenticated source on numeric-loopback HTTP sends the bearer token in plaintext to whichever process listens on that port, so verify that listener before you refresh. OpenRouter documents bearer authentication for its model catalog. Check each service's current discovery contract before you choose a URL.

Numeric loopback HTTP and HTTPS endpoints are accepted without remote permission. Hostnames such as `localhost` do not count as local. Every other endpoint requires HTTPS and the explicit `--allow-remote` flag. Proxy environment variables are ignored. For a remote endpoint, every DNS answer must be public, and the connection uses one checked numeric address. Private, loopback and link-local remote addresses are refused. Redirects are not followed. Refresh sends GET only to the metadata URLs you supply.

## Choosing sources

Point each source at a metadata URL that you control or trust, and use the kind that matches its response. A local runtime listener at the ports of [the named local runtime recipes](named-local-runtimes.md) is a typical source. Check your runtime version and listener before you refresh, because response shapes differ between servers and versions.

- A server that lists models at `/v1/models` uses `openai_models`. Aliases are API selectors, not fixed weight identities, and an alias such as the llama.cpp `--alias` or a vLLM served name is what the list reports.
- An Ollama server uses `ollama_tags` with `/api/tags`. That list is the available models, not the running models.
- A hosted service that documents a public models list, such as the OpenCode Go and Ollama Cloud lists, can use the same kinds. Read IDs as the list gives them. Do not prepend a client namespace such as `opencode-go/`, and do not replace a tag with a CLI alias.
- For a listener that you set up with authentication, use the schema version 2 credential reference described above. Do not add a dummy key or read a runtime's login cache.

These are metadata mappings, not route approval. Pricing, limits, capabilities and API base URLs in the metadata cannot change connection authority, download weights or enable inference.

Save the manifest in a protected directory that you own. Run `trestle config models refresh` with `--allow-remote` for public HTTPS sources and a new proposal path. Review the IDs, the metadata, the source failures and the two digests, and only then run `trestle config models apply`.

A 403 or a malformed response is reported as `metadata_unavailable`, not as an empty, successful catalog, and the previous successful entries for that source are kept. Review `failures` even if refresh exits successfully. A failed metadata refresh does not mean that a model was removed, and a successful one does not allow its use.

## Review and apply

Protect the manifest and its directory before you run either command. The files and all their ancestors must pass the same checks for ownership, symlinks and write authority as protected runtime configuration. All paths must be distinct, including the paths of the writer locks. Catalogs and proposals are written with mode `0600`. Locks are held only during the write. Do not remove lock files while any writer might be active.

```sh
trestle config models refresh \
  --sources /private/model-sources.json \
  --current /private/model-catalog.json \
  --proposal /private/model-proposal-1.json
```

The proposal path must be new. Refresh does not overwrite a proposal or write the current catalog. Its JSON output on stdout gives `proposal_digest`, `current_digest`, a diff of `added`, `removed` and `changed` models, and source failures. A change includes the before and after metadata for the same selector. Inspect stdout and the protected proposal file. For explicit public HTTPS sources, add `--allow-remote` to refresh.

Apply requires the two digests from that review:

```sh
trestle config models apply \
  --sources /private/model-sources.json \
  --current /private/model-catalog.json \
  --proposal /private/model-proposal-1.json \
  --expected-proposal REVIEWED_PROPOSAL_SHA256 \
  --expected-current REVIEWED_CURRENT_SHA256_OR_absent
```

For the first catalog, use the literal `absent` as the current digest. Digests cover the file bytes, including whitespace. Apply checks the proposal bytes, the manifest bytes, the source bindings and the current bytes, then checks them again before it replaces anything. It makes no network calls. A stale digest, a changed manifest, corrupt input, an untrusted path or a held writer lock refuses application. Generate a fresh proposal at a new path rather than overwriting the reviewed file.

### How failures are recorded

Each failed source keeps its previous successful snapshot and records `metadata_unavailable`. A failed new source has an empty snapshot and that failure. Successful sources still contribute their changes. So even a refresh in which every source failed can be reviewed and applied to record the failures, without erasing the last-known-good model entries. No provider error bodies are copied into failures.

A source failure is a reviewable result with exit code 0, so inspect `failures`. Malformed inputs and persistence errors return a nonzero exit code and replace nothing.

### How files are written

Writes use a temporary file in the same directory, a file sync, an atomic replacement and a parent-directory sync. The first installation uses a no-clobber hard link of the staged file. Existing catalogs are replaced with a rename under the exclusive writer lock. Failures in metadata, parsing, digests or persistence before the commit leave the current catalog unchanged.

As with any atomic file replacement, a parent sync failure happens **after** the new file became visible. In that case the command reports `replaced; directory durability unconfirmed`. Inspect the actual current digest before you retry, and do not assume that a nonzero exit means a rollback. How well data survives a power loss depends on the host filesystem.

### Limits

The limits are 32 sources, 10,000 models per source, 4 MiB per HTTP body, 16 KiB of response headers, 8 MiB per protected file, 5 seconds per source and a 60-second aggregate network budget. HTTP requests run one after another, and Open Trestle does not retry them. Duplicate JSON keys, duplicate selectors, invalid selectors, malformed documents and unexpected shapes fail the affected source. Open Trestle installs no scheduler, route approval or activation hook.

The body limit only controls whether a fetch is accepted. Proposals and catalogs are written as compact JSON with a trailing newline and without HTML escaping. As a result, each stored model is at most 20 bytes longer than its object in the list, so any one list that the fetch accepts fits the 8 MiB file limit.

A stored proposal nests each model object four levels deeper than its list. The fetch therefore refuses a model object that is nested more than 58 levels deep, counting its own members as level 1. That source is recorded as `metadata_unavailable`, and the other sources still refresh. Every list that the fetch accepts therefore also fits the 64-level document depth bound once stored. Several large sources together can still exceed the 8 MiB limit, and then nothing is written.

Catalogs and proposals written in the earlier indented format still read back and apply.

### Wrapper script

The installed wrapper at `/usr/local/share/open-trestle/scripts/model_catalog.py` and the wrapper in the source tree both run this product command and do nothing else:

```sh
python3 tools/model_catalog.py --trestle /opt/trestle/bin/trestle refresh \
  --sources /private/model-sources.json --current /private/model-catalog.json \
  --proposal /private/model-proposal-2.json
```

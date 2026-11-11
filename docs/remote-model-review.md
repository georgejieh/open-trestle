# Remote model review

This guide runs `trestle local-git model-review` against strong remote models in
a few commands. `trestle setup bootstrap init --provider ...` writes the protected
route inventory, runtime policy and privacy witnesses for you and derives every
record, evidence, account, credential-reference, inventory and policy identity.
You never hand-author `routes.json` or compute a hash.

The review is the existing foreground direct path,
`local-git model-review --egress policy-approved`. It sends sanitized, scanned
selected source to the provider you configure. Bootstrap itself makes no model
call; its only network request is, for `ollama-signin`, one bounded `GET
/api/tags` to your local Ollama daemon. There is no daemon, resume or
publication in this journey.

Supported providers:

| `--provider` | Endpoint | Zone | Request profile |
|---|---|---|---|
| `openrouter-zdr` | `https://openrouter.ai/api/v1` | `brokered_remote` | [`openrouter_zdr_chat_v1`](openrouter-zdr-profile.md) |
| `opencode-go` | `https://opencode.ai/inference/go/openai/v1` | `brokered_remote` | [`opencode_go_chat_v1`](opencode-go-profile.md) |
| `ollama-cloud` | `https://ollama.com/v1` | `private_remote` | none (generic Chat Completions) |
| `ollama-signin` | `http://127.0.0.1:11434/v1` (your local Ollama, relaying to Ollama Cloud) | `private_remote` | `ollama_signin_chat_v1`, no credential |

Both roles use the same provider with two different models. Verification is
`distinct_model`; that is not a claim that the models come from different
training families. Offline tests prove the configuration and dispatch path with
synthetic transports only. They do not qualify any live account, model or
service.

## Prerequisite 1: a scanner-bound binary and installed scanner

Remote egress is refused unless every request passes two Betterleaks scans in the
sandboxed scanner. A plain `go build` has no injected scanner digests, so it fails
closed. Build the packaged binaries from a clean committed checkout and install
the unsigned Linux amd64 candidate (see [operations](operations.md)):

```sh
python3 tools/package_secret_scanner.py --output .container
python3 tools/package_secret_scanner.py --verify .container
# build open-trestle-linux-amd64.pyz as described in docs/operations.md, then
sha256sum -c open-trestle-linux-amd64.pyz.sha256
sudo ./open-trestle-linux-amd64.pyz install
```

The packaging tool injects the launcher and worker SHA-256 values into both
`trestle` and `trestled` with `-ldflags -X`. `install` places the scanner pair at
`/usr/local/libexec/open-trestle/` as root-owned `0555` files, which is the only
location the client trusts. Use the installed `/usr/local/bin/trestle` for every
command below. `bootstrap check` reports this prerequisite before any review:

- `refused` with `sanitized_egress_scanner`: this binary has no digests (a
  development build) or the platform is not Linux.
- `pending` with `sanitized_egress_scanner`: the binary has digests, but the
  installed scanner is missing or does not match them.

## Prerequisite 2: credentials by name only

Every credential flag takes an environment variable **name** matching
`OPEN_TRESTLE_PROVIDER_[A-Z0-9_]+`. A value that looks like a key is refused.
Only the name, and a digest of the name, is stored. Export the key from your
approved secret store in the shell that runs `check` and the review:

```sh
export OPEN_TRESTLE_PROVIDER_OPENROUTER="$(your-secret-tool read openrouter-key)"
```

`check` reports `credential_environment_present` as pending until each named
variable is non-empty. It never prints or stores the value. Use
`--verification-credential-environment` only if the verifier uses a different key.

## The journey

```sh
install -d -m 0700 "$HOME/.local/state/open-trestle/remote"

trestle setup bootstrap init --provider openrouter-zdr \
  --directory "$HOME/.local/state/open-trestle/remote" \
  --tenant personal --repository project \
  --checkout /approved/project --base refs/heads/main --head HEAD \
  --repository-authority local.test --repository-namespace personal \
  --repository-name project \
  --generation-model YOUR_GENERATION_MODEL \
  --verification-model YOUR_DIFFERENT_VERIFIER_MODEL \
  --generation-credential-environment OPEN_TRESTLE_PROVIDER_OPENROUTER \
  --declared-by owner \
  --context-tokens 128000 --output-tokens 8192 \
  --input-micro-usd-per-million-tokens 3000000 \
  --output-micro-usd-per-million-tokens 15000000 \
  --max-cost-micro-usd 500000 \
  --declare-remote-route \
  --generation-provider-slug YOUR_GENERATION_SLUG \
  --verification-provider-slug YOUR_VERIFIER_SLUG \
  --generation-upstream-evidence https://example.invalid/upstream-a,SHA256 \
  --verification-upstream-evidence https://example.invalid/upstream-b,SHA256 \
  --generation-slug-evidence https://example.invalid/slug-a,SHA256 \
  --verification-slug-evidence https://example.invalid/slug-b,SHA256 \
  --broker-evidence https://example.invalid/openrouter-zdr,SHA256 \
  --account-evidence https://example.invalid/account-review,SHA256 \
  --evidence-retrieved-at 2026-11-07T09:00:00Z --reviewed-at 2026-11-07T10:00:00Z \
  --valid-from 2026-11-07T10:00:00Z --valid-until 2026-12-07T00:00:00Z \
  --declare-openrouter-zdr-account

trestle setup bootstrap check --directory "$HOME/.local/state/open-trestle/remote"
```

Replace every placeholder. Prices, capacities and slugs are illustrative, not
recommendations. When `check` returns `ready` (exit 0), run its `review_command`
array exactly as printed. It is
`trestle local-git model-review --checkout ... --egress policy-approved --timeout 10m --format text`
with the pinned base and head commit digests and this directory's `routes.json`
and `policy.json`. `inspect` is the same read-only report as `check`.

Results: `ready` (exit 0), `pending` (exit 3), `refused` (exit 4); usage errors
exit 2. Every refusal prints a reason on stderr and in `messages`. An input that
fails validation writes nothing. Repeating `init` with identical inputs accepts the existing
byte-identical files; different inputs refuse, so use a new directory. A pending
or refused prerequisite is reported by `check`, never discovered mid-review.

Checks reported by `check`:

- `privacy_declaration_current`: the declared review window contains now
  (named profiles only). Before `--valid-from` it is pending; after
  `--valid-until` it is refused and needs a fresh review and directory.
- `dispatch_catalog_validated`: the protected files construct the
  policy-approved dispatcher catalog, without credential retrieval or requests.
- `credential_environment_present` and `sanitized_egress_scanner`: above.
- `ollama_cloud_models_listed` (`ollama-signin` only): the local Ollama daemon
  still lists both models as Ollama Cloud models. A daemon that is not running
  is pending; a model it no longer relays to `https://ollama.com` is refused.

`ready` means these local prerequisites hold. It is not provider qualification,
review clearance or proof of any declared fact.

## Common declarations

`--declare-remote-route` is required for every provider. With it, you declare
that both models have the stated context and output capacity, return
structured JSON, are used with content logging disabled, cost no more than the
stated per-million-token prices, and are currently available. Without it, init
refuses rather than inventing those facts. Reviews reserve the 4096-token output
cap plus the actual request size against `--max-cost-micro-usd`. Init refuses a
cap that cannot cover the output reservation. Set the prices to the higher of
the two models. Declare `0` prices only if your plan has no per-token charge.
`--declared-by` names the operator recorded in each evidence manifest.

The generation and verification models must differ. Endpoints for the named
profiles are fixed, so `--endpoint` is refused for them.

## OpenRouter ZDR

`--declare-openrouter-zdr-account` is your explicit declaration that you checked
the actual key's effective account and guardrails. It means Safety Retention is
denied for Google and other providers, training and content logging are disabled,
and BYOK, private endpoints, tools and plugins are unused. You also accept
`openrouter_zdr_with_documented_exceptions`, not unconditional non-retention.
Without the flag, init refuses to write any ZDR claim. Read
[the OpenRouter ZDR profile](openrouter-zdr-profile.md) first.

Each role needs its own routing slug and its own upstream and slug-coverage
evidence. The broker and account review evidence are shared. Each `--*-evidence`
value is `HTTPS_URL,SHA256`, where the digest covers the exact bytes you reviewed
(for example `sha256sum saved-page.pdf`). URLs must have a host and no
credentials, query or fragment. Bootstrap does not fetch URLs or prove that an
artifact supports a claim. Times are canonical UTC RFC3339 and must satisfy
retrieval <= review <= `--valid-from` < `--valid-until`.

## OpenCode Go

`--declare-opencode-go-account` declares that the key belongs to a single-member Go
workspace with privacy training and extra usage disabled, and that both models
document zero-day retention without training. Supply `--generation-model-evidence`,
`--verification-model-evidence`, `--broker-evidence` and `--account-evidence`,
plus the same four times. See [the OpenCode Go profile](opencode-go-profile.md).
This bootstrap uses the brokered Go route for both roles on the direct path. The
profile document describes setup-checker support for a separate private direct
verifier; this bootstrap does not run that setup checker or configure a daemon.

## Ollama Cloud

Ollama Cloud uses the generic `private_remote` zone with
`openai_chat_completions` at `https://ollama.com/v1` and bearer authentication.
There is no named Ollama request profile or privacy witness. The route evidence
manifest records only your operator declaration, so no retention or zero-data
claim is made. Review Ollama's current privacy terms and your plan before you
send private source.

```sh
export OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD="$(your-secret-tool read ollama-key)"

trestle setup bootstrap init --provider ollama-cloud \
  --directory "$HOME/.local/state/open-trestle/ollama" \
  --tenant personal --repository project \
  --checkout /approved/project --base refs/heads/main --head HEAD \
  --repository-authority local.test --repository-namespace personal \
  --repository-name project \
  --generation-model YOUR_OLLAMA_GENERATION_MODEL \
  --verification-model YOUR_DIFFERENT_OLLAMA_MODEL \
  --generation-credential-environment OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD \
  --declared-by owner \
  --context-tokens 128000 --output-tokens 8192 \
  --input-micro-usd-per-million-tokens 0 \
  --output-micro-usd-per-million-tokens 0 \
  --max-cost-micro-usd 0 \
  --declare-remote-route

trestle setup bootstrap check --directory "$HOME/.local/state/open-trestle/ollama"
```

Zero prices fit a plan without per-token billing; plan quotas still apply and are
not checked. When the account has no usage credit Ollama answers HTTP 402, and
for a retired model HTTP 410; a review then fails as `policy (task candidates):
provider_payment_required` or `provider_model_retired` with a fixed hint (see
[provider refusals](local-model-review.md#provider-refusals)). Ollama's own
message is never shown or stored. `--endpoint` may replace the base with
another remote HTTPS Ollama Cloud base. Loopback or private endpoints are
refused; use the
[local-first bootstrap](local-first-bootstrap.md) for models that run on this
machine, or `ollama-signin` (below) for a local Ollama signed in to Ollama Cloud.

## Ollama signed in to Ollama Cloud

`--provider ollama-signin` is for an Ollama daemon on this machine that you
signed in with `ollama signin`. That daemon serves Ollama Cloud models (names
whose tag is `cloud` or ends in `-cloud`, such as `gpt-oss:120b-cloud`) by
forwarding each request to `https://ollama.com` under your Ollama account.
Open Trestle talks only to the loopback daemon and stores and sends no API key,
but **your repository source leaves this machine**: it is sent to Ollama Cloud.
This is remote egress, and it is treated exactly like the other remote routes:

- The route's zone is `private_remote`, never `local`. The sanitizer and both
  secret scans run before every request, the scanner prerequisite applies, and
  `--egress local-only` refuses the route.
- The connection uses the closed request profile `ollama_signin_chat_v1` in
  runtime policy schema version 7. It is the only profile under which a
  loopback endpoint may serve a non-local zone, and it requires all of: Chat
  Completions, `credential_mode` `none`, an endpoint of exactly
  `http://127.0.0.1:PORT/v1`, provider ID `ollama-signin`, and model IDs with
  the Ollama cloud suffix. Every other profile, and a policy with no profile,
  still refuses a loopback endpoint in a remote zone.
- `init` reads the daemon's model list once (`GET /api/tags`, no source, no
  key) and refuses unless both models are listed with
  `remote_host` `https://ollama.com`. `check` repeats that read and sends no
  model request, so it cannot see a missing credit or a retired model; a
  listed model can still be retired.
- Budget, usage and timeout handling are the same as for `ollama-cloud`. The
  daemon relays Ollama Cloud's refusals: HTTP 402 (no usage credit) and 410
  (retired model) fail a review as `provider_payment_required` and
  `provider_model_retired`, 401 (not signed in) as
  `provider_authentication_failed`, each with a fixed hint and never Ollama's
  own message (see [provider refusals](local-model-review.md#provider-refusals)).

`--declare-ollama-cloud-signin` is your explicit consent: the daemon is signed
in to an Ollama account you control, and each review sends the selected source,
after secret scanning, from that daemon to Ollama Cloud under that account.
Without it, init refuses. Open Trestle records no retention or zero-data claim
for Ollama Cloud; read Ollama's current terms (https://docs.ollama.com/cloud).
Setup does not prove that the daemon is signed in; see the wizard's optional
sign-in check below.

```sh
ollama signin            # once, in your own terminal
ollama pull gpt-oss:120b-cloud
ollama pull qwen3-coder:480b-cloud

install -d -m 0700 "$HOME/.local/state/open-trestle/ollama-signin"

trestle setup bootstrap init --provider ollama-signin \
  --directory "$HOME/.local/state/open-trestle/ollama-signin" \
  --tenant personal --repository project \
  --checkout /approved/project --base refs/heads/main --head HEAD \
  --repository-authority local.test --repository-namespace personal \
  --repository-name project \
  --generation-model gpt-oss:120b-cloud \
  --verification-model qwen3-coder:480b-cloud \
  --declared-by owner \
  --context-tokens 128000 --output-tokens 8192 \
  --input-micro-usd-per-million-tokens 0 \
  --output-micro-usd-per-million-tokens 0 \
  --max-cost-micro-usd 0 \
  --declare-remote-route --declare-ollama-cloud-signin

trestle setup bootstrap check --directory "$HOME/.local/state/open-trestle/ollama-signin"
```

The model names are examples; use two different cloud models your daemon
lists. `--endpoint http://127.0.0.1:PORT/v1` replaces the default port; any
other address is refused. `--generation-credential-environment` is refused:
there is no key to name. A model your daemon runs locally is refused here; use
the [local-first bootstrap](local-first-bootstrap.md) for it.

In `trestle init`, choose "Ollama on this machine, signed in to Ollama Cloud".
The wizard checks that the `ollama` command is installed, reads the daemon's
model list and offers only its Ollama Cloud models. If you agree, it sends one
fixed test message, "Reply with OK", to the finder model to check the sign-in.
That message contains none of your code, but it goes to Ollama Cloud and uses
your Ollama Cloud usage. If the daemon answers 401 or 403 (not signed in), the
wizard offers to run `ollama signin` with your terminal attached (only on `y`)
and then sends the same message once more. If it answers 402, the wizard says
Ollama Cloud refused the message for billing, prints the review's hint ("the
provider refused the request for billing: add credit or a subscription to the
provider account, or choose another route") and asks whether to continue. If it
answers 404 or 410, the chosen model is not served or has been retired: the
wizard prints the review's hint ("the provider no longer serves this model:
choose a model the provider lists as available and re-run setup" for 410) and
stops before writing anything. The body of the answer is never read or shown.

## Limits

- Bootstrap records operator declarations. It does not verify account settings,
  provider conduct, model capability, price or availability.
- The direct review is foreground and ephemeral: no resume, daemon state or
  publication. Investigation and retained memory remain local-only.
- The checkout source uses the existing bounded Git reader with the
  `loose-and-pack-index-v1` profile. Dirty worktree and index content are not
  reviewed.
- Live inference, credentials, private-source egress and charges are your
  explicit decision. Nothing here provisions credentials or signs you in to
  Ollama.

# Remote model review

This guide shows how to run `trestle local-git model-review` against remote
models from a provider such as OpenRouter, Ollama Cloud or OpenCode Go. It takes
a few commands. `trestle setup bootstrap init --provider ...` writes the
protected route inventory, the runtime policy and the privacy witnesses for you.
It also derives every identity that those files need, such as the identities of
records, evidence, accounts, credential references, the inventory and the
policy. You never write `routes.json` by hand or compute a hash.

The review itself is the existing foreground direct path,
`local-git model-review --egress policy-approved`. It sends selected source
code to the provider you configure, after Open Trestle has sanitized and
scanned it. Bootstrap makes no model call. It makes only these network
requests:

- For `ollama-signin`, one bounded `GET /api/tags` to your local Ollama daemon.
- For OpenRouter, one bounded `GET` each of OpenRouter's public model list and
  its zero-data-retention endpoint list, both without a credential.

This journey has no daemon, no resume and no publication.

Supported providers:

| `--provider` | Endpoint | Zone | Request profile |
|---|---|---|---|
| `openrouter-zdr` | `https://openrouter.ai/api/v1` | `brokered_remote` | [`openrouter_zdr_chat_v2`](openrouter-zdr-profile.md): zero data retention required on every request |
| `openrouter` | `https://openrouter.ai/api/v1` | `private_remote` | none (generic Chat Completions); zero data retention not required by Open Trestle |
| `opencode-go` | `https://opencode.ai/inference/go/openai/v1` | `brokered_remote` | [`opencode_go_chat_v1`](opencode-go-profile.md) |
| `ollama-cloud` | `https://ollama.com/v1` | `private_remote` | none (generic Chat Completions) |
| `ollama-signin` | `http://127.0.0.1:11434/v1` (your local Ollama, relaying to Ollama Cloud) | `private_remote` | `ollama_signin_chat_v1`, no credential |

Both roles (generation and verification) use the same provider with two
different models. The verification mode is `distinct_model`, which means only
that the two models differ. It does not claim that they come from different
training families. Offline tests exercise the configuration and the dispatch
path with synthetic transports only. They do not qualify any live account,
model or service.

## Prerequisite 1: a scanner-bound binary and installed scanner

Open Trestle refuses to send source to a remote provider unless every request
passes two Betterleaks scans in the sandboxed scanner. A plain `go build` has no
injected scanner digests, so it fails closed. The scanner and the packaged
install exist only for Linux amd64 today. Remote review is refused on other
systems and on a development build. macOS and Windows are planned for the next
release (see [platforms](platforms.md) and the [roadmap](roadmap.md#next-release)).

Build the packaged binaries from a clean committed checkout, then install the
unsigned Linux amd64 candidate (see [operations](operations.md)):

```sh
python3 tools/package_secret_scanner.py --output .container
python3 tools/package_secret_scanner.py --verify .container
# build open-trestle-linux-amd64.pyz as described in docs/operations.md, then
sha256sum -c open-trestle-linux-amd64.pyz.sha256
sudo ./open-trestle-linux-amd64.pyz install
```

The packaging tool injects the SHA-256 values of the scanner launcher and worker
into both `trestle` and `trestled` with `-ldflags -X`. `install` places the
scanner pair at `/usr/local/libexec/open-trestle/` as root-owned `0555` files.
That is the only location the client trusts. Use the installed
`/usr/local/bin/trestle` for every command below.

`bootstrap check` reports this prerequisite before any review:

- `refused` with `sanitized_egress_scanner` means that this binary has no
  digests (it is a development build) or that the platform is not Linux.
- `pending` with `sanitized_egress_scanner` means that the binary has digests,
  but the installed scanner is missing or does not match them.

## Prerequisite 2: credentials by name only

Every credential flag takes the **name** of an environment variable, and the
name must match `OPEN_TRESTLE_PROVIDER_[A-Z0-9_]+`. Open Trestle refuses a value
that looks like a key. It stores only the name and a digest of the name. Export
the key from your approved secret store in the shell that runs `check` and the
review:

```sh
export OPEN_TRESTLE_PROVIDER_OPENROUTER="$(your-secret-tool read openrouter-key)"
```

`check` reports `credential_environment_present` as pending until it finds a key
for each named variable. It looks in the environment first, and then in the
credential store that `trestle init` and `trestle keys set` write (see
[API keys](keys.md)). It never prints or stores the value. Use
`--verification-credential-environment` only if the verifier uses a different
key.

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
  --max-cost-micro-usd 500000 \
  --declare-remote-route

trestle setup bootstrap check --directory "$HOME/.local/state/open-trestle/remote"
```

Replace every placeholder. The cost cap is an illustration, not a
recommendation. For OpenRouter, the context size, the output size, the prices and
the routing slugs come from OpenRouter's API (see [OpenRouter](#openrouter)).
Other providers also need `--context-tokens N --output-tokens N
--input-micro-usd-per-million-tokens N --output-micro-usd-per-million-tokens N`
and their own declarations below.

When `check` returns `ready` (exit 0), run its `review_command` array exactly as
printed. The command has this form:

`trestle local-git model-review --checkout ... --egress policy-approved --timeout 10m --format text --specialists auto`

It carries the base and head commit digests from the moment of setup, and this
directory's `routes.json` and `policy.json`. `--specialists auto` is present
unless you passed `--specialists none` to `init`.

Those commits describe only the change that existed at setup. `check` no longer
needs them to exist. Inside the repository, `trestle review` reviews the latest
change with the same configuration and fresh commits (see
[getting started](getting-started.md#running-it-again)).

When a request's output allowance gives it more than four minutes (see
[OpenAI provider](openai-provider.md)), the timeout leaves room for two such
requests plus two minutes, up to 15 minutes. An OpenRouter setup with the
16384-token allowance, for example, uses `--timeout 12m`.

`inspect` prints the same read-only report as `check`. A review that fails
prints a failure detail such as `provider_request_rejected` or
`provider_response_invalid`; see [failure details](failure-details.md).

The exit codes of `check` are 0 for `ready`, 3 for `pending` and 4 for
`refused`. Usage errors exit 2. Every refusal prints a reason on stderr and in
`messages`. An input that fails validation writes nothing. If you repeat `init`
with identical inputs, it accepts the existing files, which are byte-identical.
If the inputs differ, it refuses, so use a new directory. `check` reports a
prerequisite that is pending or refused up front, so you never discover it in
the middle of a review.

`check` reports these checks:

- `privacy_declaration_current` verifies that the declared review window
  contains the current time. It applies to OpenCode Go and to OpenRouter setups
  made before zero data retention was detected. Before `--valid-from` the check
  is pending. After `--valid-until` it is refused, and you need a fresh review
  and directory.
- `dispatch_catalog_validated` verifies that the protected files build the
  catalog of dispatchers that the policy approves. It retrieves no credential
  and makes no request.
- `credential_environment_present` and `sanitized_egress_scanner` are described
  above.
- `ollama_cloud_models_listed` applies to `ollama-signin` only. It verifies that
  the local Ollama daemon still lists both models as Ollama Cloud models. A
  daemon that is not running makes the check pending. A model that the daemon no
  longer relays to `https://ollama.com` makes it refused.

For OpenRouter, the result also carries `data_retention`, which is
`required_per_request` or `not_required_by_open_trestle`. It states what each
request requires, never what a provider retains.

`ready` means that these local prerequisites hold. It is not a qualification of
the provider, not clearance of the review and not proof of any declared fact.

## Common declarations

Every provider requires `--declare-remote-route`. With it, you declare that
both models:

- Have the stated context and output capacity.
- Return structured JSON.
- Are used with content logging disabled.
- Cost no more than the stated per-million-token prices.
- Are currently available.

Without the flag, `init` refuses instead of inventing those facts. For
OpenRouter, those facts come from its API, so the flag is your consent that each
review sends the selected source to OpenRouter, and your statement that prompt
logging is off for the key.

Each review reserves the output allowance plus the actual size of the request
against `--max-cost-micro-usd`. The output allowance is 4096 tokens unless
`--max-output-tokens` sets it. For OpenRouter it is the allowance that setup
chose. `init` refuses a cap that cannot cover the output reservation.
(`trestle init` computes the reservation as the cost of a request that fills the
whole context, rounded up to a cent.) The cap bounds each request. To limit
spending over a week, a month or a year, set a per-key
[spending limit](spending-limits.md).

Set the prices to the higher of the two models. Declare `0` prices only if your
plan has no per-token charge. `--declared-by` names the operator who is recorded
in each evidence manifest.

The generation and verification models must differ. The endpoints of the named
profiles are fixed, so `--endpoint` is refused for them.

## OpenRouter

Bootstrap reads `https://openrouter.ai/api/v1/endpoints/zdr` and
`https://openrouter.ai/api/v1/models` once each, without a key. It records the
exact SHA-256 and the time of each response.

For each model, bootstrap pins the zero-data-retention (ZDR) endpoints that
allow the review output allowance. That allowance is 16384 tokens unless
`--max-output-tokens` sets it or `--output-tokens` caps it. Bootstrap leaves out
the endpoints that allow less, and it records them. If no endpoint of a model
allows the allowance, that model keeps all its usable endpoints, and the
allowance becomes the smallest output that they allow.

From the pinned endpoints alone, bootstrap fills in their routing slugs, the
smallest context and output limit, the highest input and output price, and the
policy's `max_output_tokens`. Any of these flags overrides the detected value:
`--context-tokens`, `--output-tokens`, `--max-output-tokens`,
`--input-micro-usd-per-million-tokens`, `--output-micro-usd-per-million-tokens`
and `--*-provider-slug SLUG[,SLUG]`. Bootstrap records these facts as OpenRouter's
API reports them. It does not verify them.

Without ZDR (`--provider openrouter`), bootstrap pins nothing. The allowance is
16384 tokens, within the smaller output that the two models list. See
[what setup reads](openrouter-zdr-profile.md#what-setup-reads).

The two OpenRouter providers differ as follows:

- `--provider openrouter-zdr` requires ZDR on every request (`provider.zdr`),
  limited to the pinned endpoints. It refuses a model that has no ZDR endpoint,
  and says so. If it cannot read the API, pass the four flags for capacity and
  price. The route then requires ZDR without pinning endpoints.
- `--provider openrouter` does not require ZDR. It is a generic `private_remote`
  route that sends no provider controls, so a model provider may keep prompts
  under its own terms. Your account or key settings may still enforce ZDR.
  `bootstrap check` and every review result say this.

The API does not report whether your account or key enforces ZDR, and setup does
not claim either way. If OpenRouter refuses a request with HTTP 404, Open
Trestle records `provider_no_allowed_endpoint` with a hint that names the ZDR
setting.

These flags from the earlier reviewed setup are refused because they are no
longer used: `--*-upstream-evidence`, `--*-slug-evidence`, `--broker-evidence`,
`--account-evidence`, the four times and `--declare-openrouter-zdr-account`.
For details, including what the witness records, see
[OpenRouter zero data retention](openrouter-zdr-profile.md).

## OpenCode Go

`--declare-opencode-go-account` declares two things: that the key belongs to a
single-member Go workspace with privacy training and extra usage disabled, and
that both models document zero-day retention without training. Supply
`--generation-model-evidence`, `--verification-model-evidence`,
`--broker-evidence` and `--account-evidence`, plus the same four times. See
[the OpenCode Go profile](opencode-go-profile.md).

This bootstrap uses the brokered Go route for both roles on the direct path. The
profile document describes how the setup checker supports a separate private
direct verifier. This bootstrap does not run that setup checker and does not
configure a daemon.

## Ollama Cloud

Ollama Cloud uses the generic `private_remote` zone with
`openai_chat_completions` at `https://ollama.com/v1`, and it authenticates with a
bearer token. There is no named Ollama request profile and no privacy witness.
The route evidence manifest records only your own declaration, so Open Trestle
makes no claim about retention or zero data retention. Review Ollama's current
privacy terms and your plan before you send private source.

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

Zero prices fit a plan without per-token billing. Plan quotas still apply, and
Open Trestle does not check them. When the account has no usage credit, Ollama
answers HTTP 402. For a retired model it answers HTTP 410. The review then fails
as `policy (task candidates): provider_payment_required` or
`provider_model_retired`, with a fixed hint (see
[provider refusals](local-model-review.md#provider-refusals)). Open Trestle
never shows or stores Ollama's own message.

`--endpoint` may replace the base with another remote HTTPS Ollama Cloud base.
Open Trestle refuses loopback and private endpoints. For models that run on
this machine, use the [local-first bootstrap](local-first-bootstrap.md). For a
local Ollama that is signed in to Ollama Cloud, use `ollama-signin` (below).

## Ollama signed in to Ollama Cloud

`--provider ollama-signin` is for an Ollama daemon on this machine that you
signed in with `ollama signin`. That daemon serves Ollama Cloud models by
forwarding each request to `https://ollama.com` under your Ollama account. These
are models whose tag is `cloud` or ends in `-cloud`, such as
`gpt-oss:120b-cloud`. Open Trestle talks only to the loopback daemon, and it
stores and sends no API key. But **your repository source leaves this machine**:
the daemon sends it to Ollama Cloud. This is remote egress, and Open Trestle
treats it exactly like the other remote routes:

- The route's zone is `private_remote`, never `local`. The sanitizer and both
  secret scans run before every request, the scanner prerequisite applies, and
  `--egress local-only` refuses the route.
- The connection uses the closed request profile `ollama_signin_chat_v1` in
  runtime policy schema version 7. It is the only profile under which a
  loopback endpoint may serve a zone that is not local. It requires all of these:
  Chat Completions, `credential_mode` `none`, an endpoint of exactly
  `http://127.0.0.1:PORT/v1`, the provider ID `ollama-signin`, and model IDs
  with the Ollama cloud suffix. Every other profile, and a policy with no
  profile, still refuses a loopback endpoint in a remote zone.
- `init` reads the daemon's model list once (`GET /api/tags`, no source, no
  key). It refuses unless both models are listed with `remote_host`
  `https://ollama.com`. `check` repeats that read and sends no model request, so
  it cannot see a missing credit or a retired model. A model that is listed can
  still be retired.
- Budget, usage and timeout handling are the same as for `ollama-cloud`. The
  daemon relays Ollama Cloud's refusals. HTTP 402 (no usage credit) and 410
  (retired model) fail a review as `provider_payment_required` and
  `provider_model_retired`. HTTP 401 (not signed in) fails it as
  `provider_authentication_failed`. Each comes with a fixed hint, and Open
  Trestle never shows Ollama's own message (see
  [provider refusals](local-model-review.md#provider-refusals)).

`--declare-ollama-cloud-signin` is your explicit consent. It says that the daemon
is signed in to an Ollama account you control, and that each review sends the
selected source from that daemon to Ollama Cloud under that account, after secret
scanning. Without it, `init` refuses. Open Trestle records no claim about
retention or zero data retention for Ollama Cloud. Read Ollama's current terms
(https://docs.ollama.com/cloud). Setup does not prove that the daemon is signed
in; see the wizard's optional sign-in check below.

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

The model names are examples. Use two different cloud models that your daemon
lists. `--endpoint http://127.0.0.1:PORT/v1` replaces the default port, and
Open Trestle refuses any other address. It also refuses
`--generation-credential-environment`, because there is no key to name. It
refuses a model that your daemon runs locally. For such a model, use the
[local-first bootstrap](local-first-bootstrap.md).

In `trestle init`, choose "Ollama on this machine, signed in to Ollama Cloud".
The wizard checks that the `ollama` command is installed, reads the daemon's
model list and offers only its Ollama Cloud models. If you agree, it sends one
fixed test message, "Reply with OK", to the finder model to check the sign-in.
That message contains none of your code, but it goes to Ollama Cloud and counts
against your Ollama Cloud usage.

The wizard reacts to the daemon's answer as follows:

- On 401 or 403 (not signed in), the wizard offers to run `ollama signin` with
  your terminal attached, and runs it only if you answer `y`. It then sends the
  same message once more.
- On 402, the wizard says that Ollama Cloud refused the message for billing. It
  prints the review's hint ("the provider refused the request for billing: add
  credit or a subscription to the provider account, or choose another route")
  and asks whether to continue.
- On 404 or 410, the chosen model is not served or has been retired. The wizard
  prints the review's hint (for 410, "the provider no longer serves this model:
  choose a model the provider lists as available and re-run setup") and stops
  before it writes anything.

The wizard never reads or shows the body of the answer.

## Limits

- Bootstrap records your declarations and, for OpenRouter, what OpenRouter's API
  reported at setup time. It does not verify account settings, provider conduct,
  model capability, price or availability.
- The direct review runs in the foreground and leaves nothing behind. It has no
  resume, no daemon state and no publication. Investigation and retained memory
  stay local.
- The checkout source uses the existing bounded Git reader with the
  `loose-and-pack-index-v1` profile. Open Trestle does not review content that
  is only in the dirty worktree or the index.
- Live inference, credentials, sending private source to a provider and the
  resulting charges are your decision. Nothing here provisions credentials or
  signs you in to Ollama.

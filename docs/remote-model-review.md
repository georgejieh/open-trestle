# Remote model review

This guide shows how to run `trestle local-git model-review` against remote
models from a provider such as OpenRouter, Ollama Cloud or OpenCode Go.
`trestle setup bootstrap init --provider ...` writes the protected route
inventory, the runtime policy and the privacy witnesses, and derives every
identity that those files need, so you never write `routes.json` by hand or
compute a hash.

The review runs on the existing foreground direct path,
`local-git model-review --egress policy-approved`, which has no daemon, no
resume and no publication. It sends selected source code to the provider you
configure after Open Trestle has sanitized and scanned it. Bootstrap makes no
model call, and its only network requests are these:

- For `ollama-signin`, one `GET /api/tags` to your local Ollama daemon.
- For OpenRouter, one `GET` each of OpenRouter's public model list and its
  zero-data-retention endpoint list, both without a credential.

The supported providers are:

| `--provider` | Endpoint | Zone | Request profile |
|---|---|---|---|
| `openrouter-zdr` | `https://openrouter.ai/api/v1` | `brokered_remote` | [`openrouter_zdr_chat_v2`](openrouter-zdr-profile.md): zero data retention required on every request |
| `openrouter` | `https://openrouter.ai/api/v1` | `private_remote` | none (generic Chat Completions); zero data retention not required by Open Trestle |
| `opencode-go` | `https://opencode.ai/inference/go/openai/v1` | `brokered_remote` | [`opencode_go_chat_v1`](opencode-go-profile.md) |
| `ollama-cloud` | `https://ollama.com/v1` | `private_remote` | none (generic Chat Completions) |
| `ollama-signin` | `http://127.0.0.1:11434/v1` (your local Ollama, relaying to Ollama Cloud) | `private_remote` | `ollama_signin_chat_v1`, no credential |

Generation and verification use the same provider with two different models,
because the verification mode is `distinct_model`.

## Prerequisite 1: a trestle with its secret scanner

Open Trestle sends source to a remote provider only if every request passes two
Betterleaks scans in the secret scan helper. A plain `go build` pins no helper,
so it refuses every review. Use one of the two builds below.

On Linux or Windows (with Go 1.26.11 and Python 3), make a development build
and run `DIR/bin/trestle` (see [install](install.md#build-from-source) for what
it writes):

```sh
python3 tools/package_secret_scanner.py --development DIR
```

On Linux amd64 you can instead build the packaged binaries from a clean,
committed checkout and install the unsigned candidate (see
[operations](operations.md)):

```sh
python3 tools/package_secret_scanner.py --output .container
python3 tools/package_secret_scanner.py --verify .container
# build open-trestle-linux-amd64.pyz as described in docs/operations.md, then
sha256sum -c open-trestle-linux-amd64.pyz.sha256
sudo ./open-trestle-linux-amd64.pyz install
```

The packaging tool pins the helper's SHA-256 into both `trestle` and `trestled`
at link time. Before each start, the program checks the helper's location,
ownership, write permission and digest, as described in
[the secret-scanner runtime boundary](operations.md#secret-scanner-runtime-boundary).
If the helper is missing or changed, the review is refused with a message and
nothing is sent. Use the installed `/usr/local/bin/trestle` for every command
below.

The first review fills the scanner cache and prints `Preparing the secret
scanner for first use; this can take a minute.` For where the cache lives, see
[environment variables and files](environment-and-files.md#paths).

`bootstrap check` reports this prerequisite before any review:

- `refused` with `sanitized_egress_scanner` means that the binary pins no
  helper (a plain `go build`).
- `pending` with `sanitized_egress_scanner` means that the binary pins a helper,
  but the helper is missing or does not match.

### What the scan does

Before a request is authorized, the host extracts its typed text fields and
scans them in the helper. It replaces the reported bytes without changing the
byte length or the line breaks, and a second scan then checks the projected
request. Dispatch is denied unless both scans complete and the second finds
nothing. Generation and verification requests are sanitized separately.

The pinned scanner is Betterleaks v1.8.1, commit
`5eab48332cc48565864514e3bc6de89df091a7c4`, with 417 embedded default rules at
ruleset identity
`27ded783c81940d13c22cc46556a3f8184baf397bff08a69fcfae87991925f42`. It runs as a
WebAssembly guest in the helper and evaluates regular expressions with RE2. A
scan accepts 1 to 256 UTF-8 fields, with at most 256 KiB per field and 2 MiB in
total. Invalid input, a timeout, cancellation, resource exhaustion, a helper
fault or any remaining finding means that nothing is dispatched.

The scanner output and the durable receipt keep identities, counts, field roles,
rule IDs and byte spans, but no field text, path, snippet or matched value.
Because the spans reveal where a match is and how long it is, limit access to
receipts. The scanner cannot guarantee that a request contains no secret. False
negatives and false positives are possible, and the remote provider receives
the sanitized request.

## Prerequisite 2: credentials by name only

Every credential flag takes the **name** of an environment variable, and the
name must match `OPEN_TRESTLE_PROVIDER_[A-Z0-9_]+`. Open Trestle refuses a value
that looks like a key, and it stores only the name and a digest of the name.
Export the key from your approved secret store in the shell that runs `check`
and the review:

```sh
export OPEN_TRESTLE_PROVIDER_OPENROUTER="$(your-secret-tool read openrouter-key)"
```

`check` reports `credential_environment_present` as pending until it finds a key
for each named variable. It looks first in the environment and then in the
credential store that `trestle init` and `trestle keys set` write (see
[API keys](keys.md)), and it does not print or store the value. Use
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
recommendation. For OpenRouter, the context size, the output size, the prices
and the routing slugs come from OpenRouter's API (see [OpenRouter](#openrouter)).
Other providers also need `--context-tokens N --output-tokens N
--input-micro-usd-per-million-tokens N --output-micro-usd-per-million-tokens N`
and their own declarations, described below.

When `check` returns `ready` (exit 0), run its `review_command` array exactly as
printed. The command has this form:

`trestle local-git model-review --checkout ... --egress policy-approved --timeout 10m --format text --specialists auto`

It carries the base and head commit digests from the time of setup, and this
directory's `routes.json` and `policy.json`. It includes `--specialists auto`
unless you passed `--specialists none` to `init`. Because those commits describe
the change as it was at setup, run `trestle review` inside the repository to
review a later change with the same configuration and fresh commits (see
[getting started](getting-started.md#running-it-again)).

The saved `--timeout` depends on the output allowance (see
[Output allowance and request deadline](#output-allowance-and-request-deadline)).
For example, an OpenRouter setup with the 16384-token allowance uses
`--timeout 12m`.

`inspect` prints the same read-only report as `check`. A review that fails
prints a failure detail such as `provider_request_rejected` or
`provider_response_invalid` (see [Provider failures](#provider-failures)).

For the exit codes of `check`, see [exit codes](exit-codes.md#setup). Every
refusal prints a reason on stderr and in `messages`, and an input that fails
validation writes nothing. If you repeat `init` with identical inputs, it
accepts the existing files when they are byte-identical. When they differ, it
refuses, and you need a new directory. OpenRouter files embed the time the
model and endpoint lists were fetched, so a later repeat always differs and is
refused.

`check` reports these checks:

- `privacy_declaration_current` verifies that the current time falls within the
  declared review window. It applies to OpenCode Go, and to OpenRouter setups
  made before zero data retention was detected. The check is pending before
  `--valid-from`. After `--valid-until` it is refused, and you need a fresh
  review and directory.
- `dispatch_catalog_validated` verifies that the protected files build the
  catalog of dispatchers that the policy approves. It retrieves no credential
  and makes no request.
- `credential_environment_present` and `sanitized_egress_scanner` are described
  above.
- `ollama_cloud_models_listed` applies to `ollama-signin` only. It verifies that
  the local Ollama daemon still lists both models as Ollama Cloud models. The
  check is pending when the daemon is not running, and refused when the daemon
  no longer relays a model to `https://ollama.com`.

For OpenRouter, the result also carries `data_retention` (see
[the two routes](openrouter-zdr-profile.md#the-two-routes)).

`ready` means that these local prerequisites hold. It does not check the
provider or your declarations.

## Common declarations

Every provider requires `--declare-remote-route`, and `init` refuses without it.
With the flag, you declare that both models:

- Have the stated context and output capacity.
- Return structured JSON.
- Are used with content logging disabled.
- Cost no more than the stated per-million-token prices.
- Are currently available.

For OpenRouter, those facts come from its API, so the flag is your consent that
each review sends the selected source to OpenRouter, and your statement that
prompt logging is off for the key.

Each review reserves the output allowance plus the actual size of the request
against `--max-cost-micro-usd`, and `init` refuses a cap that cannot cover the
output reservation. The cap bounds each request, and `trestle init` derives it
from the cost of a request that fills the whole context (see
[getting started](getting-started.md#step-3-the-two-models)). To limit spending
over a week, a month or a year, set a per-key
[spending limit](spending-limits.md).

Set each price to the higher of the two models' prices, and declare `0` prices
only if your plan has no per-token charge. `--declared-by` names the operator
who is recorded in each evidence manifest. The endpoints of the named profiles
are fixed, so `--endpoint` is refused for them.

### Output allowance and request deadline

The output allowance is the most a model may write in one request (the runtime
policy's `max_output_tokens`), and it is separate from each route's declared
output capacity. It is 4096 tokens unless `--max-output-tokens N` raises it, up
to the declared `--output-tokens`. For OpenRouter it is 16384 tokens unless the
pinned endpoints allow less (see
[OpenRouter zero data retention](openrouter-zdr-profile.md#the-output-allowance)).

A reasoning model that spends the whole allowance on its reasoning fails with
`model_output_exhausted`. Where the endpoints accept it, OpenRouter requests ask
for low reasoning effort, which leaves most of the allowance for the answer (see
[OpenRouter zero data retention](openrouter-zdr-profile.md#the-two-routes)).
The wizard marks any model that OpenRouter lists as a reasoning model.

The built-in HTTP client gives each request a deadline of two minutes for every
4096 tokens of its output allowance, but never less than two minutes or more
than five, so a 16384-token allowance gets five minutes. A deadline that the
caller sets earlier still wins, so a shorter review `--timeout` ends a request
sooner. When the allowance gives a request more than four minutes, setup saves
a `--timeout` that leaves room for two such requests plus two minutes, up to 15
minutes.

## OpenRouter

Bootstrap reads `https://openrouter.ai/api/v1/endpoints/zdr` and
`https://openrouter.ai/api/v1/models` once each, without a key, and records the
SHA-256 and the time of each response. For each model, it pins the
zero-data-retention (ZDR) endpoints that allow the review output allowance and
records the endpoints it leaves out. The pinning rules are in
[OpenRouter zero data retention](openrouter-zdr-profile.md#what-setup-reads).

From the pinned endpoints, bootstrap fills in their routing slugs, the smallest
context and output limit, the highest input and output price, and the policy's
`max_output_tokens`, as OpenRouter's API reports them. Any of these flags
overrides the detected value: `--context-tokens`, `--output-tokens`,
`--max-output-tokens`, `--input-micro-usd-per-million-tokens`,
`--output-micro-usd-per-million-tokens` and `--*-provider-slug SLUG[,SLUG]`.

The two OpenRouter providers differ as follows:

- `--provider openrouter-zdr` requires ZDR on every request (`provider.zdr`),
  limited to the pinned endpoints. It refuses a model that has no ZDR endpoint,
  and says so. If it cannot read the API, pass the four capacity and price
  flags, and the route then requires ZDR without pinning endpoints.
- `--provider openrouter` does not require ZDR and pins nothing. It is a generic
  `private_remote` route that sends no provider controls, and `bootstrap check`
  and every review result say so. Its allowance is 16384 tokens, within the
  smaller output that the two models list.

For how requests are pinned, what the witness records and what an HTTP 404
from OpenRouter means, see
[OpenRouter zero data retention](openrouter-zdr-profile.md).

## OpenCode Go

`--declare-opencode-go-account` declares two things: that the key belongs to a
single-member Go workspace with privacy training and extra usage disabled, and
that both models document zero-day retention without training. Also supply
`--generation-model-evidence`, `--verification-model-evidence`,
`--broker-evidence` and `--account-evidence`, and the four times
`--evidence-retrieved-at`, `--reviewed-at`, `--valid-from` and `--valid-until`.
See [the OpenCode Go profile](opencode-go-profile.md).

This bootstrap uses the brokered Go route for both roles on the direct path. It
does not configure a daemon.

## Ollama Cloud

Ollama Cloud uses the generic `private_remote` zone with
`openai_chat_completions` at `https://ollama.com/v1`, and it authenticates with
a bearer token. There is no named Ollama request profile and no privacy
witness, so the route evidence manifest records only your own declaration. Open
Trestle makes no claim about Ollama's retention, so review its current privacy
terms and your plan before you send private source.

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
Open Trestle does not check them. Ollama answers HTTP 402 when the account has
no usage credit, and HTTP 410 for a retired model (see
[Provider failures](#provider-failures)).

`--endpoint` may replace the base with another remote HTTPS Ollama Cloud base,
but Open Trestle refuses loopback and private endpoints. For models that run on
this machine, use the [local-first bootstrap](local-first-bootstrap.md). For a
local Ollama that is signed in to Ollama Cloud, use `ollama-signin`, described
next.

## Ollama signed in to Ollama Cloud

`--provider ollama-signin` is for an Ollama daemon on this machine that you
signed in with `ollama signin`. That daemon serves Ollama Cloud models, whose
tag is `cloud` or ends in `-cloud` (such as `gpt-oss:120b-cloud`), by forwarding
each request to `https://ollama.com` under your Ollama account. Open Trestle
talks only to the loopback daemon, and it stores and sends no API key. But
**your repository source leaves this machine**, because the daemon sends it to
Ollama Cloud. Open Trestle therefore treats this route like the other remote
routes:

- The route's zone is `private_remote`, not `local`. The sanitizer and both
  secret scans run before every request, the scanner prerequisite applies, and
  `--egress local-only` refuses the route.
- The connection uses the closed request profile `ollama_signin_chat_v1` in
  runtime policy schema version 7, the only profile under which a loopback
  endpoint may serve a zone that is not local. The profile requires Chat
  Completions, `credential_mode` `none`, an endpoint of
  `http://127.0.0.1:PORT/v1`, the provider ID `ollama-signin`, and model IDs
  with the Ollama cloud suffix. Every other profile, and a policy with no
  profile, still refuses a loopback endpoint in a remote zone.
- `init` reads the daemon's model list once (`GET /api/tags`, with no source
  and no key) and refuses unless both models are listed with `remote_host`
  `https://ollama.com`. `check` repeats that read but sends no model request, so
  it cannot detect a missing credit or a retired model.
- Budget, usage and timeout handling are the same as for `ollama-cloud`, and the
  daemon relays Ollama Cloud's refusals. HTTP 401 (not signed in) fails a review
  as `provider_authentication_failed` (see [Provider failures](#provider-failures)).

`--declare-ollama-cloud-signin` is your explicit consent, and `init` refuses
without it. It states that the daemon is signed in to an Ollama account you
control, and that each review sends the selected source from that daemon to
Ollama Cloud under that account, after secret scanning. Open Trestle makes no
claim about Ollama Cloud retention, so read Ollama's current terms
(https://docs.ollama.com/cloud). Setup does not check that the daemon is signed
in, but the wizard offers an optional sign-in check, described below.

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

The model names are examples, so use two different cloud models that your
daemon lists. `--endpoint http://127.0.0.1:PORT/v1` changes the default port,
and Open Trestle refuses any other address. It also refuses
`--generation-credential-environment`, because there is no key to name, and it
refuses a model that your daemon runs locally. For such a model, use the
[local-first bootstrap](local-first-bootstrap.md).

In `trestle init`, choose "Ollama on this machine, signed in to Ollama Cloud".
The wizard checks that the `ollama` command is installed, reads the daemon's
model list and offers only its Ollama Cloud models. If you agree, it checks the
sign-in by sending one fixed test message, "Reply with OK", to the finder model.
The message contains none of your code, but it goes to Ollama Cloud and counts
against your usage there. The wizard then acts on the daemon's answer, without
ever showing the body of an error answer:

- On 401 or 403 (not signed in), it offers to run `ollama signin` with your
  terminal attached, runs it only if you answer `y`, and then sends the message
  once more.
- On 402, it says that Ollama Cloud refused the message for billing, prints the
  review's hint and asks whether to continue.
- On 404 or 410 (the model is not served or has been retired), it prints the
  review's hint and stops before it writes anything.

## Provider failures

Open Trestle classifies a provider's HTTP refusal by its status alone. It
discards the error body, so a provider's message never reaches a result, record
or log. Every request profile, including OpenCode Console, uses this mapping:

| HTTP status | Route failure | Run failure | `failure_detail` |
|---|---|---|---|
| 400, 405, 415, 422 | `request_rejected` | `policy` | `provider_request_rejected` |
| 401 | `authentication` | `policy` | `provider_authentication_failed` |
| 402 | `payment_required` | `policy` | `provider_payment_required` |
| 403 | `authorization` | `policy` | `provider_authorization_denied` |
| 404 | `model_unavailable` | `policy` | `provider_model_unavailable` |
| 410 | `model_retired` | `policy` | `provider_model_retired` |
| 429, or 503 with a `Retry-After` in seconds | `rate_limited` | `transient` | `provider_rate_limited` |
| 408, 504 | `timeout` | `transient` | none |
| 413 | `budget_exhausted` | `policy` | none |
| other 5xx | `provider_server` | `transient` | none |
| 200 with a reply the adapter refuses, or a status no other row names (for example 409) | `invalid_response` | `internal` | `provider_response_invalid` |

A `policy` run is `refused` with the CI disposition `blocked` and exit code 4,
and a `transient` run is `failed` with exit code 1. A review prints the failing
task, the detail and a fixed one-line hint, for example
`failure: policy (task candidates): provider_payment_required`. A 400 usually
means an unknown model ID or a parameter that the model or endpoint does not
accept. On an OpenRouter route, a 404 records `provider_no_allowed_endpoint`
instead (see
[OpenRouter zero data retention](openrouter-zdr-profile.md#when-openrouter-refuses-a-request)).

A rate limit is the only provider refusal that is retried, because the provider
refused the request before processing it. The model handler retries the request
on the same route at most twice within the task attempt, each time waiting for
the provider's `Retry-After` and at least one second. If the `Retry-After` is
more than 15 minutes away or would end after the review's `--timeout`, the task
fails at once. A retry takes over the cost reservation of the refused attempt,
which records known zero usage. If the second retry is also rate-limited, the
review fails as `transient` with `provider_rate_limited`.

When the adapter accepts a reply but the review then refuses the answer, Open
Trestle records `model_output_invalid` with the `internal` failure, and the
result's `model_output_problem` and the hint say what was wrong (see
[failure details](failure-details.md)). Two forms are accepted before the same
strict checks:

- An answer that is one complete JSON object followed only by text that is not
  JSON (for example a stray template token) is read as that object, and the
  tail is ignored. Text before the object, a second document or an incomplete
  one is still refused.
- On an OpenRouter or Ollama Cloud sign-in route, a single outer Markdown code
  fence (with no language or with `json`) around the whole answer is removed.

A reply that stops at the output limit records `model_output_exhausted` (see
[Output allowance and request deadline](#output-allowance-and-request-deadline)).

In `trestle review`, when an answer is `model_output_invalid` (other than a
`refusal`) or ends as `model_output_exhausted`, its request is sent once more.
The finder and the checker each get one such retry, which repeats the same
request on the same route, with nothing added and without the rejected answer.
If the second answer is valid, the review goes on. If not, the review fails with
the second answer's detail and class. The retry is a second paid request with
its own cost reservation. The rejected answer's tokens and cost stay counted in
`token_usage`, `actual_cost_micro_usd` and the usage ledger, and the retry is
refused if it could take a key past its spending limit (see
[spending limits](spending-limits.md)). A request gets at most two same-route
retries in all, so a request that was already rate-limited twice gets no answer
retry. What the result records after a retry is in
[failure details](failure-details.md). Neither the result nor the text output
quotes the rejected answer.

A daemon run classifies refusals the same way and records the same detail as
its task failure reason. `trestle runs status` prints the detail and its hint
on stderr.

## Limits

- Bootstrap records your declarations and, for OpenRouter, what OpenRouter's
  API reported at setup time. It does not verify them.
- The direct review runs in the foreground. It keeps a repository index and
  spending records, but it has no resume, no daemon state and no publication.
- The checkout source uses the Git reader with the `loose-and-pack-index-v1`
  profile. Open Trestle does not review content that exists only in the dirty
  worktree or the index.
- Nothing here provisions credentials. The wizard runs `ollama signin` only if
  you agree.

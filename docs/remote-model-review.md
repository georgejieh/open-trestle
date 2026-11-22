# Remote model review

This guide shows how to run `trestle local-git model-review` against remote
models from a provider such as OpenRouter, Ollama Cloud or OpenCode Go. It takes
a few commands. `trestle setup bootstrap init --provider ...` writes the
protected route inventory, the runtime policy and the privacy witnesses, and
derives every identity that those files need. You do not write `routes.json` by
hand or compute a hash.

The review itself is the existing foreground direct path,
`local-git model-review --egress policy-approved`. It sends selected source
code to the provider you configure, after Open Trestle has sanitized and
scanned it. Bootstrap makes no model call. It makes only these network
requests:

- For `ollama-signin`, one `GET /api/tags` to your local Ollama daemon.
- For OpenRouter, one `GET` each of OpenRouter's public model list and its
  zero-data-retention endpoint list, both without a credential.

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
different models. The verification mode is `distinct_model`, which means that
the two models differ.

## Prerequisite 1: a trestle with its secret scanner

Open Trestle refuses to send source to a remote provider unless every request
passes two Betterleaks scans in the secret scan helper. A plain `go build` pins
no helper, so it refuses every review. Use one of two builds.

On Linux or Windows (needs Go 1.26.11 and Python 3), build a development
build and run `DIR/bin/trestle`:

```sh
python3 tools/package_secret_scanner.py --development DIR
```

`DIR` is relative to the current directory. Add `--target GOOS/GOARCH` to build
for another system. The tool writes `DIR/bin/trestle`, `DIR/bin/trestled` and
`DIR/libexec/open-trestle/open-trestle-scan-helper` (`.exe` names for Windows).
The helper is the file that the two programs check before each review.

On Linux amd64 you can instead build the packaged binaries from a clean
committed checkout and install the unsigned candidate (see
[operations](operations.md)):

```sh
python3 tools/package_secret_scanner.py --output .container
python3 tools/package_secret_scanner.py --verify .container
# build open-trestle-linux-amd64.pyz as described in docs/operations.md, then
sha256sum -c open-trestle-linux-amd64.pyz.sha256
sudo ./open-trestle-linux-amd64.pyz install
```

The packaging tool pins the SHA-256 of the helper into both `trestle` and
`trestled` at link time. `install` places the helper at
`/usr/local/libexec/open-trestle/open-trestle-scan-helper` as a root-owned
`0555` file. The programs look for the helper at
`<folder of the program>/../libexec/open-trestle/open-trestle-scan-helper`.
Before each start they check that the file is not writable, is owned by you or
root (on Windows, by you or a system account), and matches the pinned SHA-256.
A missing or changed helper refuses the review with a message, and nothing is
sent. Use the installed `/usr/local/bin/trestle` for every command below.

The first review fills the scanner cache and prints `Preparing the secret
scanner for first use; this can take a minute.` See
[environment variables and files](environment-and-files.md#paths) for where it
lives.

`bootstrap check` reports this prerequisite before any review:

- `refused` with `sanitized_egress_scanner` means that this binary pins no
  helper (a plain `go build`).
- `pending` with `sanitized_egress_scanner` means that the binary pins a helper,
  but the helper is missing or does not match.

### What the scan does

Before a request is authorized, the host extracts its typed text fields and scans
them in the helper. It replaces reported bytes without changing the byte length
or the line breaks. A second scan then checks the projected request. Dispatch is
denied unless both scans complete and the second finds nothing. Generation and
verification are sanitized separately.

The pinned scanner is Betterleaks v1.8.1, commit
`5eab48332cc48565864514e3bc6de89df091a7c4`, with 417 embedded default rules at
ruleset identity
`27ded783c81940d13c22cc46556a3f8184baf397bff08a69fcfae87991925f42`. It runs as a
WebAssembly guest in the helper and evaluates regular expressions with RE2. A
scan accepts 1 to 256 UTF-8 fields, with at most 256 KiB per field and 2 MiB in
total. Invalid input, a timeout, cancellation, resource exhaustion, a helper
fault or any remaining finding produces no remote dispatch.

The scanner output and the durable receipt keep identities, counts, field roles,
rule IDs and byte spans, and no field text, path, snippet or matched value. The
spans reveal the location and length of a match, so limit access to receipts.
The scanner does not guarantee that a request contains no secret: false
negatives and false positives are possible, and a remote provider receives the
sanitized request.

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
[API keys](keys.md)). It does not print or store the value. Use
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

When `check` returns `ready` (exit 0), run its `review_command` array as
printed. The command has this form:

`trestle local-git model-review --checkout ... --egress policy-approved --timeout 10m --format text --specialists auto`

It carries the base and head commit digests from the moment of setup, and this
directory's `routes.json` and `policy.json`. `--specialists auto` is present
unless you passed `--specialists none` to `init`.

Those commits describe the change that existed at setup. Inside the repository, `trestle review` reviews the latest
change with the same configuration and fresh commits (see
[getting started](getting-started.md#running-it-again)).

The saved `--timeout` depends on the output allowance (see
[Output allowance and request deadline](#output-allowance-and-request-deadline)).
An OpenRouter setup with the 16384-token allowance, for example, uses
`--timeout 12m`.

`inspect` prints the same read-only report as `check`. A review that fails
prints a failure detail such as `provider_request_rejected` or
`provider_response_invalid`; see [Provider failures](#provider-failures).

The exit codes of `check` are 0 for `ready`, 3 for `pending` and 4 for
`refused`. Usage errors exit 2. Every refusal prints a reason on stderr and in
`messages`. An input that fails validation writes nothing. If you repeat `init`
with identical inputs, it accepts the existing files when they are byte-identical.
OpenRouter files embed the time the model and endpoint lists were fetched, so a
repeat at a later time differs and is refused. If the files differ, it refuses,
so use a new directory.

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
request requires, not what a provider retains.

`ready` means that these local prerequisites hold. It does not check the provider
or your declarations.

## Common declarations

Every provider requires `--declare-remote-route`. With it, you declare that
both models:

- Have the stated context and output capacity.
- Return structured JSON.
- Are used with content logging disabled.
- Cost no more than the stated per-million-token prices.
- Are currently available.

Without the flag, `init` refuses. For OpenRouter, those facts come from its API,
so the flag is your consent that each review sends the selected source to
OpenRouter, and your statement that prompt logging is off for the key.

Each review reserves the output allowance plus the actual size of the request
against `--max-cost-micro-usd`. `init` refuses a cap that cannot cover the
output reservation. (`trestle init` computes the reservation as the cost of a
request that fills the whole context, rounded up to a cent.) The cap bounds each
request. To limit spending over a week, a month or a year, set a per-key
[spending limit](spending-limits.md).

Set the prices to the higher of the two models. Declare `0` prices only if your
plan has no per-token charge. `--declared-by` names the operator who is recorded
in each evidence manifest.

The generation and verification models must differ. The endpoints of the named
profiles are fixed, so `--endpoint` is refused for them.

### Output allowance and request deadline

The output allowance is the most a model may write in one request (the runtime
policy's `max_output_tokens`). It is 4096 tokens unless `--max-output-tokens N`
raises it, up to the declared `--output-tokens`. For OpenRouter it is 16384 tokens
unless the pinned endpoints allow less (see
[OpenRouter zero data retention](openrouter-zdr-profile.md#the-output-allowance)).
It is separate from the declared output capacity of each route. A reasoning model
that spends the whole allowance on its reasoning fails with
`model_output_exhausted`.

The built-in HTTP client gives each request a deadline of two minutes for every
4096 tokens of its output allowance, with a minimum of two minutes and a maximum
of five. A 16384-token allowance therefore gets five minutes. A deadline that the
caller sets earlier still wins, so the `--timeout` of the review ends a request
earlier when it is shorter. When the allowance gives a request more than four
minutes, setup saves a `--timeout` that leaves room for two such requests plus
two minutes, up to 15 minutes.

## OpenRouter

Bootstrap reads `https://openrouter.ai/api/v1/endpoints/zdr` and
`https://openrouter.ai/api/v1/models` once each, without a key. It records the
SHA-256 and the time of each response.

For each model, bootstrap pins the zero-data-retention (ZDR) endpoints that
allow the review output allowance and records the endpoints it leaves out. The
pinning rules are in
[OpenRouter zero data retention](openrouter-zdr-profile.md#what-setup-reads).

From the pinned endpoints, bootstrap fills in their routing slugs, the
smallest context and output limit, the highest input and output price, and the
policy's `max_output_tokens`. Any of these flags overrides the detected value:
`--context-tokens`, `--output-tokens`, `--max-output-tokens`,
`--input-micro-usd-per-million-tokens`, `--output-micro-usd-per-million-tokens`
and `--*-provider-slug SLUG[,SLUG]`. Bootstrap records these facts as OpenRouter's
API reports them.

Without ZDR (`--provider openrouter`), bootstrap pins nothing. The allowance is
16384 tokens, within the smaller output that the two models list.

The two OpenRouter providers differ as follows:

- `--provider openrouter-zdr` requires ZDR on every request (`provider.zdr`),
  limited to the pinned endpoints. It refuses a model that has no ZDR endpoint,
  and says so. If it cannot read the API, pass the four flags for capacity and
  price. The route then requires ZDR without pinning endpoints.
- `--provider openrouter` does not require ZDR. It is a generic `private_remote`
  route that sends no provider controls. `bootstrap check` and every review
  result say so.

If OpenRouter refuses a request with HTTP 404, Open Trestle records
`provider_no_allowed_endpoint` with a hint that names the ZDR setting. For how
requests are pinned and what the witness records, see
[OpenRouter zero data retention](openrouter-zdr-profile.md).

## OpenCode Go

`--declare-opencode-go-account` declares two things: that the key belongs to a
single-member Go workspace with privacy training and extra usage disabled, and
that both models document zero-day retention without training. Supply
`--generation-model-evidence`, `--verification-model-evidence`,
`--broker-evidence` and `--account-evidence`, plus the same four times. See
[the OpenCode Go profile](opencode-go-profile.md).

This bootstrap uses the brokered Go route for both roles on the direct path. It
does not configure a daemon.

## Ollama Cloud

Ollama Cloud uses the generic `private_remote` zone with
`openai_chat_completions` at `https://ollama.com/v1`, and it authenticates with a
bearer token. There is no named Ollama request profile and no privacy witness.
The route evidence manifest records only your own declaration. Open Trestle
makes no claim about Ollama's retention, so review its current privacy terms
and your plan before you send private source.

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
answers HTTP 402, and for a retired model it answers HTTP 410 (see
[Provider failures](#provider-failures)).

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
the daemon sends it to Ollama Cloud. Open Trestle treats this like the other
remote routes:

- The route's zone is `private_remote`, not `local`. The sanitizer and both
  secret scans run before every request, the scanner prerequisite applies, and
  `--egress local-only` refuses the route.
- The connection uses the closed request profile `ollama_signin_chat_v1` in
  runtime policy schema version 7. It is the only profile under which a
  loopback endpoint may serve a zone that is not local. It requires all of these:
  Chat Completions, `credential_mode` `none`, an endpoint of
  `http://127.0.0.1:PORT/v1`, the provider ID `ollama-signin`, and model IDs
  with the Ollama cloud suffix. Every other profile, and a policy with no
  profile, still refuses a loopback endpoint in a remote zone.
- `init` reads the daemon's model list once (`GET /api/tags`, no source, no
  key). It refuses unless both models are listed with `remote_host`
  `https://ollama.com`. `check` repeats that read and sends no model request, so
  it cannot see a missing credit or a retired model.
- Budget, usage and timeout handling are the same as for `ollama-cloud`. The
  daemon relays Ollama Cloud's refusals. HTTP 401 (not signed in) fails a review
  as `provider_authentication_failed` (see [Provider failures](#provider-failures)).

`--declare-ollama-cloud-signin` is your explicit consent. It says that the daemon
is signed in to an Ollama account you control, and that each review sends the
selected source from that daemon to Ollama Cloud under that account, after secret
scanning. Without it, `init` refuses. Open Trestle makes no claim about
Ollama Cloud retention; read Ollama's current terms
(https://docs.ollama.com/cloud). Setup does not check that the daemon is signed
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
  prints the review's hint and asks whether to continue.
- On 404 or 410, the chosen model is not served or has been retired. The wizard
  prints the review's hint and stops before it writes anything.

The wizard does not show the body of an error answer.

## Provider failures

A provider's HTTP refusal is classified by its status alone. Open Trestle discards
the error body, so a provider's message never reaches a result, record or
log. Every request profile, including OpenCode Console, uses the same mapping:

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

A `policy` run is `refused` with the CI disposition `blocked` and exit code 4. A
`transient` run is `failed` with exit code 1. A review prints the failing task,
the detail and a fixed one-line hint, for example
`failure: policy (task candidates): provider_payment_required`. A 400 is usually
an unknown model ID or a parameter that the model or endpoint does not accept. On
an OpenRouter route a 404 records `provider_no_allowed_endpoint` instead (see
[OpenRouter zero data retention](openrouter-zdr-profile.md#when-openrouter-refuses-a-request)).

A rate limit is the only retried failure. The provider refused the request before
processing it, so the model handler retries it on the same route at most twice
inside the task attempt. Each retry waits for the `Retry-After` of the provider
and at least one second. If the `Retry-After` is beyond 15 minutes or would end
after the review's `--timeout`, the task fails at once. A retry takes over the
cost reservation of the refused attempt, and the refused attempt records known
zero usage. A 503 without a `Retry-After` in seconds is a `provider_server`
failure and is not retried. When the second retry is rate-limited too, the review
fails as `transient` with `provider_rate_limited`.

A reply that the adapter accepted but the review then refuses records
`model_output_invalid` with the `internal` failure. This covers an answer that is
not one JSON document, a refusal, a document of the wrong shape and a document
that breaks the review rules. Nothing is repaired. The one exception is on an
OpenRouter or Ollama Cloud sign-in route: a single outer Markdown code fence
(with no language or with `json`) around the whole answer is removed before the
same strict checks. A reply that stops at the output limit records
`model_output_exhausted` (see
[Output allowance and request deadline](#output-allowance-and-request-deadline)).

A daemon run classifies refusals the same way and records the same detail as its
task failure reason. `trestle runs status` prints the detail and its hint on
stderr.

## Limits

- Bootstrap records your declarations and, for OpenRouter, what OpenRouter's API
  reported at setup time. It does not verify them.
- The direct review runs in the foreground. It keeps a repository index and
  spending records. It has no resume, no daemon state and no publication.
- The checkout source uses the Git reader with the `loose-and-pack-index-v1`
  profile. Open Trestle does not review content that is only in the dirty
  worktree or the index.
- Nothing here provisions credentials. The wizard runs `ollama signin` only if you
  agree.

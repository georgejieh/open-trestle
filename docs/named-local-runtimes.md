# Named local runtimes

These maintained templates use the existing protected inventory, policy binding,
setup checker and shared OpenAI-compatible Chat adapter. There is no separate
runtime registry. Choose one explicitly; none is a default. LM Studio is the
selected Mac server: its official requirements cover Apple Silicon on macOS 14+
(not Intel Macs). This selection is not a claim of Mac-host qualification.

| Directory under `examples/named-local-runtimes/` | Generation API base | Verification API base | Exact model selectors |
| --- | --- | --- | --- |
| `llama-cpp` | `http://127.0.0.1:8080/v1` | `http://127.0.0.1:8081/v1` | `trestle-generation`, `trestle-verification` |
| `ollama-local` | `http://127.0.0.1:11434/v1` | same | `qwen3:8b`, `gemma3:4b` |
| `vllm` | `http://127.0.0.1:8000/v1` | `http://127.0.0.1:8001/v1` | `trestle-generation`, `trestle-verification` |
| `lm-studio` | `http://127.0.0.1:1234/v1` | same | `trestle-generation`, `trestle-verification` |

All connections select `implementation:openai_chat_completions` and
`credential_mode:none`. No dummy key is necessary. For an authenticated local
server, explicitly change the connection to `bearer` with a protected credential
environment reference using the existing policy contract. Do not put keys in JSON.
These templates require two different underlying models, not two aliases for one
model. Different aliases alone do not prove model independence. The policy uses
`distinct_model`, not `distinct_provider`; choose a stronger independent pair if
your review requirements demand one.

## Server preparation

The following commands are recipes for an operator who has already installed the
server and obtained approved local model files. They were not executed to qualify
these templates. Do not download a model, start a server, or send a probe without
permission. Replace uppercase paths/keys with your selected local artifacts.
Record the server build, exact model file digests, configuration, template,
capacity and logging posture in your route evidence before approval. Load chat
models whose ordinary assistant output follows the required review JSON schema.
No tool calling, remote URLs, MCP, or model download is part of this path.

### Context length

Each template route declares `max_context_tokens: 32768`, and each recipe below
starts its server with the same context length: llama.cpp `--ctx-size`, Ollama
`OLLAMA_CONTEXT_LENGTH`, vLLM `--max-model-len` and LM Studio
`lms load --context-length`. Keep the declaration and the server setting equal;
lower both together only for a model that cannot hold 32768 tokens. Open Trestle
reserves every request as a byte-based upper bound on its input tokens (a token
never covers less than one byte) plus the output allowance, and refuses a route
whose declared context is smaller, rather than risk a server silently
truncating an over-long prompt, which could drop the trusted system message.
Even the fixed setup probe reserves about 9,700 tokens, and a review request is
larger, so an 8192-token context cannot run any review.

### llama.cpp

Run two foreground servers in separate terminals with distinct GGUF files:

```sh
llama-server -m /APPROVED/GENERATION.gguf --alias trestle-generation --host 127.0.0.1 --port 8080 --ctx-size 32768
llama-server -m /APPROVED/VERIFICATION.gguf --alias trestle-verification --host 127.0.0.1 --port 8081 --ctx-size 32768
```

The alias is the API selector. Keep the route `model_version` empty, since a
nonempty value overrides `model_id` on the wire. Use a supported chat template.
The shared adapter accepts the documented inert `timings` fields and optional
`message.reasoning_content`; neither becomes review output or authoritative
usage. Unsupported fields still refuse. Avoid reasoning-only or tool-only
responses. This path does not request streaming or llama.cpp control APIs.

### Ollama local

A loopback Ollama endpoint can relay cloud models. Loopback alone does **not**
prove local inference. Start the server with cloud features disabled and inspect
the documented `Ollama cloud disabled: true` log after restart:

```sh
OLLAMA_NO_CLOUD=1 OLLAMA_HOST=127.0.0.1:11434 OLLAMA_CONTEXT_LENGTH=32768 ollama serve
```

Use only locally present `qwen3:8b` and `gemma3:4b` artifacts, or replace both
selectors with your explicit local choices and rebind. Inspect `ollama list` and
local artifact evidence; do not use `:cloud` selectors, sign in, or implicitly
pull missing models. The template cannot attest the server environment or inspect
its routing. Host egress restrictions provide an additional boundary when needed.
Any returned selector must equal the configured string, including the tag.

> **Warning: `:cloud` models do not run on this machine.** A model whose name
> ends in `:cloud` or `-cloud` (for example `gpt-oss:120b-cloud`), or whose
> `GET /api/tags` entry carries a `remote_host`, is forwarded by the local Ollama
> to Ollama Cloud, so your source would leave this machine. The local bootstrap
> and `trestle init` refuse such a model with "this model runs on Ollama Cloud,
> not on this machine; use --provider ollama-signin". They refuse a cloud name
> whether or not the server lists it yet, ask the server's `/api/tags` list once
> at setup for the `remote_host` check, and refuse when an Ollama daemon answers
> that path but its list cannot be read.
> To use those models deliberately, as remote egress with the sanitizer and
> secret scanner, see
> [Ollama signed in to Ollama Cloud](remote-model-review.md#ollama-signed-in-to-ollama-cloud).

A thinking model whose response adds unsupported fields will refuse; qualify the
exact model/server combination rather than weakening response admission.

### vLLM

Run two servers on the same host with distinct already-present local model
folders. Select the intended device/resources separately for each process:

```sh
HF_HUB_OFFLINE=1 VLLM_NO_USAGE_STATS=1 vllm serve /APPROVED/GENERATION --host 127.0.0.1 --port 8000 --served-model-name trestle-generation --max-model-len 32768
HF_HUB_OFFLINE=1 VLLM_NO_USAGE_STATS=1 vllm serve /APPROVED/VERIFICATION --host 127.0.0.1 --port 8001 --served-model-name trestle-verification --max-model-len 32768
```

Use one served name per process. vLLM documents that the response uses the first
served name when multiple names are supplied; aliases are not interchangeable
under exact selector admission. Chat models need a chat template. Do not enable
remote model code or development/weight-update APIs for this path. Inspect and
disable prompt/content logging before declaring it disabled in route evidence.
Usage-stat opt-out is not proof of no other egress. vLLM is not the selected Mac
server; use a supported vLLM host/runtime.

### LM Studio on Mac

Use two different already-downloaded local models from `lms ls`, not LM Link
remote devices. In an explicitly authorized running local LM Studio instance:

```sh
lms load GENERATION_MODEL_KEY --identifier trestle-generation --context-length 32768
lms load VERIFICATION_MODEL_KEY --identifier trestle-verification --context-length 32768
lms server start --bind 127.0.0.1 --port 1234
```

The identifiers are the selectors in the templates, not model names to download.
Keep serving on loopback, do not enable CORS, MCP or LM Link, and inspect local
logging and just-in-time model loading settings. The recipe uses preloaded
artifacts only. LM Studio documents offline local serving once models exist;
that is not a measurement of this host or an assurance about unrelated features.
If server authentication is enabled, use explicit bearer credentials instead.

## Use the existing configuration and setup caller

1. Copy your selected directory's `routes.json` and
   `runtime-policy.template.json` into a private directory owned by you or root.
   Use mode `0600` for files and `0700` for the directory. Do not bind repository
   files as protected production configuration.
2. Replace the illustrative review-policy identity, model/capability declarations
   and base64 evidence manifest with your reviewed inputs. The examples use
   `pending`, unknown health/quota/logging/pricing and unmeasured latency on
   purpose. The named templates are not readiness evidence. Never promote these
   placeholders merely to make a check pass. After qualification, record approved
   registry status, measured health/quota, content logging disabled and known
   local pricing (zero provider charge does not mean zero hardware cost).
3. Bind the protected copies through the existing offline command:

```sh
trestle config bind \
  --route-inventory /PROTECTED/routes.json \
  --runtime-policy-template /PROTECTED/runtime-policy.template.json \
  --generation-adapter local-generation \
  --verification-adapter local-verification
```

Save stdout as a new protected `runtime-policy.json`. Binding creates identities,
not approval or model calls. Run `trestle config validate` with the same inventory
and bound policy. Follow [Setup planning](setup.md#runtime-policy-approval-and-dry-run)
to initialize the local plan, record the returned identities and recovery-owner
approval, run `setup check policy`, and only with explicit probe consent run
`setup check inference`. That existing caller builds the shared local catalog
from these exact connections. The probe uses a fixed tiny synthetic source
function through the existing candidate and verification request builders, not
repository/private source. It permits two requests at most, 256 output tokens
per request, reported input up to each request's own byte-based reservation,
one 90-second deadline and no fallback.
No server startup, model download or credential discovery is implicit.

These files also feed the existing local model-review and opt-in full-review
runtime paths. See [Local model review](local-model-review.md) for source selection
and [Setup planning](setup.md) for durable setup. A successful probe is not a
finding-quality evaluation or publication permission.

## Offline fixtures and limits

Each named directory ships `generation.response.json`,
`verification.response.json` and `refusal.response.json`. These are synthetic
protocol fixtures derived from the documented Chat contract, **not recorded live
service responses**. The selectors match the templates. llama.cpp includes its
documented timings extension. The refusal is deliberately synthetic: local
models may express refusal as ordinary text, which is not magically converted to
a structured refusal. Such text cannot pass candidate/verifier JSON admission.

`setup/named_local_runtimes_test.go` copies and binds these exact templates into
owned temporary files. Only those temporary test copies receive synthetic
approved/healthy declarations and ephemeral fixture endpoints. Tests cover:

- Pending templates bind but cannot pass setup readiness.
- Exact selector, POST path, trusted system/user messages, no authentication,
  `max_tokens` and `stream:false` through the shared confined local transport.
- Known prompt/completion usage; absent usage stays unknown; inconsistent totals
  and mismatched returned selectors refuse.
- Refusal remains refusal rather than a finding; setup requires valid empty
  candidate/verifier objects and known bounded usage.
- Cancellation before dispatch sends nothing; in-flight cancellation stops the
  client and the owned fake server observes cancellation. This is not proof that
  a real engine has reclaimed memory or stopped GPU work. No server cancel or
  administrative abort endpoint is called.
- The actual setup inference checker reaches both shared adapters, parses the
  fixed contracts and passes for an owned synthetic pair for every template.

The decoder keeps an 8 MiB response-body bound and rejects unknown fields.
Timings do not fill missing usage. Separate adapter tests reject malformed,
negative, overflowing or unknown timings, invalid reasoning types and oversize
bodies, and prove reasoning text does not become review content. No fixture
establishes live service conformance, no-cloud operation, intended-host/Mac
qualification, model quality or privacy approval. Those remain explicit operator
qualification inputs.

## Official references

Read on 2026-10-31. These are current moving documentation URLs, not a pinned
server version. Recheck them against the installed version before qualification.

- [llama.cpp server](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md):
  alias/host/port/context flags; Chat endpoint; standard usage, timings and
  reasoning content. llama.cpp explicitly does not make a strong universal
  OpenAI compatibility claim.
- [Ollama OpenAI compatibility](https://docs.ollama.com/api/openai-compatibility):
  local `/v1/chat/completions`, model selectors, supported subset and cloud relay.
- [Ollama FAQ](https://docs.ollama.com/faq): `OLLAMA_NO_CLOUD`, loopback binding,
  restart/log confirmation, context length and local-only mode.
- [vLLM online serving](https://docs.vllm.ai/en/latest/serving/online_serving/):
  Chat route and chat-template requirement.
- [vLLM serve arguments](https://docs.vllm.ai/en/stable/cli/serve/):
  local model path, binding, context length and first served-name response rule.
- [vLLM usage statistics](https://docs.vllm.ai/en/stable/usage/usage_stats/):
  explicit metadata collection opt-out.
- [LM Studio Chat](https://lmstudio.ai/docs/developer/openai-compat/chat-completions):
  Chat endpoint, supported `messages`, `max_tokens`, `stream` and model fields.
- [LM Studio load](https://lmstudio.ai/docs/cli/local-models/load) and
  [server start](https://lmstudio.ai/docs/cli/serve/server-start):
  local keys, exact custom identifiers, context length and explicit loopback bind.
- [LM Studio offline operation](https://lmstudio.ai/docs/app/offline) and
  [system requirements](https://lmstudio.ai/docs/app/system-requirements):
  downloaded local model serving and the selected Mac host requirements.

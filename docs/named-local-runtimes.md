# Named local runtimes

Four maintained configuration templates set up both review models to run on your own machine, with llama.cpp, Ollama, vLLM or LM Studio. They use the protected inventory, the policy binding, the setup checker and the shared OpenAI-compatible Chat adapter.

Choose one template; none of them is a default. LM Studio's own requirements cover Apple Silicon on macOS 14 or later (not Intel Macs), but Open Trestle itself is not supported on macOS (see [platforms](platforms.md#macos)).

`trestle init` does not use these templates. It looks for a server at the default ports (Ollama 11434, LM Studio 1234, llama.cpp 8080, vLLM 8000), offers whatever answers, and writes its own setup folder. Use the templates when you bind and check the configuration by hand.

| Directory under `examples/named-local-runtimes/` | Generation API base | Verification API base | Model selectors |
| --- | --- | --- | --- |
| `llama-cpp` | `http://127.0.0.1:8080/v1` | `http://127.0.0.1:8081/v1` | `trestle-generation`, `trestle-verification` |
| `ollama-local` | `http://127.0.0.1:11434/v1` | same | `qwen3:8b`, `gemma3:4b` |
| `vllm` | `http://127.0.0.1:8000/v1` | `http://127.0.0.1:8001/v1` | `trestle-generation`, `trestle-verification` |
| `lm-studio` | `http://127.0.0.1:1234/v1` | same | `trestle-generation`, `trestle-verification` |

All connections select `implementation:openai_chat_completions` and `credential_mode:none`, so no dummy key is needed. The templates need two different underlying models, not two aliases for one model, because the policy uses `distinct_model`, not `distinct_provider`.

## Server preparation

The recipes below assume that you have already installed the server and obtained the local model files. Replace the uppercase paths and keys with the local artifacts you selected.

Before you approve the route, record the server build, the model file digests, the configuration, the chat template, the capacity and the logging posture in your route evidence. Load chat models whose ordinary assistant output follows the required review JSON schema. Tool calling, remote URLs, MCP and model downloads are not part of this path.

### Context length

Each template route declares `max_context_tokens: 32768`, and each recipe below starts its server with the same context length: `--ctx-size` for llama.cpp, `OLLAMA_CONTEXT_LENGTH` for Ollama, `--max-model-len` for vLLM and `lms load --context-length` for LM Studio. Keep the declaration and the server setting equal, and lower both together only for a model that cannot hold 32768 tokens.

Open Trestle reserves every request as a byte-based upper bound on its input tokens (a token never covers less than one byte) plus the output allowance, and it refuses a route whose declared context is smaller. The setup probe alone reserves about 9,700 tokens, and a review request is larger, so an 8192-token context cannot run any review.

When a route is too small, the refusal names the tokens the review needs, the context the route declares and what to raise (see [Local model review](local-model-review.md#route-context-too-small)).

### llama.cpp

Run two foreground servers in separate terminals, with distinct GGUF files:

```sh
llama-server -m /APPROVED/GENERATION.gguf --alias trestle-generation --host 127.0.0.1 --port 8080 --ctx-size 32768
llama-server -m /APPROVED/VERIFICATION.gguf --alias trestle-verification --host 127.0.0.1 --port 8081 --ctx-size 32768
```

The alias is the API selector. Keep the route `model_version` empty, because a nonempty value overrides `model_id` on the wire, and use a supported chat template.

The shared adapter accepts the documented `timings` fields and the optional `message.reasoning_content`, but neither becomes review output or usage. Unsupported fields are refused, so avoid responses that contain only reasoning or only tool calls. This path does not request streaming or the llama.cpp control APIs.

### Ollama local

A loopback Ollama endpoint can relay cloud models, so a loopback address does **not** mean that inference is local. Start the server with cloud features disabled, restart, and check the log for the documented line `Ollama cloud disabled: true`:

```sh
OLLAMA_NO_CLOUD=1 OLLAMA_HOST=127.0.0.1:11434 OLLAMA_CONTEXT_LENGTH=32768 ollama serve
```

Use only the `qwen3:8b` and `gemma3:4b` artifacts that are already present locally, or replace both selectors with your own explicit local choices and rebind. Check `ollama list` and the local artifact evidence. Do not use `:cloud` selectors, sign in, or pull missing models. The template cannot check the server environment or its routing, so add restrictions on host egress when you need that boundary. Any selector the server returns must equal the configured string, including the tag.

> **Warning: `:cloud` models do not run on this machine.** A model whose name
> ends in `:cloud` or `-cloud` (for example `gpt-oss:120b-cloud`), or whose
> `GET /api/tags` entry carries a `remote_host`, is forwarded by the local Ollama
> to Ollama Cloud, so your source would leave this machine. The local bootstrap
> and `trestle init` refuse such a model with "this model runs on Ollama Cloud,
> not on this machine; use --provider ollama-signin". They refuse a cloud name
> whether or not the server lists it. For the `remote_host` check they read the
> server's `/api/tags` list at setup, once for each model role, and they refuse
> when an Ollama daemon answers that path but its list cannot be read.
> To use those models deliberately, as remote egress with the sanitizer and
> secret scanner, see
> [Ollama signed in to Ollama Cloud](remote-model-review.md#ollama-signed-in-to-ollama-cloud).

A thinking model whose response adds unsupported fields is refused.

### vLLM

Run two servers on the same host, each with its own local model folder, and select the device and resources separately for each process:

```sh
HF_HUB_OFFLINE=1 VLLM_NO_USAGE_STATS=1 vllm serve /APPROVED/GENERATION --host 127.0.0.1 --port 8000 --served-model-name trestle-generation --max-model-len 32768
HF_HUB_OFFLINE=1 VLLM_NO_USAGE_STATS=1 vllm serve /APPROVED/VERIFICATION --host 127.0.0.1 --port 8001 --served-model-name trestle-verification --max-model-len 32768
```

Use one served name per process. vLLM documents that when you supply several names, the response uses the first one, so aliases are not interchangeable. Chat models need a chat template. Do not enable remote model code or the development and weight-update APIs for this path. Inspect prompt and content logging and disable it before you declare content logging disabled in the route evidence. Use a host and runtime that vLLM supports.

### LM Studio

Use two different local models that are already downloaded (see `lms ls`), not remote devices from LM Link. Run these commands in a local LM Studio instance that you control:

```sh
lms load GENERATION_MODEL_KEY --identifier trestle-generation --context-length 32768
lms load VERIFICATION_MODEL_KEY --identifier trestle-verification --context-length 32768
lms server start --bind 127.0.0.1 --port 1234
```

The identifiers are the selectors in the templates, not model names to download. Keep serving on loopback, and do not enable CORS, MCP or LM Link. Inspect the local logging settings and the just-in-time model loading settings. The recipe uses preloaded models only. If you enable server authentication, use bearer credentials instead.

## Use the existing configuration and setup caller

1. Copy `routes.json` and `runtime-policy.template.json` from your selected directory into a private directory that you or root own. Use mode `0600` for the files and `0700` for the directory. Do not bind repository files as protected production configuration.
2. Replace the example review-policy identity, the model and capability declarations and the base64 evidence manifest with your own. The examples use `pending` and unknown health, quota, logging and pricing, with unmeasured latency. Do not promote these placeholders just to make a check pass. Once you have checked your setup, record the approved registry status, the measured health and quota, content logging disabled, and the known local pricing. A zero provider charge does not mean zero hardware cost.
3. Bind the protected copies with the existing offline command:

```sh
trestle config bind \
  --route-inventory /PROTECTED/routes.json \
  --runtime-policy-template /PROTECTED/runtime-policy.template.json \
  --generation-adapter local-generation \
  --verification-adapter local-verification
```

Save stdout as a new protected `runtime-policy.json`. Binding creates identities and makes no model calls. Then run `trestle config validate` with the same inventory and the bound policy.

The optional local inference check builds the shared local catalog from these connections. `trestle init` asks before it runs the check, and `trestle setup bootstrap check` runs it only with `--allow-local-probe`.

The probe sends a tiny synthetic source function, never repository or private source, through the candidate and verification request builders. It allows at most two requests, 256 output tokens per request, reported input up to each request's own byte-based reservation, one 90-second deadline and no fallback. Nothing starts a server, downloads a model or discovers a credential.

These files also feed the local model-review and opt-in full-review runtime paths. See [Local model review](local-model-review.md) for source selection and [Setup plan](setup.md) for the plan itself.

## Servers without an API key

Some local model servers do not need an API key. Runtime policy schema v2 lets you declare that with `credential_mode: "none"` on a connection. It applies to an approved `local` route whose endpoint is a numeric loopback address, and it works with the `openai_responses` and `openai_chat_completions` implementations. The templates above use it.

```json
{
  "implementation": "openai_chat_completions",
  "adapter_id": "local-chat",
  "endpoint": "http://127.0.0.1:1234/v1",
  "credential_mode": "none"
}
```

Do not include `credential_environment`, even as an empty string or null. No key, placeholder or environment reference is needed, and Open Trestle neither resolves credentials nor sends an Authorization header for this connection. The inventory must still contain a matching approved `local` namespace, and schema v2 requires its explicit grant for a verification route. Pass the protected runtime policy and route inventory to `trestle local-git model-review` as usual.

If you omit `credential_mode`, the connection keeps bearer authentication and still requires its credential environment. An explicit `"bearer"` does not change that connection's identity. For a local server that requires authentication, set `bearer` explicitly with a protected credential environment reference, and never put keys in JSON.

Open Trestle refuses `none` for a remote endpoint, a remote route zone, a loopback hostname such as `localhost`, and a connection with conflicting credential authority. Setting `none` does not approve a route or change sanitization or logging policy, and Open Trestle cannot tell whether a local server forwards content elsewhere.

## Offline fixtures

Each named directory ships `generation.response.json`, `verification.response.json` and `refusal.response.json`. These are synthetic protocol fixtures based on the documented Chat contract, not recorded live service responses. The tests in `setup/named_local_runtimes_test.go` bind copies of the templates and check them against the shared adapters. The fixtures do not show that a live service conforms or that your host works.

The adapter decoder limits response bodies to 8 MiB and rejects unknown fields. A local model may express a refusal as ordinary text, and Open Trestle does not convert that text into a structured refusal, so such a reply cannot pass candidate or verifier JSON admission.

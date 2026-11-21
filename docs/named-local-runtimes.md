# Named local runtimes

This page covers four maintained configuration templates for running both review models on your own machine: llama.cpp, Ollama, vLLM and LM Studio. The templates use the protected inventory, the policy binding, the setup checker and the shared OpenAI-compatible Chat adapter.

Choose one template. None of them is a default. LM Studio is the Mac server, and its requirements cover Apple Silicon on macOS 14 or later (not Intel Macs).

`trestle init` does not use these templates. It looks for a server at the default ports (Ollama 11434, LM Studio 1234, llama.cpp 8080, vLLM 8000), offers whatever answers, and writes its own setup folder. Use the templates when you bind and check the configuration by hand.

| Directory under `examples/named-local-runtimes/` | Generation API base | Verification API base | Model selectors |
| --- | --- | --- | --- |
| `llama-cpp` | `http://127.0.0.1:8080/v1` | `http://127.0.0.1:8081/v1` | `trestle-generation`, `trestle-verification` |
| `ollama-local` | `http://127.0.0.1:11434/v1` | same | `qwen3:8b`, `gemma3:4b` |
| `vllm` | `http://127.0.0.1:8000/v1` | `http://127.0.0.1:8001/v1` | `trestle-generation`, `trestle-verification` |
| `lm-studio` | `http://127.0.0.1:1234/v1` | same | `trestle-generation`, `trestle-verification` |

All connections select `implementation:openai_chat_completions` and `credential_mode:none`, so no dummy key is necessary. For a local server that requires authentication, change the connection to `bearer` explicitly, with a protected credential environment reference. Do not put keys in JSON.

The templates need two different underlying models, not two aliases for one model. The policy uses `distinct_model`, not `distinct_provider`.

## Server preparation

The commands below are recipes for a server that you have already installed, with local model files that you have already obtained. Replace the uppercase paths and keys with the local artifacts you selected.

Before you approve the route, record these in your route evidence: the server build, the model file digests, the configuration, the chat template, the capacity and the logging posture. Load chat models whose ordinary assistant output follows the required review JSON schema. Tool calling, remote URLs, MCP and model downloads are not part of this path.

### Context length

Each template route declares `max_context_tokens: 32768`, and each recipe below starts its server with the same context length. The setting is `--ctx-size` for llama.cpp, `OLLAMA_CONTEXT_LENGTH` for Ollama, `--max-model-len` for vLLM and `lms load --context-length` for LM Studio. Keep the declaration and the server setting equal. Lower both together only for a model that cannot hold 32768 tokens.

Open Trestle reserves every request as a byte-based upper bound on its input tokens (a token never covers less than one byte) plus the output allowance. It refuses a route whose declared context is smaller. The setup probe alone reserves about 9,700 tokens, and a review request is larger, so an 8192-token context cannot run any review.

When a route is too small, the refusal names the tokens the review needs, the context the route declares and what to raise (see [Local model review](local-model-review.md#route-context-too-small)).

### llama.cpp

Run two foreground servers in separate terminals, with distinct GGUF files:

```sh
llama-server -m /APPROVED/GENERATION.gguf --alias trestle-generation --host 127.0.0.1 --port 8080 --ctx-size 32768
llama-server -m /APPROVED/VERIFICATION.gguf --alias trestle-verification --host 127.0.0.1 --port 8081 --ctx-size 32768
```

The alias is the API selector. Keep the route `model_version` empty, because a nonempty value overrides `model_id` on the wire. Use a supported chat template.

The shared adapter accepts the documented `timings` fields and the optional `message.reasoning_content`. Neither becomes review output or usage. Unsupported fields are refused. Avoid responses that contain only reasoning or only tool calls. This path does not request streaming or the llama.cpp control APIs.

### Ollama local

A loopback Ollama endpoint can relay cloud models, so a loopback address does **not** mean that inference is local. Start the server with cloud features disabled, restart, and check the log for the documented line `Ollama cloud disabled: true`:

```sh
OLLAMA_NO_CLOUD=1 OLLAMA_HOST=127.0.0.1:11434 OLLAMA_CONTEXT_LENGTH=32768 ollama serve
```

Use only the `qwen3:8b` and `gemma3:4b` artifacts that are already present locally, or replace both selectors with your own explicit local choices and rebind. Check `ollama list` and the local artifact evidence. Do not use `:cloud` selectors, sign in, or pull missing models. The template cannot check the server environment or its routing. Restrictions on host egress add a boundary when you need one. Any selector the server returns must equal the configured string, including the tag.

> **Warning: `:cloud` models do not run on this machine.** A model whose name
> ends in `:cloud` or `-cloud` (for example `gpt-oss:120b-cloud`), or whose
> `GET /api/tags` entry carries a `remote_host`, is forwarded by the local Ollama
> to Ollama Cloud, so your source would leave this machine. The local bootstrap
> and `trestle init` refuse such a model with "this model runs on Ollama Cloud,
> not on this machine; use --provider ollama-signin". They refuse a cloud name
> whether or not the server lists it, read the server's `/api/tags` list once
> at setup for the `remote_host` check, and refuse when an Ollama daemon answers
> that path but its list cannot be read.
> To use those models deliberately, as remote egress with the sanitizer and
> secret scanner, see
> [Ollama signed in to Ollama Cloud](remote-model-review.md#ollama-signed-in-to-ollama-cloud).

A thinking model whose response adds unsupported fields is refused.

### vLLM

Run two servers on the same host, each with its own local model folder. Select the device and resources separately for each process:

```sh
HF_HUB_OFFLINE=1 VLLM_NO_USAGE_STATS=1 vllm serve /APPROVED/GENERATION --host 127.0.0.1 --port 8000 --served-model-name trestle-generation --max-model-len 32768
HF_HUB_OFFLINE=1 VLLM_NO_USAGE_STATS=1 vllm serve /APPROVED/VERIFICATION --host 127.0.0.1 --port 8001 --served-model-name trestle-verification --max-model-len 32768
```

Use one served name per process. vLLM documents that, when you supply several names, the response uses the first one. Aliases are therefore not interchangeable. Chat models need a chat template. Do not enable remote model code or development and weight-update APIs for this path. Before you declare content logging disabled in the route evidence, inspect prompt and content logging and disable it. vLLM is not the Mac server, so use a supported vLLM host and runtime.

### LM Studio on Mac

Use two different local models that are already downloaded (see `lms ls`), not remote devices from LM Link. Run these commands in a local LM Studio instance that you control:

```sh
lms load GENERATION_MODEL_KEY --identifier trestle-generation --context-length 32768
lms load VERIFICATION_MODEL_KEY --identifier trestle-verification --context-length 32768
lms server start --bind 127.0.0.1 --port 1234
```

The identifiers are the selectors in the templates, not model names to download. Keep serving on loopback and do not enable CORS, MCP or LM Link. Inspect the local logging settings and the just-in-time model loading settings. The recipe uses preloaded models only. If you enable server authentication, use bearer credentials instead.

## Use the existing configuration and setup caller

1. Copy `routes.json` and `runtime-policy.template.json` from your selected directory into a private directory that you or root own. Use mode `0600` for the files and `0700` for the directory. Do not bind repository files as protected production configuration.
2. Replace the example review-policy identity, the model and capability declarations and the base64 evidence manifest with your own. The examples use `pending` and unknown health, quota, logging and pricing, with unmeasured latency. Do not promote these placeholders only to make a check pass. After you have checked your setup, record the approved registry status, the measured health and quota, content logging disabled, and the known local pricing. A zero provider charge does not mean zero hardware cost.
3. Bind the protected copies with the existing offline command:

```sh
trestle config bind \
  --route-inventory /PROTECTED/routes.json \
  --runtime-policy-template /PROTECTED/runtime-policy.template.json \
  --generation-adapter local-generation \
  --verification-adapter local-verification
```

Save stdout as a new protected `runtime-policy.json`. Binding creates identities and makes no model calls. Run `trestle config validate` with the same inventory and the bound policy.

The optional local inference check builds the shared local catalog from these connections. `trestle init` asks before it runs the check, and `trestle setup bootstrap check` runs it only with `--allow-local-probe`.

The probe sends a tiny synthetic source function through the candidate and verification request builders. It does not send repository or private source. It allows at most two requests, 256 output tokens per request, reported input up to each request's own byte-based reservation, one 90-second deadline and no fallback. Nothing starts a server, downloads a model or discovers a credential.

These files also feed the local model-review and opt-in full-review runtime paths. See [Local model review](local-model-review.md) for source selection and [Setup plan](setup.md) for the setup plan.

## Offline fixtures and limits

Each named directory ships `generation.response.json`, `verification.response.json` and `refusal.response.json`. These are synthetic protocol fixtures based on the documented Chat contract, **not recorded live service responses**. The selectors match the templates, and the llama.cpp fixtures include its documented timings extension. Local models may express a refusal as ordinary text, and Open Trestle does not convert that text into a structured refusal; it cannot pass candidate or verifier JSON admission.

`setup/named_local_runtimes_test.go` copies and binds these templates into temporary files. Only those copies receive synthetic approved and healthy declarations and temporary fixture endpoints. The tests cover these cases:

- Pending templates bind but cannot pass setup readiness.
- The shared confined local transport sends the selector, the POST path, system and user messages, no authentication, `max_tokens` and `stream:false`.
- Known prompt and completion usage is accepted. Absent usage stays unknown. Inconsistent totals and mismatched returned selectors are refused.
- A refusal does not become a finding. Setup requires valid empty candidate and verifier objects and known, bounded usage.
- Cancellation before dispatch sends nothing. In-flight cancellation stops the client, and the fake server observes it. No server cancel or abort endpoint is called, so a real engine may keep working.
- The setup inference checker reaches both shared adapters, parses the contracts and passes for a synthetic pair, for every template.

The decoder limits response bodies to 8 MiB and rejects unknown fields. Timings do not fill in missing usage. Separate adapter tests reject malformed, negative, overflowing or unknown timings, invalid reasoning types and oversize bodies, and they show that reasoning text does not become review content.

The fixtures do not show that a live service conforms or that your host works.

## Official references

These were read on 2026-10-31. They are current documentation URLs, not a pinned server version. Check them against your installed version.

- [llama.cpp server](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md): alias, host, port and context flags, the Chat endpoint, and standard usage, timings and reasoning content. llama.cpp makes no universal claim of OpenAI compatibility.
- [Ollama OpenAI compatibility](https://docs.ollama.com/api/openai-compatibility): local `/v1/chat/completions`, model selectors, the supported subset and the cloud relay.
- [Ollama FAQ](https://docs.ollama.com/faq): `OLLAMA_NO_CLOUD`, loopback binding, confirmation by restart and log, context length and local-only mode.
- [vLLM online serving](https://docs.vllm.ai/en/latest/serving/online_serving/): the Chat route and the chat-template requirement.
- [vLLM serve arguments](https://docs.vllm.ai/en/stable/cli/serve/): the local model path, binding, context length and the rule that the response uses the first served name.
- [vLLM usage statistics](https://docs.vllm.ai/en/stable/usage/usage_stats/): the explicit opt-out from metadata collection.
- [LM Studio Chat](https://lmstudio.ai/docs/developer/openai-compat/chat-completions): the Chat endpoint and the supported `messages`, `max_tokens`, `stream` and model fields.
- [LM Studio load](https://lmstudio.ai/docs/cli/local-models/load) and [server start](https://lmstudio.ai/docs/cli/serve/server-start): local keys, exact custom identifiers, context length and an explicit loopback bind.
- [LM Studio offline operation](https://lmstudio.ai/docs/app/offline) and [system requirements](https://lmstudio.ai/docs/app/system-requirements): serving of downloaded local models and the requirements of the selected Mac host.

# Local-first bootstrap

`trestle setup bootstrap` prepares and checks a review of one repository that uses models running on your own machine. `trestle init` runs the commands on this page for you and is the usual way to set up such a review; see [getting started](getting-started.md). Use `trestle setup bootstrap` directly when you need the daemon scope or want to script the setup. Install the Linux amd64 binaries first, with the [distribution instructions](operations.md).

The journey is advisory and local-only: it runs as one user and uses authenticated access. It configures machinery that already exists. During initialization it does not install a service, start a daemon, download models, provision credentials or make a model request.

## Choose the repository and model pair

### The repository

Prepare an ordinary checkout that you own, with both selected commits already present. The resolved Git objects directory must already be a private `0700` directory with trusted ownership and no symlink path components. Bootstrap refuses a normal Git-created `0755` objects directory before it writes any output.

Check the exact resolved objects path and its ownership before you select it. Change that objects directory to `0700` only if you own the private checkout and have confirmed that no shared readers need access. Do not change a shared checkout's permissions just to pass setup. Choose a separate private checkout that you own instead. Bootstrap never changes checkout permissions, repacks, or repairs the source directory.

Name the commits with a full `refs/heads/...` or `refs/tags/...` name, `HEAD`, or a full lowercase commit ID. Bootstrap does not fetch and does not infer a merge base. It resolves and pins the commits with the existing bounded Git metadata reader. It does not review dirty worktree or index content.

The durable daemon currently requires complete loose Git commit, tree and blob objects. A source that exists only in pack files is refused during initialization, and the command does not repack or copy your repository. Linked worktrees can use the shared object directory that they resolve to, if that source meets the same requirements.

### The direct-review scope

These source rules exist for the durable daemon, which pins the objects root for its lifetime. To prepare only the foreground `local-git model-review --checkout` review, add `--scope direct-review` to `init`. That scope reads both commits with the review's own `loose-and-pack-index-v1` reader, which verifies every object against its hash. An ordinary packed clone with a `0755` objects folder is therefore accepted. Alternates, multi-pack-index and promisor packs are still refused.

With this scope, the manifest records the scope and carries no daemon `review_command`, `launch_command` or `status_command`. `prepare-review` and `check --scope daemon` refuse it. `trestle init` uses this scope for local servers.

### The models

Select two distinct local model IDs, their exact API bases and a transport. Neither the provider nor the model has a shipped default. Both servers may be the same local service running different models. Bootstrap requires `distinct_model` verification, which does not claim that the two selectors come from different training families.

The `--declare-local-capabilities` flag is an explicit declaration by you, the operator. It says that both models:

- are actually local, not a loopback gateway to cloud inference
- support structured output
- have the capacities you supplied
- do not log content
- have zero inference price
- are currently available

These declarations produce route eligibility records, not measured proof that the service conforms. Do not pass the flag if you do not know those facts. The receipt keeps that distinction. See [local model review](local-model-review.md) for transport limits.

```sh
install -d -m 0700 "$HOME/.local/state/open-trestle/bootstrap"
install -d -m 0700 "$HOME/.local/state/open-trestle/backups"

trestle setup bootstrap init \
  --directory "$HOME/.local/state/open-trestle/bootstrap" \
  --tenant personal --repository project --recovery-owner owner \
  --checkout /approved/project --base refs/heads/main --head HEAD \
  --repository-authority local.test --repository-namespace personal \
  --repository-name project \
  --generation-endpoint http://127.0.0.1:8080/v1 \
  --generation-model YOUR_GENERATION_MODEL \
  --verification-endpoint http://127.0.0.1:8081/v1 \
  --verification-model YOUR_DIFFERENT_VERIFIER_MODEL \
  --transport openai_responses \
  --context-tokens 128000 --output-tokens 8192 \
  --declare-local-capabilities
```

Replace every path, model and scope label with your own choices. The example capacity is illustrative, and it is neither a recommendation nor a measurement.

Both models must declare at least 8192 tokens of context and 4096 of output, and the declared context must not exceed the context length that each server is started with. Reviews reserve input as a byte-based upper bound, so a review request needs well over 8192 tokens. The [named local runtimes](named-local-runtimes.md#context-length) declare and start 32768.

Generated reviews have a review output allowance of 4096 tokens by default, and a zero monetary budget. `--max-output-tokens` raises the allowance, up to `--output-tokens`. The built-in review-policy version derives its identity from local-only, distinct-model, no-publication behavior. You never compute inventory, route, policy or setup hashes yourself.

### Other transports and servers

Use `openai_chat_completions` instead for servers that are compatible with Chat Completions. The endpoint must be a canonical numeric loopback API base. The generated policy states explicitly that local access is anonymous.

For a local server that needs bearer authentication, add `--generation-credential-environment OPEN_TRESTLE_PROVIDER_LOCAL_GENERATION`, `--verification-credential-environment OPEN_TRESTLE_PROVIDER_LOCAL_VERIFICATION`, or both. Bootstrap stores only the references. Provision those environment values through your approved secret store before you check or review. Never paste secrets into CLI flags, checked-in files or receipts.

Do not use this local mode for remote services, cloud model selectors, browser sessions or sign-in token caches. For OpenRouter, OpenCode Go or Ollama Cloud models, use the remote mode in [remote model review](remote-model-review.md). There, `init --provider` writes the protected remote configuration, and `check` reports the scanner and credential prerequisites for the direct `--egress policy-approved` review.

## Check and resume

### What initialization writes

Initialization writes the protected `0600` inventory, policy template, bound policy and `bootstrap.json` in the existing private `0700` directory. It creates private `0700` `runs` and `runs/setup` directories there. The single setup plan is `runs/setup/plan.json`, and its `.lock` and `.receipts` ledger sit beside it.

The daemon command that bootstrap prints uses `runs` as its state root and that same nested setup plan. Bootstrap uses the existing configuration binder and protected writers. It returns `pending` (exit 3), not a false ready state.

Repeating the same initialization accepts byte-identical files without overwriting them. A different configuration at an existing output path is refused. You can repeat an interrupted initialization with the same selections. Unknown or partial files are not overwritten or deleted, so inspect and preserve them before you choose a fresh private directory. Never modify the plan or the receipt ledger by hand.

### Older bootstrap directories

These bootstrap commands, including `init` and `inspect`, refuse older bootstrap directories that have `plan.json`, `plan.json.lock`, `plan.json.receipts` or `plan.json.next` directly under the bootstrap directory. No legacy setup is copied, moved, deleted or migrated automatically. Preserve the old root and its commands, and use a fresh private bootstrap directory for a new selection.

A daemon command printed by an earlier bootstrap that uses an external setup plan is not necessarily blocked at startup, but it does not provide the nested setup layout that the offline `recovery-point` needs. Moving state directories that are bound to an owner, or copying only the plan, is not a supported repair. Any offline transfer of setup history needs separate review and the complete, verified receipt ledger. This bootstrap command does not perform that transfer and does not qualify the recovery of old runs.

### Tokens

Provision separate random operator and observer tokens of at least 32 bytes each, in `OPEN_TRESTLE_API_TOKEN` and `OPEN_TRESTLE_OBSERVER_TOKEN` respectively. Use your approved secret-management path, not command arguments. Bootstrap creates, prints, hashes and copies no credential values.

### Run the checks

```sh
# Offline policy/storage/identity/credential-posture checks only.
trestle setup bootstrap check \
  --directory "$HOME/.local/state/open-trestle/bootstrap" --approved-by owner

# Explicitly permit two bounded requests containing only fixed synthetic code.
# This still sends no repository source.
trestle setup bootstrap check \
  --directory "$HOME/.local/state/open-trestle/bootstrap" --approved-by owner \
  --allow-local-probe \
  --backup-directory "$HOME/.local/state/open-trestle/backups"

trestle setup bootstrap inspect \
  --directory "$HOME/.local/state/open-trestle/bootstrap"
```

### What `check` does

The approval label must match the recovery owner. The checker records the existing checks for storage, administrator, observer credential, policy, dry-run, local inference and backup. The backup directory must be protected and outside the live bootstrap directory. Its snapshot name is derived automatically from the current plan.

A missing permission, a missing credential, an unavailable model, invalid model output or an unsupported backup location cannot become ready. Correct the dependency and repeat `check`.

When a model server refuses the probe with HTTP 400, 401, 402, 403, 404, 405, 410, 415, 422 or 429, the result adds `messages`. Each message names the check, the review's failure detail and its fixed hint, for example `local_inference_validated: provider_model_unavailable: the provider does not serve this model at this endpoint: ...`. `trestle init` shows the same reason. The server's own message is never shown. Otherwise `messages` is absent, and `check` sends no request beyond the probe.

- A probe that is rejected as an invalid request (400, 405, 415 or 422, for example an unknown model ID) names `provider_request_rejected`. `trestle init` says the server refused the test request, with the hint to check the model ID, the endpoint and its transport, structured output support and the output allowance.
- A probe that the server answered with HTTP 200 and a reply the adapter refused names `provider_response_invalid`. So does a probe answered with a status that no failure class names (such as 409, but not a 5xx). `trestle init` says the server answered the test request with a reply not in the expected format.

Passed checks are historical receipts, not fresh liveness checks. Repeated calls do not silently repeat a successful inference probe. `inspect` is read-only and never contacts models.

### The direct-review scope

You record the direct-review scope with `init --scope direct-review`, or request it with `check --scope direct-review` on a daemon setup. In this scope, `check` runs the storage, administrator, policy and dry-run checks, plus the local inference probe when you pass `--allow-local-probe`. It skips the observer-token and backup checks, which the foreground review never uses.

The result carries `"scope": "direct-review"` and omits the daemon commands. It is `ready` when those checks have passed, and a probe that was attempted and failed still counts as attempted. The setup plan itself is unchanged and is not ready for a daemon. `--backup-directory` is refused in this scope.

### Exit codes and readiness

`ready` (exit 0) means that these setup checks passed. It does not mean the release is ready, that the model quality is qualified, or that a daemon is running. `pending` (exit 3) lists the checks that are not complete. `refused` (exit 4) means an unsafe input or a blocked checker. Usage errors use exit 2, and output failures use exit 1. Unavailable checkers keep setup from being ready. The canonical plan remains the source of setup readiness.

## Launch and request the first review

Start the daemon with `launch_command`. When you are ready to submit source, prepare one persisted first-review intent. This creates a new protected `review-intent.json` exactly once. Repeated calls, `check` and `inspect` reuse its timestamp and commands. Preparation makes no model request and uploads no source.

```sh
trestle setup bootstrap prepare-review \
  --directory "$HOME/.local/state/open-trestle/bootstrap"
```

The JSON result includes exact argument arrays:

- `launch_command`: the foreground `trestled` with protected state, the setup root, the source identity, the runtime policy, local full-review admission and model workers.
- `review_command`: `trestle local-git submit-review` with the exact immutable commits, all derived policy identities, a stable first-review run ID and a persisted creation time.
- `status_command`: retrieves the canonical diagnostics for that run.
- `ephemeral_review_command`: an optional direct checkout model review. This path is separate and has no durable resume. Do not mistake it for daemon work.

Execute each array as arguments. Do not join it into an unescaped shell string, and do not run `eval`. For example, copy the array values into your process launcher. If you use a shell, quote every argument separately. Bootstrap never executes these commands. Its receipt contains non-secret paths and labels, but keep it private, because they can reveal local machine and repository names.

### Start the daemon

Start the daemon with the operator and observer tokens in its environment. Keep it in the foreground, and stop it with the existing shutdown procedure. Bootstrap generates no systemd unit and no unattended job. The generated listener is `127.0.0.1:8741` by default, so make sure that port is free. The submit and status commands bind `http://127.0.0.1:8741` explicitly rather than inheriting another API URL.

### Submit the review

Execute `review_command` only after you approve the use of your source, and with the operator token in its environment. This is the separate boundary where repository source goes to the model. It requests the review pipeline on the pinned commits: nine tasks over eight stage kinds, because source is acquired once for the base and once for the head. The ordinary checkout is a local source authority, not authentication of a forge origin.

This command enables no publication task and no forge credentials. The runtime still needs its existing pinned scanner binaries and host confinement support. Bootstrap does not install or weaken those dependencies. A refusal at startup is not readiness.

Submit within five minutes of `prepare-review` for the first admission, so prepare only after the daemon is running. Inspection never refreshes that identity. Save the exact submit array and repeat it for retries after admission. If you miss the first-admission window, the submission stays refused. Do not edit or delete the intent file to manufacture freshness. Prepare a new, explicit setup in a fresh protected directory if you need one.

Use `status_command` to inspect the durable result. A successful submit or status retrieval is not approval of the review. Read the findings, the coverage, the omissions, the abstention and the uncertainty. Empty diagnostics and results with no candidates do not clear the repository. See [daemon API](daemon-api.md), [setup](setup.md), and [local model review](local-model-review.md) for recovery and the limits of results.

## Stopped-state recovery comparison

For a newly initialized bootstrap, the printed `--state-dir` is `DIR/runs` and `--setup-state` is `DIR/runs/setup/plan.json`. This is the nested setup layout that the [offline recovery comparison](operations.md#offline-in-place-recovery-comparison) requires.

Stop the daemon with SIGTERM and wait for the process and its workers to exit. Only then take a consistent backup or run `recovery-point` and `verify-restore`. Retain the state, artifact and Git-root directory identities and the exact runtime assets. A matching comparison reports `restart_authorized:false`. It does not approve a restart, model quality, durability across power loss or a portable restore. A setup-only backup preserves the setup receipt ledger, not application state.

A new change or a different model configuration needs a new, explicit bootstrap selection in a fresh protected directory. This command does not change old runs, rotate credentials, authorize remote egress or transfer historical approvals.

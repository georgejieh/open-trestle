# Local-first bootstrap

Use `trestle setup bootstrap` after installing the Linux amd64 binaries with the
[distribution instructions](operations.md). This is a same-user,
authenticated, local-only advisory journey. It configures existing machinery;
it does not install a service, start a daemon, download models, provision
credentials, or make a model request during initialization.

## Choose the repository and model pair

Prepare an owned ordinary checkout with both selected commits already present.
The resolved Git objects directory must already be a private `0700` directory
with trusted ownership and no symlink path components. A normal Git-created
`0755` objects directory is refused before any bootstrap output is written.
Check the exact resolved objects path and its ownership before selecting it.
Only an operator who owns that private checkout and has confirmed that no shared
readers need access should change that chosen objects directory to `0700`.
Do not change a shared checkout's permissions merely to pass setup; choose a
separate owned private checkout instead. Bootstrap never changes checkout
permissions, repacks, or repairs the source directory.
Use full `refs/heads/...` or `refs/tags/...` names, `HEAD`, or full lowercase commit
IDs. There is no fetch or inferred merge base. The command resolves and pins the
commits using the existing bounded Git metadata reader. Dirty worktree and index
content are not reviewed. The durable daemon currently requires complete loose
Git commit/tree/blob objects. Packed-only source refuses during initialization;
the command does not repack or copy your repository. Linked worktrees can use the
resolved shared object directory if that source satisfies the same requirements.

Select two distinct local model IDs, their exact API bases, and a transport.
Neither provider nor model has a shipped default. The two servers may be the same
local service with different models. `distinct_model` verification is required;
it is not a claim that two selectors use different training families.

The `--declare-local-capabilities` flag is an explicit operator declaration:
both models are actually local (not a loopback gateway to cloud inference),
support structured output, have the supplied capacities, do not log content,
have zero inference price, and are currently available. These declarations
produce route eligibility records, not measured service conformance. Do not
supply the flag if those facts are unknown. The receipt keeps that distinction.
See [local model review](local-model-review.md) for transport limits.

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

Replace every path, model and scope label with your choices. The example capacity
is illustrative, not a recommendation or measurement. Both models must declare
at least 8192 context and 4096 output tokens. Generated reviews have a 4096 output
token cap and zero monetary budget. The built-in review-policy version derives
its identity from local-only, distinct-model, no-publication behavior. You never
compute inventory, route, policy or setup hashes.

Use `openai_chat_completions` instead for compatible Chat Completions servers.
The endpoint must be a canonical numeric loopback API base. Anonymous local
access is explicit in the generated policy. For a local server needing bearer
authentication, add `--generation-credential-environment OPEN_TRESTLE_PROVIDER_LOCAL_GENERATION`
and/or `--verification-credential-environment OPEN_TRESTLE_PROVIDER_LOCAL_VERIFICATION`.
Only references are stored. Provision those environment values through your
approved secret store before checking or reviewing. Never paste secrets into
CLI flags, checked-in files or receipts. Do not use this bootstrap for remote
services, cloud model selectors, browser sessions or sign-in token caches.

## Check and resume

Initialization writes protected `0600` inventory, policy template, bound policy,
setup plan/receipt ledger and `bootstrap.json` beneath the existing private
`0700` directory. It uses the existing configuration binder and protected
writers. It returns `pending` (exit 3), not a false ready state. Repeating the
same initialization accepts byte-identical files without overwriting them.
A different configuration at an existing output path refuses. Interrupted
initialization can be repeated with the same selections; unknown or partial
files are not overwritten or deleted. Inspect and preserve them before choosing
a fresh private directory. Never modify the plan or receipt ledger by hand.

Provision separate random operator and observer tokens of at least 32 bytes in
`OPEN_TRESTLE_API_TOKEN` and `OPEN_TRESTLE_OBSERVER_TOKEN`, respectively. Use your
approved secret-management path, not command arguments. No credential values are
created, printed, hashed or copied by bootstrap.

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

The approval label must match the recovery owner. The checker records existing
storage, administrator, observer credential, policy, dry-run, local inference and
backup checks. The backup directory must be protected and outside the live
bootstrap directory. Its snapshot name is derived automatically from the current
plan. A missing permission, credential, unavailable model, invalid model output
or unsupported backup location cannot become ready. Correct the dependency and
repeat `check`. Passed checks are historical receipts, not fresh liveness checks;
repeat calls do not silently repeat a successful inference probe. `inspect` is
read-only and never contacts models.

`ready` (exit 0) means these setup checks passed. It does not mean release-ready,
model-quality-qualified, or that a daemon is running. `pending` (exit 3) lists
uncompleted checks. `refused` (exit 4) means an unsafe input or blocked checker;
usage errors use exit 2 and output failures use exit 1. Unavailable checkers keep
setup non-ready. The canonical plan remains the source of setup readiness.

## Launch and request the first review

Start the daemon using `launch_command`. Once ready to submit source, prepare one
persisted first-review intent. This creates a new protected `review-intent.json`
exactly once; repeated calls, `check` and `inspect` reuse its timestamp and commands.
No model request or source upload occurs during preparation.

```sh
trestle setup bootstrap prepare-review \
  --directory "$HOME/.local/state/open-trestle/bootstrap"
```

The JSON result includes exact argument arrays:

- `launch_command`: foreground `trestled` with protected state, setup root,
  source identity, runtime policy, local full-review admission and model workers.
- `review_command`: `trestle local-git submit-review` with exact immutable commits,
  all derived policy identities, a stable first-review run ID and a persisted creation time.
- `status_command`: retrieve the canonical diagnostics for that run.
- `ephemeral_review_command`: optional direct checkout model review. This path
  is separate, has no durable resume, and must not be mistaken for daemon work.

Execute each array as arguments, not by joining it into an unescaped shell
string or running `eval`. For example, copy the array values into your process
launcher. Shell users can quote every argument separately. Bootstrap never
executes these commands. Its receipt contains non-secret paths and labels; keep
it private because those can reveal local machine/repository names.

Start the daemon with the operator and observer tokens in its environment. Keep
it in the foreground; use the existing shutdown procedure to stop it. There is
no generated systemd unit or unattended job. The default generated listener is
`127.0.0.1:8741`; ensure that port is free. Submit and status commands explicitly
bind `http://127.0.0.1:8741` rather than inheriting another API URL.

Only after approving source use, execute `review_command` with the operator
token in its environment. This is the separate repository-source-to-model effect
boundary. It requests the nine-stage review pipeline on the pinned commits. The
ordinary checkout is a local source authority, not forge-origin authentication.
No publication task or forge credentials are enabled. The runtime still needs
its existing pinned scanner binaries and host confinement support; bootstrap
does not install or weaken those dependencies. Startup refusal is not readiness.

First admission requires submitting within five minutes of `prepare-review`.
Prepare only after the daemon is running. Inspection never refreshes that
identity. Save and repeat the exact submit array for retries after admission.
A missed first-admission window remains refused; do not edit or delete the
intent file to manufacture freshness. Prepare a new explicit setup in a fresh
protected directory if needed. Use `status_command` to inspect the durable result. A successful submit
or status retrieval is not review approval. Read findings, coverage, omissions,
abstention and uncertainty. Empty diagnostics and no-candidate results are not
repository clearance. See [daemon API](daemon-api.md), [setup](setup.md), and
[local model review](local-model-review.md) for recovery and result limits.

A new change or different model configuration needs a new explicit bootstrap
selection in a fresh protected directory. This command does not mutate old runs,
rotate credentials, authorize remote egress, or transfer historical approvals.

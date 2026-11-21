# Setup planning

A setup plan is a record of a deployment's posture and of the checks that still block readiness. It contains no secrets, and it is content-addressed, meaning that its identity is a hash of its contents. Creating a plan does not contact a provider or connect a forge.

This page is for operators who run `trestled` and need a deployment plan. To set up a review of one repository on your own machine, run `trestle init` instead. It asks a few questions and writes the setup folder and its plan for you, and `trestle review` then reviews the latest change. See [getting started](getting-started.md), and [local-first bootstrap](local-first-bootstrap.md) for the commands that `trestle init` runs.

## Create a protected plan

Create a private directory and initialize one deployment profile:

```sh
install -d -m 0700 "$HOME/.local/state/open-trestle/setup"
trestle setup init \
  --profile local_single_node \
  --tenant example \
  --repository example-repository \
  --recovery-owner platform-owner \
  --state "$HOME/.local/state/open-trestle/setup/plan.json"
```

The state path must not exist. Its parent must be a directory that is not a symlink and has no group or other write permission. The CLI creates the plan with mode `0600`, synchronizes the file and its parent directory, and never overwrites an existing plan.

Only `Runner.Run` creates later revisions. It executes an approved checker and applies that checker's receipt for the current plan through the protected state writer. Each revision increments the revision number and binds the previous identity and the checker-catalog identity. It is written by an atomic replacement, and the receipt and parent directories are synchronized.

If a stop occurs after the receipt is durable but before the plan head changes, `StateFile.PendingReceipt` exposes that one fenced receipt. The same transition can then finish without rerunning the check.

Inspect and validate the canonical state with:

```sh
trestle setup inspect \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --expected-root-identity "$RECORDED_INITIAL_PLAN_IDENTITY"
```

Initialization also creates a private, append-only receipt ledger beside the plan, at `plan.json.receipts`. Back up, restore and transfer the plan and the receipt ledger together. A plan that is copied without its ledger is rejected once it contains a closed check.

For the daemon, keep `--setup-state` either under the private `--state-dir/setup/plan.json` directory or outside `--state-dir` (such as the sibling of a `runs` state root). Do not use a direct child such as `--state-dir/plan.json` or `--state-dir/setup.json`. Daemon startup rejects this layout, including its `.lock`, `.receipts` and possible `.next` siblings. See [daemon root inventory](daemon-api.md#start-a-local-daemon).

### Offline move of a direct-root setup plan

Use this procedure to move a plan that sits directly under `--state-dir` to a layout that daemon startup accepts.

1. Stop the daemon and all setup writers.
2. Inspect the original state, and record its exact initial root identity and its current plan identity.
3. Create a protected backup snapshot at a new path that does not exist, outside the live setup directory: `trestle setup backup create --state "$OLD_DIRECT_PLAN" --destination "$NEW_PROTECTED_BACKUP" --expected-plan-identity "$CURRENT_PLAN_IDENTITY"`. The snapshot contains the complete, verified receipt ledger, not only `plan.json`.
4. Restore the snapshot with the backup and restore commands below, to a new protected `--state-dir/setup/plan.json` or to a path outside the root. Pass both `--expected-root-identity "$RECORDED_INITIAL_PLAN_IDENTITY"` and `--expected-plan-identity "$BACKED_UP_PLAN_IDENTITY"`. The destination plan path must not exist, and its private, trusted parent directory must already exist. Restore never overwrites.
5. Inspect the restored path with `trestle setup inspect --state "$NEW_PLAN" --expected-root-identity "$RECORDED_INITIAL_PLAN_IDENTITY"`, and verify its exact plan identity and its full receipt history. Keep the verified external backup.
6. While both writers are still stopped, move the original direct-root plan, lock, receipt ledger and staging entries to a protected location outside `--state-dir`. Do this through an offline transfer that an operator has reviewed. Do not leave direct-root copies in place.
7. Only after those entries are gone, update `--setup-state` and check that the daemon starts. Keep the original protected copy until you have verified the restored path and the startup.

An unknown direct entry continues to block startup. Open Trestle does not move or delete these files itself.

### How receipts are written

Receipt writes require a filesystem that supports hard links within one directory and file and directory synchronization. Open Trestle writes each receipt to its canonical receipt filename plus `.next`, synchronizes it and closes it. A hard link then installs the immutable final name without overwriting anything. The ledger directory is synchronized before and after the staging file is removed. If the filesystem does not support hard links or synchronization, the write fails. There is no fallback that overwrites.

When a writer reopens the ledger, it can reclaim one protected staging file, either for the next revision or for a receipt that is already installed and verified. Read-only inspection leaves that staging file unchanged. A complete staging file without a final name is uncommitted, and Open Trestle discards it. Only a complete final receipt can resume a transition without rerunning its check. Unknown names, unsafe staging files and malformed committed receipts remain errors.

During restore, staging recovery is limited to the next receipt after a valid, contiguous installed prefix. Restore checks the snapshot and root identities before it opens the destination, and checks all installed receipts against the snapshot before it installs the plan.

The initial and restored plan files are written and synchronized under the protected `<state>.next` name. A hard link then installs the complete final plan without overwriting anything. When a writer reopens, it can discard the uncommitted plan staging file. A partially written final plan remains an error and is not overwritten automatically.

Inspection rejects symlinks, broad file permissions, replacement races, unknown fields, noncanonical JSON, invalid identities, unsafe profile combinations and inconsistent readiness.

## Offline posture checks

Three built-in checks can advance the protected plan without network access:

```sh
trestle setup check storage \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --storage-root "$HOME/.local/state/open-trestle"

OPEN_TRESTLE_API_TOKEN="$OPERATOR_TOKEN" \
OPEN_TRESTLE_OBSERVER_TOKEN="$OBSERVER_TOKEN" \
  trestle setup check observer \
  --state "$HOME/.local/state/open-trestle/setup/plan.json"

trestle setup check administrator \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --approved-by platform-owner
```

### Storage and observer checks

The storage posture check opens one directory that the current user owns, with mode `0700`, and rechecks every ancestor up to the filesystem root. Each ancestor must be owned by the current user or by root. An ancestor with group or other write access must also be sticky and protect a child entry that the current user owns. Symlinked or replaceable path components are rejected.

Several checks depend on file ownership: administrator, backup, storage and protected runtime files. On Windows they read each file's and folder's owner and access control list instead of its mode (see [platforms](platforms.md#protected-files-on-windows)). They return `unavailable` on platforms where ownership authority is not implemented, and protected setup state refuses to open or inspect there. The mutable state, lock and receipt files must be owned by the user of the setup process. Their parent chain must prevent another local principal from replacing them before the check creates a lock, changes a mode, cleans up or reads. The storage check does not claim that backup, capacity or crash recovery was tested.

The observer credential posture check validates that both values are safe in a header and that the credentials differ. It does not store either credential, and it does not check that a daemon accepts the observer credential.

### Administrator check

The administrator check binds the setup root, tenant, repository, named recovery owner, and the effective operating-system user and group of the current process. `--approved-by` must match the plan's recovery owner. It does not create an account or grant operating-system privileges.

### Backups

Record the current plan identity, then create a protected backup snapshot:

```sh
trestle setup backup create \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --destination "$HOME/backups/open-trestle/plan.snapshot.json" \
  --expected-plan-identity "$CURRENT_PLAN_IDENTITY"

trestle setup check backup \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --backup-snapshot "$HOME/backups/open-trestle/plan.snapshot.json"
```

The destination directory must already exist with mode `0700`, have a stable, trusted chain of ancestors, differ from the live state directory, and not be nested beneath it. Snapshot creation never overwrites a path. The file has mode `0600` and contains the plan and its complete receipt history.

The checker requires that the current process owns the file and that its plan and root identities equal the live plan's. A stale snapshot cannot pass a later check after another receipt changes the plan.

Restore only to a new protected state path, and fence both recorded identities:

```sh
trestle setup backup restore \
  --snapshot "$HOME/backups/open-trestle/plan.snapshot.json" \
  --destination "$HOME/.local/state/open-trestle-restored/plan.json" \
  --expected-root-identity "$RECORDED_INITIAL_PLAN_IDENTITY" \
  --expected-plan-identity "$BACKED_UP_PLAN_IDENTITY"
```

Restore rebuilds the append-only receipt ledger and validates the restored state before it returns. It never overwrites state, and it can resume an interrupted rebuild of the ledger. A passing backup check confirms that one separate, protected copy of the setup state is complete. It does not cover independent media, off-site retention, application artifacts, which remain your responsibility.

### Exit codes

A passed check exits with code `0`. A `blocked` or `unavailable` check that completed writes its canonical receipt and exits with code `3`. Malformed arguments, invalid setup identifiers and unsupported profiles print usage and exit with code `2`. An identity mismatch, stale state, checker failure or persistence failure exits with code `1`.

Offline checks write only the protected plan and the receipt ledger. Backup creation writes only its new snapshot, and restore writes only its new state path, lock and receipt ledger. None of these contacts a provider, forge or model.

## Checks that no profile uses

The `provider`, `integration` and `webhook` checks and the `trestle setup github` commands remain in the CLI, but no current profile requires them, so they cannot make a plan ready.

## Runtime policy approval and dry run

For a new runtime policy, first compute the route inventory identity and bind it into the policy document:

```sh
trestle config inventory-identity \
  --route-inventory /etc/open-trestle/routes.json
```

For a v1 policy, copy the reported `inventory_identity` into the runtime policy, and optionally add preferences from the reported `route_record_identities`. Setup rejects generation pins in v1 policies. For a local generation route and an explicit verifier route, bind a v2 policy instead:

```sh
trestle config bind \
  --route-inventory /etc/open-trestle/routes.json \
  --runtime-policy-template /etc/open-trestle/runtime-policy.template.json \
  --generation-adapter local-generation \
  --verification-adapter local-verification
```

Save its stdout as a new protected runtime-policy file before you validate. The adapters must identify different local records that satisfy the independence requirement of the policy. Binding does not approve routes, read credentials, contact providers or change setup state. See [local configuration bootstrap](local-model-review.md#local-responses-configuration-bootstrap).

Next, validate the protected route inventory and the bound runtime policy:

```sh
trestle config validate \
  --route-inventory /etc/open-trestle/routes.json \
  --runtime-policy /etc/open-trestle/runtime-policy.json
```

Record the reported `inventory_identity`, `runtime_policy_identity` and `review_policy_identity`. When you advance the setup plan, the named recovery owner must then approve those identities:

```sh
trestle setup check policy \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --route-inventory /etc/open-trestle/routes.json \
  --runtime-policy /etc/open-trestle/runtime-policy.json \
  --approve-inventory-identity "$INVENTORY_IDENTITY" \
  --approve-runtime-policy-identity "$RUNTIME_POLICY_IDENTITY" \
  --approve-review-policy-identity "$REVIEW_POLICY_IDENTITY" \
  --approved-by platform-owner
```

The files and their ancestors must be owned by the current user or by root. Configuration files cannot be writable by the group or by others. Shared writable ancestors need the same sticky-directory protections as the local storage checks. The checker does not resolve a credential reference or connect to an endpoint.

### What a passing policy must satisfy

A passing policy must match the selected setup posture. It must meet all of these conditions:

- It uses only declared privacy zones.
- It binds every adapter to one unambiguous zone, provider, connection, logging, endpoint and credential authority.
- It disables content logging.
- It stays within the cost cap of the profile.
- It provides at least two routes that are currently approved and usable, at the required independence level.
- It uses canonical endpoints. The local profile accepts only numeric loopback endpoints and local routes. The offline check does not resolve DNS names.
- It blocks publication on inconclusive verification, and its publication independence floor is not weaker than its verification floor.

Local v2 policies must bind a generation pin and an explicit verifier record. Both records must be eligible and must satisfy the required independence level. Another usable pair in the inventory cannot substitute for them. v1 policies are unpinned.
### Local inference check

Validate actual local inference after the exact policy receipt is durable:

```sh
trestle setup check inference \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --route-inventory /etc/open-trestle/routes.json \
  --runtime-policy /etc/open-trestle/runtime-policy.json \
  --approve-inventory-identity "$INVENTORY_IDENTITY" \
  --approve-runtime-policy-identity "$RUNTIME_POLICY_IDENTITY" \
  --approve-review-policy-identity "$REVIEW_POLICY_IDENTITY" \
  --approved-by platform-owner
```

This is a functional probe, not an offline validation. It reads each selected credential environment only when it sends a request. It sends at most two fixed prompts that contain no secrets, to two models from the approved local inventory, and stops after the first failed step. A pass requires one generation response and one verification response. Both adapters must return the empty candidate and verification contracts through the normal path for admitting responses.

Each request reserves a byte-based input estimate, as review planning does. The estimate is the request payload plus the trusted system channel plus 256 framing bytes, and on a [local structured-output](local-model-review.md#chat-completions-transport) connection it also includes the serialized `response_format`. A route must therefore declare enough context for it. Each request permits at most 256 output tokens, reported input above the reservation is rejected, and the check has one total deadline of 90 seconds.

For v2, generation uses the pinned record, and verification uses only the explicit verifier record, ranked without the generation pin. For v1, verification keeps the ordered preferences after excluding routes that are not independent. The probe does not retry or fall back. Its HTTP transport disables proxies and connection reuse, accepts only numeric-loopback dial targets, and does not resolve DNS. The policy must disable content logging.

The plan stores only identities, and not the credential, the prompt, the model text, the endpoint, the model name or the token counts. A pass means that the approved local generation and verification paths completed the fixed contract at that time. It says nothing about review quality. Authentication, malformed output or a policy mismatch blocks the check. A transient connection failure, a timeout, a rate limit or a server failure records `unavailable`.

### Dry run

After the policy receipt is stored, run the review dry run with the same approval:

```sh
trestle setup check dry-run \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --route-inventory /etc/open-trestle/routes.json \
  --runtime-policy /etc/open-trestle/runtime-policy.json \
  --approve-inventory-identity "$INVENTORY_IDENTITY" \
  --approve-runtime-policy-identity "$RUNTIME_POLICY_IDENTITY" \
  --approve-review-policy-identity "$REVIEW_POLICY_IDENTITY" \
  --approved-by platform-owner
```

The dry run uses fixed content and local dispatchers. It selects the generation and verifier records in the same way as the inference check. It exercises these parts of the pipeline:

- the configured eligibility filter and ranking
- generation authorization and verification authorization
- the provider-neutral dispatch contract
- admission of candidate and verifier output
- terminal attempt records
- cost reconciliation
- output lineage
- the independence receipt

It has a limit of five seconds. It has no publisher, source writer, validation process, network client or credential resolver, so it cannot publish, change source or contact a model endpoint. A policy file that changed or is missing produces a blocked or unavailable receipt.

## Guided local web setup

Start the setup service on a numeric loopback address, with a dedicated random token:

```sh
export OPEN_TRESTLE_SETUP_TOKEN='replace-with-a-distinct-long-random-token'
trestle setup web \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --listen 127.0.0.1:8742
```

Open the `/console/setup` address that the command prints, and enter the setup token. The service does not print the token. It accepts only a numeric loopback listener and checks the Host header to prevent DNS rebinding. It rejects a token that equals the daemon's operator or observer token. The browser keeps the token and all form values only in memory, and sends the token only in an authorization header.

When no plan exists, the guided surface shows the profile, the scope and the recovery owner. Creating a plan needs a separate confirmation. An existing plan opens at its first pending requirement, and shows its readiness, effect posture, recovery action, evidence identity and receipt history. Each check requires an inline confirmation that is bound to the displayed plan identity and requirement key. Stale plans are rejected.

### Checks the web setup can run

The local setup API can initialize a plan and run these built-in checkers:

- local administrator
- backup snapshot
- local storage
- observer credential posture
- runtime policy
- explicit local inference
- non-publishing dry run

Creating and restoring a backup snapshot stay explicit CLI operations. Other requirements remain visibly pending, and the console says that no built-in web checker is available for them.

The API requires valid UTF-8 JSON and rejects duplicate keys, unknown or case-folded member names, and forbidden fields even when they are empty. Inspecting missing state changes nothing. Starting the service does not run a check or create setup state.

### Shutdown

On shutdown, the service allows five seconds for the HTTP shutdown. If that fails, it forces the server to close.

## Keyboard-first setup

After initialization, you can inspect and advance the same protected plan in a foreground terminal:

```sh
trestle setup tui \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --storage-root "$HOME/.local/state/open-trestle" \
  --backup-snapshot "$HOME/backups/open-trestle/plan.snapshot.json" \
  --administrator-approved-by platform-owner
```

Use `j` and `k` to select a requirement. Press `x`, then type the displayed `run REQUIREMENT_KEY` command to confirm one receipt write. Use `r` to reload and `q` to quit. The interface shows the states pending, passed, blocked and unavailable, plus the recovery action and the recent receipt history.

The interface executes only the checker configurations that were supplied when it started. Unsupported requirements remain pending, and the interface says that no checker is configured. The flags for policy approval and local inference are the same as those of the non-interactive commands. Local inference stays disabled until the policy check passes, and it still needs the `x` key plus the `run local_inference_validated` confirmation. See [Foreground terminal interface](tui.md#setup-terminal-interface).

## Profiles

| Profile | Storage default | Inference default | Network and integration default |
|---|---|---|---|
| `local_single_node` | private local metadata and artifacts | local only | egress denied, local integration |

The profile starts with 30-day retention, provider content logging disabled, provider fallback disabled, publication disabled and dynamic validation disabled. It permits no remote model spend. Choosing a profile does not create infrastructure or connect an external service.

## Readiness checks

The plan contains an ordered set of requirements. Each is a scripted check, a probe, an authorization or a dry run. Facts that need no environment are recorded when the plan is created. All requirements that depend on the environment start as `pending`. A plan becomes `ready` only when every required check has a receipt from an approved checker.

Each plan embeds one checker catalog and the ordered history of check receipts. When Open Trestle decodes a plan, it replays that history from the initial plan. Every plan identity, checker identity, receipt identity, revision, timestamp, latest result for a requirement, and the final readiness value must match. Editing the plan alone cannot create readiness, and swapping the catalog is rejected.

A check receipt binds the current plan identity, the requirement key, the approved checker identity, an outcome, the evidence identity, the recovery action and a UTC timestamp. Stale receipts, and checkers that are not in the catalog, are rejected. `blocked` and `unavailable` checks keep the plan unready and name one recovery action. A later check must bind the newer plan identity.

### Replacing a prerequisite receipt

Replacing an existing prerequisite receipt resets its dependent requirements to `pending` and clears their current evidence fields:

- Replacing the policy receipt resets the local-inference and dry-run checks.

This applies to replacement outcomes of passed, blocked and unavailable, even when the evidence digest is unchanged. Historical receipts remain immutable, and unrelated requirements keep their state. Run the dependent checks again against the new plan before you rely on readiness.

A history that kept a dependent result after its prerequisite was replaced fails validation, and Open Trestle does not rewrite or migrate it. Preserve the original state and ledger. Then either restore a verified, compatible backup with its expected root identity, or initialize a separate protected state path and repeat the approvals and checks. Do not edit receipts or overwrite the old ledger.

Older binaries cannot replay histories that contain these resets, so do not mix setup writers across versions.

### What setup state holds

Setup state contains no tokens, passwords, provider endpoints, source, prompts, model responses or secret values. Setup receipts carry only identities and outcomes.

`trestle setup inspect` reports `ready` only after the embedded chain of approved receipts replays successfully, and every receipt has an identical record in the protected ledger. Record the initial plan identity that `setup init` returns. After an import or restore, require it with `--expected-root-identity` to detect that the root was substituted.

### The trust boundary

The local state owner, and the process that runs the approved checkers, form the setup trust boundary. They can authorize state transitions. File permissions and the append-only ledger protect against other local users, accidental edits, incomplete copies, stale writes and interrupted replacement. They do not protect against a malicious owner of the operating system.

### Published contracts

The published contracts are:

- `schemas/setup/setup-command-result-v1.schema.json`
- `schemas/setup/setup-plan-v1.schema.json`
- `schemas/setup/setup-check-receipt-v1.schema.json`
- `schemas/setup/setup-init-request-v1.schema.json`
- `schemas/setup/setup-check-request-v1.schema.json`
- `schemas/setup/setup-check-request-v2.schema.json`
- `schemas/setup/setup-session-v1.schema.json`
- `schemas/setup/setup-check-result-v1.schema.json`
- `schemas/setup/setup-error-v1.schema.json`

The runtime parsers also rebuild identities, enforce the order and sources of the profile requirements, check the ordering of timestamps, and require canonical encoding.

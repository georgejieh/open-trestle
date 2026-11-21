# Setup plan

For a setup that uses local models, `trestle init` writes a setup plan at `runs/setup/plan.json` in the setup folder. The plan records the repository scope, the setup owner and the result of each setup check. It contains no secrets, and its identity is a hash of its contents. To set up a repository, run `trestle init`; see [getting started](getting-started.md) and [local-first bootstrap](local-first-bootstrap.md).

The only profile is `local_single_node`: local storage, local models only, no network egress, no publication.

## Checks

`trestle setup bootstrap check`, which `trestle init` runs for you, runs these checks and records a receipt for each one. A check that already passed is skipped, and the run stops at the first check that does not pass.

| Check | What it confirms |
| --- | --- |
| `state_storage_posture_validated` | The setup folder is private to you, and no other ordinary account can change its parent folders. Unix checks owners and modes; Windows checks the owner and the access control list. |
| `local_administrator_validated` | The name given with `--approved-by` matches the plan's recovery owner. The identity of the running process is recorded. |
| `policy_validated` | The saved route inventory and runtime policy match the local profile and your approval. |
| `dry_run_validated` | A review pipeline run with fixed content and no model passes. |
| `local_inference_validated` | Only with `--allow-local-probe`: both models answered one fixed test request. |
| `observer_credential_posture_validated` | Daemon only: the operator and observer tokens differ, and each is 32 to 512 printable ASCII characters with no spaces. |
| `backup_validated` | Daemon only, with `--backup-directory`: a protected backup of the plan exists. |

`trestle init` skips the two daemon-only checks. A direct review can therefore be ready while the plan is not: review readiness needs the checks above that apply to a direct review, plus the secret scanner.

A plan is `ready` only when every check in its own catalog has a passing receipt. Four requirements (`profile_selected`, `scope_valid`, `effect_posture_locked`, `recovery_owner_named`) pass when the plan is created and need no receipt. A blocked or unavailable check keeps the plan unready. Replacing the policy receipt resets the local-inference and dry-run checks to pending.

The plan embeds its receipt history, and a private, append-only ledger beside it at `plan.json.receipts` holds a copy of each receipt. Reading the plan replays that history, so editing the plan file cannot make it ready. Keep the plan and its ledger together.

## Inspect the plan

```sh
trestle setup inspect \
  --state "$SETUP_DIR/runs/setup/plan.json" \
  --expected-root-identity "$RECORDED_INITIAL_PLAN_IDENTITY"
```

It prints the canonical plan. `--expected-root-identity` is optional; with it, a plan whose initial identity differs is refused. Inspection changes nothing on disk.

## Back up and restore

Create a protected snapshot of the plan and its full receipt history:

```sh
trestle setup backup create \
  --state "$SETUP_DIR/runs/setup/plan.json" \
  --destination "$HOME/backups/open-trestle/plan.snapshot.json" \
  --expected-plan-identity "$CURRENT_PLAN_IDENTITY"
```

The destination folder must exist with mode `0700` and must not be the plan's folder or inside it. Snapshot creation never overwrites a path.

Restore to a new path only, and fence both identities:

```sh
trestle setup backup restore \
  --snapshot "$HOME/backups/open-trestle/plan.snapshot.json" \
  --destination "$HOME/.local/state/open-trestle-restored/plan.json" \
  --expected-root-identity "$RECORDED_INITIAL_PLAN_IDENTITY" \
  --expected-plan-identity "$BACKED_UP_PLAN_IDENTITY"
```

Restore rebuilds the receipt ledger and validates the recorded receipts; it reruns no checks. It never overwrites, and it can resume an interrupted rebuild. Creating a snapshot does not record `backup_validated`; the bootstrap check does that. A snapshot is one protected copy; keeping it on separate media is your responsibility.

On success both commands print an `open-trestle/setup-command-result` record and exit `0`. A failure exits `1` and a usage error exits `2`, each with a message on standard error.

## Plan location for the daemon

Keep `--setup-state` under `--state-dir/setup/plan.json` or outside `--state-dir`. Daemon startup rejects a plan directly inside `--state-dir`, such as `--state-dir/plan.json`, together with its `.lock`, `.receipts` and `.next` siblings. See [daemon root inventory](daemon-api.md#start-a-local-daemon).

### Offline move of a direct-root setup plan

1. Stop the daemon and every other writer.
2. Inspect the plan and record its initial root identity and its current plan identity.
3. Create a backup snapshot outside the setup folder with `trestle setup backup create`.
4. Restore it to a new `--state-dir/setup/plan.json`, or to a path outside the root, with `trestle setup backup restore` and both expected identities. The parent folder must already exist and be private.
5. Inspect the restored plan with `trestle setup inspect` and `--expected-root-identity`.
6. Move the original plan, lock, receipt ledger and staging files out of `--state-dir`. Open Trestle does not move or delete them.
7. Update `--setup-state` and start the daemon.

## Published contracts

- `schemas/setup/setup-plan-v1.schema.json`
- `schemas/setup/setup-check-receipt-v1.schema.json`
- `schemas/setup/setup-command-result-v1.schema.json`

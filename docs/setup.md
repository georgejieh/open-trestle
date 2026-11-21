# Setup plan

For a setup that uses local models, `trestle init` writes a setup plan at `runs/setup/plan.json` in the setup folder. The plan records the repository scope, the setup owner and the result of each setup check. It contains no secrets, and its identity is a hash of its contents. To set up a repository, run `trestle init`; see [getting started](getting-started.md) and [local-first bootstrap](local-first-bootstrap.md).

The only profile is `local_single_node`: local storage, local models only, no network egress, no publication.

## Checks

`trestle init` and `trestle setup bootstrap check` run these checks and record a receipt for each one:

| Check | What it confirms |
| --- | --- |
| `state_storage_posture_validated` | The setup folder and its parents are owned by you and not writable by others. |
| `local_administrator_validated` | The current account is the setup owner. |
| `policy_validated` | The saved route inventory and runtime policy match the local profile and your approval. |
| `dry_run_validated` | A review pipeline run with fixed content and no model passes. |
| `local_inference_validated` | Optional: both models answered one fixed test request. |
| `observer_credential_posture_validated` | Daemon only: the operator and observer tokens are set and differ. |
| `backup_validated` | Daemon only: a protected backup of the plan exists. |

A plan is `ready` only when every check has a passing receipt from the built-in checker. A blocked or unavailable check keeps the plan unready. Replacing the policy receipt resets the local-inference and dry-run checks to pending.

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

Restore rebuilds the receipt ledger and validates the restored plan. It never overwrites, and it can resume an interrupted rebuild. A snapshot is one protected copy; keeping it on separate media is your responsibility.

Both commands print an `open-trestle/setup-command-result` record and exit `0` on success, `1` on failure and `2` on a usage error.

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

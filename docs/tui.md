# Foreground terminal interface

`trestle tui` is a terminal screen for watching one review run through the
authenticated daemon API. It is for operators who run the daemon and want to see
a run's progress, its task state and its review diagnostics. It shows the run receipt, task state, and review diagnostics. Diagnostic versions 1 through 5 contain verified findings, and version 6 contains unverified deterministic observations. The interface does not schedule work, read repository files, execute commands, claim work leases, change policy, invoke models, or publish results.

## Start

Set the same bearer credential that the daemon API uses:

```sh
export OPEN_TRESTLE_API_TOKEN='replace-with-a-long-random-token'
go run ./cmd/trestle tui \
  --server http://127.0.0.1:8741 \
  --tenant tenant-a \
  --repository repository-a \
  --run review-run-a
```

The interface accepts plain HTTP only for a server at an IP-literal loopback
address. Any other server must use HTTPS. The interface rejects redirects, so a credential is not forwarded to another origin.

The display width depends on where the output goes:

- On an interactive terminal (no `--plain`, `TERM` not `dumb`), the width
  defaults to the terminal's column count, clamped to 60 through 240.
- With an explicit `--width`, with plain output, or with non-terminal output, the
  width is 100 unless you set it.

`trestle setup tui` follows the same rule. The accepted display width is 60
through 240 columns.

The interface refreshes every two seconds by default, and it accepts an interval
from 250 milliseconds to one minute. Non-terminal output and `TERM=dumb` disable
screen-control sequences automatically, and `--plain` disables them explicitly.
`--once` writes one snapshot and exits, which is useful for logs and support
capture.

## Commands

Commands are line based and limited to 256 bytes:

- `r` refreshes immediately.
- `c` starts cancellation confirmation.
- `cancel RUN_ID` confirms cancellation, but only after `c` and only for the displayed run.
- `q` exits without changing the run.

Cancellation is the only operation that changes state. It uses the same scoped
daemon endpoint as `trestle runs cancel`.

## What the screen shows

If polling fails, the interface keeps the last authenticated snapshot visible and
labels it as stale.

When the daemon answers that the run was not found, and intake refused its webhook
delivery instead of opening it, the interface reads the recorded refusal
(`GET .../refusal`). It shows the scope, `Run not opened`, the reason token with a
fixed explanation, the refusal time, and the delivery and planner identities, and then exits. It does not show delivery content. Any other failure to load the run is
reported as an error, even when a refusal is recorded.

A task that failed with a recorded reason prints a `Reason` line after the
disposition. The line names the task, the reason token and a fixed explanation.
The reason tokens depend on the task:

- A source task records `no_merge_base`, `nothing_to_review` or
  `merge_base_unavailable`.
- A context task that was refused for its route records
  `route_context_insufficient` or `no_eligible_route`.
- A generation or verification task that the provider refused records one of
  `provider_payment_required`, `provider_model_unavailable`,
  `provider_model_retired`, `provider_authentication_failed`,
  `provider_authorization_denied` or `provider_rate_limited`. It records
  `provider_request_rejected` when the provider rejected the request as invalid
  (for example an unknown model ID), and `provider_response_invalid` when the
  provider answered with a reply that the adapter refused. It records
  `model_output_invalid` when the model's answer was not a valid review document.

Some results add further lines:

- A `route_context_insufficient` refusal adds a `Hint` line with the same text as
  the local review. A provider refusal adds a `Hint` line with the local review's
  action.
- A final result that carries the refusal prints a `Context refusal` line.
- A final result recorded after its evidence expired prints an `Evidence expired`
  line, which says that the outcome comes from the run journal only.

These lines wrap to the terminal width instead of being truncated. The interface
shows missing review diagnostics as unavailable rather than inferring them from
the run state.

The diagnostics depend on the diagnostic-set version:

- Version 2 prints candidate, verified, rejected and inconclusive counts.
- Version 3 also prints analyzed, selected and omitted source counts.
- Version 4 prints each content-free aggregate omission reason on one line, and it leaves out the reason section when no source was omitted.
- Version 5 prints the static-debug check as a `Cleared gate`, `Failed check`,
  `Incomplete check` or `Abstention`, followed by checked and applicable
  changed-Go-range counts and the matches.
- Version 6 prints the deterministic check and its observations. It labels them as not verified and does not count them as verified findings.

Only `passed` is called cleared, and only for that rule. A not-applicable
result is shown as an abstention: no changed Go range was applicable, and the rule
is not cleared. Nonzero inconclusive or omitted counts, and incomplete checks,
stay explicit.

## Trust boundary

Diagnostic titles and paths are display text. The renderer removes control
characters, collapses line breaks, limits visible lengths, and labels the
section. It does not render model text as terminal control sequences. Only the
API client holds the bearer credential, and the credential does not appear in
the screen model or in an error message.

## Setup terminal interface

`trestle setup tui` opens one existing protected setup plan directly. It needs
neither the daemon nor a network connection:

```sh
trestle setup tui \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --storage-root "$HOME/.local/state/open-trestle" \
  --backup-snapshot "$HOME/backups/open-trestle/plan.snapshot.json" \
  --administrator-approved-by platform-owner
```

The screen shows the selected profile, the effect boundary, the readiness derived
by replaying the plan, every ordered requirement, the selected requirement's
recovery action, and the last five receipt identities. Commands are line based and
limited to 256 bytes:

- `j` selects the next requirement.
- `k` selects the previous requirement.
- `x` starts confirmation for the selected requirement.
- `run REQUIREMENT_KEY` writes the requirement's check receipt, but only when the key matches the pending confirmation and its checker configuration was
  supplied at startup.
- `r` reloads the protected plan.
- `q` exits.

Navigation, refresh and one-shot rendering only read. Every check receipt needs
the two-step confirmation: `x`, then `run REQUIREMENT_KEY`. The following checks
use the same approved checkers, runner, receipt ledger and stale-state fences as
the non-interactive setup commands: local-administrator approval, protected backup
snapshot, local and PostgreSQL storage, observer credential posture, runtime policy, local inference, and non-publishing dry-run checks. The
administrator and backup options contain no secret, and paths and operating-system
identity details never enter the screen or a receipt.

Each check needs its own flags and reads its credentials only after you confirm:

- PostgreSQL validation requires `--approve-postgres-authority-identity` and
  `--postgres-approved-by`. It reads the runtime DSN only after confirmation.
- KMS secret-backend validation requires `--approve-kms-authority-identity`,
  `--kms-region`, `--kms-key-arn` and `--kms-approved-by`; `--kms-endpoint` is
  optional. It reads AWS credentials only after confirmation and runs the generate-and-unwrap check without an S3 request.
- Envelope-storage validation additionally requires
  `--approve-envelope-storage-authority-identity`, the four `--s3-*` values and
  `--envelope-approved-by`. After confirmation it uses separately named S3 and KMS
  credential environments. It writes one fixed public encrypted object, reads it
  through the envelope path, deletes its version, and verifies that the
  object is gone, all within 90 seconds.
- Remote-provider authorization, policy, local-inference and dry-run checks
  require the same protected paths, three approval identities, and named
  approver flags documented in [Setup planning](setup.md). Remote-provider
  authorization needs no credential and makes no network request. It approves only the remote connection and routing snapshot.
- GitHub integration-permission validation requires the permission authority, endpoint, API version, installation ID, repository full name, and
  approver flags. Only after terminal confirmation does it read the dedicated
  setup token for the installation permission map and the separate runtime token for the repository scope, and then it performs the read-only inspection.
- GitHub webhook conformance additionally requires
  `--approve-webhook-authority-identity`, `--github-webhook-key-id` and
  `--webhook-approved-by`. It stays disabled until the integration receipt
  passes. After confirmation it reads the separate webhook secret, runs five fixed
  requests directly against the production handler and a disposable private inbox,
  clears the verifier secret, and removes the inbox before passing. It opens no
  listener and makes no network request.
- Kubernetes HA shared-rate-limit validation requires
  `--approve-shared-rate-limit-authority-identity`,
  `--postgres-database-authority-identity` and `--shared-rate-limit-approved-by`,
  after the PostgreSQL receipt. It reads the database URL only after terminal
  confirmation, and it checks shared quota, key cardinality, database-time expiry, concurrent final-permit serialization, and cleanup of its disposable rows.
- Local inference is the only terminal setup check that contacts model endpoints.
  It requires a prior policy receipt, an additional confirmation, and
  canonical numeric-loopback routes. It sends two fixed contract probes with no
  retry or fallback, and it keeps response content out of setup state.

Observer values are read from `OPEN_TRESTLE_API_TOKEN` and
`OPEN_TRESTLE_OBSERVER_TOKEN` only when that check runs, and they never enter the
screen or the plan. A requirement without a configured local checker stays pending
and states that no checker is available. Skipped work is not shown as a pass.

The ownership-dependent checks are currently available on Unix platforms and
Windows: the administrator, backup, storage and protected runtime-file checks.
They return `unavailable` on any other platform where this release does not
implement an ownership authority check. Plan inspection and the checks that do not
depend on ownership remain available there.

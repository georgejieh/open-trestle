# Foreground terminal interface

`trestle tui` is a terminal screen for watching one review run through the
authenticated daemon API. It is for operators who run the daemon and want to see
a run's progress, its task state and its review diagnostics. It shows the run receipt, task state, and review diagnostics. Diagnostic versions 1 through 5 and 8 contain verified findings, version 6 contains unverified deterministic observations, and version 7 is the final full-review result. The interface does not schedule work, read repository files, execute commands, claim work leases, change policy, invoke models, or publish results.

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
- Version 7 prints the terminal outcome and the deterministic and verified parts it carries, each with the lines of its own version.
- Version 8 prints like version 5. A finding on removed base lines shows its path and `removed base lines` with the base line range.

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

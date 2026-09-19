# Foreground terminal interface

`trestle tui` observes one exact review run through the authenticated daemon API. It renders the canonical run receipt, bounded task state, and the independently verified diagnostic snapshot. It does not duplicate scheduling, read repository files, execute commands, claim work leases, change policy, invoke models, or publish results.

## Start

Set the same bearer credential used by the daemon API:

```sh
export OPEN_TRESTLE_API_TOKEN='replace-with-a-long-random-token'
go run ./cmd/trestle tui \
  --server http://127.0.0.1:8741 \
  --tenant tenant-a \
  --repository repository-a \
  --run review-run-a
```

Plain HTTP is accepted only for an IP-literal loopback server. Other servers require HTTPS. Redirects are rejected so a credential cannot be forwarded to another origin.

The interface refreshes every two seconds by default. The accepted interval is 250 milliseconds through one minute, and the accepted display width is 60 through 240 columns. Non-terminal output and `TERM=dumb` disable screen-control sequences automatically. `--plain` also disables them explicitly. `--once` writes one snapshot and exits, which is useful for logs and support capture.

## Commands

Commands are line based and bounded to 256 bytes:

- `r` refreshes immediately.
- `c` starts cancellation confirmation.
- `cancel RUN_ID` confirms cancellation only after `c` and only for the displayed run.
- `q` exits without changing the run.

Cancellation is the interface's only mutating operation. It uses the same scoped daemon endpoint as `trestle runs cancel`. A polling failure keeps the last authenticated snapshot visible and labels it as stale. A missing verified diagnostic set is shown as unavailable rather than inferred from run state. Diagnostic-set version 2 prints exact candidate, verified, rejected, and inconclusive counts. Version 3 also prints bounded analyzed, selected, and omitted source counts. Version 4 prints each content-free aggregate omission reason on one bounded line and suppresses the reason section when no source was omitted. Version 5 prints the static-debug check as a `Cleared gate`, `Failed check`, `Incomplete check`, or `Abstention`, followed by checked/applicable changed-Go-range counts and exact matches. Only `passed` is called cleared, and only for that exact rule. Not-applicable explicitly abstains because no changed Go range was applicable and does not clear the rule. Nonzero inconclusive or omitted counts and incomplete checks remain explicit. Versions 1 through 4 remain readable without inventing newer evidence.

## Trust boundary

Diagnostic titles and paths are verified result fields but remain untrusted display text. The renderer removes control characters, collapses line breaks, bounds visible lengths, and labels the section explicitly. It never renders model text as terminal control sequences. The bearer credential is held only by the API client and is never included in the screen model or an error message.

## Setup terminal interface

`trestle setup tui` opens one existing protected setup plan directly. It does not require the daemon or a network connection:

```sh
trestle setup tui \
  --state "$HOME/.local/state/open-trestle/setup/plan.json" \
  --storage-root "$HOME/.local/state/open-trestle" \
  --backup-snapshot "$HOME/backups/open-trestle/plan.snapshot.json" \
  --administrator-approved-by platform-owner
```

The screen shows the selected profile, effect boundary, replay-derived readiness, every ordered requirement, the selected requirement's recovery action, and the last five receipt identities. Commands are line based and bounded to 256 bytes:

- `j` selects the next requirement.
- `k` selects the previous requirement.
- `x` starts confirmation for the selected requirement.
- `run REQUIREMENT_KEY` writes its check receipt only when the key exactly matches the pending confirmation and its checker configuration was supplied at startup.
- `r` reloads the protected plan.
- `q` exits.

Navigation, refresh, and one-shot rendering are read-only. Every check receipt requires the two-step `x` then `run REQUIREMENT_KEY` confirmation. Local-administrator approval, protected backup snapshot, local and PostgreSQL storage, observer credential posture, exact runtime policy, explicit local inference, and non-publishing dry-run checks use the same approved checkers, runner, receipt ledger, and stale-state fences as the non-interactive setup commands. The administrator and backup options contain no secret; paths and operating-system identity details never enter the screen or receipt. PostgreSQL validation requires `--approve-postgres-authority-identity` plus `--postgres-approved-by` and reads the runtime DSN only after confirmation. KMS secret-backend validation requires `--approve-kms-authority-identity`, `--kms-region`, `--kms-key-arn`, and `--kms-approved-by`; `--kms-endpoint` is optional. It reads AWS credentials only after confirmation and performs the bounded generate-and-unwrap check without an S3 request. Envelope-storage validation additionally requires `--approve-envelope-storage-authority-identity`, the four `--s3-*` values, and `--envelope-approved-by`. It uses separately named S3 and KMS credential environments only after confirmation, writes one fixed public encrypted object, reads it through the envelope path, deletes its exact version, and verifies absence under a 90-second bound. Remote-provider authorization, policy, local-inference, and dry-run checks require the same protected paths, three exact approval identities, and named approver flags documented in [Setup planning](setup.md). Remote-provider authorization is credential-free and network-free; it approves only the exact remote connection and routing snapshot. GitHub integration-permission validation requires the exact permission authority, endpoint, API version, installation ID, repository full name, and approver flags. Only after terminal confirmation does it read the dedicated setup token for the installation permission map and the separate runtime token for exact repository scope, then perform the bounded read-only inspection. GitHub webhook conformance additionally requires `--approve-webhook-authority-identity`, `--github-webhook-key-id`, and `--webhook-approved-by`. It remains disabled until the integration receipt passes. After confirmation it reads the separate webhook secret, runs five fixed requests directly against the production handler and disposable private inbox, clears the verifier secret, and removes the inbox before passing. It opens no listener and makes no network request. Kubernetes HA shared-rate-limit validation requires `--approve-shared-rate-limit-authority-identity`, `--postgres-database-authority-identity`, and `--shared-rate-limit-approved-by` after the PostgreSQL receipt. It reads the database URL only after terminal confirmation and proves shared quota, key cardinality, database-time expiry, concurrent final-permit serialization, and exact disposable-row cleanup. Local inference is the only terminal setup check that contacts model endpoints. It requires a prior exact policy receipt, an additional confirmation, and canonical numeric-loopback routes. It sends two fixed contract probes with no retry or fallback and keeps response content out of setup state. Observer values are read from `OPEN_TRESTLE_API_TOKEN` and `OPEN_TRESTLE_OBSERVER_TOKEN` only when that check runs. They never enter the screen or plan. A requirement without a configured local checker remains pending and states that no checker is available. The interface never converts skipped work into a pass.

Ownership-dependent administrator, backup, storage, and protected runtime-file checks are currently available on Unix platforms. They return `unavailable` on Windows and other platforms where this release does not implement an ownership authority check. Plan inspection and ownership-independent checks remain available there.

# Spending limits

Open Trestle records what each model review may have cost and lets you set a
spending limit per API key, for a week, a month or a year, with alerts as the
total approaches it. It is meant to work like the limits you can set with your
API provider, with two differences you should keep in mind:

- **The figures are an estimate, not a bill.** A review's cost is the
  provider-reported tokens priced at the route's declared price, which for
  OpenRouter is the highest price among the pinned endpoints. When a request's
  usage is not reported, it counts at the cost reserved for it, an upper bound.
  Your provider usually charges less: on one OpenRouter key, OpenRouter
  reported $0.08 for the month while Open Trestle's settlement of the same
  calls was about $0.60.
- **The limit is best effort.** Concurrent reviews, other tools that use the
  same key and provider price changes are invisible to it. Your provider's own
  limit is the guarantee; set one there as well (for OpenRouter, in the key's
  settings).

Every spending message repeats this in one sentence.

## Setting a limit

`trestle init` asks one optional question for a remote provider that charges
per token, after the key variable is known:

```text
  Optional: a spending limit for this key. Open Trestle adds
  up what each review may have cost, prints an alert when
  the month's total reaches the alert percent, and refuses
  to start a review once it reaches the limit. ...
  OpenRouter reports $0.08 used this month of this key's
  $50.00 monthly limit.
  Spending limit for this key, USD per month (optional) [none]: 10
  Alert at percent [80]:
```

Enter means no limit. A limit alerts at the percentage you give and at the
limit itself, and is saved only after the setup is saved. A key that already
has a limit keeps it, and the wizard says so instead of asking. With
`--no-input`, `--spending-limit USD` and `--spending-alert PERCENT` answer the
question; without them there is no limit, and nothing is reported missing.

At any time:

```sh
trestle usage set --credential-env OPEN_TRESTLE_PROVIDER_OPENROUTER --limit 10
trestle usage set --credential-env OPEN_TRESTLE_PROVIDER_OPENROUTER --limit 25.50 --period week --alert 50,90
trestle usage clear --credential-env OPEN_TRESTLE_PROVIDER_OPENROUTER
```

- `--credential-env` is the **name** of the variable that holds the key, never
  the key. A value that looks like a key is refused.
- `--limit` is in US dollars with at most two decimals, from $0.01 to
  $1,000,000.00.
- `--period` is `week`, `month` (the default) or `year`: calendar periods in
  UTC, a week from Monday 00:00, a month from its first day and a year from
  1 January, as providers reset them.
- `--alert` lists ascending percentages from 1 to 100 (default `80,100`).
- `--provider` is needed only for a variable that is not a provider's usual
  name. `OPEN_TRESTLE_PROVIDER_OPENROUTER`, `OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD`
  and `OPEN_TRESTLE_PROVIDER_OPENCODE_GO` imply `openrouter`, `ollama-cloud`
  and `opencode-go`; for any other name, give the provider ID its routes use,
  unless one limit already names the variable.

A limit belongs to the provider and the key variable, not to one setup: every
setup that names the same variable shares it. It is keyed by the credential
reference identity that setup already records for the variable name (the
SHA-256 of `open-trestle/provider-credential-environment/` and the name), so
the key itself is never stored.

## What a review does

Before each review run starts, and before any credential is read or any request
is sent, `trestle local-git model-review` compares the limits of the API keys
its remote routes use with the usage ledger:

- When the spend recorded in the current period is at or over a limit, the
  review is refused. JSON uses result schema version 6 with `status: refused`,
  `ci_disposition: blocked`, `run_status: not_opened`, `failure: policy` and
  `failure_detail: spending_limit_reached`, and no `token_usage`; the exit code
  is 4. Text output reads:

  ```text
  status: refused
  ci: blocked
  run: not_opened
  failure: policy: spending_limit_reached
  hint: the spend recorded for an API key this review uses has reached its spending limit for the current period, so the review was not started and nothing was sent: run trestle usage to see it, then raise or clear the limit (trestle usage set, trestle usage clear) or wait for the next period; the figures are Open Trestle's upper-bound estimate at the highest pinned price, not a bill, and the limit is best effort, so your provider's own limit is the guarantee
  ```

- When the review's worst case could take the recorded spend past a limit, it
  runs with a warning. The worst case is two requests (one to each model) at
  the per-request bound, `max_cost_micro_usd`, or an `--investigation-policy`
  run's budget.
- After a run that sent at least one request, one ledger entry is appended.
  When that crosses an alert percentage, one line says so.

These lines go to standard error, so JSON and SARIF stay one document; text
output also ends with each limited key's state. A review that takes $7.90 of
a $10.00 monthly limit to $8.12 prints:

```text
Spending alert: $8.12 of your $10.00 monthly limit for OPEN_TRESTLE_PROVIDER_OPENROUTER (81%)
Spending figures are Open Trestle's upper-bound estimate at the highest pinned price, not a bill; the limit is best effort, and your provider's own limit is the guarantee.
```

With $9.20 already recorded and a $0.69 per-request bound, a review starts
with:

```text
Spending warning: this review may cost up to $1.38, which could take the $9.20 recorded this month past your $10.00 monthly limit for OPEN_TRESTLE_PROVIDER_OPENROUTER; it runs anyway.
Spending figures are Open Trestle's upper-bound estimate at the highest pinned price, not a bill; the limit is best effort, and your provider's own limit is the guarantee.
```

A `--specialists` review set checks and records each member, so a member
refused at the limit stops the set like any member that did not complete. When
the two models use different key variables, each key is charged the whole
review, so each total stays an upper bound. Routes to a model server on this
machine cost nothing per request, and the Ollama sign-in route sends no key, so
neither is recorded or limited. A usage folder that cannot be read never blocks
a review: the review says the limit was not checked, or that its spend was not
recorded, and runs.

The per-request bound itself is not a spending limit. `trestle init` sets it to
the cost of one request that fills the whole context and writes the whole
output allowance, rounded up to a cent, and shows it in the summary panel
("up to $0.69 a request, $1.38 a review"); `--max-cost-micro-usd` sets another
one, for CI and advanced use.

## Seeing the state

`trestle usage` lists every limited key, every key with spend recorded this
month, and `OPEN_TRESTLE_PROVIDER_OPENROUTER` when that variable is set in the
shell, even with no limit or spend yet, so OpenRouter's own figures show:

```text
Spending recorded by Open Trestle (usage folder ~/.local/state/open-trestle/usage):
  OPEN_TRESTLE_PROVIDER_OPENROUTER (openrouter): $0.60 of your $10.00 monthly limit this month (6%), alerts at 80% and 100%
    OpenRouter reports $0.08 used this month of this key's $50.00 monthly limit.
Spending figures are Open Trestle's upper-bound estimate at the highest pinned price, not a bill; the limit is best effort, and your provider's own limit is the guarantee.
```

A review whose usage was not reported is noted as counted at its reservation.
Running `trestle init` again in a configured repository shows the same state.

For an OpenRouter key whose variable is set, `trestle usage` and `trestle init`
also read OpenRouter's own figures with one `GET
https://openrouter.ai/api/v1/key`, sending the key as the bearer credential.
That read costs nothing and sends no source. It follows no redirect, reads at
most 64 KiB and waits at most ten seconds. Only the numeric fields `limit`,
`limit_remaining`, `usage`, `usage_daily`, `usage_weekly` and `usage_monthly`
and the reset word `limit_reset` are read; the `label`, which holds a masked
form of the key, is never read. When the read fails, the line says only
"OpenRouter's usage could not be read" and a short reason, and nothing else is
affected.

## Where it is stored

The usage folder is `$XDG_STATE_HOME/open-trestle/usage` when `XDG_STATE_HOME`
is an absolute path, and otherwise `~/.local/state/open-trestle/usage`. It is
created with mode `0700`, every file is `0600`, and a folder or file that is
not private or not owned by your account is refused, not used.

- One `limit-<64 hex>.json` file per key: an `open-trestle/spending-limit` v1
  record (`schemas/runtime/spending-limit-v1.schema.json`), replaced atomically
  through a protected temporary file and removed only after its content is
  checked.
- One `ledger-YYYY-MM.jsonl` file per UTC month, at most 8 MiB, one
  `open-trestle/usage-ledger-entry` v1 line per review run
  (`schemas/runtime/usage-ledger-entry-v1.schema.json`), appended under
  `ledger.lock`. An entry records the time, the review run ID, the runtime
  policy identity, the keys and models, the requests sent, `usage_known` and
  `cost_micro_usd`, which is the settled cost (`cost: settled_usage`) or, when
  usage was not known for every request, the reservation upper bound (`cost:
  reservation_upper_bound`), always with `price_basis: route_max_price`. It
  never holds a key, source, prompt or model reply.

A final line left incomplete by an interrupted write is ignored and closed by
the next append. Any other line that is not a canonical entry makes the ledger
unreadable rather than being skipped, so a hand edit cannot quietly lower the
total. See [protocol contracts](protocol-contracts.md).

## Not covered yet

The background daemon (`trestled`) does not record spend or enforce these
limits yet; its runs are not in the ledger. A later phase will compute period
spend from the daemon's journal and show it in the console. No notification is
sent anywhere other than the terminal.

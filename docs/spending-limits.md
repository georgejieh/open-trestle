# Spending limits

Open Trestle records what each model review may have cost, and it lets you set a
spending limit per API key, for a week, a month or a year, with alerts as the
total approaches the limit. This page explains how to set a limit, what a review
does when it nears or reaches one, and where the records are kept.

The limits are meant to work like the ones you can set with your API provider,
with two differences you should keep in mind.

First, the figures are an estimate, not a bill. A review's cost is the
provider-reported tokens priced at the route's declared price, which for
OpenRouter is the highest price among the pinned endpoints. When a request's
usage is not reported, it counts at the cost reserved for it, which is an upper
bound. Your provider usually charges less, because it bills the endpoint that
served the request, and that endpoint can be cheaper than the highest pinned
price. When the two figures differ, trust your provider's.

Second, the limit is best effort. Open Trestle cannot see concurrent reviews,
other tools that use the same key, or provider price changes. Your provider's
own limit is the guarantee, so set one there as well (for OpenRouter, in the
key's settings).

Every spending message repeats this in one sentence.

## Setting a limit

For a remote provider that charges per token, `trestle init` asks one question
after the key variable is known:

```text
  Spending limit for this key. Open Trestle adds up what each
  review may have cost, prints an alert when the month's
  total reaches 80% of the limit, and refuses to start a
  review once it reaches the limit. ... Type none for no
  limit.
  OpenRouter reports $0.08 used this month of this key's
  $50.00 monthly limit.
  Spending limit for this key, USD per month [20]:
```

Enter accepts $20 a month, and the wizard then says so and prints the
`trestle usage set` command that changes it; `none` means no limit. A limit alerts at 80% and
at the limit itself; the percentage is not asked. It is saved only after the
setup is saved. If the key already has a limit, it keeps it, and the wizard says
so instead of asking. `--spending-limit USD` answers the question, and
`--spending-alert PERCENT` with it sets another alert percentage. With
`--no-input` and without them there is no limit, and nothing is reported
missing.

You can set or clear a limit at any time:

```sh
trestle usage set --credential-env OPEN_TRESTLE_PROVIDER_OPENROUTER --limit 10
trestle usage set --credential-env OPEN_TRESTLE_PROVIDER_OPENROUTER --limit 25.50 --period week --alert 50,90
trestle usage clear --credential-env OPEN_TRESTLE_PROVIDER_OPENROUTER
```

- `--credential-env` is the name of the variable that holds the key, never the
  key. Open Trestle refuses a value that looks like a key.
- `--limit` is in US dollars with at most two decimals, from $0.01 to
  $1,000,000.00.
- `--period` is `week`, `month` (the default) or `year`. These are calendar
  periods in UTC, as providers reset them: a week starts on Monday at 00:00, a
  month on its first day, and a year on 1 January.
- `--alert` lists ascending percentages from 1 to 100 (default `80,100`).
- `--provider` is needed only for a variable that is not a provider's usual
  name. `OPEN_TRESTLE_PROVIDER_OPENROUTER`, `OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD`
  and `OPEN_TRESTLE_PROVIDER_OPENCODE_GO` imply `openrouter`, `ollama-cloud` and
  `opencode-go`. For any other name, give the provider ID that its routes use,
  unless one limit already names the variable.

A limit belongs to the provider and the key variable, not to one setup, so every
setup that names the same variable shares it. It is keyed by the credential
reference identity that the setup already records for the variable name (the
SHA-256 of `open-trestle/provider-credential-environment/` and the name), so the
key itself is never stored.

## What a review does

Before each review run starts, and before it reads any credential or sends any
request, `trestle local-git model-review` compares the limits of the API keys its
remote routes use with the usage ledger. There are three outcomes.

If the spend recorded in the current period is at or over a limit, the review is
refused. JSON output uses result schema version 6 with `status: refused`,
`ci_disposition: blocked`, `run_status: not_opened`, `failure: policy` and
`failure_detail: spending_limit_reached`, and it has no `token_usage`. The exit
code is 4. Text output reads:

```text
status: refused
ci: blocked
run: not_opened
failure: policy: spending_limit_reached
hint: the spend recorded for an API key this review uses has reached its spending limit for the current period, so the review was not started and nothing was sent: run trestle usage to see it, then raise or clear the limit (trestle usage set, trestle usage clear) or wait for the next period; the figures are Open Trestle's upper-bound estimate at the highest pinned price, not a bill, and the limit is best effort, so your provider's own limit is the guarantee
```

If the review's worst case could take the recorded spend past a limit, the
review runs with a warning. The worst case is two requests (one to each model) at
the per-request bound, `max_cost_micro_usd`, or the budget of an
`--investigation-policy` run. A specialist review set (the default of a new
setup) may run the general review and up to `--max-specialists` specialists
(default 3), each a full review. Its one warning, printed before the first
member, counts all of them and adds a line such as "That counts every review
this command may run: the general review and up to 3 specialist reviews, each up
to $1.38." Open Trestle still checks each member before it starts and refuses it
at the limit. Specialists run concurrently only when no limited key could reach
its limit during the concurrent wave.

A model answer that is not usable is sent once more (see
[remote model review](remote-model-review.md#provider-failures)). That retry is a
second paid request. It is sent only when the recorded spend plus the worst case
above, every retry already sent in the command and this one could not reach a
limit; otherwise the review fails on the first answer. A key without a limit
allows it. Both requests count in the review's cost and requests sent.

After a run that sent at least one request, Open Trestle appends one ledger
entry. When that entry crosses an alert percentage, one line says so.

These lines go to standard error, so JSON and SARIF stay one document. Text
output also ends with the state of each limited key. A review that takes $7.90 of
a $10.00 monthly limit to $8.12 prints:

```text
Spending alert: $8.12 of your $10.00 monthly limit for OPEN_TRESTLE_PROVIDER_OPENROUTER (81%)
Spending figures are Open Trestle's upper-bound estimate at the highest pinned price, not a bill; the limit is best effort, and your provider's own limit is the guarantee.
```

With $9.20 already recorded and a $0.69 per-request bound, a review starts with:

```text
Spending warning: this review may cost up to $1.38, which could take the $9.20 recorded this month past your $10.00 monthly limit for OPEN_TRESTLE_PROVIDER_OPENROUTER; it runs anyway.
Spending figures are Open Trestle's upper-bound estimate at the highest pinned price, not a bill; the limit is best effort, and your provider's own limit is the guarantee.
```

A `--specialists` review set checks and records each member. A member that is
refused at the limit therefore stops the set, like any member that did not
complete. When the two models use different key variables, each key is charged
the whole review, so each total stays an upper bound.

Routes to a model server on this machine cost nothing per request, and the
Ollama sign-in route sends no key, so Open Trestle neither records nor limits
either of them. A usage folder that cannot be read never blocks a review. The
review says that it did not check the limit, or that it did not record the spend,
and runs.

The per-request bound is not a spending limit. `trestle init` sets it to the
cost of one request that fills the whole context and writes the whole output
allowance, rounded up to a cent, and shows it in the summary panel ("up to $0.69
a request, $1.38 a review"). `--max-cost-micro-usd` sets a different bound, for
CI and advanced use.

## Seeing the state

`trestle usage` lists every limited key and every key with spend recorded this
month. It also lists `OPEN_TRESTLE_PROVIDER_OPENROUTER` when a key for it is set
in the shell or saved with [`trestle keys`](keys.md), even with no limit or spend
yet, so that OpenRouter's own figures show:

```text
Spending recorded by Open Trestle (usage folder ~/.local/state/open-trestle/usage):
  OPEN_TRESTLE_PROVIDER_OPENROUTER (openrouter): $0.60 of your $10.00 monthly limit this month (6%), alerts at 80% and 100%
    OpenRouter reports $0.08 used this month of this key's $50.00 monthly limit.
Spending figures are Open Trestle's upper-bound estimate at the highest pinned price, not a bill; the limit is best effort, and your provider's own limit is the guarantee.
```

That is the text without a terminal, for scripts. On a terminal each key is a
row whose mark and color follow its percentage of the limit: `✓` (dim below
50%), `…` in amber from the first alert percentage, and `✗` in red at 100% or
more. A key without a limit has `–`:

```text
Spending recorded by Open Trestle
  Usage folder ~/.local/state/open-trestle/usage.
  ✓ OPEN_TRESTLE_PROVIDER_OPENROUTER (openrouter)
    $0.60 of your $10.00 monthly limit this month (6%),
    alerts at 80% and 100%
    OpenRouter reports $0.08 used this month of this key's
    $50.00 monthly limit.
  Spending figures are Open Trestle's upper-bound estimate
  at the highest pinned price, not a bill; the limit is best
  effort, and your provider's own limit is the guarantee.
```

A review whose usage was not reported is noted as counted at its reservation.
Running `trestle init` again in a configured repository shows the same state.

For an OpenRouter key that is set in the shell or saved (the environment wins),
`trestle usage` and `trestle init` also read OpenRouter's own figures with one
`GET
https://openrouter.ai/api/v1/key`, sending the key as the bearer credential. That
read costs nothing and sends no source. It follows no redirect, reads at most 64
KiB and waits at most ten seconds. It reads only the numeric fields `limit`,
`limit_remaining`, `usage`, `usage_daily`, `usage_weekly` and `usage_monthly`, and
the reset word `limit_reset`. It does not read the `label`, which holds a masked
form of the key. When the read fails, the line says only "OpenRouter's usage
could not be read" and gives a short reason, and nothing else is affected.

## Where it is stored

The usage folder is `$XDG_STATE_HOME/open-trestle/usage` when `XDG_STATE_HOME` is
an absolute path, and otherwise `~/.local/state/open-trestle/usage`. It is
created with mode `0700` and every file is `0600`. Open Trestle refuses to use a
folder or file that is not private or not owned by your account.

- There is one `limit-<64 hex>.json` file per key. It holds an
  `open-trestle/spending-limit` v1 record
  (`schemas/runtime/spending-limit-v1.schema.json`). Open Trestle replaces it
  atomically through a protected temporary file, and removes it only after
  checking its content.
- There is one `ledger-YYYY-MM.jsonl` file per UTC month, at most 8 MiB, with one
  `open-trestle/usage-ledger-entry` v1 line per review run
  (`schemas/runtime/usage-ledger-entry-v1.schema.json`), appended under
  `ledger.lock`. An entry records the time, the review run ID, the runtime policy
  identity, the keys and models, the requests sent, `usage_known` and
  `cost_micro_usd`. The cost is the settled cost (`cost: settled_usage`) or, when
  usage was not known for every request, the reservation upper bound (`cost:
  reservation_upper_bound`), always with `price_basis: route_max_price`. An entry
  holds no key, source, prompt or model reply.

Open Trestle ignores a final line that an interrupted write left incomplete, and
the next append removes it. Any other line that is not a canonical entry makes the
ledger unreadable instead of being skipped, so a hand edit cannot quietly lower
the total. See [protocol contracts](protocol-contracts.md).

## Not covered yet

The background daemon (`trestled`) does not record spend or enforce these limits
yet, so its runs are not in the ledger. A later phase will compute period spend
from the daemon's journal and show it in the console. Open Trestle sends no
notification anywhere other than the terminal.

# Spending limits

Open Trestle records what each model review may have cost. You can set a
spending limit for each API key, per week, month or year, with alerts as the
total approaches the limit.

The limits work like the ones you can set with your API provider, with two
differences.

First, the figures are an estimate, not a bill. A review's cost prices the tokens
the provider reports at the route's declared price, which for OpenRouter is the
highest price among the pinned endpoints. When a request's usage is not
reported, it counts at the cost reserved for it, which is an upper bound. Your
provider usually charges less, because it bills for the endpoint that served the
request, which can be cheaper than the highest pinned price. When the two
figures differ, trust your provider's.

Second, the limit is best effort. Open Trestle cannot see concurrent reviews,
other tools that use the same key, or changes to provider prices. Your
provider's own limit is the guarantee, so set one there as well (for OpenRouter,
in the key's settings). Every spending message repeats this in one sentence.

## Setting a limit

For a remote provider that charges per token, `trestle init` asks one question
once the key variable is known:

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

Enter accepts $20 a month, and the wizard then tells you so and prints the
`trestle usage set` command that changes it. Typing `none` means no limit. A
limit alerts at 80% and at the limit itself, and the wizard does not ask for the
percentage. The limit is saved only after the setup is saved. A key that already
has a limit keeps it, and the wizard says so instead of asking.
`--spending-limit USD` answers the question, and `--spending-alert PERCENT`
sets a different alert percentage when given with it. With `--no-input` and
neither flag, there is no limit, and nothing is reported missing.

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
  periods in UTC, which reset the way providers reset theirs: a week starts on
  Monday at 00:00, a month on its first day, and a year on 1 January.
- `--alert` lists ascending percentages from 1 to 100 (default `80,100`).
- `--provider` is needed only for a variable that does not have a provider's
  usual name. `OPEN_TRESTLE_PROVIDER_OPENROUTER`,
  `OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD` and `OPEN_TRESTLE_PROVIDER_OPENCODE_GO`
  imply `openrouter`, `ollama-cloud` and `opencode-go` respectively. For any
  other name, give the provider ID that its routes use, unless an existing limit
  already names the variable.

A limit belongs to the provider and the key variable, not to a single setup, so
every setup that names the same variable shares it. It is keyed by the
credential reference identity that the setup already records for the variable
name (the SHA-256 of `open-trestle/provider-credential-environment/` and the
name), so the key itself is never stored.

## What a review does

Before each review run starts, and before it reads any credential or sends any
request, `trestle local-git model-review` compares the limits of the API keys
that its remote routes use against the usage ledger. There are three outcomes.

If the spend recorded in the current period is at or over a limit, the review is
refused with exit code 4. JSON output has `status: refused`,
`failure_detail: spending_limit_reached` and no `token_usage` (see
[failure details](failure-details.md)). Text output reads:

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
`--investigation-policy` run. A specialist review set (the default for a new
setup) may run the general review and up to `--max-specialists` specialists
(default 3), each a full review. The set prints a single warning before its
first member, counting all the members and adding a line such as "That counts
every review this command may run: the general review and up to 3 specialist
reviews, each up to $1.38." Open Trestle still checks each member before it
starts and refuses it at the limit. Specialists run concurrently only when no
limited key could reach its limit while they run together.

If a model answer is not usable, the request is sent once more (see
[remote model review](remote-model-review.md#provider-failures)). That retry is a
second paid request, so it is sent only if the recorded spend, plus the worst
case above, every retry already sent in the command and this retry, could not
reach a limit. Otherwise, the review fails on the first answer. A key without a
limit allows the retry. Both requests count toward the review's cost and its number of
requests sent.

After a run that sent at least one request, Open Trestle appends one entry to the
ledger. When that entry crosses an alert percentage, a line says so.

These lines go to standard error, so JSON and SARIF output each stay a single
document. Text output also ends with the state of each limited key. For example, a
review that takes the spend on a $10.00 monthly limit from $7.90 to $8.12 prints:

```text
Spending alert: $8.12 of your $10.00 monthly limit for OPEN_TRESTLE_PROVIDER_OPENROUTER (81%)
Spending figures are Open Trestle's upper-bound estimate at the highest pinned price, not a bill; the limit is best effort, and your provider's own limit is the guarantee.
```

With $9.20 already recorded and a $0.69 per-request bound, a review starts with:

```text
Spending warning: this review may cost up to $1.38, which could take the $9.20 recorded this month past your $10.00 monthly limit for OPEN_TRESTLE_PROVIDER_OPENROUTER; it runs anyway.
Spending figures are Open Trestle's upper-bound estimate at the highest pinned price, not a bill; the limit is best effort, and your provider's own limit is the guarantee.
```

A `--specialists` review set checks and records each member, so a member that is
refused at the limit stops the set, like any member that did not complete. When
the two models use different key variables, each key is charged for the whole
review, so each total stays an upper bound.

Routes to a model server on this machine cost nothing per request, and the
Ollama sign-in route sends no key, so Open Trestle neither records nor limits
either of them. A usage folder that cannot be read never blocks a review. The
review says that it did not check the limit or record the spend, and runs
anyway.

The per-request bound is not a spending limit. `trestle init` sets it to the
cost of one request that fills the whole context and writes the whole output
allowance, rounded up to a cent, and shows it in the summary panel ("up to $0.69
a request, $1.38 a review"). For CI and advanced use, `--max-cost-micro-usd`
sets a different bound.

## Seeing the state

`trestle usage` lists every key that has a limit and every key with spend
recorded this month. It also lists `OPEN_TRESTLE_PROVIDER_OPENROUTER` when a key
for it is set in the shell or saved with [`trestle keys`](keys.md), even with no
limit or spend yet, so that OpenRouter's own figures appear:

```text
Spending recorded by Open Trestle (usage folder ~/.local/state/open-trestle/usage):
  OPEN_TRESTLE_PROVIDER_OPENROUTER (openrouter): $0.60 of your $10.00 monthly limit this month (6%), alerts at 80% and 100%
    OpenRouter reports $0.08 used this month of this key's $50.00 monthly limit.
Spending figures are Open Trestle's upper-bound estimate at the highest pinned price, not a bill; the limit is best effort, and your provider's own limit is the guarantee.
```

That is the output without a terminal, for scripts. On a terminal, each key is a
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

For an OpenRouter key that is set in the shell or saved (the environment takes
precedence), `trestle usage` and `trestle init` also read OpenRouter's own
figures with one `GET https://openrouter.ai/api/v1/key` request, which sends the
key as the bearer credential. The read costs nothing and sends no source. It
follows no redirect, reads at most 64 KiB and waits at most ten seconds. It
reads only the numeric fields `limit`, `limit_remaining`, `usage`,
`usage_daily`, `usage_weekly` and `usage_monthly`, and the reset word
`limit_reset`, never the `label`, which holds a masked form of the key. When the
read fails, the line says only "OpenRouter's usage could not be read" and gives
a short reason. Nothing else is affected.

## Where it is stored

The usage folder is `$XDG_STATE_HOME/open-trestle/usage` when `XDG_STATE_HOME` is
an absolute path, and `~/.local/state/open-trestle/usage` otherwise. It is
created with mode `0700`, and every file in it is `0600`. Open Trestle refuses
to use a folder or file that is not private or is not owned by your account.

- There is one `limit-<64 hex>.json` file per key. It holds an
  `open-trestle/spending-limit` v1 record
  (`schemas/runtime/spending-limit-v1.schema.json`). Open Trestle replaces the
  file atomically through a protected temporary file, and it removes the file
  only after checking its content.
- There is one `ledger-YYYY-MM.jsonl` file per UTC month, of at most 8 MiB, with
  one `open-trestle/usage-ledger-entry` v1 line per review run
  (`schemas/runtime/usage-ledger-entry-v1.schema.json`). Lines are appended
  while `ledger.lock` is held. An entry holds no key, source, prompt or model
  reply. Its fields, including the cost basis (`settled_usage` or
  `reservation_upper_bound`), are listed in
  [protocol contracts](protocol-contracts.md).

Open Trestle ignores a final line that an interrupted write left incomplete, and
the next append removes it. Any other line that is not a canonical entry makes
the ledger unreadable instead of being skipped, so a hand edit cannot quietly
lower the total.

## Not covered yet

The background daemon (`trestled`) does not record spend or enforce these limits
yet, so its runs are not in the ledger. A later phase will compute period spend
from the daemon's journal and show it in the console. Open Trestle sends no
notification anywhere other than the terminal.

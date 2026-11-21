# Exit codes

This page lists the exit codes of each `trestle` command, so that scripts and CI
steps can react to them. The codes stay the same for a given command. Most
commands use `0` for success, `1` for a failure and `2` for wrong usage. Reviews
and setup bootstrap commands add `3` for work that is not finished and `4` for a refusal.
Read the output as well, because a code alone does not say which refusal or
failure it was. For a failed review, see [failure details](failure-details.md).

## Reviews

### `trestle review` and `trestle local-git model-review`

`trestle review` runs the same review as `trestle local-git model-review` with
the saved setup, and returns its code.

| Code | Meaning |
| --- | --- |
| `0` | Never by default, even when the review finds nothing: a completed review is not a clearance. Only an [exit-code policy](#exit-code-policy) returns `0`. |
| `4` | The result is blocked: a confirmed medium, high or critical finding, or a policy or resource refusal (a provider refused the request, a limit was reached, a spending limit stopped the review). |
| `3` | The result is inconclusive: only low-severity or pre-existing findings (advisory), no candidates, incomplete coverage, or a canceled review. For `trestle review` alone, also nothing was sent: no setup (run `trestle init`), no committed change, or no API key (run `trestle keys set NAME`). |
| `2` | Invalid usage, for example an unknown `--format` or a `--base` that is not a commit. |
| `1` | The run failed, for example a model reply could not be accepted or a provider failed temporarily. |

A review set (`--specialists`) merges the results of its members. The exit code
is `4` when a member did not finish and the merged set has an introduced
finding of high or critical severity, when every member finished and the set
has an introduced finding of medium severity or higher, or when a member was
refused. See
[the set table](local-model-review.md#specialist-review-set-opt-in).

### Exit-code policy

`--exit-code-policy` changes only the process exit status. The result, its
`status`, its `ci_disposition` and `comprehensive_clearance: false` are the same
under every policy. Exit `0` is a pipeline decision, not a statement that the
change is clear.

| Policy | Exit `0` when | Otherwise |
| --- | --- | --- |
| `default` (when the flag is absent) | never | `4`, `3`, `2` or `1` as above |
| `findings` | the run succeeded and no verified finding that is not pre-existing has high or critical severity, including no candidates, medium or low findings only, and coverage gaps | the default code |
| `strict` | the run succeeded with no candidates at all | the default code, so any verified finding fails the step |
| `always-zero` | a valid result was written, including a refused or failed run (for a review set, the general review must have succeeded) | `1` if the result could not be written, `2` for invalid usage |

Under `always-zero`, a passing step says nothing about whether the review ran, so
read the SARIF or the JSON `status`. For review sets, see
[the exit policy on the merged set](local-model-review.md#specialist-review-set-opt-in).

## `trestle init`

| Code | Meaning |
| --- | --- |
| `0` | Setup is ready and the review was declined, or the first review finished with `findings` or `no_candidates`. |
| `3` | Something must be fixed before a review can run, or the review was incomplete or canceled. |
| `4` | A declaration was declined, setup was refused, a setup check refused (for example the scanner check of a build that pins no secret scan helper; the setup is kept), or the review was refused. |
| `2` | A missing or invalid answer, end of input, or three unusable answers in a row. With `--no-input`, every missing flag is listed. |
| `1` | An internal error, or the first review failed. |

The first review inside `trestle init` uses these codes, not the table for
`trestle review`.

## `trestle update`

| Code | `trestle update` | `trestle update --check` |
| --- | --- | --- |
| `0` | Updated, already up to date, or you answered no. | Nothing newer was found where it looked. |
| `10` | Not used. | A newer version is available; for a release, its signature verified. |
| `1` | Not a Linux amd64 system, not installed as a package, a check failed, GitHub could not be read, or the upgrade failed. | Not a Linux amd64 system, not installed as a package, a check failed, or GitHub could not be read. |
| `2` | A usage error, or no terminal to confirm and no `--yes`. | A usage error. |

## Keys, usage and the home screen

| Command | Codes |
| --- | --- |
| `trestle keys`, `list` | `0`; `1` when the credential folder cannot be found. |
| `trestle keys set` | `0` saved; `4` OpenRouter refused the key, nothing saved; `2` no usable key was given or the name is not an `OPEN_TRESTLE_PROVIDER_` variable; `1` hidden input is unavailable, or the key could not be saved. |
| `trestle keys remove` | `0`; `2` for a bad name; `1` when the key could not be removed. |
| `trestle usage`, `set`, `clear` | `0`; `2` for a bad flag or value; `1` when the usage folder cannot be found or used. |
| `trestle` | In a terminal: `0` after you quit or outside a Git repository, and a chosen action returns its own code. Without a terminal: `2`, with the usage on standard error. |
| `--help`, `-h`, `help` | `0`, usage on standard output. |
| An unknown command | `2`, usage on standard error. |

## Checks, index and profile

| Command | Codes |
| --- | --- |
| `trestle checks on`, `off`, `status` | `0`; `2` for a bad usage or when the folder is not inside a Git checkout; `3` when the repository has no setup yet; `4` when the answer could not be saved. |
| `trestle index build`, `status`, `query` | `0`; `1` for a failure; `2` for a bad usage or a `--commit` that does not resolve. |
| `trestle profile` | The same as `trestle index`. |
| `trestle build-info` | `0`; `1` when the build identity cannot be written; `2` for a bad usage. |

## Setup

| Command | Codes |
| --- | --- |
| `trestle setup bootstrap init`, `check`, `inspect`, `prepare-review` | `0` ready; `3` checks pending; `4` refused; `1` failure; `2` usage. |
| Other `setup`, `config`, `admin`, `runs` and static `local-git` commands | `0` success; `1` failure; `2` usage. `local-git retained-memory-input` also returns `3` when canceled and `4` when it refuses protected input. |

## Fixtures and evaluation

| Command | Codes |
| --- | --- |
| `trestle review PATH` | `0` findings or no findings; `3` inconclusive; `4` blocked; `1` an error. |
| `trestle ci --format=json PATH`, `--format=sarif PATH` | `0`, or `3` when inconclusive, or `4` when blocked, or `1`. |
| `trestle validate-fixture PATH` | `0` valid; `1` invalid. |
| `trestle evaluate static-debug` | `0` the built-in cases passed; `3` they did not; `1` failure. |
| `trestle evaluate deterministic-corpus-candidate` | `3` mismatch; `4` matched; `1` failure. |
| `trestle evaluate model-contract-candidate` | `4` after printing the report; `1` failure. |

The observers (`trestle tui`, `mcp`, `lsp`, `acp`) run until their input closes. The terminal UI also exits on `q` or `quit`, and after one snapshot with `--once`.

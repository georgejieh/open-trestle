# Troubleshooting

Find the line Open Trestle printed, then the fix. For a failed review, the
`failure:` line names a [failure detail](failure-details.md); for a code,
see [exit codes](exit-codes.md). Nothing here changes a setup unless a step
says so.

## Setup and first run

### This folder is not inside a Git checkout

`trestle init` and `trestle review` work inside a Git repository. Change into it
and run the command again. To review a fixture file instead, run
`trestle review PATH`.

### This repository has no Open Trestle setup yet

Run `trestle init` in the repository. It asks a few questions, sends no source,
and can run the first review. If the setup is in a folder you named with
`--directory`, pass the same `--directory` to `trestle review`.

### No API key for OPEN_TRESTLE_PROVIDER_NAME

Nothing was sent. Save the key once, with hidden input:

```sh
trestle keys set OPEN_TRESTLE_PROVIDER_NAME
```

Or export the variable in the shell that runs the review. The environment wins
over a saved key. Run `trestle keys` to see each variable and where its key comes
from. See [API keys](keys.md).

### The key was refused

`trestle keys set` exits `4` when OpenRouter refuses the key and saves
nothing. Copy the whole key again. For another provider the key is checked by the
first review, which reports `provider_authentication_failed`.

### Hidden input is not available on this terminal

Pipe the key in instead: `printf '%s' "$KEY" | trestle keys set NAME`, or export
the variable. Do not put a key on a command line.

### Nothing to review, or no default branch

`trestle review` compares `HEAD` with its merge base on the default branch. It
exits `3` and says why when `HEAD` is already the default branch with nothing
ahead of it, or when no `main` or `master` exists. Commit your change, or pass
`--base REF`, for example `--base main`. Uncommitted changes are not reviewed.

### Setup refuses to send source to a remote provider

A plain `go build` has no secret scanner, so it refuses remote providers with
`sandboxed secret scanner is available only on Linux` or a message about the
missing scanner. The saved setup is kept. Use the packaged Linux amd64 install, or
a model server on your machine. See [install](install.md) and
[platforms](platforms.md).

### The repository's storage cannot be read

Reviews read loose objects and ordinary pack files. They do not follow
alternates (clones made with `--shared` or `--reference`), a multi-pack-index or
partial-clone packs. Make a separate full copy with
`git clone --no-local --no-hardlinks` and run `trestle init` there.

### A shallow clone or a partial clone

The review never fetches. In a shallow clone, fetch the missing base:
`git fetch --no-tags --depth=N origin SHA`. In GitHub Actions use
`actions/checkout` with `fetch-depth: 0`. In a partial clone, check out again
without a filter. See
[shallow and pull-request checkouts](local-model-review.md#shallow-and-pull-request-checkouts).

### A folder is refused as not private

The credential, usage and setup folders must be mode `0700`, and their files
`0600`, owned by you, with no symbolic links and no parent writable by others.
Fix the mode with `chmod 700 FOLDER`, or move the folder. The message names the
folder and the mode it found. See
[environment variables and files](environment-and-files.md#paths). On Windows
these checks are not implemented, so the files are refused; see
[platforms](platforms.md).

## A review failed

Match the `failure_detail` on the `failure:` line. Each hint is printed with the
failure; the fixes below add what to check.

| `failure_detail` | Fix |
| --- | --- |
| `provider_payment_required` | Add credit or a subscription to the provider account, or choose another route. |
| `provider_authentication_failed` | Check the key the route names, `trestle keys`, then run the review again. For `ollama-signin`, run `ollama signin`. |
| `provider_authorization_denied` | The account cannot use that model or endpoint. Check the account's access. |
| `provider_model_unavailable`, `provider_model_retired` | Pick a model the provider lists, then run `trestle init` again with `--generation-model` and `--verification-model`. |
| `provider_no_allowed_endpoint` | OpenRouter has no allowed endpoint for the model. With zero data retention required, choose a model that has zero-data-retention endpoints. |
| `provider_request_rejected` | Check the model ID, the endpoint and that the model accepts structured output and the output allowance, then re-run setup. |
| `provider_rate_limited` | Wait and run the review again. Open Trestle already retried twice. |
| `provider_response_invalid`, `model_output_invalid` | Run the review again. If it repeats, choose another model or route. |
| `model_output_exhausted` | The model spent its output allowance on reasoning. Choose a model that does not reason at length for that role, or raise the output allowance with `trestle init --max-output-tokens N`. |
| `route_context_insufficient` | The route's declared context is too small. Raise `max_context_tokens` on the route and the model server's context length to at least the number the hint prints. See [named local runtimes](named-local-runtimes.md#context-length). |
| `spending_limit_reached` | Run `trestle usage`, then raise or clear the limit (`trestle usage set`, `trestle usage clear`) or wait for the next period. Nothing was sent. |

A failure with no detail:

- `policy (task context)`: usually no changed source could be supplied to the
  model. Look at the source omissions in the result.
- `resource_limit (task context)`: the changed source did not fit the context
  budget. Review a smaller range with `--base` and `--head`.
- `transient`: a network or provider error. Run the review again.

A review that exits `3` with `no_candidates` or incomplete coverage is not a
clearance. Read the `limitations` and run with `--verbose`.

## Updating

| Message | Fix |
| --- | --- |
| `Open Trestle is not installed as a package on this machine` | `trestle update` updates only the packaged Linux amd64 install. See [install](install.md). |
| `this build cannot verify releases` | The build pins no release key. Install the packaged release, or use `--from FILE` or the local update folder. |
| `installing needs your confirmation` | Run `trestle update` in a terminal, or pass `--yes`. Nothing was installed. |
| A local folder `must be private (mode 0700, not 0755)` | `chmod 700 ~/.local/share/open-trestle/updates`. |

To stop the once-a-day update notice, set `OPEN_TRESTLE_UPDATE_CHECK=off`.

## Still stuck

Run the command again with the output kept, and read the `hint:` line. Do not
paste keys or source into an issue. See [SUPPORT.md](../SUPPORT.md) for where to
ask and [SECURITY.md](../SECURITY.md) for a vulnerability.

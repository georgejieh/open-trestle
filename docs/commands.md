# Commands

This page lists every `trestle` command and its flags, grouped as
`trestle --help` groups them. For a first walkthrough, start with
[getting started](getting-started.md). Exit codes are in
[exit codes](exit-codes.md), and variables and paths are in
[environment variables and files](environment-and-files.md).

`trestle --help`, `trestle -h` and `trestle help` print a short overview to
standard output and exit `0`. The overview has a "Start here" block, then each
group with one line per command. `trestle COMMAND --help` prints that command's
full usage. A bare `trestle` without a terminal, or a known command with wrong
arguments, prints the overview to standard error and exits `2`. An unknown
command prints three lines to standard error and exits `2`:

```text
trestle: "reveiw" is not a trestle command.
Did you mean: review?
Run trestle --help to see all commands.
```

The second line appears only when a command name is close. Each command also
prints its own usage when its arguments are wrong.

When standard output is a terminal, `trestle keys`, `trestle usage`,
`trestle checks` and `trestle update --check` print a heading, then one row per
item with a mark and the labels lined up, then the next command after `->`,
wrapped at 60 columns. Without a terminal they print plain text for scripts.
The marks and colors are listed under
[terminal symbols and colors](#terminal-symbols-and-colors).

`trestle keys` puts each variable name on its own row with its state indented beneath, so a long name never widens a column.

`--flag=value` and `--flag value` both work, except in `profiles` and
`local-git`, which take each flag and its value as two separate words. `init`,
`review`, `update` and `usage` reject a flag that you give twice.

### Terminal symbols and colors

Every screen uses the same marks, one for each state, so color is never the
only signal:

| Mark | With `TERM=dumb` | Color | Meaning |
| --- | --- | --- | --- |
| `✓` | `[ok]` | green | Done, found, or within its limit. |
| `…` | `[..]` | amber | Needs attention, or waiting. |
| `✗` | `[x]` | red | Needs a fix, refused, or at its limit. |
| `–` | `[--]` | dim | Optional, or not set up. |
| `->` | `->` | dim | The command to run next. |

Titles are bold blue, questions are blue, frames and the bridge mark are slate,
and hints are dim. Other text keeps the terminal's own color, so it reads on
light and dark themes. Lines are at most 60 columns wide, but a command to copy
is never wrapped, even when it is longer.

Color is used only when standard output is a terminal. `NO_COLOR` (set to any
value) turns color off and keeps the marks. `TERM=dumb` turns color off and
switches the marks and frames to the ASCII forms above. `trestle init
--no-input` prints no color either.

A refusal names the command, says what happened and what did or did not
change, and gives the command to run next on its own line:

```text
trestle review: this repository has no Open Trestle setup yet (looked in ~/.local/state/open-trestle/app-1a2b3c4d). Nothing was sent.
  -> trestle init
```

## Everyday

### `trestle`

In a terminal, `trestle` shows this repository's setup, key, spending and last
review, with numbered next actions. A row that needs action starts with its
mark and has the command that fixes it beneath it, and a known update is the
last row. See [getting started](getting-started.md#running-it-again). Outside
a Git repository, it says so and exits `0`. It prints the usage and exits `2`
when standard input or output is not a terminal, or when `NO_COLOR` or
`TERM=dumb` is set.

### `trestle review`

Reviews the latest committed change with the setup that `trestle init` made.

It shows [progress](local-model-review.md#progress) on standard error and ends a finished review with `Review took 2m 14s.`.

| Flag | Meaning |
| --- | --- |
| `--base REF`, `--head REF` | The two commits. Default: `HEAD` against its merge base with the default branch; with `--head` alone, that head against its merge base. |
| `--directory PATH` | The setup folder, when it is not the one `trestle init` proposes. |
| `--format text\|json\|sarif\|markdown` | The result format. Default: the setup's. |
| `--all` | List every finding, not only confirmed high and medium ones. |
| `--verbose` | Add internal fields to the text output. On a terminal, print the full text document instead of the [short view](local-model-review.md#the-result-on-a-terminal). |
| `--timeout DURATION` | The time limit for the review. |
| `--profile ID` | Run one [specialist profile](agent-profiles.md). |
| `--specialists auto\|none\|ID[,ID...]` | Run the general review plus the selected specialists. |
| `--max-specialists N` | The most specialists a set runs. |
| `--exit-code-policy default\|findings\|strict\|always-zero` | How a completed review maps to an exit status. See [exit codes](exit-codes.md#exit-code-policy). |
| `--checks`, `--no-checks` | Run or skip the [repository checks](repository-checks.md) for this review, whatever the saved answer. |
| `--model-checks` | Ask the checker to write a test for each of up to 3 verified findings, and keep the tests that fail on head and pass, or cannot be built, on base. Needs the repository checks and never changes the status. See [model-written checks](repository-checks.md#model-written-checks). |
| `--stop-on-stdin-close` | Stop the review, as Ctrl-C does, when standard input reaches end of file, so a program can cancel it by closing its input. The checks question is not asked. |

You cannot combine `--profile` and `--specialists`. `trestle review PATH`
reviews a local fixture file instead.

### `trestle status`

```text
trestle status [--json]
```

Prints the home screen's card without the actions: repository, setup folder,
models, where reviews run, key, this month's spending, last review and any
known update. It reads local files only and sends nothing. The update row
comes from the home screen's cached notice.

On a terminal it prints the card. Without a terminal it prints one
`Label:  value` line per row, and a row that needs action ends with
`-> COMMAND`:

```text
Repository:  ~/work/app (on branch main)
Setup:       ~/.local/state/open-trestle/app-1a2b3c4d
Models:      finder gemma4:31b · checker qwen3.5:397b
Runs on:     Ollama Cloud (https://ollama.com/v1)
Key:         OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD (not set) -> trestle keys set OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD
Spending:    $0.00 recorded this month; no limit set (an upper-bound estimate, not a bill)
Last run:    none recorded yet
```

`--json` prints one document with `contract` (`open-trestle/status`),
`schema_version`, `ready` and `rows`. Each row has `label`, `value`, `state`
(`ok`, `optional`, `attention` or `fail`) and, when there is one, `next` (the
commands that fix it). The command exits `0` with a usable setup, and `1`
outside a Git checkout or without a usable setup.

### `trestle update`

Installs a newer, verified build of the packaged Linux install. See
[updates](updates.md).

On a terminal, the download and the archive check show a spinner with the elapsed time on standard error; otherwise plain lines are printed.

| Flag | Meaning |
| --- | --- |
| `--check` | Report only, and exit `10` when a newer version exists. |
| `--yes` | Install without asking. |
| `--channel auto\|release\|local` | Where to look. Defaults to `auto`. |
| `--from FILE` | Install the archive `FILE`, with `FILE.sha256` beside it. Cannot be combined with `--channel`. |

### `trestle usage`

Shows the spending recorded in this period against each key's limit. See
[spending limits](spending-limits.md).

| Command | Meaning |
| --- | --- |
| `trestle usage` | Show each limited key's state. |
| `trestle usage set --credential-env NAME --limit USD` | Set a limit. Also takes `--period week\|month\|year`, `--alert 80,100` and `--provider ID`. |
| `trestle usage clear --credential-env NAME` | Remove a limit. Also takes `--provider ID`. |

On a terminal, each key's mark and color follow its percentage of the limit:
a dim `✓` below 50%, a plain `✓` from 50%, an amber `…` from the first alert
percentage (80% by default), and a red `✗` at 100% or more. The percentage is
always printed.

### `trestle profiles`

| Command | Meaning |
| --- | --- |
| `trestle profiles list [--format text\|json]` | List the nine packaged specialist profiles. |
| `trestle profiles plan --assignments PATH --features PATH` | Print the plan for an assignments document and a set of change features. See [agent profiles](agent-profiles.md). |

## Setup and keys

### `trestle init`

Guided setup and first review for the Git repository in the current directory.
Every answer has a flag, and `--no-input` never prompts. See
[getting started](getting-started.md#non-interactive-use).

| Group | Flags |
| --- | --- |
| Where | `--directory`, `--base`, `--head` |
| Provider | `--provider openrouter\|openrouter-zdr\|ollama-cloud\|opencode-go\|local\|ollama-signin`, `--endpoint`, `--verification-endpoint`, `--transport openai_chat_completions\|openai_responses` |
| Models | `--generation-model`, `--verification-model`, `--generation-provider-slug`, `--verification-provider-slug` |
| Key | `--credential-env OPEN_TRESTLE_PROVIDER_NAME` |
| Names | `--owner`, `--tenant`, `--repository`, `--repository-authority`, `--repository-namespace`, `--repository-name` |
| Capacity and price | `--context-tokens`, `--output-tokens`, `--max-output-tokens`, `--input-micro-usd-per-million-tokens`, `--output-micro-usd-per-million-tokens`, `--max-cost-micro-usd` |
| Spending | `--spending-limit USD`, `--spending-alert PERCENT` |
| Review | `--specialists auto\|none`, `--run-review`, `--allow-local-probe`, `--checks` |
| Evidence | `--generation-model-evidence`, `--verification-model-evidence`, `--broker-evidence`, `--account-evidence`, `--evidence-retrieved-at`, `--reviewed-at`, `--valid-from`, `--valid-until` |
| Declarations | `--declare-remote-route`, `--declare-opencode-go-account`, `--declare-ollama-cloud-signin`, `--declare-local-capabilities`, `--without-zdr` |
| Mode | `--no-input` |

### `trestle keys`

See [API keys](keys.md).

| Command | Meaning |
| --- | --- |
| `trestle keys` or `trestle keys list` | Show each key variable and where its key comes from. |
| `trestle keys set OPEN_TRESTLE_PROVIDER_NAME` | Type the key (hidden) or pipe it in. The key is checked and saved. |
| `trestle keys remove OPEN_TRESTLE_PROVIDER_NAME` | Delete the saved key. |

### `trestle checks`

Allows or stops running the repository's own tests in a sandbox before each
review. See [repository checks](repository-checks.md).

| Command | Meaning |
| --- | --- |
| `trestle checks on` | Run the checks before every review of this repository. |
| `trestle checks off` | Never run them, and stop asking. |
| `trestle checks status` | Show the saved answer and whether this machine has what the sandbox needs. |

Each takes `--directory PATH` for a setup in another folder.

### `trestle doctor`

```text
trestle doctor [--live] [--json]
```

Checks this install, the repository in the current folder and its setup, and
names the command that fixes each problem. It changes nothing and sends no
source. The sections, in order:

| Section | What it checks |
| --- | --- |
| Install | The version and source revision, the secret scan helper (whether it is found, and the one this build pins), and the platform. |
| Repository | A Git checkout, its default branch, a shallow clone, and uncommitted changes (which reviews leave out). |
| Setup | The setup folder and whether it loads, the provider, the two models, the route checks of `trestle setup bootstrap check`, and the zero-data-retention requirement for OpenRouter. |
| Keys | Each key variable the setup names, whether it is from the environment or saved, and at most its last four characters. |
| Spending | Each key's limit and how much of it is used, from the usage folder. |
| Repository checks | Whether checks are on, off or not decided, and whether the sandbox can run here. |
| Update | The cached update notice. Doctor itself never asks for one. |

Each row has a mark (see [terminal symbols and colors](#terminal-symbols-and-colors)),
and a row marked `✗` or `…` has the command to run beneath it:

```text
Keys
  ✗ Key       OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD is not set
              in this shell and not saved
    -> trestle keys set OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD
```

The report ends with `All checks passed.`, with `Nothing to fix.` and a count
of the rows marked for attention, or with a numbered list of the problems and
their commands. Only `✗` rows are problems, so `…` and `–` rows never fail.
Outside a Git checkout, the repository and setup sections say so and the rest
still run.

`--live` adds network checks, which send no source. For OpenRouter it checks
that the key is accepted (the free `GET /api/v1/key`). It then reads the
provider's model list, with the key where the provider takes one, and checks
that both models are still listed.

`--json` prints one document with `contract` (`open-trestle/doctor`),
`schema_version`, `live`, `passed`, `sections` (each a `title` and `rows`) and
`problems` (the `fail` rows). Rows have the fields of `trestle status --json`.
Without a terminal the output is the same text without color. The command
exits `0` when nothing needs fixing and `1` when something does.

## Integrations

### `trestle local-git model-review`

The direct review that the CI example runs and that `trestle review` wraps. See
[local model review](local-model-review.md).

You name the source in one of two ways. With an objects folder, use
`--objects-root PATH`, `--repository-authority`, `--repository-namespace`,
`--repository-name`, `--revision-algorithm sha1|sha256`,
`--base-revision-digest` and `--head-revision-digest`, and optionally
`--object-store loose-only|loose-and-pack-index-v1`. With a checkout, use
`--checkout PATH --base REF --head REF` in place of the objects and revision
flags.

The other flags are `--tenant`, `--repository`, `--route-inventory PATH`,
`--runtime-policy PATH`, `--egress local-only|policy-approved`,
`--timeout DURATION`, `--format json|text|sarif|markdown`, `--all`,
`--verbose`, `--repository-checks` (with `--model-checks`),
`--exit-code-policy`, `--investigation-policy PATH` or
`--retained-memory-input PATH`, and `--profile` or `--specialists` with
`--max-specialists`.

### `trestle local-git submit-review`

Submits a full review to the local daemon. It takes the objects-folder source
flags, `--server LOOPBACK_URL`, `--tenant`, `--repository`, `--run`,
`--review-policy-identity`, `--inventory-identity`, `--runtime-policy-identity`
and, optionally, `--created-at-unix-milliseconds`.

### `trestle runs`

These commands are clients of a running daemon, `trestled`, which is a
separate binary. See [daemon API](daemon-api.md).

| Command | Flags |
| --- | --- |
| `trestle runs submit` | `--plan PATH`, `--server URL` |
| `trestle runs status` | `--tenant`, `--repository`, `--run`, `--server`, `--format run\|progress\|json\|sarif` |
| `trestle runs cancel` | The same as `status`, except that `--format` accepts only `run` |
| `trestle runs refusal` | `--tenant`, `--repository`, `--run`, `--server` |

`--server` defaults to `OPEN_TRESTLE_API_URL`, or else
`http://127.0.0.1:8741`.

### Observers

| Command | Flags | Page |
| --- | --- | --- |
| `trestle mcp` | `--server URL` | [MCP](mcp.md) |
| `trestle lsp` | `--diagnostics PATH`, `--server URL` | [LSP](lsp.md) |

## Operators

These commands set up and check a daemon deployment, or print identities. They
are documented in [setup](setup.md), [operations](operations.md) and
[configuration validation](configuration-validation.md).

### `trestle setup`

| Command | Flags |
| --- | --- |
| `setup inspect` | `--state`, `--expected-root-identity` |
| `setup backup create` | `--state`, `--destination`, `--expected-plan-identity` |
| `setup backup restore` | `--snapshot`, `--destination`, `--expected-root-identity`, `--expected-plan-identity` |

### `trestle setup bootstrap`

Writes the protected configuration for a local or remote first review.
`trestle init` runs the same code.

| Command | Flags |
| --- | --- |
| `init` (local model server) | `--directory`, `--tenant`, `--repository`, `--recovery-owner`, `--checkout`, `--base`, `--head`, `--repository-authority`, `--repository-namespace`, `--repository-name`, `--generation-endpoint`, `--generation-model`, `--generation-credential-environment`, `--verification-endpoint`, `--verification-model`, `--verification-credential-environment`, `--transport`, `--context-tokens`, `--output-tokens`, `--max-output-tokens`, `--declare-local-capabilities`, `--specialists auto\|none`, `--scope direct-review` |
| `init --provider openrouter-zdr\|openrouter\|opencode-go\|ollama-cloud\|ollama-signin` | `--directory`, `--provider`, `--specialists`, `--tenant`, `--repository`, `--checkout`, `--base`, `--head`, the repository name flags, `--generation-model`, `--verification-model`, `--generation-credential-environment`, `--verification-credential-environment`, `--endpoint`, `--declared-by`, `--context-tokens`, `--output-tokens`, `--max-output-tokens`, `--input-micro-usd-per-million-tokens`, `--output-micro-usd-per-million-tokens`, `--max-cost-micro-usd`, and the provider declarations in [remote model review](remote-model-review.md) |
| `check` | Local: `--directory`, `--approved-by`, `--scope`, `--allow-local-probe`, `--backup-directory`. Remote: `--directory` only. |
| `inspect` | `--directory` |
| `prepare-review` | `--directory` (local only) |

### `trestle config`

| Command | Flags |
| --- | --- |
| `config validate` | `--route-inventory`, `--runtime-policy` |
| `config bind` | `--route-inventory`, `--runtime-policy-template`, `--generation-adapter`, `--verification-adapter` |
| `config inventory-identity` | `--route-inventory` |
| `config models refresh` | `--sources`, `--current`, `--proposal`, `--allow-remote` |
| `config models apply` | `--sources`, `--current`, `--proposal`, `--expected-proposal`, `--expected-current` |

### `trestle admin`

| Command | Flags |
| --- | --- |
| `admin runtime status` | `--tenant`, `--repository`, `--server`, `--timeout` |

### Static local Git commands

These commands read loose objects only, make no model call and do not publish.
See [inspect](local-git-inspect.md), [change](local-git-change.md) and
[review](local-git-review.md).

| Command | Flags |
| --- | --- |
| `local-git inspect` | `--objects-root`, `--repository-authority`, `--repository-namespace`, `--repository-name`, `--revision-algorithm`, `--revision-digest` |
| `local-git change` | The same, with `--base-revision-digest` and `--head-revision-digest` |
| `local-git review` | The same as `change`, plus `--format json\|sarif`. To review through the daemon, add `--tenant`, `--repository`, `--run` and `--server`. |
| `local-git retained-memory-input` | See below the table. |

`local-git retained-memory-input` takes `--repository-authority`,
`--repository-namespace` and `--repository-name`; either `--revision-algorithm`
with `--head-revision-digest`, or `--review-input`; `--tenant`, `--repository`,
`--route-inventory`, `--runtime-policy`, `--egress local-only` and `--timeout`;
either `--valid-for` with `--feedback-input` and `--output`, or
`--remove-input`; and optionally `--format json|text`.

### `trestle index`

Builds and queries the [repository index](repository-index.md) of the checkout in the current directory, and keeps it in the setup folder. It reads the verified Git object store and makes no model call.

| Command | Flags |
| --- | --- |
| `index build`, `index status` | `--commit REF`, `--directory PATH` |
| `index query definitions\|references\|tests NAME`, `index query imports PATH` | `--commit REF`, `--directory PATH` |
| `index query dependents` | `--base REF` (required), `--commit REF`, `--directory PATH` |

### `trestle profile`

Prints the repository profile of a commit (default `HEAD`) of the checkout in the current directory: its languages and their shares, its test frameworks and layout, the checks its CI enforces (grouped by class), and the checks that are only configured. A check counts as enforced when a GitHub Actions step runs it, on pushes or pull requests, and the step is not disabled or allowed to fail. Checks in other CI systems, or only in a linter configuration, are listed as configured. Configuration files are read as data from the verified Git object store and never run. A review reads the checks of its base commit. Flags: `--commit REF`, `--directory PATH`, `--json`.

### `trestle version`

`trestle version` and `trestle --version` print one line: `Open Trestle 0.1.0
(source revision 3f2a9c1d0e4b), the packaged Linux amd64 install` for the
packaged install, `Open Trestle 0.1.0 (source revision ...)` for a release
archive install, and `Open Trestle development build (source revision ...)`
for any other build. `trestle build-info` is the JSON form.

### `trestle build-info`

Prints the source revision and source tree embedded in the build as one JSON line. A build without an embedded identity reports `source_bound: false`.

## Evaluation

| Command | Meaning |
| --- | --- |
| `trestle evaluate adjudication --adjudication PATH --adjudication-sha256 SHA256 --observed PATH` | Compare a human adjudication record with an observed result. See [quality evaluation](quality-evaluation.md). |
| `trestle evaluate static-debug` | Run the built-in static-debug evaluation cases and print a JSON report. |
| `trestle evaluate deterministic-corpus-candidate`, `trestle evaluate model-contract-candidate` | Print a JSON report of the built-in candidate, which is pending adjudication. |
| `trestle evaluate model-result --result PATH --result-sha256 SHA256 --case CASE_ID --objects-root DIR` and the repository and revision flags | Capture a model-review result for one corpus case. See [model result evaluation](model-result-evaluation.md). |
| `trestle validate-fixture PATH` | Validate a local fixture file. |
| `trestle ci --format=json PATH`, `trestle ci --format=sarif PATH` | Review a fixture file and print the result as JSON or SARIF. |

# Commands

This page lists every `trestle` command and its flags, grouped as `trestle --help`
groups them. Use it to look up a flag; for a first walkthrough, start with
[getting started](getting-started.md).

`trestle --help`, `trestle -h` and `trestle help` print the usage to standard
output and exit `0`. A command line that Open Trestle does not recognise, and a
bare `trestle` without a terminal, print the same usage to standard error and
exit `2`. Each command also prints its own usage when its arguments are wrong.
Exit codes are in [exit codes](exit-codes.md), and variables and paths are in
[environment variables and files](environment-and-files.md).

`--flag=value` and `--flag value` both work. `init`, `review`, `update` and
`usage` reject a flag that you give twice.

## Everyday

### `trestle`

In a terminal, `trestle` shows this repository's setup, key, spending and last
review, with numbered next actions. See
[getting started](getting-started.md#running-it-again). Outside a Git
repository, it says so and exits `0`. Without a terminal on both sides, or with
`NO_COLOR` set or `TERM=dumb`, it prints the usage and exits `2`.

### `trestle review`

Reviews the latest committed change with the setup that `trestle init` made.

| Flag | Meaning |
| --- | --- |
| `--base REF`, `--head REF` | Pick the two commits. Default: `HEAD` against its merge base with the default branch. |
| `--directory PATH` | The setup folder, when it is not the one `trestle init` proposes. |
| `--format text\|json\|sarif\|markdown` | Result format. Default: the setup's. |
| `--all` | List every finding, not only confirmed high and medium ones. |
| `--verbose` | Add internal fields to the text output. |
| `--timeout DURATION` | Time limit for the review. |
| `--profile ID` | Run one [specialist profile](agent-profiles.md). |
| `--specialists auto\|none\|ID[,ID...]` | Run the general review plus selected specialists. |
| `--max-specialists N` | Cap the specialists a set runs. |
| `--exit-code-policy default\|findings\|strict\|always-zero` | Map a completed review to an exit status. See [exit codes](exit-codes.md#exit-code-policy). |

You cannot combine `--profile` and `--specialists`. `trestle review PATH`
reviews a local fixture file instead.

### `trestle update`

Installs a newer, verified build of the packaged Linux install. See
[updates](updates.md).

| Flag | Meaning |
| --- | --- |
| `--check` | Report only; exit `10` when a newer version exists. |
| `--yes` | Install without asking. |
| `--channel auto\|release\|local` | Where to look. Default: `auto`. |
| `--from FILE` | Install the archive `FILE`, with `FILE.sha256` beside it. Excludes `--channel`. |

### `trestle usage`

Shows the spending recorded in this period against each key's limit. See
[spending limits](spending-limits.md).

| Command | Meaning |
| --- | --- |
| `trestle usage` | Show each limited key's state. |
| `trestle usage set --credential-env NAME --limit USD` | Set a limit. Also takes `--period week\|month\|year`, `--alert 80,100` and `--provider ID`. |
| `trestle usage clear --credential-env NAME` | Remove a limit. Also takes `--provider ID`. |

### `trestle profiles`

| Command | Meaning |
| --- | --- |
| `trestle profiles list [--format text\|json]` | List the nine packaged specialist profiles. |
| `trestle profiles plan --assignments PATH --features PATH` | Print the plan for an assignments document and change features. See [agent profiles](agent-profiles.md). |

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
| Review | `--specialists auto\|none`, `--run-review`, `--allow-local-probe` |
| Evidence | `--generation-model-evidence`, `--verification-model-evidence`, `--broker-evidence`, `--account-evidence`, `--evidence-retrieved-at`, `--reviewed-at`, `--valid-from`, `--valid-until` |
| Declarations | `--declare-remote-route`, `--declare-opencode-go-account`, `--declare-ollama-cloud-signin`, `--declare-local-capabilities`, `--without-zdr` |
| Mode | `--no-input` |

### `trestle keys`

See [API keys](keys.md).

| Command | Meaning |
| --- | --- |
| `trestle keys` or `trestle keys list` | Each key variable and where its key comes from. |
| `trestle keys set OPEN_TRESTLE_PROVIDER_NAME` | Type the key (hidden) or pipe it in; it is checked and saved. |
| `trestle keys remove OPEN_TRESTLE_PROVIDER_NAME` | Delete the saved key. |

## Integrations

### `trestle local-git model-review`

The direct review that the CI example runs and that `trestle review` wraps. See
[local model review](local-model-review.md).

You name the source in one of two ways. With an objects folder, use
`--objects-root PATH`, `--repository-authority`, `--repository-namespace`,
`--repository-name`, `--revision-algorithm sha1|sha256`,
`--base-revision-digest` and `--head-revision-digest`, and optionally
`--object-store loose-only|loose-and-pack-index-v1`. With a checkout, use
`--checkout PATH --base REF --head REF`, which replaces the objects and revision
flags.

The other flags are `--tenant`, `--repository`, `--route-inventory PATH`, `--runtime-policy
PATH`, `--egress local-only|policy-approved`, `--timeout DURATION`, `--format
json|text|sarif|markdown`, `--all`, `--verbose`, `--exit-code-policy`,
`--investigation-policy PATH` or `--retained-memory-input PATH`, and `--profile`
or `--specialists` with `--max-specialists`.

### `trestle local-git submit-review`

Submits a full review to the local daemon. It takes the objects-folder source flags,
`--server LOOPBACK_URL`, `--tenant`, `--repository`, `--run`,
`--review-policy-identity`, `--inventory-identity`, `--runtime-policy-identity`
and optionally `--created-at-unix-milliseconds`.

### `trestle runs`

These commands are clients of a running daemon. See [daemon API](daemon-api.md).
The daemon is `trestled`, a separate binary.

| Command | Flags |
| --- | --- |
| `trestle runs submit` | `--plan PATH`, `--server URL` |
| `trestle runs status` | `--tenant`, `--repository`, `--run`, `--server`, `--format run\|progress\|json\|sarif` |
| `trestle runs cancel` | the same as `status` |
| `trestle runs refusal` | `--tenant`, `--repository`, `--run`, `--server` |

`--server` defaults to `http://127.0.0.1:8741`, or `OPEN_TRESTLE_API_URL`.

### Observers

| Command | Flags | Page |
| --- | --- | --- |
| `trestle tui` | `--tenant`, `--repository`, `--run`, `--server`, `--refresh DURATION`, `--width COLUMNS`, `--plain`, `--once` | [terminal UI](tui.md) |
| `trestle mcp` | `--server URL` | [MCP](mcp.md) |
| `trestle lsp` | `--diagnostics PATH`, `--server URL` | [LSP](lsp.md) |
| `trestle acp` | `--tenant`, `--repository`, `--run`, `--server` | [ACP](acp.md) |

## Operators

These commands set up and check a daemon deployment, or print identities. They
are documented in [setup](setup.md), [operations](operations.md) and
[configuration validation](configuration-validation.md).

### `trestle setup`

| Command | Flags |
| --- | --- |
| `setup init` | `--profile`, `--tenant`, `--repository`, `--recovery-owner`, `--state` |
| `setup inspect` | `--state`, `--expected-root-identity` |
| `setup check storage` | `--state`, `--storage-root` |
| `setup check observer` | `--state` |
| `setup check postgres` | `--state`, `--approve-postgres-authority-identity`, `--approved-by` |
| `setup check secret` | `--state`, `--approve-kms-authority-identity`, `--kms-region`, `--kms-key-arn`, `--kms-endpoint`, `--approved-by` |
| `setup check envelope` | `--state`, `--approve-envelope-storage-authority-identity`, `--s3-endpoint`, `--s3-region`, `--s3-bucket`, `--s3-prefix`, `--kms-region`, `--kms-key-arn`, `--kms-endpoint`, `--approved-by` |
| `setup check integration` | `--state`, `--approve-integration-permission-authority-identity`, `--approve-github-source-broker-authority-identity`, `--allow-github-installation-token-creation`, `--approved-by`; or the older `--github-api-endpoint`, `--github-api-version`, `--github-installation-id`, `--github-repository-full-name` |
| `setup check webhook` | `--state`, `--approve-webhook-authority-identity`, `--github-webhook-key-id`, `--approved-by` |
| `setup check rate-limit` | `--state`, `--approve-shared-rate-limit-authority-identity`, `--postgres-database-authority-identity`, `--approved-by` |
| `setup check reconciliation` | `--state`, `--approve-replica-reconciliation-authority-identity`, `--postgres-database-authority-identity`, `--approved-by` |
| `setup check bundle` | `--state`, `--approve-signed-bundle-authority-identity`, `--bundle`, `--bundle-sha256`, `--bundle-bytes`, `--public-key`, `--signature`, `--approved-by` |
| `setup check administrator` | `--state`, `--approved-by` |
| `setup check backup` | `--state`, `--backup-snapshot` |
| `setup check provider`, `policy`, `dry-run`, `inference` | `--state`, `--route-inventory`, `--runtime-policy`, `--approve-inventory-identity`, `--approve-runtime-policy-identity`, `--approve-review-policy-identity`, `--approved-by` |
| `setup backup create` | `--state`, `--destination`, `--expected-plan-identity` |
| `setup backup restore` | `--snapshot`, `--destination`, `--expected-root-identity`, `--expected-plan-identity` |
| `setup tui` | `--state`, `--storage-root`, `--backup-snapshot`, `--administrator-approved-by`, the approval flags of the checks above with one approver flag each (`--postgres-approved-by`, `--kms-approved-by`, `--envelope-approved-by`, `--integration-approved-by`, `--webhook-approved-by`, `--shared-rate-limit-approved-by`, `--replica-reconciliation-approved-by`, `--signed-bundle-approved-by`), `--approved-by` for the policy checks, `--width`, `--plain`, `--once` |
| `setup web` | `--state`, `--listen LOOPBACK:PORT` (default `127.0.0.1:8742`), `--approve-github-source-broker-authority-identity` |

### `trestle setup bootstrap`

Writes the protected configuration for a local or remote first review.
`trestle init` runs the same code.

| Command | Flags |
| --- | --- |
| `init` (local model server) | `--directory`, `--tenant`, `--repository`, `--recovery-owner`, `--checkout`, `--base`, `--head`, `--repository-authority`, `--repository-namespace`, `--repository-name`, `--generation-endpoint`, `--generation-model`, `--verification-endpoint`, `--verification-model`, `--transport`, `--context-tokens`, `--output-tokens`, `--max-output-tokens`, `--declare-local-capabilities`, `--scope direct-review` |
| `init --provider openrouter-zdr\|openrouter\|opencode-go\|ollama-cloud\|ollama-signin` | `--directory`, `--provider`, `--specialists`, `--tenant`, `--repository`, `--checkout`, `--base`, `--head`, the repository name flags, `--generation-model`, `--verification-model`, `--generation-credential-environment`, `--verification-credential-environment`, `--endpoint`, `--declared-by`, `--context-tokens`, `--output-tokens`, `--max-output-tokens`, `--input-micro-usd-per-million-tokens`, `--output-micro-usd-per-million-tokens`, `--max-cost-micro-usd`, and the provider declarations in [remote model review](remote-model-review.md) |
| `check` | `--directory`, `--approved-by`, `--scope`, `--allow-local-probe`, `--backup-directory` (local); `--directory` only (remote) |
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
| `config codex-session status` | none |

### `trestle admin`

| Command | Flags |
| --- | --- |
| `admin bundle statement` | `--bundle-sha256`, `--bundle-bytes` |
| `admin bundle identity` | `--bundle-sha256`, `--bundle-bytes`, `--public-key`, `--signature` |
| `admin kms identity` | `--tenant`, `--region`, `--key-arn` |
| `admin envelope identity` | `--tenant`, `--s3-endpoint`, `--s3-region`, `--s3-bucket`, `--s3-prefix`, `--kms-region`, `--kms-key-arn`, `--kms-endpoint` |
| `admin github permissions identity` | `--api-endpoint`, `--api-version`, `--installation-id`, `--repository-full-name`; or `--broker-config PATH` |
| `admin github webhook identity` | `--tenant`, `--repository`, `--key-id` |
| `admin runtime status` | `--tenant`, `--repository`, `--server`, `--timeout` |
| `admin postgres migrate`, `identity` | `--timeout` |
| `admin postgres verify` | `--authority-identity`, `--expected-receipt-identity`, `--timeout` |
| `admin postgres initialize` | `--authority-identity`, `--timeout` |
| `admin postgres rate-limit identity`, `reconciliation identity` | `--database-authority-identity`, `--setup-root-identity` |

### Static local Git commands

These commands read loose objects only, make no model call and do not publish.
See
[inspect](local-git-inspect.md), [change](local-git-change.md) and
[review](local-git-review.md).

| Command | Flags |
| --- | --- |
| `local-git inspect` | `--objects-root`, `--repository-authority`, `--repository-namespace`, `--repository-name`, `--revision-algorithm`, `--revision-digest` |
| `local-git change` | the same, with `--base-revision-digest` and `--head-revision-digest` |
| `local-git review` | the same as `change`, plus `--format json\|sarif`; or add `--tenant`, `--repository`, `--run`, `--server` to review through the daemon |
| `local-git retained-memory-input` | `--repository-authority`, `--repository-namespace`, `--repository-name`, `--revision-algorithm` with `--head-revision-digest`, or `--review-input`, `--tenant`, `--repository`, `--route-inventory`, `--runtime-policy`, `--egress local-only`, `--timeout`, `--valid-for` with `--feedback-input` and `--output`, or `--remove-input`, `--format json\|text` |

### `trestle build-info`

Prints the source revision and source tree embedded in the build as one JSON line. A build without an embedded identity reports `source_bound: false`.

## Evaluation

| Command | Meaning |
| --- | --- |
| `trestle evaluate adjudication --adjudication PATH --adjudication-sha256 SHA256 --observed PATH` | Compare a human adjudication record with an observed result. See [quality evaluation](quality-evaluation.md). |
| `trestle evaluate static-debug` | Run the built-in static-debug evaluation cases and print a JSON report. |
| `trestle evaluate deterministic-corpus-candidate`, `trestle evaluate model-contract-candidate` | Print a JSON report of the built-in candidate, pending adjudication. |
| `trestle evaluate model-result --result PATH --result-sha256 SHA256 --case CASE_ID --objects-root DIR` and the repository and revision flags | Capture a model-review result for one corpus case. See [model result evaluation](model-result-evaluation.md). |
| `trestle validate-fixture PATH` | Validate a local fixture file. |
| `trestle ci --format=json PATH`, `trestle ci --format=sarif PATH` | Review a fixture file and print the result as JSON or SARIF. |

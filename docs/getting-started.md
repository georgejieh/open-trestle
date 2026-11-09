# Getting started

`trestle init` is the first step. Run it inside the Git repository you want
reviewed. It asks a few plain questions, saves a protected configuration, runs
the setup checks, and offers to run your first review. If something is missing,
it says what is missing and what to do, then stops without guessing.

```sh
cd path/to/your-repository
trestle init
```

The wizard is a front end over the existing
[local-first bootstrap](local-first-bootstrap.md) and
[remote model review](remote-model-review.md) commands. It calls the same
`trestle setup bootstrap init` and `check` code in-process and runs the same
`trestle local-git model-review` command they print. It adds no configuration
format, default model, privacy claim or shortcut. Everything it records is still
your explicit answer.

## Before you start

- **A Git checkout with committed changes.** Only committed work is reviewed;
  uncommitted edits are ignored. The review compares exactly two commits and
  never fetches. By default the base is the merge base of your default branch
  and `HEAD`, the same commit a pull request is compared against.
- **Somewhere to run two models.** One model looks for problems, a different
  model double-checks them. Choose one of:
  - OpenRouter with zero-data-retention routes, Ollama Cloud, or OpenCode Go.
    You need an account and an API key.
  - A model server on this machine: Ollama, llama.cpp, vLLM or LM Studio
    (any OpenAI-compatible server on `127.0.0.1`).
  - Ollama on this machine, signed in to Ollama Cloud with `ollama signin`. It
    needs no API key, but it is a remote provider: the models run on Ollama
    Cloud and your source is sent there when you run a review. See
    [Ollama signed in to Ollama Cloud](remote-model-review.md#ollama-signed-in-to-ollama-cloud).
- **A `trestle` binary.** Nothing is released yet. In a clone of this repository,
  `go build -o trestle ./cmd/trestle` builds a development binary; run it by its
  path or put it on your `PATH`. That build works with a model server on this
  machine.
- **For remote providers: the packaged `trestle` binary and its secret scanner.**
  Every request is scanned for secrets in a sandboxed scanner before it leaves
  the machine. A plain `go build` has no scanner fingerprints and refuses to send
  source. The wizard detects such a development build before you choose a
  provider, explains why, and shows packaging and install commands; the complete
  sequence, which also runs the passive vulnerability gate before the candidate
  builder, is in
  [operations](operations.md#build-and-inspect-the-unsigned-linux-amd64-candidate).
  A local model server still works with a development build. See
  [prerequisite 1](remote-model-review.md#prerequisite-1-a-scanner-bound-binary-and-installed-scanner).
- **An ordinary clone is fine.** Every mode, local included, uses the direct
  checkout review, which reads loose objects and ordinary pack files and verifies
  each object against its hash. Right after you pick the commits, the wizard reads
  both of them the same way. It stops early, with a `git clone --no-local
  --no-hardlinks` command for a separate full copy, only for storage that review
  cannot read: alternates (clones made with `--shared` or `--reference`), a
  multi-pack-index, or partial-clone packs. The wizard never changes repository
  permissions. The private `0700`, loose-object source described in
  [choose the repository](local-first-bootstrap.md#choose-the-repository-and-model-pair)
  is needed only for the optional background daemon.

No repository source is sent anywhere during setup. Setup does make a few network
reads, each described below: it may fetch a provider's public model list, list
models with your API key only when you agree (the key goes only to that
provider's model-list address), and fetch a public evidence page you name once
you confirm. With a local Ollama it reads that Ollama's model list
(`/api/tags` on `127.0.0.1`), and for the Ollama Cloud sign-in option it can send
one fixed test message, only if you agree. Your source goes to the models only
when you agree to run a review.

## What the wizard asks

1. **What will be reviewed.** It finds your default branch (`origin/HEAD`'s
   branch when it exists locally, otherwise `main` or `master`) and proposes the
   merge base of that branch and `HEAD` as the base (shown as, for example,
   "merge base with main"; it runs only the read-only `git merge-base`), and
   `HEAD` as the head. The commit count and changed-file summary come from those
   same two commits, so commits added to the default branch after you branched
   are not shown as your changes. If Git finds no merge base, the branch itself
   is proposed. You can type a branch name, tag, full ref or commit ID instead.
2. **How a review works.** A short explanation; nothing to answer.
3. **Where the models run.** Pick a provider or a local server. The options are
   OpenRouter, Ollama Cloud, OpenCode Go, a model server on this machine, and
   "Ollama on this machine, signed in to Ollama Cloud".
4. **The two models.** For Ollama Cloud and OpenCode Go it reads the public model
   list (no key or code is sent). For a local server it reads the server's
   `/v1/models` list from `127.0.0.1` only. For OpenRouter, if your key variable
   (such as `OPEN_TRESTLE_PROVIDER_OPENROUTER`) is already set, it offers to read
   `https://openrouter.ai/api/v1/models` with it; the key is sent only there and
   never shown. A successful read shows the list is reachable, not that the key
   may run models. Each list read accepts a response of at most 4 MiB; a larger
   or unreadable list falls back to typing the IDs. Otherwise type the IDs
   exactly, for example `vendor/model-name`.
   A list longer than 40 entries asks for part of a name first. The checker must
   differ from the finder; choosing the same model asks again. Models that look like 7B parameters or fewer are
   flagged: they give weak reviews. You also state each model's context window
   and output limit, and for remote providers the prices and a per-review cost cap.
   No model, capacity or price is filled in unless it came from the model list
   you just read, except that a local server is proposed a 32768-token context
   (or the smaller listed value): start both servers with that context length, as
   [named local runtimes](named-local-runtimes.md#context-length) describes.

   With a local server, a model that the local Ollama relays to Ollama Cloud is
   refused, because it would send your source off this machine: the wizard
   refuses any name ending in `:cloud` or `-cloud`, then asks the server's
   `/api/tags` list and refuses an entry with a `remote_host`. If an Ollama
   daemon answers but its list cannot be read, the wizard refuses too, because
   it cannot tell where the model runs. Choose the Ollama Cloud sign-in option
   for cloud models instead.

   With "Ollama on this machine, signed in to Ollama Cloud", the wizard checks
   that the `ollama` command is installed, reads the daemon's `/api/tags` list
   and offers only the models it relays to `https://ollama.com`. It then offers a
   sign-in check: one fixed test message, "Reply with OK", sent to the finder
   model only if you agree. The message contains none of your code, but it goes
   to Ollama Cloud and uses your Ollama Cloud usage. If Ollama answers that you
   are not signed in, the wizard offers to run `ollama signin` in this terminal
   (only on `y`) and then sends the same message once more.
5. **API key.** (Not asked for the Ollama Cloud sign-in option, which sends no
   key.) You choose the name of an environment variable, such as
   `OPEN_TRESTLE_PROVIDER_OPENROUTER`. The key is never asked for, stored or
   printed. If the variable is not set, the wizard shows how to set it without
   echoing the key (`read -rs NAME && export NAME`). A running program cannot see
   a variable exported later, so continue, export it, and run `trestle init`
   again to re-check.
6. **Declarations.** Each fact the bootstrap needs is shown in plain words with a
   link, and you must type `yes`. Typing `no` stops with nothing written.
   - Every remote provider: the [route declaration](remote-model-review.md#common-declarations)
     (capacity, structured output, logging off, prices, availability).
   - OpenRouter: provider slugs, six evidence items, a review window and the
     [account declaration](remote-model-review.md#openrouter-zdr). A slug names
     the upstream provider and cannot be derived from the model ID, so you type
     the finder's slug once; the checker's question proposes the same slug. When
     both slugs match, the checker's upstream and slug evidence propose the
     finder's answers, one keypress each.
   - OpenCode Go: four evidence items, a review window and the
     [workspace declaration](remote-model-review.md#opencode-go).
   - Ollama signed in to Ollama Cloud: the
     [sign-in declaration](remote-model-review.md#ollama-signed-in-to-ollama-cloud)
     (`--declare-ollama-cloud-signin`) that your source is sent to Ollama Cloud
     under your signed-in account.
   - Local server: the [local capability declaration](local-first-bootstrap.md#choose-the-repository-and-model-pair).

   For evidence, give the web address you read. OpenRouter's broker and slug
   evidence propose the ZDR guide that
   [the profile](openrouter-zdr-profile.md) cites,
   `https://openrouter.ai/docs/guides/features/zdr`; press Enter to use it or type
   the page you actually reviewed. For a public page the wizard offers to fetch it
   once and compute the SHA-256 on this machine: one `https` GET with no key,
   cookie, query or repository content, public addresses only, at most 8 MiB and
   20 seconds. It shows the address and digest, and records them only if you
   confirm. Otherwise give the SHA-256 of a copy you saved, or that file's path,
   and the wizard hashes it locally. Account evidence is never fetched: save a
   copy of your own account page and give its path. The review window proposes
   `now` as the review time and 30 days of validity, and cannot be earlier than a
   fetch made during setup. Both are shown in the declaration you confirm, so
   change them if they are not accurate.
7. **Names.** Labels for the configuration and review records, derived from your
   user and repository names. Accept them or type your own.
8. **Save and check.** The configuration goes into a new private folder,
   `~/.local/state/open-trestle/<repository>-<8 hex characters>` by default
   (mode `0700`, files `0600`). Existing files are never overwritten. Long paths
   are shortened on screen (`~` for your home folder, `...` in the middle);
   commands and `NEXT-STEPS.txt` always keep the full paths.

## Reading the check results

| Mark | Meaning |
| --- | --- |
| `✓` | Passed. |
| `…` | Waiting: not done yet, or runs after an earlier item. A one-line hint says what to do. |
| `✗` | Needs a fix. The hint gives the exact remedy. |
| `–` | Optional and not set up (local mode: the test requests you did not allow, and items only the background daemon needs). |

With `TERM=dumb` the marks are `[ok]`, `[..]`, `[x]` and `[--]`.

Remote checks: the review window is current (OpenRouter, OpenCode Go), the saved
configuration loads, the API key variable is set, and the secret scanner is
installed. A review is offered only when all of them pass.

Local checks run in the bootstrap's direct-review scope
(`trestle setup bootstrap check --scope direct-review`): the setup folder is
private, you are its owner, the model configuration is approved and a dry run
without models passes. A review is offered only when all of them pass. The
daemon tokens and backup are shown as one optional line, because the direct
review never reads them; they belong to the daemon journey in
[check and resume](local-first-bootstrap.md#check-and-resume). The wizard also
offers two test requests to your local servers. They carry fixed sample code,
never your source, and are sent only if you answer `y`; a failed test request
must be fixed before a review is offered.

## The first review

The wizard shows the exact review command, each argument quoted for a POSIX
shell, and saves it with the check command in `NEXT-STEPS.txt` in the setup
folder. It then asks:

```text
  A review sends the selected source to OpenRouter (https://openrouter.ai/api/v1).
  Run the first review now? (y/N):
```

Only `y` runs it. The review runs in the foreground and keeps nothing for
resume; it can take several minutes.

### Reading the result

- `findings`: each listed finding was proposed by the finder and confirmed by
  the checker. Read them like a colleague's review comments.
- `no_candidates`: nothing was found and confirmed. That is not proof the change
  is correct.
- `incomplete`: part of the change was not covered; see the coverage and
  omission lines.
- `refused`, `failed` or `canceled`: no usable result; the wizard says what to try.

Every result says `comprehensive clearance: false`. A review is not an audit.
See [local model review](local-model-review.md) for the full result format.

## Running it again

Run `trestle init` again in the same repository (with the same `--directory`, if
you chose one). It finds the saved setup and offers to re-run the checks, or the
checks and then a review. It never re-initializes or changes the saved files. To
set up something different, use a new folder: `trestle init --directory NEW_FOLDER`.

## Non-interactive use

Every answer has a flag. With `--no-input` the wizard never prompts; if any
answer is missing it lists every missing flag and exits `2` without writing
anything. Proposals that are only labels (base, head, names, folder) are accepted
in `--no-input` mode; facts you must declare are not.

| Answer | Flag |
| --- | --- |
| Commits | `--base REF`, `--head REF` |
| Setup folder | `--directory PATH` |
| Provider | `--provider openrouter-zdr\|ollama-cloud\|opencode-go\|local\|ollama-signin` |
| Local server | `--endpoint URL`, optional `--verification-endpoint URL`, `--transport openai_chat_completions\|openai_responses` (for `ollama-signin`, `--endpoint http://127.0.0.1:PORT/v1` names the local Ollama) |
| Models | `--generation-model ID`, `--verification-model ID` |
| Capacity | `--context-tokens N`, `--output-tokens N` |
| Prices (remote) | `--input-micro-usd-per-million-tokens N`, `--output-micro-usd-per-million-tokens N`, `--max-cost-micro-usd N` (1 USD = 1000000) |
| Key variable | `--credential-env OPEN_TRESTLE_PROVIDER_NAME` |
| Names | `--owner`, `--tenant`, `--repository`, `--repository-authority`, `--repository-namespace`, `--repository-name` |
| OpenRouter | `--generation-provider-slug`, `--verification-provider-slug`, `--generation-upstream-evidence`, `--verification-upstream-evidence`, `--generation-slug-evidence`, `--verification-slug-evidence` |
| OpenCode Go | `--generation-model-evidence`, `--verification-model-evidence` |
| Evidence window | `--broker-evidence`, `--account-evidence`, `--evidence-retrieved-at`, `--reviewed-at`, `--valid-from`, `--valid-until` |
| Declarations | `--declare-remote-route`, `--declare-openrouter-zdr-account`, `--declare-opencode-go-account`, `--declare-ollama-cloud-signin`, `--declare-local-capabilities` |
| Local test requests | `--allow-local-probe` |
| Consent to review | `--run-review` |

There is no blanket "yes to everything" flag. Each declaration is its own
existing bootstrap flag, and the review runs only with `--run-review`. Evidence
values are `HTTPS_URL,SHA256`, exactly as for the bootstrap.

```sh
trestle init --no-input --provider ollama-cloud \
  --generation-model YOUR_OLLAMA_GENERATION_MODEL \
  --verification-model YOUR_DIFFERENT_OLLAMA_MODEL \
  --context-tokens 128000 --output-tokens 8192 \
  --input-micro-usd-per-million-tokens 0 --output-micro-usd-per-million-tokens 0 \
  --max-cost-micro-usd 0 \
  --credential-env OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD \
  --declare-remote-route
```

The values above are placeholders, not recommendations.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Done: setup is ready (review declined), or the first review finished with `findings` or `no_candidates`. |
| `3` | Pending: something must be fixed before a review can run, or the review was incomplete or canceled. |
| `4` | Refused: a declaration was declined, setup was refused, or the review was refused. |
| `2` | Usage: a missing or invalid answer, end of input (Ctrl-D), or three unusable answers in a row. |
| `1` | Internal error. |

Ending input early, or three unusable answers to one question, stops without
writing anything if setup was not yet saved.

## Limits

- The wizard records your declarations; it cannot check account settings,
  provider conduct, model capability, price or availability.
- It never installs software, downloads models, starts servers, provisions keys
  or changes repository permissions.
- The local model list and remote catalogs are availability observations, not
  approvals. A loopback address does not prove that a model runs locally; an
  Ollama `:cloud` model is flagged because it would send source to Ollama's cloud.
- A local setup made by the wizard is for the direct review only. It does not
  prepare the background daemon, which still needs a private `0700`, loose-object
  source; set that up with the
  [local-first bootstrap](local-first-bootstrap.md) directly.

For details, see [local-first bootstrap](local-first-bootstrap.md),
[remote model review](remote-model-review.md), [model catalog](model-catalog.md)
and [named local runtimes](named-local-runtimes.md).

# Getting started

`trestle init` is the first step. Run it inside the Git repository you want
reviewed. It asks only what it cannot work out itself, shows every setting in
one panel, saves a protected configuration, runs the setup checks, and offers
to run your first review. If something is missing,
it says what is missing and what to do, then stops without guessing.

Remote providers (OpenRouter, Ollama Cloud, OpenCode Go, and Ollama signed in
to Ollama Cloud) work only with the packaged Linux amd64 install, which places
its secret scanner under `/usr/local` as root. A plain `go build`, and any
platform other than Linux, refuses to send source to them. A model server on
this machine works with a development build. See
[prerequisite 1](remote-model-review.md#prerequisite-1-a-scanner-bound-binary-and-installed-scanner).

```sh
cd path/to/your-repository
trestle init
```

The wizard is a front end over the existing
[local-first bootstrap](local-first-bootstrap.md) and
[remote model review](remote-model-review.md) commands. It calls the same
`trestle setup bootstrap init` and `check` code in-process and runs the same
`trestle local-git model-review` command they print. It adds no configuration
format, default model, privacy claim or shortcut. What it fills in for you is
shown before you consent, and every declaration is still your explicit answer.

## Before you start

- **A Git checkout with committed changes.** Only committed work is reviewed;
  uncommitted edits are ignored. The review compares exactly two commits and
  never fetches. By default the base is the merge base of your default branch
  and `HEAD`, the same commit a pull request is compared against.
- **Somewhere to run two models.** One model looks for problems, a different
  model double-checks them. Choose one of:
  - OpenRouter, Ollama Cloud, or OpenCode Go. You need an account and an API
    key. For OpenRouter, zero data retention is recommended and on by default.
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
- **For remote providers: the packaged Linux amd64 `trestle` install and its secret scanner.**
  Every request is scanned for secrets in a sandboxed scanner before it leaves
  the machine. A plain `go build` has no scanner fingerprints and refuses to send
  source. The wizard detects such a development build before you choose a
  provider, explains why, and shows the packaging and install commands from
  [operations](operations.md#build-and-inspect-the-unsigned-linux-amd64-candidate),
  including the passive vulnerability gate, in the order they run. A local model
  server still works with a development build. If you set up a remote provider
  with it anyway, the setup is saved, its scanner check fails, and the wizard
  shows those commands and the `/usr/local/bin/trestle init` command that
  continues the same setup. See
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
reads, each described below: it may fetch a provider's public model list (for
OpenRouter, also its public zero-data-retention endpoint list), and fetch a
public evidence page you name once you confirm. None of these sends a key. With
a local Ollama it reads that Ollama's model list (`/api/tags` on `127.0.0.1`),
and for the Ollama Cloud sign-in option it can send one fixed test message, only
if you agree. Your source goes to the models only
when you agree to run a review.

## What the wizard asks

The wizard asks only what you alone can answer: where the models run, which
two models, the API key when none is set yet (with hidden input), whether to
require zero data retention on OpenRouter, an optional spending limit for the
API key, and your consent. Everything it can work out
itself is filled in and shown in a settings panel before you consent; Enter
accepts each recommended default. It runs in six steps:

```text
   |X|\            /|X|
 __|X| \___----___/ |X|__   Open Trestle · setup
===|X|=|==|==|==|===|X|===

  Two AI models review your change: one lists possible
  problems, a different one double-checks each, and only
  confirmed findings are reported. Setup sends no source.
  Enter accepts a value in [brackets]; Ctrl-D stops.

●○○○○○  Step 1 of 6 · What will be reviewed
───────────────────────────────────────────
  Repository: ~/src/project  (on branch feature)
  Base:       1a2b3c4d5e6f  (merge base with main)
  Head:       HEAD  (7f8e9d0c1b2a)
  Changes:    3 commits · 4 files changed, 52 insertions(+)
  Open Trestle compares exactly these two commits; it does
  not fetch.

●●○○○○  Step 2 of 6 · Where the models run
──────────────────────────────────────────
    1) OpenRouter (remote, needs an API key)
    2) Ollama Cloud (remote, needs an API key)
    3) OpenCode Go (remote, needs an API key)
    4) A model server on this machine (Ollama, llama.cpp,
       vLLM, LM Studio)
    5) Ollama on this machine, signed in to Ollama Cloud
       (remote)
  Choose (1-5):
```

1. **What will be reviewed.** The merge base of your default branch and `HEAD`.
   The default branch is the one `origin/HEAD` names, otherwise `main` or
   `master`, as your repository has it or as `origin` has it; when both exist,
   the newer merge base counts (see [which commits](#running-it-again)). It
   runs only read-only Git queries; the commit count and change summary come
   from those same two commits. Nothing is asked unless no default branch is
   found. To review other commits, pass `--base` and `--head`, or change them
   in step 4.
2. **Where the models run.** OpenRouter, Ollama Cloud, OpenCode Go, a model
   server on this machine, or "Ollama on this machine, signed in to Ollama
   Cloud".
3. **The two models.** Pick each from the provider's list; the checker must
   differ from the finder. A list longer than 40 entries asks for part of a name
   first, and models that look like 7B parameters or fewer are flagged as weak.
   - **OpenRouter** reads its public model and zero-data-retention lists (no key
     or code is sent), shows what the API reported for each model and fills in
     the routing, limits and prices. It pins only the zero-data-retention
     endpoints that allow 16384 output tokens, says how many it left out, and
     lets each request write up to 16384 tokens; when no endpoint of a model
     allows that much, it keeps that model's endpoints, says so, and uses the
     smallest output they allow. It then asks "Require zero data retention on
     every request (recommended)?", where Enter means yes. A model without a ZDR
     endpoint is warned about, because an account or key with ZDR enforced will
     refuse it, and can be replaced; keeping it, or answering no, continues after
     one `y`. See [OpenRouter zero data retention](openrouter-zdr-profile.md).
   - **A local server** answering on its usual port (Ollama 11434, LM Studio
     1234, llama.cpp 8080, vLLM 8000) is used without a question; otherwise pick
     it or type its `127.0.0.1` address. The checker shares the server when it
     lists two models. No key is assumed when both model lists were read without
     one. The limits are the proposed 32768-token context (or a smaller listed
     value) and a 4096-token output: start both servers with that context, as
     [named local runtimes](named-local-runtimes.md#context-length) describes. A
     model the local Ollama relays to Ollama Cloud is refused here; choose the
     sign-in option for cloud models.
   - **Ollama signed in to Ollama Cloud** uses the local daemon at
     `http://127.0.0.1:11434/v1` (or `--endpoint`), offers only the models it
     relays to `https://ollama.com`, and offers one fixed test message, "Reply
     with OK", only if you agree; it can run `ollama signin` for you on `y`.
   - **Ollama Cloud and OpenCode Go** ask for the limits when the model list does
     not state them, and whether your plan charges per token.

   When the provider's key variable has no key yet, in the environment or
   saved, and the wizard runs in a terminal, it then asks for the key with
   hidden input, checks an OpenRouter key with one free call, and offers to
   save it once the setup is saved; Enter skips. Without a terminal, or with
   `--no-input`, it never asks. See [API keys](keys.md).

   The most one model request may cost is not asked: setup uses the cost of a
   request that fills the whole context and writes the whole output allowance,
   rounded up to a cent, and the settings panel shows it with what a review of
   two requests can cost (`--max-cost-micro-usd` sets another bound). For a
   provider that charges per token, the wizard then asks one optional
   question, "Spending limit for this key, USD per month (optional) [none]",
   and, if you give one, "Alert at percent [80]". Enter means no limit. For
   OpenRouter it first shows OpenRouter's own figures for the key when the
   key variable is set. The limit is checked before each review and counts
   Open Trestle's upper-bound estimate, not a bill; it is best effort, and your
   provider's own limit is the guarantee. A key that already has a limit keeps
   it. See [spending limits](spending-limits.md).
4. **Your settings.** One panel shows everything, asked or filled in:

   ```text
   ┌─ Setup summary ──────────────────────────────────────────┐
   │ Review    1a2b3c4d5e6f → 7f8e9d0c1b2a                    │
   │ Runs on   OpenRouter, zero data retention required on    │
   │           every request                                  │
   │ Finder    vendor/finder-model                            │
   │ Checker   other/checker-model                            │
   │ Limits    context 128000 · output 16000 tokens           │
   │ Cost      $3.30 in · $16.50 out per million tokens · up  │
   │           to $0.69 a request, $1.38 a review             │
   │ Spending  $10.00 a month for this key · alerts at 80%    │
   │           and 100%                                       │
   │ Key       OPEN_TRESTLE_PROVIDER_OPENROUTER (from the     │
   │           environment)                                   │
   │ Source    github.com/owner/project                       │
   │ Names     tenant personal · repository project · owner   │
   │           you                                            │
   │ Folder    ~/.local/state/open-trestle/project-1a2b3c4d   │
   └──────────────────────────────────────────────────────────┘
     Use these settings? (Y/n):
   ```

   The key variable is the provider's usual name. The `Key` row says where its
   key comes from: from the environment, saved in
   `~/.config/open-trestle/credentials`, to be saved with the setup, entered
   for this session only, or not set yet. The key itself is never printed or
   written to the setup folder. The names come from `origin`'s URL (its host,
   namespace and name; a credential in the URL is ignored) or the folder name,
   and the owner from `$USER`. Answering `n` offers to change the commits, the
   names, the key variable, or the limits and prices, then shows the panel
   again. Every value also has a flag (see [non-interactive use](#non-interactive-use)).
   The spending limit is saved after the setup, in the usage folder every
   setup shares; `trestle usage` shows and changes it.
5. **Your consent.** Each fact the bootstrap needs is shown in plain words with a
   link, and you must type `yes`. Typing `no` stops with nothing written.
   - OpenRouter: that each review sends the selected source, after secret
     scanning, to OpenRouter for the two models, whether zero data retention is
     required, and that you have not turned on prompt logging for the key.
   - Ollama Cloud and OpenCode Go: the [route declaration](remote-model-review.md#common-declarations)
     (capacity, structured output, logging off, prices, availability).
   - OpenCode Go also asks for four evidence items, a review window and the
     [workspace declaration](remote-model-review.md#opencode-go). For a public
     page the wizard offers to fetch it once and compute its SHA-256 here: one
     `https` GET with no key, cookie, query or repository content, public
     addresses only, at most 8 MiB and 20 seconds. Account evidence is never
     fetched: save a copy of your own account page and give its path.
   - Ollama signed in to Ollama Cloud: the
     [sign-in declaration](remote-model-review.md#ollama-signed-in-to-ollama-cloud)
     that your source is sent to Ollama Cloud under your signed-in account.
   - Local server: the [local capability declaration](local-first-bootstrap.md#choose-the-repository-and-model-pair).
6. **Save and check.** The configuration goes into a new private folder,
   `~/.local/state/open-trestle/<repository>-<8 hex characters>` by default
   (mode `0700`, files `0600`). Existing files are never overwritten. A key you
   chose to save is saved now, after the setup. If no key is found for the key
   variable, the check says so and shows two commands: `trestle keys set NAME`,
   which saves it with hidden input, and `read -rs NAME && export NAME`, which
   exports it without echoing it. Then run `trestle init` again.

### How it looks

Every line fits in 60 columns, the terminal interface's minimum width; only a
command to copy, or a link too long for a line, keeps its full length. Long
paths are shortened on screen (`~` for your home folder, `...` in the middle);
commands and `NEXT-STEPS.txt` keep full paths. On an interactive terminal the
wizard uses the web console's colors: cobalt for the title, the current step
and questions, slate for rules and frames, green, amber and red for `✓`, `…`
and `✗`, and dim text for hints, in 24-bit color when `COLORTERM` is
`truecolor` or `24bit` and 256 colors otherwise. Body text keeps your
terminal's own color, and every state keeps its mark. It prints no color when
`NO_COLOR` is set to any value, `TERM` is `dumb`, the output is not a terminal,
or with `--no-input`.

## Reading the check results

| Mark | Meaning |
| --- | --- |
| `✓` | Passed. |
| `…` | Waiting: not done yet, or runs after an earlier item. A one-line hint says what to do. |
| `✗` | Needs a fix. The hint gives the exact remedy. |
| `–` | Optional and not set up (local mode: the test requests you did not allow, and items only the background daemon needs). |

With `TERM=dumb` the marks are `[ok]`, `[..]`, `[x]` and `[--]`, the step
indicator is `#` and `.`, and frames are ASCII.

Remote checks: the review window is current (OpenCode Go, and OpenRouter setups
made before ZDR was detected), the saved configuration loads, a key is found
for the API key variable (the line says where: from the environment or saved),
and the secret scanner is installed. For OpenRouter a last line
says whether zero data retention is required on every request or not required
by Open Trestle. For the Ollama Cloud sign-in option, the key check is replaced
by a check that your local Ollama lists both models as Ollama Cloud models. A
review is offered only when all of them pass.

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

The first review compares the two commits from step 1. The wizard then shows
the one command that reviews your latest change from now on, `trestle review`
(see [running it again](#running-it-again)), and saves it with the check
command in `NEXT-STEPS.txt` in the setup folder. It then asks:

```text
  A review sends the selected source to OpenRouter (https://openrouter.ai/api/v1), zero data retention required on every request.
  Run the first review now? (y/N):
```

Only `y` runs it. The review runs in the foreground and keeps nothing for
resume; it can take several minutes.

A new setup runs specialist reviews by default: the general review first, then
up to three specialist reviews (such as `bug_hunter` or `security_probe`)
picked from the change without a model call, each a full review with its own
independent check. The settings panel shows it as `Specialists on: ...`. On
remote models the specialists run at the same time, up to three at once; on a
model on this machine they run one after another. To review with the general
review only, give `trestle init --specialists none` (the panel then says
`Specialists off`), or run `trestle review --specialists none` once. The
spending warning counts every review the command may run. See
[specialist review set](local-model-review.md#specialist-review-set-opt-in).

The result starts with a walkthrough of what was checked, then the confirmed
findings, most important first:

```text
walkthrough:
verified: secret scan: 2 model requests scanned before sending (292 bytes, 0 secret matches)
verified: static check static_debug_output: passed (1 file checked, 0 matches)
verified: style detection: ran (1 recommendation, 0 withheld)
verified: semantic impact: 1 changed declaration, 0 public API changes, 1 reference (0 from tests), 0 gaps
verified: independent verifier (distinct_provider): 1 of 1 candidate confirmed, 0 rejected, 0 inconclusive
file: a.go modified +1 -1; changed function Changed
missing verification: no test file references the changed function Changed (a.go)
confirmed findings (ranked): 1
finding: error Zero-valued caller now panics
rank: 1
source: a.go:2-2
message: Consume passes zero to Changed after removal of the division guard.
```

A specialist review set first summarizes which reviews ran (`specialist review
set: status=findings ...`, `members run: ...`) and lists, under each finding,
the reviews that confirmed it (`contributors: general, bug_hunter`).

### Reading the result

- `findings`: each listed finding was proposed by the finder and confirmed by
  the checker. Read them like a colleague's review comments. A finding about
  code the change removed is located on the removed lines of the base commit
  (`path removed base lines a-b`), not on head lines.
- `walkthrough:` lines: what was verified (the secret scan of the model
  requests, the deterministic checks, style detection, the semantic-impact
  analysis and the checker's confirmed, rejected and inconclusive counts), each
  changed file with its line counts and changed Go declarations, and
  `missing verification:` notes for changed functions no test file references.
  These notes are information, not defects.
- `confirmed findings (ranked)`: high, critical and medium findings, most
  important first. Findings that repeat one another are merged. Lower-severity
  findings are counted on a `hidden:` line; `trestle review --all` lists them.
  When every confirmed finding is low severity, up to ten of them are listed,
  so the result never hides them all.
- `pre-existing findings`: confirmed problems on unchanged lines that cite
  nothing the change touched. They are listed separately and never make the
  review blocking.
- `ci: inconclusive` with `status: findings`: an advisory review. Every
  confirmed finding is low severity or pre-existing, so none blocks CI (exit
  `3` by default, `0` with `--exit-code-policy findings`), and the closing line
  says so. Only a medium, high or critical finding the change introduced makes
  a review `ci: blocked` (exit `4`).
- `no_candidates`: nothing was found and confirmed. That is not proof the change
  is correct.
- `incomplete`: part of the change was not covered; see the coverage and
  omission lines.
- `refused`, `failed` or `canceled`: no usable result; the wizard says what to try.
- `style:` lines: when the base commit declares no style for a changed language
  that has a style detector, the result suggests a standard one. It is advice,
  not a finding, and never changes the result. See [style recommendations](local-model-review.md#style-recommendations).

Every result says `comprehensive clearance: false`. A review is not an audit.
See [local model review](local-model-review.md) for the full result format.

## Running it again

After setup, reviewing your latest change is one command, run anywhere in the
repository:

```sh
trestle review
```

It finds the setup the way `trestle init` does (the folder from step 6, or the
one you name with `--directory PATH`), picks the two commits again, says what
it compares and where the source goes, and runs the same review with the
setup's routes, policy, names and egress. The commits saved at setup time are
never reused, and a setup keeps working after they are rewritten or
garbage-collected.

- **Which commits.** The head is `HEAD`, the commit checked out now. The base
  is the newest commit `HEAD` shares with the default branch, as your
  repository has it or as `origin` has it, whichever is newer: one
  `git merge-base HEAD main origin/main`. A local `main` that is behind
  `origin` therefore does not pull commits that are already upstream into the
  review. On the default branch itself the base is `origin`'s copy, so your
  unpushed commits are the change. The default branch is the one `origin/HEAD`
  names, otherwise `main`, otherwise `master`. `--base REF` and `--head REF`
  pick commits exactly, as in `trestle init`.
- **Uncommitted changes are not included.** Only committed work is reviewed.
  When you have uncommitted changes or untracked files, the review says they
  are not included and that committing them includes them. It writes nothing
  into your repository and never fetches.
- **Output.** The result goes to standard output in the setup's text format;
  `--format json` or `--format sarif` prints one JSON or SARIF document there.
  Every other line goes to standard error, including the egress,
  secret-scanning and spending messages, which are exactly those of
  `trestle local-git model-review`. `--timeout`, `--profile`, `--specialists`,
  `--max-specialists` and `--exit-code-policy` pass through to that command,
  and so do its [exit codes](local-model-review.md) (for example `4` when a
  confirmed medium, high or critical finding blocks, and `3` for an
  [advisory](local-model-review.md#advisory-results) review whose findings are
  all low severity or pre-existing).
- **Nothing is sent** when the repository has no setup (run `trestle init`),
  when there is no committed change to review, or when no API key is found
  (`trestle keys set NAME`); `trestle review` says so and exits `3`.

`trestle` on its own, in a terminal, shows a status card and numbered next
actions, each two steps away (`trestle`, then the number):

```text
┌─ project ────────────────────────────────────────────────┐
│ Repository  ~/src/project (on branch feature)            │
│ Setup       ~/.local/state/open-trestle/project-1a2b3c4d │
│ Models      finder vendor/finder-model · checker         │
│             other/checker-model                          │
│ Runs on     OpenRouter (https://openrouter.ai/api/v1),   │
│             zero data retention required on every        │
│             request                                      │
│ Key         OPEN_TRESTLE_PROVIDER_OPENROUTER (saved in   │
│             ~/.config/open-trestle/credentials)          │
│ Spending    $0.60 of your $10.00 monthly limit this      │
│             month (6%), alerts at 80% and 100% (an       │
│             upper-bound estimate, not a bill)            │
│ Last run    1 confirmed finding · 14 Nov 10:32 UTC ·     │
│             1a2b3c4d5e6f → 7f8e9d0c1b2a                  │
└──────────────────────────────────────────────────────────┘

  1) Review the latest change  trestle review
  2) See spending              trestle usage
  3) Change the API key        trestle keys
  4) Re-run setup              trestle init
  5) Read the guides           docs/getting-started.md
  Choose 1-5, or Enter to quit:
```

The card reads only local files: the setup folder, the usage folder and the
credential store; it sends nothing. `Last run` comes from `last-review.json`
in the setup folder, a small record (time, status, number of confirmed
findings and the two commits, nothing else) that `trestle review`, the home
screen and `trestle init` write after each review; a review run directly with
`trestle local-git model-review` is not recorded. In a repository without a
setup the only action is `trestle init`. Without a terminal on both sides, or
with `NO_COLOR` set or `TERM=dumb`, `trestle` prints the usage text and exits
`2`, as before.

Run `trestle init` again in the same repository to re-check the setup. `trestle
init`, `trestle review` and the home screen find the setup in the folder setup
proposes or, failing that, the most recently saved setup for this repository in
another folder of `~/.local/state/open-trestle`, so a setup made with
`--directory` there needs no flag later. A setup saved anywhere else needs the
same `--directory` again. It offers:

```text
    1) Review the latest change (sends it to OpenRouter)
    2) Re-run the setup checks
    3) Quit without changes
```

The first re-runs the checks, then reviews the latest change exactly as
`trestle review` does; with `--no-input`, `--run-review` does the same. If the
setup's key is missing, it asks for it first (see [API keys](keys.md)). It
never re-initializes or changes the saved files. To set up something
different, use a new folder: `trestle init --directory NEW_FOLDER`.

## Non-interactive use

Every answer has a flag. With `--no-input` the wizard never prompts; if any
answer is missing it lists every missing flag and exits `2` without writing
anything. Without `--provider` it lists only that flag, because the provider
decides which other answers are needed. Everything the wizard fills in by
itself (commits, names, owner, folder, key variable, and limits and prices a
provider or model list states) is filled in the same way with `--no-input`,
and a flag overrides it; facts you must declare are not filled in. A complete
`--no-input` run prints the settings panel, without color.

| Answer | Flag |
| --- | --- |
| Commits | `--base REF`, `--head REF` |
| Setup folder | `--directory PATH` |
| Provider | `--provider openrouter\|openrouter-zdr\|ollama-cloud\|opencode-go\|local\|ollama-signin` (`openrouter-zdr` requires zero data retention) |
| Local server | `--endpoint URL`, optional `--verification-endpoint URL`, `--transport openai_chat_completions\|openai_responses` (for `ollama-signin`, `--endpoint http://127.0.0.1:PORT/v1` names the local Ollama) |
| Models | `--generation-model ID`, `--verification-model ID` |
| Capacity | `--context-tokens N`, `--output-tokens N` (OpenRouter: detected unless given) |
| Review output allowance (optional, no question) | `--max-output-tokens N`, from 4096 up to `--output-tokens` (default 4096; OpenRouter: 16384 or the most every pinned endpoint allows) |
| Prices (remote) | `--input-micro-usd-per-million-tokens N`, `--output-micro-usd-per-million-tokens N` (OpenRouter: detected unless given) |
| Per-request cost bound (optional, no question) | `--max-cost-micro-usd N` (1 USD = 1000000; default: the cost of a request that fills the whole context, rounded up to a cent) |
| Specialist reviews (optional, no question) | `--specialists auto\|none` (default `auto`: the saved review runs the general review, then up to three specialist reviews picked from the change; `none` saves the general review only). `trestle setup bootstrap init` takes the same flag |
| Spending limit for the key (optional) | `--spending-limit USD`, `--spending-alert PERCENT` (default 80; alerts also at the limit). Only for a remote provider that charges per token; without it there is no limit. See [spending limits](spending-limits.md) |
| Key variable (default: the provider's usual name) | `--credential-env OPEN_TRESTLE_PROVIDER_NAME` |
| Names (default: from `origin`, the folder and `$USER`) | `--owner`, `--tenant`, `--repository`, `--repository-authority`, `--repository-namespace`, `--repository-name` |
| OpenRouter | `--without-zdr` (continue without zero data retention), `--generation-provider-slug SLUG[,SLUG]` and `--verification-provider-slug SLUG[,SLUG]` (override the detected ZDR endpoints) |
| OpenCode Go | `--generation-model-evidence`, `--verification-model-evidence` |
| Evidence window | `--broker-evidence`, `--account-evidence`, `--evidence-retrieved-at`, `--reviewed-at`, `--valid-from`, `--valid-until` |
| Declarations | `--declare-remote-route`, `--declare-opencode-go-account`, `--declare-ollama-cloud-signin`, `--declare-local-capabilities` |
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
  --credential-env OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD \
  --declare-remote-route
```

For OpenRouter, the model facts come from its API:

```sh
trestle init --no-input --provider openrouter \
  --generation-model YOUR_OPENROUTER_GENERATION_MODEL \
  --verification-model YOUR_DIFFERENT_OPENROUTER_MODEL \
  --spending-limit 10 \
  --credential-env OPEN_TRESTLE_PROVIDER_OPENROUTER \
  --declare-remote-route
```

It requires zero data retention when both models have ZDR endpoints. If one has
none, it stops and names `--without-zdr`; with `--provider openrouter-zdr` it
stops instead. If OpenRouter's API cannot be read, it lists the capacity and
price flags to add.

The values above are placeholders, not recommendations.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Done: setup is ready (review declined), or the first review finished with `findings` or `no_candidates`. |
| `3` | Pending: something must be fixed before a review can run, or the review was incomplete or canceled. |
| `4` | Refused: a declaration was declined, setup was refused, a setup check refused (such as the scanner check of a development build set up for a remote provider; the setup is kept), or the review was refused. |
| `2` | Usage: a missing or invalid answer, end of input (Ctrl-D), or three unusable answers in a row. |
| `1` | Internal error, or the first review failed. |

Ending input early, or three unusable answers to one question, stops without
writing anything if setup was not yet saved.

## Limits

- The wizard records your declarations; it cannot check account settings,
  provider conduct, model capability, price or availability. OpenRouter facts
  are recorded as reported by its API at setup time, not verified. OpenRouter's
  API does not say whether your account or key enforces zero data retention, so
  the wizard never claims it does or does not.
- It never installs software, downloads models, starts servers, provisions keys
  or changes repository permissions.
- A spending limit is Open Trestle's own, best-effort check of its upper-bound
  estimate, not your provider's bill or limit; set a limit with your provider
  too. See [spending limits](spending-limits.md).
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

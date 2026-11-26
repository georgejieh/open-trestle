# Getting started

This page walks you through your first review. You run `trestle init` inside
the Git repository you want reviewed. It asks only what it cannot work out for
itself, shows every setting in one panel, saves a protected configuration, runs
the setup checks, and offers to run your first review. If something is missing,
it tells you what is missing and what to do, then stops without guessing. Every
command is listed in [commands](commands.md), and every page is in the
[documentation index](README.md).

Every review, with a model server on this machine or a remote provider
(OpenRouter, Ollama Cloud, OpenCode Go, and Ollama signed in to Ollama Cloud),
scans each request for secrets in the secret scan helper before it is sent. A
plain `go build` pins no helper and refuses every review. The
[install scripts](install.md) install a release that includes it.
[platforms](platforms.md) says what works on each system today. See
[prerequisite 1](remote-model-review.md#prerequisite-1-a-trestle-with-its-secret-scanner).

```sh
cd path/to/your-repository
trestle init
```

The wizard is a front end over the existing
[local-first bootstrap](local-first-bootstrap.md) and
[remote model review](remote-model-review.md) commands. It runs the same
`trestle setup bootstrap init` and `check` code inside its own process, and it
runs the same `trestle local-git model-review` command that they print.
Anything it fills in is shown to you before you agree to it.

## Before you start

You need four things.

1. A Git checkout with committed changes. Only committed work is reviewed, and
   uncommitted edits are ignored. The review compares exactly two commits and
   never fetches. By default the base is the merge base of your default branch
   and `HEAD`, which is the commit a pull request is compared against.
2. Somewhere to run two models. One model looks for problems, and a different
   model double-checks them. You can use any of these:
   - OpenRouter, Ollama Cloud or OpenCode Go. You need an account and an API
     key.
   - A model server on this machine: Ollama, llama.cpp, vLLM or LM Studio (any
     OpenAI-compatible server on `127.0.0.1`).
   - Ollama on this machine, signed in to Ollama Cloud with `ollama signin`.
     This needs no API key, but it is a remote provider: the models run on
     Ollama Cloud, and your source is sent there when you run a review. See
     [Ollama signed in to Ollama Cloud](remote-model-review.md#ollama-signed-in-to-ollama-cloud).
3. A `trestle` binary with its secret scan helper. Install a release with one
   command:

   ```sh
   curl -fsSL https://georgejieh.dev/open-trestle/install.sh | bash   # Linux
   ```

   ```powershell
   irm https://georgejieh.dev/open-trestle/install.ps1 | iex          # Windows
   ```

   The first releases are unsigned pre-releases. To build from source instead,
   see [install](install.md#build-from-source). Every request is scanned for
   secrets before it is sent, and a plain `go build` pins no helper, so it
   refuses every review.

If you start `trestle init` with a plain `go build` binary, the wizard detects
it before you choose a provider and explains why it cannot continue. It shows
the `--development` command, and on Linux also the packaged install commands from
[operations](operations.md#build-and-inspect-the-unsigned-linux-amd64-candidate),
including the passive vulnerability gate, in the order they run. If the setup is
saved anyway, its scanner check refuses. See
[prerequisite 1](remote-model-review.md#prerequisite-1-a-trestle-with-its-secret-scanner).

An ordinary clone is fine. Every mode, local included, uses the direct checkout
review, which reads loose objects and ordinary pack files and verifies each
object against its hash. Right after you pick the commits, the wizard reads
both of them the same way. It stops early only for storage that the review
cannot read: alternates (clones made with `--shared` or `--reference`), a
multi-pack-index, or partial-clone packs. In that case it prints a
`git clone --no-local --no-hardlinks` command that makes a separate full copy.
You need the private `0700` copy with loose objects, described in [choose the
repository](local-first-bootstrap.md#choose-the-repository-and-model-pair), only
if you use the optional background daemon.

Setup sends no repository source. It does make a few network calls, and only the
OpenRouter key check sends a key:

- It may fetch a provider's public model list. For OpenRouter it also fetches
  the public list of zero-data-retention endpoints.
- If you enter an OpenRouter key, it checks the key with one call to OpenRouter's
  key-usage endpoint.
- It may fetch a public evidence page that you name, once you confirm.
- With a local Ollama, it reads that Ollama's model list (`/api/tags` on
  `127.0.0.1`).
- For the Ollama Cloud sign-in option, it can send one fixed test message, but
  only if you agree.

Your source goes to the models only when you agree to run a review. See
[privacy](privacy.md) for what a review sends.

## What the wizard asks

The wizard asks only what you alone can answer: where the models run, which two
models to use, the API key when none is set yet (never shown), a spending
limit for the API key, and one confirmation of the settings and where your
source goes. On OpenRouter that is six questions, then "Run the first review
now?". When you answer yes, it also asks once whether reviews may run the
repository's tests in a sandbox (see [repository checks](#repository-checks)).
It fills in everything else itself and shows it in a settings panel above the
confirmation. Enter accepts each recommended default.

The wizard runs in five steps:

```text
   |X|\            /|X|
 __|X| \___----___/ |X|__   Open Trestle · setup
===|X|=|==|==|==|===|X|===

  Two AI models review your change: one lists possible
  problems, a different one double-checks each, and only
  confirmed findings are reported. Setup sends no source.
  Enter accepts the highlighted answer; Esc goes back.

●○○○○  Step 1 of 5 · What will be reviewed
──────────────────────────────────────────
  Repository: ~/src/project  (on branch feature)
  Base:       1a2b3c4d5e6f  (merge base with main)
  Head:       HEAD  (7f8e9d0c1b2a)
  Changes:    3 commits · 4 files changed, 52 insertions(+)
  Open Trestle compares exactly these two commits; it does
  not fetch.

●●○○○  Step 2 of 5 · Where the models run
─────────────────────────────────────────
  Choose
  ↑↓ move · Enter select · Esc back · q quit
  › 1) OpenRouter (remote, needs an API key)
    2) Ollama Cloud (remote, needs an API key)
    3) OpenCode Go (remote, needs an API key)
    4) A model server on this machine (Ollama, llama.cpp,
       vLLM, LM Studio)
    5) Ollama on this machine, signed in to Ollama Cloud
       (remote)
```

### Answering

When standard input and output are both terminals, `TERM` is not `dumb` and
`--no-input` is not given, each choice is a menu. Up and Down (or `j` and `k`)
move the pointer, Enter picks the highlighted item, and a number picks that
item at once. The pointer starts on the recommended or current answer. A yes or
no question is a menu of Yes and No, and `y` or `n` answers it. Esc or Left goes
back to the previous question with your earlier answer selected, and `q` or
Ctrl-C stops with nothing written. The menu redraws in place and leaves one line
with your answer. The terminal is restored after every menu, also when you stop.
On Windows it uses the console's own key and escape-sequence modes; only Linux
terminals have been tested (see [platforms](platforms.md)).

Without such a terminal, each choice is a numbered list with a default, for
example `Choose (1-5) [1]:`; Enter takes the default. Typing `b` or `back` at
any prompt goes back, unless it is a valid answer there. Input that ends
(Ctrl-D or a closed pipe) stops with nothing written.

Going back from a step's first question returns to the previous step that asked
something; going back from a later question asks that step again from its start,
with each earlier answer selected.

### Step 1: what will be reviewed

The wizard picks the merge base of your default branch and `HEAD`. The default
branch is the one `origin/HEAD` names. If that is not set, it uses `main` or
`master`, as your repository has it or as `origin` has it; when both exist, the
newer merge base counts (see [which commits](#running-it-again)). The wizard
runs only read-only Git queries, and the commit count and change summary come
from those same two commits. It asks a question here only when it finds no
default branch. To review other commits, pass `--base` and `--head`, or change
them at the summary in step 4.

### Step 2: where the models run

Choose OpenRouter, Ollama Cloud, OpenCode Go, a model server on this machine,
or "Ollama on this machine, signed in to Ollama Cloud".

### Step 3: the two models

Pick each model from the provider's list. The checker must differ from the
finder, and a checker from a different model family is recommended (see
[the rationale](rationale.md#the-checker-should-come-from-a-different-model-family)).
When both models come from
one family (both Qwen models, for example), the wizard says so and asks whether
to keep the checker; Enter keeps it, and `n` lets you pick again. The settings
panel then marks the checker as being in the same family as the finder.

In a menu, each model is a list of the provider's models, ten at a time, that
scrolls as the pointer moves. Typing narrows it to the IDs that contain what you
typed (`Filter: claude_  2 of 312`), Backspace and Esc widen it again, and Enter
picks the highlighted model. When nothing matches, Enter uses the text exactly as
typed. Digits are part of the filter here, since model IDs contain them.

Without a menu, each model is one question, `Number, model ID, or part of a
name`. A number picks
from the list shown, and a listed ID picks that model. Other text narrows the
list to the IDs that contain it, and the same question is asked again under the
shorter list. The list shows at most 40 entries. Text that matches no listed
model is used exactly as typed only when you type it twice in a row. The wizard
flags models that look like 7B parameters or fewer as weak. What happens next
depends on the provider.

- With OpenRouter, the wizard reads OpenRouter's public model and
  zero-data-retention lists (no key or code is sent), shows what the API
  reported for each model, and fills in the routing, limits and prices. It pins
  only the zero-data-retention endpoints that allow 16384 output tokens, says
  how many it left out, and lets each request write up to 16384 tokens. When no
  endpoint of a model allows that much, it keeps that model's endpoints, says
  so, and uses the smallest output they allow. Every request requires zero data
  retention; this is not a question, and `--without-zdr` turns it off. If a
  model has no zero-data-retention endpoint, the wizard says so (an account or
  key that enforces zero data retention will refuse that model) and lists the
  models that have one. One answer picks one of them, or Enter keeps your model
  and continues without zero data retention. The summary and the confirmation
  state which you chose. See
  [OpenRouter zero data retention](openrouter-zdr-profile.md).
- With a local server, if exactly one server answers on its usual port (Ollama 11434, LM
  Studio 1234, llama.cpp 8080, vLLM 8000), the wizard uses it without asking.
  With several, or none, you pick the server or type its `127.0.0.1` address. The checker
  shares the server when it lists two models. If both model lists can be read
  without a key, the wizard assumes the server needs none. It proposes a
  32768-token context (or a smaller value if the server lists one) and a
  4096-token output. Start
  both servers with that context, as
  [named local runtimes](named-local-runtimes.md#context-length) describes. The
  wizard refuses a model that the local Ollama relays to Ollama Cloud; choose
  the sign-in option for cloud models.
- With Ollama signed in to Ollama Cloud, the wizard uses the local daemon at
  `http://127.0.0.1:11434/v1` (or `--endpoint`) and offers only the models it
  relays to `https://ollama.com`. It offers one fixed test message, "Reply with
  OK", only if you agree, and it can run `ollama signin` for you if you answer
  `y`.
- With Ollama Cloud and OpenCode Go, the wizard asks for the limits when the model
  list does not state them, and asks whether your plan charges per token.

If the provider's key variable has no key yet, in the environment or saved, and
the wizard runs in a terminal, it asks for the key. Where menus are shown, each
character you type or paste shows as `*` and Backspace works; otherwise the
input is hidden. After Enter, only the key's length and last four characters are
shown, and a key pasted twice is asked for again. It checks
an OpenRouter key with one free call and saves it once the setup is saved,
without asking. Then it prints the commands that change or remove it,
`trestle keys set NAME` and `trestle keys remove NAME`. Without a terminal, or
with `--no-input`, it never asks. See [API keys](keys.md).

The wizard does not ask how much a single model request may cost. Setup uses the
cost of a request that fills the whole context and writes the whole output
allowance, rounded up to a cent. The settings panel shows that figure and what a
review of two requests can cost. `--max-cost-micro-usd` sets a different bound.

For a provider that charges per token, the wizard then asks one question,
"Spending limit for this key, USD per month [20]". Enter accepts $20 a month,
and the wizard says so and prints the command that changes it; `none` means no limit. The limit alerts at 80% and at the limit;
`--spending-limit` with `--spending-alert` sets another percentage. For OpenRouter,
the wizard first shows OpenRouter's own figures for the key when the key
variable is set. Open Trestle checks the limit before each review and counts its
own upper-bound estimate, not a bill. The check is best effort, so also set a
limit with your provider. A key that already has a limit keeps it.
See [spending limits](spending-limits.md).

### Step 4: your settings and consent

One panel shows everything, whether you answered it or the wizard filled it in.
Under it are the facts you confirm and the spending limit, then one question:

```text
┌─ Setup summary ──────────────────────────────────────────┐
│ Review       1a2b3c4d5e6f → 7f8e9d0c1b2a                 │
│ Runs on      OpenRouter, zero data retention required on │
│              every request                               │
│ Finder       vendor/finder-model                         │
│ Checker      other/checker-model                         │
│ Specialists  on: the general review, then up to 3        │
│              specialist reviews picked from the change,  │
│              each a full review (--specialists none      │
│              turns them off)                             │
│ Limits       context 128000 · output 16000 tokens        │
│ Cost         $3.30 in · $16.50 out per million tokens ·  │
│              up to $0.69 a request, $1.38 a review       │
│ Spending     $20.00 a month for this key · alerts at 80% │
│              and 100%                                    │
│ Key          OPEN_TRESTLE_PROVIDER_OPENROUTER (from the  │
│              environment)                                │
│ Source       github.com/owner/project                    │
│ Names        tenant personal · repository project ·      │
│              owner you                                   │
│ Folder       ~/.local/state/open-trestle/project-1a2b3c4d │
└──────────────────────────────────────────────────────────┘

  Open Trestle records what you state below; it cannot check
  it for you.

  Declaration: sending your source to OpenRouter
  By confirming, you state that:
    • each review sends the selected source, after secret
      scanning, to OpenRouter for vendor/finder-model and
      other/checker-model
    • every request requires zero data retention, so
      OpenRouter uses only zero-data-retention endpoints
    • you have not turned on prompt logging for this key in
      your OpenRouter settings
  Details: docs/remote-model-review.md#openrouter

  Spending limit: $20.00 a month for this key · alerts at 80%
  and 100%
  Confirm all of the above and save this setup? (Y/n):
```

The key variable has the provider's usual name. The `Key` row says where its key
comes from: the environment, `~/.config/open-trestle/credentials`, a key to be
saved with the setup, or not set yet. The key itself is never written to the
setup folder, and only its length and last four characters are ever shown,
once, when you enter it.

The names come from the URL of `origin` (its host, namespace and name; a
credential in the URL is ignored) or from the folder name. The owner comes from
`$USER`.

Enter (or `y`) confirms every declaration shown and saves the setup. If you
answer `n`, the wizard offers to change the commits, the names, the key
variable, or the limits and prices, and then shows the panel and the
declarations again; its last option stops with nothing written. Every value
also has a flag (see [non-interactive use](#non-interactive-use)). The spending
limit is saved after the setup, in the usage folder that every setup shares.
`trestle usage` shows and changes it.

What you confirm depends on the provider:

- For OpenRouter, you confirm that each review sends the selected source, after
  secret scanning, to OpenRouter for the two models; whether zero data retention
  is required; and that you have not turned on prompt logging for the key.
- For Ollama Cloud and OpenCode Go, you confirm the
  [route declaration](remote-model-review.md#common-declarations) (where the
  source is sent, capacity, structured output, logging off, prices,
  availability).
- OpenCode Go also asks for four evidence items and a review window before the
  summary, and the same answer confirms the
  [workspace declaration](remote-model-review.md#opencode-go). For a public page,
  the wizard offers to fetch it once and compute its SHA-256 on your machine.
  The fetch is an `https` GET (it follows at most two redirects) with no key, cookie, query or repository content,
  to public addresses only, with a limit of 8 MiB and 20 seconds. The wizard
  does not fetch account evidence: save a copy of your own account page and give
  its path.
- For Ollama signed in to Ollama Cloud, you confirm the
  [sign-in declaration](remote-model-review.md#ollama-signed-in-to-ollama-cloud),
  which says that your source is sent to Ollama Cloud under your signed-in
  account.
- For a local server, you confirm the
  [local capability declaration](local-first-bootstrap.md#choose-the-repository-and-model-pair).

### Step 5: save and check

The wizard writes the configuration into a new private folder, by default
`~/.local/state/open-trestle/<repository>-<8 hex characters>` (mode `0700`, files
`0600`). It does not overwrite existing files. A key you typed is saved now,
after the setup.

If no key is found for the key variable, the check says so and shows two
commands. `trestle keys set NAME` saves the key with hidden input, and
`read -rs NAME && export NAME` exports it without echoing it. After either one,
run `trestle init` again.

### How it looks

Every line fits in 60 columns, the narrowest terminal
the wizard supports. The only exceptions are commands meant for copying and links too long
for one line. The
wizard shortens long paths on screen (`~` for your home folder, `...` in the
middle), while commands and `NEXT-STEPS.txt` keep full paths.

On an interactive terminal, the wizard uses the web console's colors: cobalt for
the title, the current step and questions; slate for rules and frames; green,
amber and red for `✓`, `…` and `✗`; and dim text for hints. It uses 24-bit color
when `COLORTERM` is `truecolor` or `24bit`, and 256 colors otherwise. Body text
keeps your terminal's own color, and every state keeps its mark. It prints no
color when `NO_COLOR` is set to any value, when `TERM` is `dumb`, when the output
is not a terminal, or with `--no-input`.

## Reading the check results

After saving, the wizard runs the setup checks and marks each one:

| Mark | Meaning |
| --- | --- |
| `✓` | Passed. |
| `…` | Waiting: not done yet, or runs after an earlier item. A one-line hint says what to do. |
| `✗` | Needs a fix. The hint gives the exact remedy. |
| `–` | Optional and not set up (local mode: the test requests you did not allow, and items only the background daemon needs). |

With `TERM=dumb` the marks are `[ok]`, `[..]`, `[x]` and `[--]`, the step
indicator is `#` and `.`, and frames are ASCII.

For a remote provider, the checks confirm that:

- the review window is current (OpenCode Go, and OpenRouter setups made before
  zero data retention was detected);
- the saved configuration loads;
- a key is found for the API key variable (the line says where: from the
  environment or saved);
- the secret scan helper is present and matches the one the program pins.

For OpenRouter, a last line says whether zero data retention is required on
every request or not required by Open Trestle. For the Ollama Cloud sign-in
option, a different check replaces the key check: it confirms that your local
Ollama lists both models as Ollama Cloud models. The wizard offers a review only
when all of these checks pass.

For a local server, the checks run in the bootstrap's direct-review scope
(`trestle setup bootstrap check --scope direct-review`). They confirm that the
setup folder is private, that you are its owner, that the model configuration is
approved, and that a dry run without models passes. The wizard offers a review
only when all of them pass.

The wizard shows the daemon tokens and backup as one optional line. They belong
to the daemon journey in
[check and resume](local-first-bootstrap.md#check-and-resume). The wizard also
offers two test requests to your local servers. They carry fixed sample code,
not your source, and are sent only if you answer `y`. If a test request fails,
you must fix it before the wizard offers a review.

## The first review

The first review compares the two commits from step 1. The wizard shows the one
command that reviews your latest change from now on, `trestle review` (see
[running it again](#running-it-again)), and saves it, together with the check
command, in `NEXT-STEPS.txt` in the setup folder. It then asks:

```text
  A review sends the selected source to OpenRouter (https://openrouter.ai/api/v1), zero data retention required on every request.
  Run the first review now? (y/N):
```

Only `y` runs it. The review runs in the foreground and keeps nothing for
resume. It can take several minutes. A line on the terminal shows the current stage and how long it has taken; see
[progress](local-model-review.md#progress). It first builds an index of the repository
on this machine, with no network, and the models see the index's context for the
change.

### Repository checks

When you answer yes to "Run the first review now?", the wizard asks once: "Run
this repository's tests inside a sandbox on this machine? It has no network and
no access to your home folder or keys." The answer is saved in `checks.json` in
the setup folder, and the default is no. If no review runs, it is not asked, and
the first review asks instead. With `--no-input`, `--checks` answers yes.
`trestle checks on`, `off` and `status` change or show the answer later. A review that has no saved
answer asks in the terminal. See [repository checks](repository-checks.md).

A new setup runs specialist reviews by default. The general review runs first,
and then up to three specialist reviews (such as `bug_hunter` or
`security_probe`) run. Open Trestle picks the specialists from the change
without a model call, and each one is a full review with its own
check. The settings panel shows this in a `Specialists` row that starts with
`on:`. On remote models, the specialists run at the same time, up to three at
once. On a model on this machine, they run one after another.

To review with the general review only, give `trestle init --specialists none`
(the row then starts with `off:`), or run `trestle review --specialists none`
once. The spending warning counts every review the command may run. See
[specialist review set](local-model-review.md#specialist-review-set-opt-in).

On a terminal, `trestle review` prints a short view: the verdict and exit
status first, then the findings, then a line on what was checked. See
[the result on a terminal](local-model-review.md#the-result-on-a-terminal).
`trestle review --verbose`, and any output that is not a terminal, print the
full text document described here.

The text document starts with the status and the reviews that ran. Then comes a
walkthrough of what was checked across all of them, followed by the confirmed
findings, most important first, each with the reviews that confirmed it. This
example comes from the offline test fixture, with the general review and two
specialists:

```text
status: findings
ci: blocked
reviewers: general, bug_hunter, backend (3 of 3 ran)
walkthrough:
verified: secret scan: 6 model requests from 3 reviewers scanned before sending (876 bytes, 0 secret matches)
verified: static check static_debug_output: passed (1 file checked, 0 matches)
verified: pattern hygiene: 0 added suppressions, 0 added workaround comments, 0 spreading anti-patterns
verified: style detection: ran (1 recommendation, 0 withheld)
verified: semantic impact: 1 changed declaration, 0 public API changes, 1 reference (0 from tests), 0 gaps
verified: independent verifier (distinct_provider): 3 of 3 candidates from 3 reviewers confirmed, 0 rejected, 0 inconclusive
file: a.go modified +1 -1; changed function Changed
missing verification: no test file references the changed function Changed (a.go)
confirmed findings (ranked): 1
finding: error Zero-valued caller now panics
rank: 1
source: a.go:2-2
message: Consume passes zero to Changed after removal of the division guard.
evidence: 8d0ff8ec..., f84bfca8...
category: correctness
fix: Restore the zero guard before dividing.
confirmed by: general, bug_hunter, backend
tokens: input=600 output=600 cached_input=0 over 6 route attempts (3 reviewers)
style: no declared Go style for 1 changed file; consider gofmt and Effective Go, and commit its configuration
comprehensive clearance: false
```

When two reviews describe one problem in different words at the same place,
Open Trestle lists it once, with the other wording on an `also reported as:`
line. A review that did not finish gets a `not finished:` line with a `hint:`.
`trestle review --verbose` adds the details behind the summary: how the
specialists were picked, each review's status, and the list of limitations.

### Reading the result

Each part of the result means the following.

- `findings`: The finder proposed each listed finding and the checker confirmed
  it. Read them like a colleague's review comments. A finding about code that
  the change removed points to the removed lines of the base commit
  (`path removed base lines a-b`), not to head lines.
- `walkthrough:` lines: These show what was verified (the secret scan of the
  model requests, the scripted checks, style detection, the semantic-impact
  analysis, and the checker's confirmed, rejected and inconclusive counts). They
  also show each changed file with its line counts and changed Go declarations,
  and `missing verification:` notes for changed functions that no test file
  references. These notes are information, not defects. A `context used:` line
  says how many enclosing definitions, callers, tests and repository map entries
  the models saw beside the changed code. A `check runs:` line says what ran when
  [repository checks](#repository-checks) were on.
- `confirmed findings (ranked)`: High, critical and medium findings, most
  important first. Findings that repeat one another are merged. Lower-severity
  findings are counted on a `hidden:` line, and `trestle review --all` lists
  them. When every confirmed finding is low severity, up to ten of them are
  listed, so the result never hides all of them.
- `pre-existing findings`: Confirmed problems on unchanged lines that the
  change provably cannot reach. They are listed separately and never make the
  review blocking. A confirmed problem on unchanged lines that the change may
  affect, such as a caller of a changed function, stays with the confirmed
  findings with an `origin: unproven` line and blocks like a new one.
- `ci: inconclusive` with `status: findings`: This is an advisory review. Every
  confirmed finding is low severity or pre-existing, so none blocks CI (exit `3`
  by default, `0` with `--exit-code-policy findings`), and the closing line says
  so. Only a medium, high or critical finding that the change introduced, or whose
  origin is unproven, makes a review `ci: blocked` (exit `4`).
- `no_candidates`: Nothing was found and confirmed. That does not mean the
  change is correct.
- `incomplete`: Part of the change was not covered. See the coverage and
  omission lines.
- `refused`, `failed` or `canceled`: There is no usable result. The wizard says
  what to try.
- `style:` lines: When the base commit declares no style for a changed language
  that has a style detector, the result suggests a standard one. This is advice,
  not a finding, and it does not change the result. See
  [style recommendations](local-model-review.md#style-recommendations).

Every result says `comprehensive clearance: false`. See [local model review](local-model-review.md) for the full result format.

## Running it again

After setup, reviewing your latest change is one command, which you can run from
anywhere in the repository:

```sh
trestle review
```

The command finds the setup the same way `trestle init` does: in the folder from
step 5, or in the one you name with `--directory PATH`. It picks the two commits
again, says what it compares and where the source goes, and runs the same review
with the setup's routes, policy, names and egress. It does not reuse the commits
saved at setup time, so a setup keeps working after those commits are rewritten
or garbage-collected.

- The head is `HEAD`, the commit checked out now. The base is
  the newest commit that `HEAD` shares with the default branch, as your
  repository has it or as `origin` has it, whichever is newer: one
  `git merge-base HEAD main origin/main`. A local `main` that is behind `origin`
  therefore does not pull commits that are already upstream into the review. On
  the default branch itself, the base is `origin`'s copy, so your unpushed
  commits are the change. The default branch is the one `origin/HEAD` names,
  otherwise `main`, otherwise `master`. `--base REF` and `--head REF` pick
  commits exactly, as in `trestle init`. With `--head REF` alone, the base is
  the newest commit that REF shares with the default branch.
- Uncommitted changes are not included. Only committed work is reviewed. When
  you have uncommitted changes or untracked files, the review says they are not
  included and that committing them includes them. It writes nothing into your
  repository and does not fetch.
- The result goes to standard output in the setup's text format.
  `--format json`, `--format sarif` or `--format markdown` prints one JSON,
  SARIF or pull request summary document there instead. Every other line goes to
  standard error, including the egress, secret-scanning and spending messages,
  which are those of `trestle local-git model-review`. The options
  `--timeout`, `--profile`, `--specialists`, `--max-specialists`,
  `--exit-code-policy`, `--all` and `--verbose` pass through to that command, and
  so do its [exit codes](local-model-review.md). For example, the exit code is
  `4` when a confirmed medium, high or critical finding blocks, and `3` for an
  [advisory](local-model-review.md#advisory-results) review whose findings are
  all low severity or pre-existing.
- Nothing is sent when the repository has no setup (run `trestle init`), when
  there is no committed change to review, or when no API key is found
  (`trestle keys set NAME`). In each case `trestle review` says so and exits `3`.

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
credential store. `Last run` comes from `last-review.json` in the setup folder.
This small record holds the time, the status, the number of confirmed findings
and the two commits, and nothing else. `trestle review`, the home screen and
`trestle init` write it after each review. A review that you run directly with
`trestle local-git model-review` is not recorded.

In a repository without a setup, the only action is `trestle init`. Without a
terminal on both sides, or with `NO_COLOR` set or `TERM=dumb`, `trestle` prints
the usage text and exits `2`, as before.

A row that needs action starts with `✗` or `…` and has the command that fixes
it beneath it, inside the card:

```text
│ Key         ✗ OPEN_TRESTLE_PROVIDER_OPENROUTER (not set) │
│             -> trestle keys set                          │
│             OPEN_TRESTLE_PROVIDER_OPENROUTER             │
```

On the packaged install, the home screen also adds a last action, "Update Open
Trestle", which runs `trestle update`. When a newer version is available, the
card's last row is `Update`, marked `…`. It comes from the home screen's only
network request, the release list GET, made at most once a day (see
[updating](#updating)). `trestle status` prints the same card without the
actions, and plain `Label:  value` lines in a script; see
[commands](commands.md#trestle-status).

### Check your setup

`trestle doctor` checks the install, this repository and its setup, the key,
the spending limit, the repository checks and the cached update notice. It
changes nothing and sends no source. Each problem has the command that fixes
it, and the last line is `All checks passed.` or a numbered list:

```sh
trestle doctor          # exits 1 when something needs fixing
trestle doctor --live   # also reads the provider's model list with the key
```

See [commands](commands.md#trestle-doctor).

Run `trestle init` again in the same repository to re-check the setup. `trestle
init`, `trestle review` and the home screen use the most recently saved setup
for this repository in `~/.local/state/open-trestle`, the folder that setup
proposes or another one beside it. A setup made with
`--directory` in that location therefore needs no flag later. A setup saved
anywhere else needs the same `--directory` again. Running `trestle init` again
offers:

```text
    1) Review the latest change (sends it to OpenRouter)
    2) Re-run the setup checks
    3) Change a setting
    4) Quit without changes
```

The first choice re-runs the checks and then reviews the latest change exactly as
`trestle review` does. With `--no-input`, `--run-review` does the same. If the
setup's key is missing, the wizard asks for it first (see [API keys](keys.md)).
It does not re-initialize the setup or change the saved files.

"Change a setting" lists the settings with their current values and asks again
only the one you pick, proposing its current value:

- **Provider and models.** A setup folder is written once and never changed, so
  the wizard makes a new setup in the next free folder beside it
  (`<repository>-<8 hex characters>-2`, then `-3`), through steps 1 to 5 and the
  same consent as a first setup, proposing the current provider and models. The
  earlier folder stays as it was. `trestle review`, the home screen and
  `trestle init` then use the newest setup for this repository.
- **API key.** It asks for the new key (one `*` per character), checks it as a
  first setup does and saves it at once in the credential store. Enter on an
  empty line keeps the current key. A key exported in the shell is still used
  before a saved one, and the wizard says so.
- **Spending limit.** It asks the limit again and saves it at once in the usage
  folder; `none` removes it. The period and alerts stay as they were.
- **Repository checks.** It asks the checks question again, with the current
  answer selected, and saves it in `checks.json`.

Esc (or `b`) at the list returns to the first menu. To keep a setup and make
another one beside it, you can still pass a new folder:
`trestle init --directory NEW_FOLDER`.

On a terminal, a finished setup, or a changed setting, ends with the commands
for everyday use:

```text
Next commands
    trestle review          review your latest change
    trestle                 status and next actions
    trestle keys set NAME   replace the API key
    trestle usage           spending and limits
    trestle init            change a setting
```

## Updating

On the packaged Linux amd64 install, one command updates Open Trestle:

```sh
trestle update
```

It finds a newer version, shows it, asks you to confirm, and runs that version's
own upgrade with `sudo`, which asks for your password. `trestle update --check`
only reports; it exits `10` when an update is available.

No release is signed yet, so today it installs only an unsigned local build: one
left in `~/.local/share/open-trestle/updates/` for a development install, or a
file named with `--from`. See [updates](updates.md) for the channels, the checks
and `OPEN_TRESTLE_UPDATE_CHECK=off`.

## Non-interactive use

Every answer has a flag. With `--no-input` the wizard never prompts. If any
answer is missing, it lists every missing flag and exits `2` without writing
anything. Without `--provider`, it lists only that flag, because the provider
decides which other answers are needed.

With `--no-input`, the wizard still fills in everything it can work out itself:
the commits, names, owner, folder, key variable, and any limits and prices that
a provider or model list states. A flag overrides what it fills in. Facts that
you must declare are not filled in. A complete `--no-input` run prints the
settings panel, without color.

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
| Spending limit for the key (optional) | `--spending-limit USD`, `--spending-alert PERCENT` (default 80; alerts also at the limit; not asked interactively). Only for a remote provider that charges per token; with `--no-input` and without it there is no limit. See [spending limits](spending-limits.md) |
| Key variable (default: the provider's usual name) | `--credential-env OPEN_TRESTLE_PROVIDER_NAME` |
| Names (default: from `origin`, the folder and `$USER`) | `--owner`, `--tenant`, `--repository`, `--repository-authority`, `--repository-namespace`, `--repository-name` |
| OpenRouter | `--without-zdr` (do not require zero data retention; interactively too, since it is not asked), `--generation-provider-slug SLUG[,SLUG]` and `--verification-provider-slug SLUG[,SLUG]` (override the detected ZDR endpoints) |
| OpenCode Go | `--generation-model-evidence`, `--verification-model-evidence` |
| Evidence window | `--broker-evidence`, `--account-evidence`, `--evidence-retrieved-at`, `--reviewed-at`, `--valid-from`, `--valid-until` |
| Declarations | `--declare-remote-route`, `--declare-opencode-go-account`, `--declare-ollama-cloud-signin`, `--declare-local-capabilities` |
| Local test requests | `--allow-local-probe` |
| Repository checks (optional) | `--checks` (run the repository's tests in a sandbox; without it, the answer is no) |
| Consent to review | `--run-review` |

There is no blanket "yes to everything" flag. Each declaration is its own
bootstrap flag, and the review runs only with `--run-review`. Evidence values are
`HTTPS_URL,SHA256`, as for the bootstrap.

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

This command requires zero data retention when both models have zero-data-retention
endpoints. If one of them has none, it stops and names `--without-zdr`. With
`--provider openrouter-zdr` it stops instead. If OpenRouter's API cannot be
read, the command lists the capacity and price flags to add.

The values above are placeholders, not recommendations.

## Exit codes

These are the exit codes of `trestle init`. [Exit codes](exit-codes.md) lists
every command's, including `trestle review`.

| Code | Meaning |
| --- | --- |
| `0` | Done: setup is ready (review declined), or the first review finished with `findings` or `no_candidates`. |
| `3` | Pending: something must be fixed before a review can run, or the review was incomplete or canceled. |
| `4` | Refused: a declaration was declined, setup was refused, a setup check refused (such as the scanner check of a build that pins no secret scan helper; the setup is kept), or the review was refused. |
| `2` | Usage: a missing or invalid answer, end of input (Ctrl-D), or three unusable answers in a row. |
| `1` | Internal error, or the first review failed. |

If you end input early, or give three unusable answers to one question, the
wizard stops without writing anything, as long as the setup was not yet saved.

## Limits

- The wizard records your declarations. It cannot check account settings,
  provider conduct, model capability, price or availability. It records
  OpenRouter facts as reported by its API at setup time. OpenRouter's API does
  not say whether your account or key enforces zero data retention, so the
  wizard does not say either way.
- The wizard does not install software, download models, start servers,
  provision keys or change repository permissions.
- A spending limit is Open Trestle's own best-effort check of its upper-bound
  estimate. It is not your provider's bill or limit, so set a limit with your
  provider too. See [spending limits](spending-limits.md).
- The local model list and the remote catalogs show what is available. A
  loopback address does not mean a model runs locally: the wizard flags an
  Ollama `:cloud` model because it would send source to Ollama's cloud.
- A local setup made by the wizard is for the direct review only. It does not
  prepare the background daemon, which still needs a private `0700`, loose-object
  source. Set that up with the
  [local-first bootstrap](local-first-bootstrap.md) directly.

For details, see [local-first bootstrap](local-first-bootstrap.md),
[remote model review](remote-model-review.md), [model catalog](model-catalog.md)
and [named local runtimes](named-local-runtimes.md).

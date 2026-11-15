# Open Trestle

<p align="center">
  <strong>An evidence-first code-review runtime you can host yourself.</strong><br>
  Every finding traceable to immutable source. Every model choice governed by policy.<br>
  Every claim backed by receipts, or not made at all.
</p>

<p align="center">
  <a href="#status">Status</a> ·
  <a href="#why-open-trestle">Why</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#documentation">Docs</a> ·
  <a href="#contributing">Contributing</a>
</p>

---

## Status

> [!WARNING]
> **Open Trestle is under active construction. One local evaluation path is now runnable end to end.**
> This tree is an unreleased development candidate. The demonstrated path is limited to
> an unsigned Linux amd64 candidate, one loopback `local_single_node` daemon, one exact
> loose-object Git base/head pair, and the existing deterministic static-debug rule. No
> version is supported for production use. Capability descriptions below describe the
> candidate, not a release, and remain contingent on the open [release gates](docs/roadmap.md).

**What is real today:** The Go packages have a full test suite, deterministic JSON and
SARIF review output, loose and packed Git inspection, a protected setup planner, a
durable run journal, an embedded read-only web console, a scoped MCP server, and read-only
ACP and LSP surfaces. The unsigned candidate can now execute one provider-free loose-object review
through durable daemon state and show the same run in the CLI and TUI plus two
phase-tagged daemon-served browser passes before and after restart. Both browser passes
bind the exact run, diagnostic set, deterministic check state, and observation identities.
This proves that exact local evaluation path only. It
does not establish review quality, repository-wide coverage, setup readiness, or a
supported deployment.

Model-backed review is also runnable against two operator-selected local models:
`trestle setup bootstrap` prepares a protected same-user setup and the exact daemon,
submit, and status commands for a durable review of one pinned base/head pair, run
as nine tasks over eight stage kinds because source is acquired once for the base and
once for the head (see [first local model review](#first-local-model-review)), and
`trestle local-git model-review` runs a direct, non-durable review of a checkout.
Both report findings together with their coverage, omissions, and abstentions; neither
is a quality claim. `trestle profiles` lists the packaged specialist review profiles
and prints a deterministic routing plan. The direct review runs them: `--profile`
adds one profile's instructions to a single review, and `--specialists auto|LIST`
runs the general review plus selected specialists as separate, independently
verified runs. The daemon does not dispatch profiles
([agent profiles](docs/agent-profiles.md)).

**What is not:** a supported production install, stable APIs, or any public claim about
review quality. CI builds and exercises an unsigned Linux amd64 candidate package, but
that package has no signer identity or published provenance and is only for explicit
local evaluation. Production support requires release and deployment evidence that has
not been published yet.

Go API upgrade note (pre-v1): `artifact.NewValidatedTaskHandler` and
`artifact.ValidatedTaskHandler` moved to `artifactvalidation`. Import the new package;
there is no compatibility shim. `artifact.ErrInvalidTaskHandler`, `artifact.Reader`,
and `artifact.Clock` remain in `artifact`.

## Why Open Trestle

AI code review today is mostly a prompt attached to a pull request. The conclusions
can't be inspected, the model routing can't be audited, and the operator owns none of
it. Open Trestle takes the opposite stance: a review conclusion is only useful if you
can see exactly where it came from and control every step that produced it.

The design rules that follow from that:

- **Evidence first.** A published finding must resolve to immutable source, policy,
  tool, and verification evidence. No evidence, no finding.
- **Models are routes, not oracle.** Model providers are selected through a
  policy-governed gateway with declared data constraints and zone allowances. Review
  logic never embeds a provider.
- **Verification is independent.** Candidate findings are checked by a separate route
  from the one that produced them.
- **Content is never authority.** Repository text, CI configuration, logs, and model
  output are data. None of it can trigger command execution or widen permissions.
- **Humans stay in the loop.** A passed review narrows routine work; it is not
  approval, proof of correctness, or a security guarantee. Coverage, limits, and
  abstentions stay visible so a reviewer can see what was actually checked.
- **Operator ownership.** Local-only, controlled-hybrid, and air-gapped deployments
  are first-class targets, not afterthoughts. For private source, prefer local
  models or a provider whose zero-data-retention terms and account settings you
  have verified. Open Trestle checks declared route policy, not a provider's
  actual retention behavior.

## Architecture

One review engine, two ways to run it. The **direct path** runs a model review
inside the `trestle` process and keeps nothing afterwards; `trestle init` and
`trestle local-git model-review` use it. The **daemon path** runs the same task
graph inside `trestled`, with durable runs, a task journal and an authenticated
API. A model review on either path runs nine tasks over eight stage kinds:
source acquisition (once for the base, once for the head), change construction,
deterministic evidence (source slices, one built-in check and a Go
semantic-impact profile), memory retrieval, context assembly, bounded candidate
generation, independent verification and publication readiness. Only a daemon
run in required mode adds a tenth task, publication, behind the idempotent
publication gate. The TUI, VS Code, the web console and ACP observe one daemon
run; they do not start a review.

```
  direct path: in the trestle process      daemon path: durable, in trestled
  ───────────────────────────────────      ────────────────────────────────
  trestle init                             trestle local-git submit-review
  trestle local-git model-review           trestle runs submit
  (the GitHub Actions example runs it)     MCP open_trestle.submit_run (a pre-built plan)
                                           verified GitHub webhook
                │                                         │
                ▼                                         ▼
  process-private session                  trestled: durable runs · journal · auth
                │                                         │
                └────────────────────┬────────────────────┘
                                     ▼
                       source (base)   source (head)
                              └───────┬───────┘
                                      ▼
                                    change
                              ┌───────┴───────┐
                              ▼               ▼
                deterministic evidence    memory retrieval
                              └───────┬───────┘
                                      ▼
          context ─► candidate generation ─► independent verification ─► readiness
                                      │
                ┌─────────────────────┴───────────────────┐
                ▼                                         ▼
  JSON, text or SARIF output               publication gate (required mode only)

  Observers of one daemon run: trestle runs status · trestle tui · VS Code through
  trestle lsp · web console · ACP · MCP open_trestle.run_status. They are read-only,
  except that trestle runs cancel and the TUI can cancel the run.
```

The provider-free local evaluation run on the daemon stops after deterministic
evidence (four tasks). The fixture commands (`trestle ci`, `trestle review
FIXTURE`) and the `local-git` inspect, change and deterministic review commands
run in the `trestle` process without a model or a daemon.

| Interface | Purpose |
|---|---|
| `trestled` | Local or server review daemon: durable runs, task journal and authenticated API |
| `trestle` | CLI and terminal user interface |
| `trestle init` | Guided setup in the current repository; runs the first review on the direct path |
| `trestle ci` | Deterministic review of local fixture files, not arbitrary checkouts |
| `trestle local-git model-review` | Direct, non-durable model-backed review of an explicit checkout base/head pair, in the `trestle` process |
| `trestle local-git submit-review`, `trestle runs` | Submit a review to `trestled`, then read its status or cancel it |
| `trestle setup bootstrap` | Protected local setup and exact commands for a durable first model review |
| `trestle profiles` | Packaged specialist profiles and deterministic routing plans; the direct review runs them via `--profile` and `--specialists`, the daemon does not |
| `trestle lsp` | Read-only editor diagnostics from one daemon run or an offline export |
| `trestle mcp` | Scoped Model Context Protocol server: reads one run's status and submits a plan an authorized planner already built |
| `trestle acp` | Read-only Agent Client Protocol endpoint for one daemon run |
| VS Code extension | Packaged read-only verified findings over the LSP boundary; deterministic observations remain outside LSP findings |
| Web console | Read-only run, diagnostic, and runtime inspection, served by `trestled` |
| Forge adapters | Verified webhook intake; governed publication behind an explicit effect gate |

A packaged GitHub Action (`action.yml`), starting a review from the TUI or VS
Code, and a desktop app are planned; see the [roadmap](docs/roadmap.md).

For noninteractive model-backed review of an explicit checkout base/head pair, use
[`trestle local-git model-review`](docs/local-model-review.md#headless-ci-use).
Its conservative CI disposition is not a repository-clearance claim.

## Quick start

Start with the guided setup. Run it inside the Git repository you want reviewed:

```sh
cd path/to/your-repository
trestle init
```

`trestle init` asks where the two models run (OpenRouter, with zero data
retention by default; Ollama Cloud; OpenCode Go; a model server on this machine;
or Ollama on this machine signed in to Ollama Cloud), which model finds problems
and which different model double-checks them. It fills in the rest (the names
from the Git remote, the key variable name, and limits and prices a provider
reports) and shows every setting in one panel. When the API key is not set, it
asks for it with hidden input, checks it where the provider has a free check,
and offers to save it in an owner-only file; `trestle keys` manages saved keys
(see [API keys](docs/keys.md)).
It shows every privacy or capability declaration in plain words and requires a
typed `yes`,
writes a protected configuration, runs the setup checks with a one-line fix for
anything missing, and runs the first review only after you agree to send the
selected source. Every answer also has a flag for `--no-input` use. Remote
providers still need the packaged scanner-bound binary. See
[getting started](docs/getting-started.md).

After setup, one command reviews your latest change, `HEAD` against its merge
base with the default branch, with the saved setup:

```sh
trestle review
```

Uncommitted changes are not included; commit them to review them. `trestle` on
its own, in a terminal, shows the repository's setup, models, key, spending
and last review, with numbered next actions. Running `trestle init` again
offers the same review of the latest change, or a re-check of the setup.

For a provider that charges per token, it also offers an optional monthly
spending limit for the API key. Every review records what it may have cost,
alerts as the total nears the limit and is refused once it reaches it;
`trestle usage` shows and changes limits, and for OpenRouter adds OpenRouter's
own figures. The total is Open Trestle's upper-bound estimate at the highest
pinned price, not a bill, and the limit is best effort, so set your provider's
own limit too. See [spending limits](docs/spending-limits.md).

### Evaluation path

There is no supported runtime package. The following clean-checkout procedure reproduces
the bounded local evaluation path and writes its evidence to a caller-selected private
directory. It does not install on `/`, contact a model or forge, publish a result, or
qualify a production deployment.

```sh
# build and check the committed console assets with the pinned Node release
# node --version must print v26.12.1; do not accept a build from another Node release.
node --version
(cd web && npm ci && npm test && npm run build && npm run dist:check)

# build the fixed runtime staging tree and passive point-in-time advisory evidence
python3 tools/package_secret_scanner.py --output .container
python3 tools/package_secret_scanner.py --verify .container
python3 tools/vulnerability_gate.py --staging .container

REVISION="$(git rev-parse HEAD)"
CREATED="$(date -u -d "$(git show -s --format=%cI "$REVISION")" +%Y-%m-%dT%H:%M:%SZ)"
python3 tools/linux_distribution.py \
  --staging .container \
  --version 0.1.0-dev \
  --revision "$REVISION" \
  --created "$CREATED" \
  --output open-trestle-linux-amd64.pyz
sha256sum -c open-trestle-linux-amd64.pyz.sha256
./open-trestle-linux-amd64.pyz verify-archive

# OUTPUT must not exist; it receives synthetic source, durable state, exports,
# lifecycle evidence, and real daemon-backed desktop/tablet/mobile screenshots.
python3 tools/local_alpha_system.py \
  --candidate "$(pwd)/open-trestle-linux-amd64.pyz" \
  --source-root "$(pwd)" \
  --browser-script "$(pwd)/web/scripts/daemon-visual-check.mjs" \
  --output "$HOME/open-trestle-local-alpha-evidence"
```

The system driver fails before creating its output directory unless the live source is
proved against the literal, unreplaced committed `HEAD` tree. It requires a non-bare Git
worktree whose effective absolute top level equals the resolved source root. Every Git read
uses the fixed trusted `/usr/bin/git`, replacement interpretation disabled, explicit
per-worktree Git directory and worktree, and the validated default index and common object
directory. Replacement refs, common or linked-worktree grafts, redirected `core.worktree`,
ambient Git authority overrides, alternate object stores, and symlinked Git object, ref,
config, index or linked-worktree control storage are rejected. The local alpha supports
only the `files` reference backend and a normal unsplit index; reftable and split-index
repositories, including redirected or symlinked stores, fail before output or execution.
Legitimate linked worktrees are supported only when their effective top level is the
supplied source root and their per-worktree and common control paths pass the same checks.

The driver reads Git objects and index metadata without refreshing the index or writing Git
objects. It rejects unresolved or staged entries, assume-unchanged, skip-worktree,
fsmonitor-valid and sparse or unsupported entries, and requires every tracked path to match
the literal tree in object type, Git executable semantics, regular-file bytes or symlink
target. Nonignored untracked paths are rejected. Ignored paths are permitted, but their own
byte, type, full mode and symlink-target identity is recorded separately and must remain
unchanged through the final source fence. The ignored identity is not a substitute for, or
proof of, tracked-tree provenance.

The canonical browser script and its local contract module execute only from output-owned
copies reconstructed from their exact `HEAD` blobs and modes. The installed
`playwright-core` 1.62.1 payload is independently pinned by a bounded path, mode and byte
identity, rejects symlinks, and is copied and rehashed in the browser sandbox. This payload
binding is toolchain evidence, not a claim that ignored files belong to the committed tree.
The driver reads and bounds the original candidate manifest without executing archive code.
Its revision and the safely read archive digest must match the independently proved source
`HEAD` and detached checksum before the output directory, browser sandbox, or execution
marker can exist. A matching manifest alone is not source provenance.

After that preflight, the driver writes the exact inspected candidate snapshot into the
output-owned sandbox, revalidates its digest and manifest, and executes only that copy with
digest fences around every archive command. Candidate and browser commands have bounded output, HTTP, log and
total-time budgets. The driver installs only into an isolated destdir, runs candidate
smoke, creates a real temporary Git repository, initializes the existing
`local_single_node` plan, starts `trestled` on numeric loopback, and executes the four-task
deterministic run. It captures the exact run in CLI, TUI and the real daemon-served console
before restart, proves the daemon process group stopped and the port can be rebound,
restarts the daemon, and repeats the same identity-bound browser matrix. JSON and SARIF
bytes must remain identical.

Normal console use and screenshot evidence both recompute the Go-compatible Runtime
configuration and status identities before rendering or exposing them for copy controls.
The browser-safe production verifier uses WebCrypto over canonical Go field order, preserves
wire `handlers:null` during hashing, and normalizes it to an empty UI array only after
identity acceptance.

Each Runtime screenshot is bound to the exact authenticated runtime-status response shown
by the UI. Run, diagnostics, displayed Runtime and post-capture Runtime reads reject
redirects, require the exact canonical final URL, enforce total deadlines, and stop reading
when their byte cap is crossed. The phase receipt records and independently validates its
status identity, configuration identity, observed time, complete configuration and
authority identities, handlers, and component names and states. The browser compares those
values with the DOM, captures the Runtime image, then performs a bounded immediate reread.
Status identities and observation times may naturally differ across reads and restart;
configuration and component semantics must remain stable. JavaScript and Python validators
reject stale, malformed, forged, redirected or misattributed responses and bind the Runtime
image SHA-256 to the phase receipt.

Final cleanup recovers and uninstalls the candidate, preserves operator sentinels, proves
process-group quiescence and port reuse, removes the private temporary alias, and repeats
the complete source proof. Process-group checks cover the candidate and daemon groups;
they cannot prove that a subprocess which detached into another session and was
reparented has exited. Inspect
`$HOME/open-trestle-local-alpha-evidence/receipt.json` for distinct committed-tree, live
tracked-tree, ignored-worktree, index, index-flag and status identities; exact browser
module and dependency bindings; candidate source/execution paths and archive digests;
phase-tagged Runtime responses and screenshot digests; independently parsed PNG dimensions;
restart checks; and cleanup bindings. These records prove only this bounded local journey.
They do not authenticate a publisher, qualify a deployment, or establish production
readiness.

The initialized setup plan is a scope and denied-effect posture fence for this narrow
review. It remains `ready:false`; pending policy, inference, dry-run, backup, observer,
and other setup gates are not bypassed or reported as passed. The deterministic run does
not perform a setup, provider, egress, publication, or source-mutation effect.

The lower-level source commands remain useful for focused inspection:

```sh
# create and inspect a protected setup plan
install -d -m 0700 "$HOME/.local/state/open-trestle/setup"
go run ./cmd/trestle setup init \
  --profile local_single_node --tenant tenant-a --repository repository-a \
  --recovery-owner platform-owner \
  --state "$HOME/.local/state/open-trestle/setup/plan.json"
go run ./cmd/trestle setup inspect \
  --state "$HOME/.local/state/open-trestle/setup/plan.json"

# validate a local fixture and emit deterministic CI output
go run ./cmd/trestle validate-fixture cmd/trestle/testdata/local-review/fixture.json
go run ./cmd/trestle review cmd/trestle/testdata/local-review/fixture.json
go run ./cmd/trestle ci --format=sarif cmd/trestle/testdata/local-review/fixture.json

# inspect loose Git objects and review an exact base/head pair
go run ./cmd/trestle local-git inspect --objects-root PATH \
  --repository-authority AUTHORITY --repository-namespace NAMESPACE \
  --repository-name NAME --revision-algorithm sha1 \
  --revision-digest FULL_LOWERCASE_SHA1
go run ./cmd/trestle local-git review --objects-root PATH \
  --repository-authority AUTHORITY --repository-namespace NAMESPACE \
  --repository-name NAME --revision-algorithm sha1 \
  --base-revision-digest FULL_LOWERCASE_BASE_SHA1 \
  --head-revision-digest FULL_LOWERCASE_HEAD_SHA1

# run the test suite
go test ./...
```

### First local model review

Once the binaries are installed, the [local-first bootstrap](docs/local-first-bootstrap.md)
guide walks one same-user journey with two local OpenAI-compatible model servers:

1. `trestle setup bootstrap init` pins the checkout's base and head commits, the two
   distinct local models, and a local-only, no-publication review policy into a
   private `0700` directory.
2. `trestle setup bootstrap check` runs the offline setup checks and, only with
   `--allow-local-probe`, two bounded synthetic-code model probes. It returns
   `ready` (exit 0), `pending` (exit 3) or `refused` (exit 4).
3. `trestle setup bootstrap prepare-review` prints the exact `launch_command`,
   `review_command` and `status_command` argument arrays. Start `trestled` with the
   launch command, then submit within five minutes.
4. Inspect the durable run with the status command, `trestle tui`, or the daemon's
   web console.

The daemon path currently needs a private `0700` Git objects directory with complete
loose objects, separate operator and observer tokens of at least 32 bytes in the
environment, and the pinned scanner binaries. Bootstrap never runs commands, installs
services, or sends repository source. Submitting the review is the source-to-model step.

For strong remote models (OpenRouter ZDR, OpenCode Go or Ollama Cloud), follow the
[remote model review](docs/remote-model-review.md) journey: `init --provider`, `check`,
then the printed direct `--egress policy-approved` review command.

### Unsigned Linux amd64 candidate

After the scanner staging and passive vulnerability gates have completed, a Linux amd64
candidate can be built without compression or external packaging dependencies:

```sh
REVISION="$(git rev-parse HEAD)"
CREATED="$(date -u -d "$(git show -s --format=%cI "$REVISION")" +%Y-%m-%dT%H:%M:%SZ)"
python3 tools/linux_distribution.py \
  --staging .container \
  --version 0.1.0-dev \
  --revision "$REVISION" \
  --created "$CREATED" \
  --output open-trestle-linux-amd64.pyz
sha256sum -c open-trestle-linux-amd64.pyz.sha256
./open-trestle-linux-amd64.pyz verify-archive
```

The pyz is unsigned. Its detached SHA-256 file detects accidental or untrusted byte
changes only when the expected digest is obtained through a separate trusted channel.
Running `verify-archive` already executes the embedded Python lifecycle code, so use
external `sha256sum -c` before execution. Neither check authenticates a publisher.
Production install requires root and targets `/usr/local`. `--destdir` is an explicit
non-production CI mode. The candidate supports only an exact verified installation to a
strictly newer same-target archive, plus one immediate-predecessor `rollback-version`.
Each upgrade keeps only the generation it replaced in that rollback slot and discards an
older one in the same transaction, so upgrades can repeat without a rollback in between.
It never configures or starts a service and never creates application configuration or
state. A fixed root transaction record makes `recover` restore the pre-commit generation
or verify the post-commit generation before bounded cleanup. On Ubuntu 24.04, the opt-in
non-production destdir matrix sends SIGKILL after every successful fsync and rename
boundary for install, upgrade into an empty or occupied rollback slot, `rollback-version`,
and recovery itself. This is not
power-loss, production-root, or filesystem qualification. See
[operations](docs/operations.md) for the exact state machine, retained rescue-candidate
requirement, inventory, lifecycle commands, and removal guarantees.

The static `local-git inspect`, `local-git change`, and deterministic `local-git review` commands support verified loose objects only. Nonempty, valid, within-budget added text is reviewed against a canonical empty base; empty, binary, removed, and over-limit entries remain explicit unsupported outcomes. Repository fields are caller-supplied scope labels, not proof that the object directory belongs to that repository. See [Local Git inspection](docs/local-git-inspect.md), [Local Git change evidence](docs/local-git-change.md), and [Local Git debug-output review](docs/local-git-review.md).

The fixture and `local-git` commands are local-only: no model calls, no repository
content execution, no source mutation, no publication. For model-backed local review
see [local model review](docs/local-model-review.md). It requires protected route
configuration, an explicit egress choice, and a finite timeout. It defaults to loose
Git objects with a separate packed-object opt-in, does not publish results, and its
results report limits rather than comprehensive clearance.

The unreleased runtime candidate also admits standard generation and independent-
verification requests to an approved private-remote OpenAI route after two fail-closed
scans. Betterleaks v1.8.1 scans up to 256 typed fields and 2 MiB of decoded text in a
fresh fixed sandbox process, the host redacts its content-free byte spans, and a second
fresh process must complete with zero residual findings. Only a generation or
verification handler can seal the receipt-bound proof accepted by the adapter.
Investigation remains local-only. The reviewed corpus found 11 of 14 expected
occurrences, missing bearer credentials, AWS secret keys, and AWS session tokens; one
`generic-api-key` near miss at `[7,51)` is redacted. This is not comprehensive secret
detection, and none of it is released or supported for production. See the
[OpenAI provider boundary](docs/openai-provider.md) and
[operations guide](docs/operations.md).

## Documentation

| Area | Reference |
|---|---|
| Architecture and roadmap | [architecture](docs/architecture.md) · [roadmap](docs/roadmap.md) · [development standards](docs/development.md) |
| Runtime | [review-run runtime](docs/review-run-runtime.md) · [daemon API](docs/daemon-api.md) · [remote workers](docs/remote-workers.md) · [task notifications](docs/task-notifications.md) · [automatic finalization](docs/automatic-finalization.md) · [handler catalogs](docs/runtime-handler-catalogs.md) |
| Review pipeline | [source acquisition](docs/source-acquisition-handler.md) · [change model](docs/change-model-handler.md) · [evidence](docs/deterministic-evidence-handler.md) · [semantic impact](docs/semantic-impact.md) · [memory retrieval](docs/memory-retrieval-handler.md) · [context assembly](docs/context-assembly-handler.md) · [candidate generation](docs/model-generation-handler.md) · [verification](docs/model-verification-handler.md) · [OpenAI provider](docs/openai-provider.md) · [publication readiness](docs/publication-readiness-handler.md) · [publication](docs/publication-handler.md) |
| Provider profiles | [OpenRouter ZDR](docs/openrouter-zdr-profile.md) · [OpenCode Go](docs/opencode-go-profile.md) · [OpenCode Console](docs/opencode-console-profile.md) · [Codex ChatGPT session status](docs/codex-chatgpt-session.md) · [local inference without bearer authentication](docs/local-provider-no-auth.md) |
| Getting started | [`trestle init`](docs/getting-started.md) · [`trestle review`](docs/getting-started.md#running-it-again) · [API keys](docs/keys.md) · [spending limits](docs/spending-limits.md) · [local-first bootstrap](docs/local-first-bootstrap.md) · [remote model review](docs/remote-model-review.md) · [setup](docs/setup.md) · [named local runtimes](docs/named-local-runtimes.md) · [model catalog](docs/model-catalog.md) |
| Local Git | [inspect](docs/local-git-inspect.md) · [change evidence](docs/local-git-change.md) · [review](docs/local-git-review.md) · [model review](docs/local-model-review.md) · [feedback](docs/local-feedback.md) |
| Specialist profiles | [agent profiles](docs/agent-profiles.md) |
| Security | [prompt-injection boundary](docs/prompt-injection-boundary.md) |
| Storage | [PostgreSQL ledgers](docs/postgresql-storage.md) · [encrypted object storage](docs/remote-artifact-storage.md) · [runtime artifacts](docs/runtime-artifacts.md) |
| Transports | [MCP](docs/mcp.md) · [ACP](docs/acp.md) · [LSP](docs/lsp.md) · [TUI](docs/tui.md) · [web console](docs/web-console.md) · [VS Code](docs/vscode.md) · [protocol contracts](docs/protocol-contracts.md) |
| Operations | [setup](docs/setup.md) · [operations and recovery](docs/operations.md) · [configuration validation](docs/configuration-validation.md) · [quality evaluation](docs/quality-evaluation.md) · [model result evaluation](docs/model-result-evaluation.md) · [passive vulnerability gate](docs/vulnerability-gate.md) |
| GitHub | [pull-request review (Actions and App)](docs/github-pr-review.md) · [source acquisition](docs/github-source-acquisition.md) · [integration permissions](docs/github-integration-permissions.md) · [webhook ingress](docs/webhook-ingress.md) · [publication](docs/github-publication.md) |

## Project scope

The implementation order is deliberately conservative:

1. local and GitHub review intake with immutable evidence;
2. deterministic repository profiling and policy-approved static adapters;
3. provider gateway and independent finding verification;
4. CLI, TUI, API, CI, IDE, and agent-protocol transports;
5. separately governed sandbox and dynamic-validation capabilities.

The tree includes deterministic SBOM generation and a bounded passive dependency
vulnerability gate. Signing, provenance, comprehensive vulnerability reporting, and
broader published evaluation evidence remain planned. The [roadmap](docs/roadmap.md)
separates planned work from shipped capability. Nothing counts as released until its
release evidence exists.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md),
[SECURITY.md](SECURITY.md), and [GOVERNANCE.md](GOVERNANCE.md) before opening a
contribution. Keep internal planning notes and private research out of the tree.

## License

[Apache License 2.0](LICENSE) · attribution in [NOTICE](NOTICE)

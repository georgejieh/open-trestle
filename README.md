# Open Trestle

<p align="center">
  <strong>An evidence-first code-review runtime you can host yourself.</strong><br>
  Every finding traceable to immutable source. Every model choice governed by policy.<br>
  Every claim backed by receipts — or not made at all.
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
> **Open Trestle is under active construction and is not yet runnable end to end.**
> This tree is an unreleased development candidate: the review engine, transports, and
> storage layers are implemented and tested, but the runtime does not yet launch as a
> finished product. No version is supported for production use, and capability
> descriptions below describe the candidate, not a release. Anything you read here is
> contingent on the [release gates](docs/roadmap.md) still being open.

**What is real today:** 55 Go packages with a full test suite, deterministic JSON and
SARIF review output, loose and packed Git inspection, a protected setup planner, a
durable run journal, an embedded read-only web console, and read-only MCP, ACP, and LSP
surfaces — all covered by `go test ./...` and a reproducible-release CI gate.

**What is not:** a one-command install, stable APIs, or any public claim about review
quality. Those require evaluation evidence that has not been published yet.

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
  are first-class targets, not afterthoughts.

## Architecture

One review engine, many entrypoints. A canonical request flows through immutable
snapshot capture, deterministic repository evidence, policy-approved analyzers,
bounded candidate generation, independent verification, and an idempotent
publication gate.

```
                    ┌─────────────────────────────────────────┐
                    │              entrypoints                │
                    │  CLI · TUI · CI · IDE · MCP · ACP · web │
                    └────────────────────┬────────────────────┘
                                         │
                    ┌────────────────────▼────────────────────┐
                    │        trestled — review daemon         │
                    │   durable runs · task journal · auth    │
                    └────────────────────┬────────────────────┘
             ┌───────────────┬───────────┼────────────┬──────────────┐
             ▼               ▼           ▼            ▼              ▼
        snapshot         evidence     policy      candidate      independent
        capture          pipeline    analyzers   generation      verification
             │               │           │            │              │
             └───────────────┴─────┬─────┴────────────┴──────────────┘
                                   ▼
                      idempotent publication gate
```

| Interface | Purpose |
|---|---|
| `trestled` | Local or server review daemon |
| `trestle` | CLI and terminal user interface |
| `trestle ci` | Headless review for CI pipelines |
| `trestle lsp` | Read-only editor diagnostics |
| `trestle mcp` | Scoped Model Context Protocol server |
| `trestle acp` | Agent Client Protocol endpoint |
| VS Code extension | Packaged read-only verified diagnostics over the LSP boundary |
| Web console | Read-only run, diagnostic, and runtime inspection |
| Forge adapters | Verified webhook intake; governed publication behind an explicit effect gate |

## Quick start

The runtime is not packaged yet, so "quick start" currently means building from
source and driving the pieces that exist. From the repository root:

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

The fixture and `local-git` commands are local-only: no model calls, no repository
content execution, no source mutation, no publication. For model-backed local review
see [local model review](docs/local-model-review.md) — it requires protected route
configuration, an explicit egress choice, and a finite timeout.

## Documentation

| Area | Reference |
|---|---|
| Architecture and roadmap | [architecture](docs/architecture.md) · [roadmap](docs/roadmap.md) |
| Runtime | [review-run runtime](docs/review-run-runtime.md) · [daemon API](docs/daemon-api.md) · [remote workers](docs/remote-workers.md) · [task notifications](docs/task-notifications.md) |
| Review pipeline | [source acquisition](docs/source-acquisition-handler.md) · [change model](docs/change-model-handler.md) · [evidence](docs/deterministic-evidence-handler.md) · [context assembly](docs/context-assembly-handler.md) · [candidate generation](docs/model-generation-handler.md) · [verification](docs/model-verification-handler.md) · [publication](docs/publication-handler.md) |
| Local Git | [inspect](docs/local-git-inspect.md) · [change evidence](docs/local-git-change.md) · [review](docs/local-git-review.md) · [model review](docs/local-model-review.md) |
| Storage | [PostgreSQL ledgers](docs/postgresql-storage.md) · [encrypted object storage](docs/remote-artifact-storage.md) · [runtime artifacts](docs/runtime-artifacts.md) |
| Transports | [MCP](docs/mcp.md) · [ACP](docs/acp.md) · [LSP](docs/lsp.md) · [TUI](docs/tui.md) · [web console](docs/web-console.md) · [VS Code](docs/vscode.md) · [protocol contracts](docs/protocol-contracts.md) |
| Operations | [setup](docs/setup.md) · [operations and recovery](docs/operations.md) · [configuration validation](docs/configuration-validation.md) · [quality evaluation](docs/quality-evaluation.md) |
| GitHub | [source acquisition](docs/github-source-acquisition.md) · [integration permissions](docs/github-integration-permissions.md) · [webhook ingress](docs/webhook-ingress.md) · [publication](docs/github-publication.md) |

## Project scope

The implementation order is deliberately conservative:

1. local and GitHub review intake with immutable evidence;
2. deterministic repository profiling and policy-approved static adapters;
3. provider gateway and independent finding verification;
4. CLI, TUI, API, CI, IDE, and agent-harness transports;
5. separately governed sandbox and dynamic-validation capabilities.

Signing, SBOM, provenance, vulnerability reporting, and published evaluation
evidence are still ahead of the tree. The [roadmap](docs/roadmap.md) separates
planned work from shipped capability — nothing counts as released until its release
evidence exists.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md),
[SECURITY.md](SECURITY.md), and [GOVERNANCE.md](GOVERNANCE.md) before opening a
contribution. Keep internal planning notes and private research out of the tree.

## License

[Apache License 2.0](LICENSE) · attribution in [NOTICE](NOTICE)

# Open Trestle

Open Trestle is an open-source, self-hostable code-review runtime for teams that want ownership of review data, policies, evidence, and model routing.

> **Project status: experimental local review foundation.** This repository ships a narrow local fixture-review path for development and conformance testing. It does not yet ship the planned daemon, hosted integrations, or a production-ready review service.

## Why Open Trestle

AI review is useful only when its conclusions can be inspected and controlled. Open Trestle is designed around:

- **Evidence first:** published findings must resolve to immutable source, policy, tool, and verification evidence.
- **Operator ownership:** local-only, controlled-hybrid, and air-gapped deployments remain first-class targets.
- **Provider neutrality:** model providers are selected through a policy-governed gateway, not embedded into review logic.
- **One engine, many entrypoints:** the same review runtime serves local Git, TUI, CI, IDE, source-control, API, MCP, ACP, and LSP workflows.
- **Safe execution:** repository text, CI configuration, logs, model output, and retrieved content are data, never authority to run commands or widen permissions.

## Intended interfaces

| Interface | Purpose |
|---|---|
| `trestled` | Local or server review daemon |
| `trestle` | CLI and terminal user interface |
| `trestle ci` | Headless review for CI pipelines |
| `trestle lsp` | Editor diagnostics and code actions |
| `trestle mcp` | Scoped Model Context Protocol server |
| `trestle acp` | Agent Client Protocol endpoint |
| Forge adapters | GitHub, GitLab, Bitbucket, and Azure DevOps integration |

The daemon, TUI, protocol, and forge interfaces remain design targets. The current `trestle` command validates and reviews local versioned fixtures, emits deterministic JSON receipts for headless CI dry runs, inspects exact loose Git revisions, and builds compact evidence for an exact base/head pair.

## Available local commands

From the repository root:

```sh
go run ./cmd/trestle validate-fixture cmd/trestle/testdata/local-review/fixture.json
go run ./cmd/trestle review cmd/trestle/testdata/local-review/fixture.json
go run ./cmd/trestle ci --format=json cmd/trestle/testdata/local-review/fixture.json
go run ./cmd/trestle ci --format=sarif cmd/trestle/testdata/local-review/fixture.json
go run ./cmd/trestle local-git inspect \
  --objects-root PATH \
  --repository-authority AUTHORITY \
  --repository-namespace NAMESPACE \
  --repository-name NAME \
  --revision-algorithm sha1 \
  --revision-digest FULL_LOWERCASE_SHA1
go run ./cmd/trestle local-git change \
  --objects-root PATH \
  --repository-authority AUTHORITY \
  --repository-namespace NAMESPACE \
  --repository-name NAME \
  --revision-algorithm sha1 \
  --base-revision-digest FULL_LOWERCASE_BASE_SHA1 \
  --head-revision-digest FULL_LOWERCASE_HEAD_SHA1
go run ./cmd/trestle local-git review \
  --objects-root PATH \
  --repository-authority AUTHORITY \
  --repository-namespace NAMESPACE \
  --repository-name NAME \
  --revision-algorithm sha1 \
  --base-revision-digest FULL_LOWERCASE_BASE_SHA1 \
  --head-revision-digest FULL_LOWERCASE_HEAD_SHA1
```

The local Git commands support verified loose objects only. Repository fields are caller-supplied scope labels, not proof that the object directory belongs to that repository. See [Local Git inspection](docs/local-git-inspect.md), [Local Git change evidence](docs/local-git-change.md), and [Local Git debug-output review](docs/local-git-review.md).

These commands are local-only. They do not call a model, execute repository content, mutate source, or publish results.

Local fixtures use schema version 1 and exact lowercase JSON field names. The current static adapter accepts one source range. `snapshot.revision` must be the lowercase SHA-256 digest of the declared source file. CI JSON receipts use schema version 2 and return verified results in a `findings` array. SARIF output uses SARIF 2.1.0 and preserves the same finding and evidence identities.

## Product boundary

Open Trestle is not a model prompt attached to a pull request. A canonical review request flows through immutable snapshot capture, deterministic repository evidence, policy-approved analyzers, bounded candidate generation, independent verification, and an idempotent publication gate.

See [the public architecture](docs/architecture.md) and [the delivery roadmap](docs/roadmap.md).

## Current scope

The first implementation sequence is intentionally conservative:

1. local and GitHub review intake with immutable evidence;
2. deterministic repository profiling and policy-approved static adapters;
3. provider gateway and independent finding verification;
4. CLI, TUI, API, CI, IDE, and agent-harness transports;
5. separately governed sandbox and dynamic-validation capabilities.

No claim here means that a capability is already implemented. Release claims require the evidence described in [SECURITY.md](SECURITY.md) and [docs/roadmap.md](docs/roadmap.md).

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), [SECURITY.md](SECURITY.md), and [GOVERNANCE.md](GOVERNANCE.md) before opening a contribution.

## License

Open Trestle is licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for attribution information.

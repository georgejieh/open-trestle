# Open Trestle

Open Trestle is an open-source, self-hostable code-review runtime for teams that want ownership of review data, policies, evidence, and model routing.

> **Project status: pre-implementation architecture.** This repository does not yet ship a runnable review service. It publishes the product boundary, public architecture, contribution rules, and release requirements that implementation must satisfy.

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
| `orsd` | Local or server review daemon |
| `ors` | CLI and terminal user interface |
| `ors ci` | Headless review for CI pipelines |
| `ors lsp` | Editor diagnostics and code actions |
| `ors mcp` | Scoped Model Context Protocol server |
| `ors acp` | Agent Client Protocol endpoint |
| Forge adapters | GitHub, GitLab, Bitbucket, and Azure DevOps integration |

The interface names are design targets, not released commands.

## Product boundary

Open Trestle is not a model prompt attached to a pull request. A canonical review request flows through immutable snapshot capture, deterministic repository evidence, policy-approved analyzers, bounded candidate generation, independent verification, and an idempotent publication gate.

See [the public architecture](docs/architecture.md), [the delivery roadmap](docs/roadmap.md), and [the public/private boundary](docs/public-boundary.md).

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

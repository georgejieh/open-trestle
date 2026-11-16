# Documentation

Find a page by what you want to do. Open Trestle is an unreleased development
candidate; each page says what the code does today. See the
[roadmap](roadmap.md) for what is planned.

## Start

- [Install](install.md): the packaged Linux install, and what other systems can do today.
- [Getting started](getting-started.md): `trestle init` and your first review.
- [Updating](updates.md): `trestle update`.
- [Platforms](platforms.md): what works on Linux, macOS and Windows.

## Use

- [API keys](keys.md): save, list and remove provider keys.
- [Spending limits](spending-limits.md): per-key limits and `trestle usage`.
- [Review output and options](local-model-review.md): text, JSON, SARIF and Markdown results, ranking, the walkthrough and specialists.
- [Specialist profiles](agent-profiles.md): the nine packaged reviewers.
- [Remote model review](remote-model-review.md): OpenRouter, OpenCode Go and Ollama Cloud.
- [Local models](named-local-runtimes.md): Ollama, llama.cpp, vLLM, LM Studio and other servers on your machine.
- [Model catalog](model-catalog.md): how setup learns model facts.
- [Local feedback](local-feedback.md).

## Integrate

- [GitHub pull-request review](github-pr-review.md): the Actions example and the GitHub App path.
- [VS Code](vscode.md).
- [MCP](mcp.md), [ACP](acp.md) and [LSP](lsp.md).
- [Terminal UI](tui.md) and [web console](web-console.md).
- [Daemon API](daemon-api.md).

## Reference

- [Commands](commands.md): every `trestle` command and flag.
- [Exit codes](exit-codes.md): per command, and the `--exit-code-policy` table.
- [Failure details](failure-details.md): every `failure_detail` value with its meaning and hint.
- [Environment variables and files](environment-and-files.md): every `OPEN_TRESTLE_*` variable and every path.
- [Protocol contracts](protocol-contracts.md).
- [Prompt-injection boundary](prompt-injection-boundary.md).

## Help

- [Troubleshooting](troubleshooting.md): symptom, cause, fix.
- [Privacy](privacy.md): what leaves your machine, when and where.
- [Support](../SUPPORT.md) and [security reports](../SECURITY.md).

## Operate

For a team or shared deployment of the daemon.

- [Setup planning](setup.md) and [operations and recovery](operations.md).
- [Configuration validation](configuration-validation.md).
- [PostgreSQL ledgers](postgresql-storage.md) and [encrypted object storage](remote-artifact-storage.md).
- [Remote workers](remote-workers.md) and [webhook ingress](webhook-ingress.md).
- GitHub: [source acquisition](github-source-acquisition.md), [integration permissions](github-integration-permissions.md) and [publication](github-publication.md).
- [Passive vulnerability gate](vulnerability-gate.md).

## Contribute

- [Contributing](../CONTRIBUTING.md) and [development standards](development.md).
- [Architecture](architecture.md) and [roadmap](roadmap.md).
- [Quality evaluation](quality-evaluation.md) and [model result evaluation](model-result-evaluation.md).
- [Review-run runtime](review-run-runtime.md) and its handlers: [source acquisition](source-acquisition-handler.md), [change model](change-model-handler.md), [evidence](deterministic-evidence-handler.md), [semantic impact](semantic-impact.md), [memory retrieval](memory-retrieval-handler.md), [context assembly](context-assembly-handler.md), [candidate generation](model-generation-handler.md), [verification](model-verification-handler.md), [publication readiness](publication-readiness-handler.md) and [publication](publication-handler.md).

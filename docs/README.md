# Documentation

This index groups the documentation by what you want to do. Open Trestle has
no release yet, and each page describes what the code does today. The
[roadmap](roadmap.md) says what is built, what is next and what is out of scope.

## Start

- [Install](install.md): the packaged Linux install, the development build, and what other systems can do today.
- [Getting started](getting-started.md): `trestle init` and your first review.
- [Updating](updates.md): `trestle update`.
- [Platforms](platforms.md): what works on Linux, macOS and Windows.

## Use

- [API keys](keys.md): save, list and remove provider keys.
- [Spending limits](spending-limits.md): per-key limits and `trestle usage`.
- [Review output and options](local-model-review.md): text, JSON, SARIF and Markdown results, ranking, the walkthrough and specialists.
- [Specialist profiles](agent-profiles.md): the nine packaged reviewers.
- [Remote model review](remote-model-review.md): OpenRouter, OpenCode Go and Ollama Cloud, with [OpenRouter zero data retention](openrouter-zdr-profile.md), the [OpenCode Go profile](opencode-go-profile.md) and the [OpenAI Responses adapter](openai-provider.md).
- [Local models](named-local-runtimes.md): Ollama, llama.cpp, vLLM, LM Studio and other servers on your machine, including servers that need no API key.
- [Local-first bootstrap](local-first-bootstrap.md): `trestle setup bootstrap` for a review with models on your machine.
- [Model catalog](model-catalog.md): how setup learns model facts.
- [Repository index](repository-index.md): `trestle index`, the map and the context a review reads from it.
- [Repository checks](repository-checks.md): run the repository's own tests in a sandbox during a review.
- [Review feedback](local-feedback.md): record your own notes on a past review so that later reviews can use them.
- Static local Git commands: [inspect](local-git-inspect.md), [change](local-git-change.md) and [debug-output review](local-git-review.md).

## Integrate

- [GitHub pull-request review](github-pr-review.md): the Actions example and the GitHub App path.
- [VS Code](vscode.md): show the findings of a daemon run in the editor.
- [MCP](mcp.md), [ACP](acp.md) and [LSP](lsp.md).
- [Terminal UI](tui.md) and [web console](web-console.md).
- [Daemon API](daemon-api.md).

## Reference

- [Commands](commands.md): every `trestle` command and flag.
- [Exit codes](exit-codes.md): per command, and the `--exit-code-policy` table.
- [Failure details](failure-details.md): every `failure_detail` value with its meaning and hint.
- [Environment variables and files](environment-and-files.md): every `OPEN_TRESTLE_*` variable and every path.
- [Protocol contracts](protocol-contracts.md): the versioned record formats and their JSON Schemas.
- [Prompt-injection boundary](prompt-injection-boundary.md): how repository text is kept from acting as instructions to the models.

## Help

- [Troubleshooting](troubleshooting.md): what each message means and how to fix it.
- [Privacy](privacy.md): what leaves your machine, when and where.
- [Support](../SUPPORT.md) and [security reports](../SECURITY.md).

## Operate

These pages are for running the daemon.

- [Setup plan](setup.md) and [operations and recovery](operations.md).
- [Configuration validation](configuration-validation.md).
- [Remote workers](remote-workers.md) and [webhook ingress](webhook-ingress.md).
- GitHub: [source acquisition](github-source-acquisition.md).
- [Passive vulnerability gate](vulnerability-gate.md).

## Contribute

- [Contributing](../CONTRIBUTING.md) and [development standards](development.md).
- [Architecture](architecture.md), [design rationale](rationale.md) and [roadmap](roadmap.md).
- [Quality evaluation](quality-evaluation.md) and [model result evaluation](model-result-evaluation.md).
- [Review-run runtime](runtime.md): the task graph, journal, workers, notifications, finalization, handler catalogs, artifacts and the handlers.
- Analysis: [semantic impact](semantic-impact.md), per-file [syntax analysis](syntax-analysis.md) and [publication readiness](publication-readiness-handler.md).

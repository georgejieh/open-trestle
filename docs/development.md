# Development standards

## Language and module design

Open Trestle chooses languages by component rather than using one language across the product.

| Component | Preferred language | Reason |
|---|---|---|
| Model evaluation, retrieval experiments, analyzers, and workflow prototypes | Python | Strong ecosystem support and fast iteration for model-facing work |
| Trusted local CLI, snapshot acquisition, compact evidence receipts, and daemon core | Go | Portable distribution, predictable resource handling, and strong boundary enforcement |
| Web console, IDE extensions, VS Code, and browser views | TypeScript | Native ecosystem fit |
| CI wrapper and GitHub Action | TypeScript, Go, or a thin shell wrapper | Select according to distribution and integration requirements |
| Policies, gate plans, and provider-routing rules | Declarative schemas | Versioned, inspectable, language-neutral contracts |
| Harness integrations | Host-native plugin language | Integrate with the environment users already operate |

The trusted core is written in Go, which does not make Go the default for unrelated components. Choose the component language before implementation and keep cross-language boundaries versioned and explicit. Modules own one coherent responsibility and depend toward stable contracts. Transport adapters, forge adapters, provider adapters, policy evaluation, evidence storage, and publishing remain separate modules.

## Google-style conventions

Code follows Google Style for the language in use. Public functions, exported types, non-obvious packages, and externally visible behavior have concise documentation. Function declarations use explicit parameter and result types. Comments explain constraints or non-obvious context, not line-by-line mechanics. Avoid comments unless they explain a magic number or a decision that cannot be inferred from the code.

## Verification

Every change includes focused tests for its behavior and boundary conditions. Contract, integration, and negative tests cover authorization, tenant scope, idempotency, error states, and untrusted input where relevant. A change is not complete because it compiles alone.

## Building and testing

The root module declares Go 1.25.0 and a `toolchain go1.26.11` line, which CI pins with `GOTOOLCHAIN=go1.26.11`. Set `GOWORK=off` so a local workspace file cannot change the build. From the repository root:

```sh
GOWORK=off go build -o trestle ./cmd/trestle
GOWORK=off go build -o trestled ./cmd/trestled
GOWORK=off go test -p=1 -timeout=30m ./...
GOWORK=off go vet ./...
```

`go test -race -p=1 ./...` runs the race tests CI also runs. The documentation tests, including the protocol schema inventory in [protocol contracts](protocol-contracts.md), are in `internal/config`: `go test ./internal/config/`. The secret scanner is a separate module: run `go test ./...` and `go vet ./...` in `workers/secret-scanner` with `GOWORK=off`.

Release and packaging tools have Python tests: `python3 -m unittest discover -s tools -p "test_*.py"`.

The web console in `web/` and the VS Code extension in `extensions/vscode/` use the Node version in `.node-version` (26.12.1); the web package declares `node >=22`. Install and check the console with:

```sh
npm ci --prefix web
npm test --prefix web
npm run check --prefix web
npm run build --prefix web
npm run dist:check --prefix web
```

`web/dist/` is committed and embedded in `trestled`, so a change to the console sources must rebuild it; CI rebuilds it and fails when the committed copy differs. The same steps work for `extensions/vscode`, which also has an `npm run package` step.

## Commit discipline

Use one coherent change per commit. A commit should normally add or alter one file, one narrowly scoped behavior, or one public contract. Keep unrelated formatting, refactors, and generated output out of the commit. Commit messages use Conventional Commits and explain the observable intent.

## Dependencies

New dependencies require an explicit license, maintenance, security, and supply-chain review. Pin dependencies through the native package manager. Do not add a library only to replace a small standard-library capability.

The secret scanner is a deliberately separate module. The root runtime declares Go 1.25.0, is built with Go 1.26.11, and does not import Betterleaks. `workers/secret-scanner` also declares Go 1.25.0, uses Go 1.26.11, and pins Betterleaks v1.8.1 at commit `5eab48332cc48565864514e3bc6de89df091a7c4`, its embedded 417-rule config hash, RE2 engine, Linux amd64 pure-Go target, module sums, linked licenses, and build flags. CI must run root and worker module verification, tests, race tests, and vet separately with `GOWORK=off`. The pre-runtime launcher is the one narrow C exception. It is built as a static PIE with the pinned Zig 0.14.1 x86_64-linux-musl toolchain closure so Landlock is active before the Go runtime creates threads.

Do not treat a dependency update as a routine version bump. A change to Betterleaks, its default config, rule IDs, regexp engine, adapter behavior, Go patch release, architecture, CGO setting, launcher toolchain, sandbox, or build flags creates a new scanner profile. Diff the public API and scanner behavior, review the complete linked license set, regenerate the ruleset and binary identities, and rerun the public span fixtures plus the private coverage and performance qualification. The accepted v1.8.1 baseline is 11/14 expected occurrences, with bearer, AWS secret key, and AWS session token misses and one `generic-api-key` near miss at `[7,51)`. Any coverage or near-miss drift needs an explicit profile decision. This baseline does not claim comprehensive secret detection.

The web and VS Code package roots disable npm's automatic audit requests, funding notices, and update-notifier checks during install. This keeps locked dependency retrieval separate from advisory network requests. CI runs the separately authorized passive dependency gate after deterministic release staging. The gate scans both Go modules, the staged Go binaries, and full plus omit-development npm lockfile scopes. See [Passive vulnerability gate](vulnerability-gate.md) for the exact fail rules, fixed tool identity, local command, evidence format, and limits.

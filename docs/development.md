# Development standards

This page sets out the conventions for working on Open Trestle: which language each component uses, how to build and test, and how to handle commits and dependencies. Read it before your first change. [CONTRIBUTING.md](../CONTRIBUTING.md) covers the pull-request process.

## Language and module design

Open Trestle picks a language for each component instead of using one language across the product.

| Component | Preferred language | Reason |
|---|---|---|
| Model evaluation, retrieval experiments, analyzers, and workflow prototypes | Python | Strong ecosystem support and fast iteration for model-facing work |
| Trusted local CLI, snapshot acquisition, compact evidence receipts, and daemon core | Go | Portable distribution, predictable resource handling, and strong boundary enforcement |
| Web console, IDE extensions, VS Code, and browser views | TypeScript | Native ecosystem fit |
| CI wrapper and GitHub Action | TypeScript, Go, or a thin shell wrapper | Select according to distribution and integration requirements |
| Policies, gate plans, and provider-routing rules | Declarative schemas | Versioned, inspectable, language-neutral contracts |
| Harness integrations | Host-native plugin language | Integrate with the environment users already operate |

The trusted core is written in Go. That does not make Go the default for unrelated components. Choose the language of a component before you implement it, and keep the boundaries between languages versioned and explicit.

Each module owns one coherent responsibility and depends on stable contracts. Transport adapters, forge adapters, provider adapters, policy evaluation, evidence storage and publishing stay in separate modules.

## Google-style conventions

Code follows Google Style for the language in use. Public functions, exported types, non-obvious packages and externally visible behavior have concise documentation. Function declarations use explicit parameter and result types. Comments explain constraints or context that the code does not show, not what each line does. Avoid a comment unless it explains a magic number or a decision that cannot be inferred from the code.

## Verification

Every change includes focused tests for its behavior and its boundary conditions. Where relevant, contract, integration and negative tests cover authorization, tenant scope, idempotency, error states and untrusted input.

## Building and testing

The root module declares Go 1.25.0 and a `toolchain go1.26.11` line, which CI pins with `GOTOOLCHAIN=go1.26.11`. Set `GOWORK=off` so that a local workspace file cannot change the build. From the repository root:

```sh
GOWORK=off go build -o trestle ./cmd/trestle
GOWORK=off go build -o trestled ./cmd/trestled
GOWORK=off go test -p=1 -timeout=30m ./...
GOWORK=off go vet ./...
```

`go test -race -p=1 ./...` runs the race tests that CI also runs. The documentation tests are in `internal/config`, and you run them with `go test ./internal/config/`. They include the protocol schema inventory described in [protocol contracts](protocol-contracts.md). The secret scanner is a separate module. Run `go test ./...` and `go vet ./...` in `workers/secret-scanner` with `GOWORK=off`.

A plain `go build` pins no secret scan helper, so the program it makes refuses every review. To run a review from a working tree, build with `python3 tools/package_secret_scanner.py --development DIR` on Linux, macOS or Windows, then run `DIR/bin/trestle`. See [operations](operations.md#package-the-secret-scanner).

The release and packaging tools have Python tests: `python3 -m unittest discover -s tools -p "test_*.py"`.

The web console in `web/` and the VS Code extension in `extensions/vscode/` use the Node version in `.node-version` (26.12.1). The web package declares `node >=22`. Install and check the console with:

```sh
npm ci --prefix web
npm test --prefix web
npm run check --prefix web
npm run build --prefix web
npm run dist:check --prefix web
```

The syntax analyzer's WebAssembly modules in `internal/syntaxwasm/modules/` are committed, compressed, and embedded. `go test ./internal/syntaxwasm` checks them against their manifest. To rebuild them, or to add a query pack for another language, see [syntax analysis](syntax-analysis.md).

`web/dist/` is committed and embedded in `trestled`. If you change the console sources, rebuild it. CI rebuilds it and fails when the committed copy differs. The same steps work for `extensions/vscode`, which also has an `npm run package` step.

## Commit discipline

Make one coherent change per commit. A commit should normally add or change one file, one narrowly scoped behavior or one public contract. Keep unrelated formatting, refactors and generated output out of it. Write commit messages in the Conventional Commits format, and state the observable intent.

## Dependencies

A new dependency needs an explicit review of its license, maintenance, security and supply chain. Pin dependencies through the native package manager. Do not add a library only to replace a small standard-library capability.

The secret scanner is a separate module. The root runtime declares Go 1.25.0, is built with Go 1.26.11 and does not import Betterleaks. `workers/secret-scanner` also declares Go 1.25.0 and uses Go 1.26.11. It pins these things:

- Betterleaks v1.8.1 at commit `5eab48332cc48565864514e3bc6de89df091a7c4`;
- the embedded config hash of its 417 rules;
- the RE2 engine;
- the WebAssembly (wasip1) guest and the wazero runtime that executes it;
- the module sums, the linked licenses and the build flags.

CI must run module verification, tests, race tests and vet separately for the root module and the scanner module, with `GOWORK=off`.

Do not treat an update to this scanner as a routine version bump. A change to any of the following creates a new scanner profile: Betterleaks, its default config, the rule IDs, the regexp engine, the adapter behavior, the Go patch release, the WebAssembly runtime, the sandbox or the build flags. For such a change, take these steps:

1. Diff the public API and the scanner behavior.
2. Review the complete set of linked licenses.
3. Regenerate the ruleset and helper identities.
4. Rerun the public span fixtures and the private coverage and performance qualification.

The accepted v1.8.1 baseline is 11 of 14 expected occurrences, with one `generic-api-key` near miss at `[7,51)`. For what the scanner misses, see [privacy](privacy.md). Any drift in coverage or near misses needs a profile decision.

The web and VS Code package roots turn off npm's automatic audit requests, funding notices and update-notifier checks during install. After deterministic release staging, CI runs the separately authorized passive dependency gate. The gate scans both Go modules, the staged Go binaries, and the npm lockfiles in the full scope and in the scope that omits development dependencies. See [Passive vulnerability gate](vulnerability-gate.md) for the fail rules, the pinned tool, the local command, the report format and the limits.

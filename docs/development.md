# Development standards

## Language and module design

Open Trestle chooses languages by component rather than using one language across the product.

| Component | Preferred language | Reason |
|---|---|---|
| Model evaluation, retrieval experiments, analyzers, and workflow prototypes | Python | Strong ecosystem support and fast iteration for model-facing work |
| Trusted local CLI, snapshot acquisition, compact evidence receipts, and daemon core | Go or Rust, pending an explicit decision | Portable distribution, predictable resource handling, and strong boundary enforcement |
| Web console, IDE extensions, VS Code, and browser views | TypeScript | Native ecosystem fit |
| CI wrapper and GitHub Action | TypeScript, Go, or a thin shell wrapper | Select according to distribution and integration requirements |
| Policies, gate plans, and provider-routing rules | Declarative schemas | Versioned, inspectable, language-neutral contracts |
| Harness integrations | Host-native plugin language | Integrate with the environment users already operate |

The existing Go foundation does not make Go the default for unrelated components. Choose the component language before implementation and keep cross-language boundaries versioned and explicit. Modules own one coherent responsibility and depend toward stable contracts. Transport adapters, forge adapters, provider adapters, policy evaluation, evidence storage, and publishing remain separate modules.

## Google-style conventions

Code follows Google Style for the language in use. Public functions, exported types, non-obvious packages, and externally visible behavior have concise documentation. Function declarations use explicit parameter and result types. Comments explain constraints or non-obvious context, not line-by-line mechanics. Avoid comments unless they explain a magic number or a decision that cannot be inferred from the code.

## Verification

Every change includes focused tests for its behavior and boundary conditions. Contract, integration, and negative tests cover authorization, tenant scope, idempotency, error states, and untrusted input where relevant. A change is not complete because it compiles alone.

## Commit discipline

Use one coherent change per commit. A commit should normally add or alter one file, one narrowly scoped behavior, or one public contract. Keep unrelated formatting, refactors, and generated output out of the commit. Commit messages use Conventional Commits and explain the observable intent.

## Dependencies

New dependencies require an explicit license, maintenance, security, and supply-chain review. Pin dependencies through the native package manager. Do not add a library only to replace a small standard-library capability.

The secret scanner is a deliberately separate module. The root runtime remains on Go 1.24.0 and does not import Betterleaks. `workers/secret-scanner` uses Go 1.25.12 and pins Betterleaks v1.8.1 at commit `5eab48332cc48565864514e3bc6de89df091a7c4`, its embedded 417-rule config hash, RE2 engine, Linux amd64 pure-Go target, module sums, linked licenses, and build flags. CI must run root and worker module verification, tests, race tests, and vet separately with `GOWORK=off`. The pre-runtime launcher is the one narrow C exception. It is built as a static PIE with the pinned Zig 0.14.1 x86_64-linux-musl toolchain closure so Landlock is active before the Go runtime creates threads.

Do not treat a dependency update as a routine version bump. A change to Betterleaks, its default config, rule IDs, regexp engine, adapter behavior, Go patch release, architecture, CGO setting, launcher toolchain, sandbox, or build flags creates a new scanner profile. Diff the public API and scanner behavior, review the complete linked license set, regenerate the ruleset and binary identities, and rerun the public span fixtures plus the private coverage and performance qualification. The accepted v1.8.1 baseline is 11/14 expected occurrences, with bearer, AWS secret key, and AWS session token misses and one `generic-api-key` near miss at `[7,51)`. Any coverage or near-miss drift needs an explicit profile decision. This baseline does not claim comprehensive secret detection.

The web and VS Code package roots disable npm's automatic audit requests, funding notices, and update-notifier checks during install. This keeps locked dependency retrieval separate from advisory network requests. It does not establish vulnerability absence or offline installation. Run vulnerability reporting only through a separately authorized release gate.

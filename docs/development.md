# Development standards

## Language and module design

The initial implementation uses Go for control-plane services and TypeScript for the web and editor surfaces. Modules own one coherent responsibility and depend toward stable contracts. Transport adapters, forge adapters, provider adapters, policy evaluation, evidence storage, and publishing remain separate modules.

## Google-style conventions

Code follows Google Style for the language in use. Public functions, exported types, non-obvious packages, and externally visible behavior have concise documentation. Function declarations use explicit parameter and result types. Comments explain constraints or non-obvious context, not line-by-line mechanics. Avoid comments unless they explain a magic number or a decision that cannot be inferred from the code.

## Verification

Every change includes focused tests for its behavior and boundary conditions. Contract, integration, and negative tests cover authorization, tenant scope, idempotency, error states, and untrusted input where relevant. A change is not complete because it compiles alone.

## Commit discipline

Use one coherent change per commit. A commit should normally add or alter one file, one narrowly scoped behavior, or one public contract. Keep unrelated formatting, refactors, and generated output out of the commit. Commit messages use Conventional Commits and explain the observable intent.

## Dependencies

New dependencies require an explicit license, maintenance, security, and supply-chain review. Pin dependencies through the native package manager. Do not add a library only to replace a small standard-library capability.

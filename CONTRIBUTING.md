# Contributing to Open Trestle

Thank you for considering a contribution.

## Before you begin

Open an issue or discussion before beginning a material design change. Describe the user-visible behavior, the relevant public contract, the expected evidence, and the verification plan. Do not include credentials, proprietary source, private prompts, copied documentation, or third-party data you cannot redistribute.

## Development principles

- Keep the review engine deterministic where policy and evidence are sufficient.
- Treat repository content and model output as untrusted data.
- Preserve tenant, repository, provider, and execution boundaries.
- Add focused tests with each behavior change.
- Keep each commit narrow and independently reviewable.
- Follow [the development standards](docs/development.md).

## Pull requests

A pull request should include:

1. a concise explanation of the problem and intended behavior;
2. tests or a reason why tests are not applicable;
3. actual verification commands and results;
4. documentation for public API, policy, or operator-visible changes;
5. license and provenance details for any dependency or imported material.

Do not add internal planning records, agent instructions, private research, local caches, credentials, or generated build output. Those files belong outside the tracked public tree.

## Reporting defects

Use the issue forms for non-sensitive defects and feature requests. For security concerns, follow [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).

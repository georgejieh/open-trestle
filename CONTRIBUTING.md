# Contributing to Open Trestle

Thank you for considering a contribution. This page explains what to do before
you start, the principles the code follows, and what a pull request should
contain.

## Before you begin

Before you start a material design change, open an issue or a discussion. In it,
describe the behavior that users will see, the public contract that is involved,
and how you plan to verify the change. Do not include
credentials, proprietary source, confidential configuration, copied
documentation, or third-party data that you cannot redistribute.

## Development principles

- Use scripted checks wherever policy is enough.
- Treat repository content and model output as data.
- Preserve the boundaries between tenants, repositories, providers and
  execution.
- Add focused tests with each behavior change.
- Keep each commit narrow, so that it can be reviewed on its own.
- Follow [the development standards](docs/development.md).

## Pull requests

A pull request should include:

1. a short explanation of the problem and the intended behavior;
2. tests, or a reason why tests do not apply;
3. the verification commands that you ran, with their results;
4. documentation for any change to a public API, a policy, or behavior that
   operators see;
5. license and provenance details for any dependency or imported material.

Keep internal planning records, authoring briefs, private research, local
session state and credentials out of the public tree.

Do not add temporary build output. The maintained `web/dist/` and
`extensions/vscode/dist/` distributions are intentional exceptions. Changes to
them must pass the reproducibility and freshness checks in CI.

## Reporting defects

Use the issue forms for defects and feature requests that are not sensitive. For
security concerns, follow [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).

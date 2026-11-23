# Changelog

## Unreleased

- Add **Review Current Branch**, which runs `trestle review` and shows its SARIF findings in the Problems panel, with **Clear Findings** and **Set Up Repository**.
- Remove the daemon connection through `trestle lsp`, its settings, the API token and the bundled protocol packages. `openTrestle.executable` is the only setting.

## 0.1.0

- Add machine-scoped connection settings and SecretStorage token management.
- Start the read-only Open Trestle LSP client for one exact review scope.
- Add explicit connect, restart, and credential-removal commands.

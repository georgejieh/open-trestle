# Environment variables and files

This page lists every `OPEN_TRESTLE_*` variable that the programs read, and every
path that they write. Open Trestle never puts a key value in a command line, a
result, a log or a setup file. Variables marked secret hold a credential, so set
them from your shell or a secret manager, never in a file in the repository.

## For everyday use

| Variable | Secret | Read by | Meaning |
| --- | --- | --- | --- |
| `OPEN_TRESTLE_PROVIDER_<NAME>` | yes | `trestle review`, `init`, `keys`, `local-git model-review` | An API key for a remote provider. The name is a convention you choose, such as `OPEN_TRESTLE_PROVIDER_OPENROUTER`; the setup records which variable each route uses. The environment wins over a saved key. See [API keys](keys.md). |
| `OPEN_TRESTLE_UPDATE_CHECK` | no | the home screen and `trestle review` | `off`, `0`, `false` or `no` turns off the once-a-day update notice. See [updates](updates.md). |

Other variables that change behavior:

| Variable | Effect |
| --- | --- |
| `XDG_CONFIG_HOME` | Where the credential folder lives, when an absolute path. |
| `XDG_STATE_HOME` | Where the usage folder and the update-check cache live, when an absolute path. The setup folder does not follow it. |
| `XDG_DATA_HOME` | Where the local update folder lives, when an absolute path. |
| `HOME` | The base for the defaults below when an XDG variable is unset or not absolute. |
| `NO_COLOR`, `TERM=dumb` | No color, and no home screen without a terminal on both sides. `COLORTERM=truecolor` or `24bit` selects 24-bit color. |
| `HTTPS_PROXY` | Honored by the update check and the update download. |

## For the daemon and operators

| Variable | Secret | Read by | Meaning |
| --- | --- | --- | --- |
| `OPEN_TRESTLE_API_TOKEN` | yes | `trestled`, `trestle runs`, `trestle admin runtime status`, `trestle mcp`, `trestle lsp`, `trestle acp`, `trestle tui` | The operator bearer token of the daemon API (at least 32 bytes). Pass the observer token here for a read-only client. See [daemon API](daemon-api.md). |
| `OPEN_TRESTLE_OBSERVER_TOKEN` | yes | `trestled`, `setup check observer` | The separate, read-only observer token. |
| `OPEN_TRESTLE_API_URL` | no | `trestle runs`, `admin runtime status`, `mcp`, `lsp`, `acp`, `tui` | The daemon address. Default `http://127.0.0.1:8741`. `--server` overrides it. |
| `OPEN_TRESTLE_POSTGRES_URL` | yes | `trestled`, `setup check postgres`, `admin postgres` | The runtime-role PostgreSQL connection string. See [PostgreSQL storage](postgresql-storage.md). |
| `OPEN_TRESTLE_POSTGRES_MIGRATION_URL` | yes | `admin postgres migrate`, `trestled --apply-migrations` | The migration-role connection string. |
| `OPEN_TRESTLE_S3_ACCESS_KEY_ID`, `OPEN_TRESTLE_S3_SECRET_ACCESS_KEY`, `OPEN_TRESTLE_S3_SESSION_TOKEN` | yes | `trestled`, `setup check envelope` | Credentials for the object-storage bucket prefix. The session token is optional. See [remote artifact storage](remote-artifact-storage.md). |
| `OPEN_TRESTLE_AWS_ACCESS_KEY_ID`, `OPEN_TRESTLE_AWS_SECRET_ACCESS_KEY`, `OPEN_TRESTLE_AWS_SESSION_TOKEN` | yes | `trestled`, `setup check secret`, `setup check envelope` | Credentials for the KMS key. The session token is optional. |
| `OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET` | yes | `trestled`, `setup check webhook` | The GitHub webhook HMAC secret. See [webhook ingress](webhook-ingress.md). |
| `OPEN_TRESTLE_GITHUB_API_TOKEN` | yes | `trestled` | The legacy source-acquisition token. Unset selects anonymous acquisition. See [GitHub source acquisition](github-source-acquisition.md). |
| `OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG` | no | `trestled`, `setup web`, `setup check integration` | The path of the protected source-broker descriptor. |
| `OPEN_TRESTLE_GITHUB_SETUP_TOKEN` | yes | `setup check integration` | A short-lived GitHub App user access token for the permission check. |
| `OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY` | yes | the GitHub source broker | The pinned GitHub App private key, held on the host. See [integration permissions](github-integration-permissions.md). |
| `OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN` | yes | `trestled` | The static token used to publish one `COMMENT` review. See [GitHub publication](github-publication.md). |
| `OPEN_TRESTLE_SETUP_TOKEN` | yes | `trestle setup web` | The bearer token of the setup API. |

The GitHub Actions example also uses `OPEN_TRESTLE_REF` and
`OPEN_TRESTLE_REPOSITORY` as workflow-level values that choose which source
revision to build. No Open Trestle program reads them.

## Paths

`~` is your home folder. An XDG variable applies only when it is set to an
absolute path.

| Path | Holds | Mode |
| --- | --- | --- |
| `$XDG_CONFIG_HOME/open-trestle/credentials/`, default `~/.config/open-trestle/credentials/` | Saved API keys, one file per variable name. See [API keys](keys.md). | folder `0700`, files `0600`, owned by you |
| `~/.local/state/open-trestle/NAME-XXXXXXXX/` | The setup folder for one repository: the folder name plus the first eight hex characters of the SHA-256 of the checkout path. | `0700` |
| `$XDG_STATE_HOME/open-trestle/usage/`, default `~/.local/state/open-trestle/usage/` | The spending limits and the usage ledger. | folder `0700`, files `0600` |
| `$XDG_STATE_HOME/open-trestle/update-check.json`, default `~/.local/state/open-trestle/update-check.json` | The update notice's cache: when it last asked and the newest versions it saw. | `0600` |
| `$XDG_DATA_HOME/open-trestle/updates/`, default `~/.local/share/open-trestle/updates/` | A development build handed over for `trestle update`. | folder `0700`, files `0600` or stricter, regular files owned by you |
| `/usr/local/share/open-trestle/distribution/receipt.json` | The package receipt that marks the packaged install. | written by the package |

The setup folder holds:

| File | Meaning |
| --- | --- |
| `bootstrap.json` | The saved setup answers. |
| `routes.json`, `policy-template.json`, `policy.json` | The protected route inventory, the runtime policy template and the bound runtime policy. |
| `review-intent.json` | The saved review command. |
| `runs/setup/plan.json` and its `.lock`, `.receipts` and `.next` companions | The setup plan and its check receipts. |
| `last-review.json` | The time, status, finding count and two commits of the last review, for the home screen. |
| `NEXT-STEPS.txt` | The commands to run next. It never holds a key. |

The usage folder holds `limit-<64 hex>.json`, one per limited key and provider,
and `ledger-YYYY-MM.jsonl`, one per UTC month. None of these files holds a key,
source, prompt or reply.

Open Trestle refuses a path that is a symbolic link, that you do not own, or that
has broader permissions than listed, and it names the reason. See
[troubleshooting](troubleshooting.md#a-folder-is-refused-as-not-private).
The platforms where these checks work are in [platforms](platforms.md).

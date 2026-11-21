# Environment variables and files

This page lists the `OPEN_TRESTLE_*` variables that you can set, and the paths
that the programs write for you to use. The daemon's own storage under `--state-dir`
is described in [the daemon API](daemon-api.md#what-the-state-directory-may-contain). Open Trestle never puts a key value in a command line, a
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
| `USERPROFILE` | On Windows, the base for the scan cache when `XDG_CACHE_HOME` is unset or not absolute. |
| `TMPDIR` | The folder where `trestle update` makes its private working folder and where the check sandbox keeps its scratch and Go seed folders. |
| `NO_COLOR`, `TERM=dumb` | No color, and no home screen without a terminal on both sides. `COLORTERM=truecolor` or `24bit` selects 24-bit color. |
| `HTTPS_PROXY` | Honored by the update check and the update download. |

## For the daemon and operators

| Variable | Secret | Read by | Meaning |
| --- | --- | --- | --- |
| `OPEN_TRESTLE_API_TOKEN` | yes | `trestled`, `trestle runs`, `trestle admin runtime status`, `trestle mcp`, `trestle lsp`, `trestle acp`, `trestle tui` | The operator bearer token of the daemon API (at least 32 bytes). Pass the observer token here for a read-only client. See [daemon API](daemon-api.md). |
| `OPEN_TRESTLE_OBSERVER_TOKEN` | yes | `trestled`, `setup bootstrap check` | The separate, read-only observer token. |
| `OPEN_TRESTLE_API_URL` | no | `trestle runs`, `admin runtime status`, `mcp`, `lsp`, `acp`, `tui` | The daemon address. Default `http://127.0.0.1:8741`. `--server` overrides it. |
| `OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET` | yes | `trestled` | The GitHub webhook HMAC secret. See [webhook ingress](webhook-ingress.md). |
| `OPEN_TRESTLE_GITHUB_API_TOKEN` | yes | `trestled` | The legacy source-acquisition token. Unset selects anonymous acquisition. See [GitHub source acquisition](github-source-acquisition.md). |
| `OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG` | no | `trestled` | The path of the protected source-broker descriptor. |
| `OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY` | yes | the GitHub source broker | The pinned GitHub App private key, held on the host. See [GitHub source acquisition](github-source-acquisition.md). |

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
| `$XDG_CACHE_HOME/open-trestle/scan-cache/`, default `~/.cache/open-trestle/scan-cache/` (Windows: `%USERPROFILE%\.cache\open-trestle\scan-cache`) | The compiled secret scanner (about 110 MB). The first review fills it. Deleting the folder is safe; the next review fills it again. | `0700`, owned by you, every folder above it changeable only by you or root |
| `<folder of the trestle program>/../libexec/open-trestle/open-trestle-scan-helper` (`.exe` on Windows) | The secret scan helper. The Linux package installs it at `/usr/local/libexec/open-trestle/open-trestle-scan-helper`. | not writable, owned by you or root (Windows: you or a system account) |
| `$XDG_STATE_HOME/open-trestle/sandbox-grants`, default `~/.local/state/open-trestle/sandbox-grants` | On Windows, the folder grants made for the check sandbox. `trestle checks off` takes them back. See [repository checks](repository-checks.md#what-the-sandbox-allows). | |
| `/usr/local/share/open-trestle/distribution/receipt.json` | The package receipt that marks the packaged install. | written by the package |

On Windows the credential, setup, usage and scan-cache folders and files have an
access control list in place of these modes, which gives only your account and
the system's own accounts access. On macOS the scan cache must also carry no
access-list entry; if it has one, Open Trestle refuses it and tells you to
remove it with `chmod -N`. See
[platforms](platforms.md#protected-files-on-windows).

The setup folder holds:

| File | Meaning |
| --- | --- |
| `bootstrap.json` | The saved setup answers. |
| `routes.json`, `policy-template.json`, `policy.json` | The protected route inventory, the runtime policy template and the bound runtime policy. |
| `review-intent.json` | The saved review command. |
| `runs/setup/plan.json` and its `.lock`, `.receipts` and `.next` companions | The setup plan and its check receipts. |
| `last-review.json` | The time, status, finding count and two commits of the last review, for the home screen. |
| `checks.json` | Whether reviews may run the [repository checks](repository-checks.md), and when that was answered. |
| `NEXT-STEPS.txt` | The commands to run next. It never holds a key. |
| `index/` | The [repository index](repository-index.md): private segment and snapshot files and, on Linux, compiled grammar modules. |

The usage folder holds `limit-<64 hex>.json`, one per limited key and provider,
and `ledger-YYYY-MM.jsonl`, one per UTC month. None of these files holds a key,
source, prompt or reply.

Open Trestle refuses a path that is a symbolic link, that you do not own, or that
has broader permissions than listed, and it names the reason. See
[troubleshooting](troubleshooting.md#a-folder-is-refused-as-not-private).
The platforms where these checks work are in [platforms](platforms.md).

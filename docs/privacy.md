# Privacy

This page says what leaves your machine, when it leaves, and where it goes. It
covers the command-line paths that a person runs: `trestle init`,
`trestle review`, `trestle update` and `trestle keys`. A deployed daemon, the
GitHub webhook and publication make further requests. These are described in
[operations](operations.md) and in the GitHub pages linked from the
[docs index](README.md#operate).

## The short version

- Your source goes to a model only when you run a review, and only to the
  provider your setup names. `trestle init` asks before it runs the first one.
- With a model server on your machine, a review sends your source only to that
  server.
- Before a request to a remote provider, Open Trestle scans it for secrets in a
  sandboxed process. A request that fails the scan is not sent.
- Open Trestle has no telemetry and no analytics.
- The update check makes one unauthenticated request, at most once a day, and
  sends nothing about you or your repository.
- API keys go to their provider as a bearer credential and nowhere else.

## What a review sends

A review sends the model four things: the review instructions, the changed code
of the two commits you compare, context from the repository around the change,
and the commit messages of the compared range as the stated intent. The context
includes instruction files. A review sends no API key and no environment
variable value. Open Trestle reads commits from the repository's stored objects
and does not read uncommitted changes.

Where the source goes depends on the route that your setup saved:

| Route | Where the source goes |
| --- | --- |
| A model server on this machine (`local`) | `127.0.0.1` only. Proxies are disabled and the connection is confined to the numeric loopback address. |
| OpenRouter with zero data retention (the default when both models have such endpoints) | OpenRouter, with zero data retention required on every request. |
| OpenRouter without it (`--without-zdr`) | OpenRouter, with zero data retention not required by Open Trestle. The text output says so on every review: your OpenRouter account settings decide. |
| Ollama Cloud, OpenCode Go | The provider's endpoint, over HTTPS. |
| Ollama on this machine, signed in to Ollama Cloud (`ollama-signin`) | Your local Ollama relays the request to Ollama Cloud. It is a remote provider. |

What a provider keeps is set by its terms and your account, beyond the
zero-data-retention requirement that Open Trestle puts in an OpenRouter
request. Read your provider's terms.

The result, the setup folder and the usage ledger stay on your machine. The
ledger holds amounts, not a key, source, prompt or reply.

## Secret scanning

Every request to a remote route passes two sandboxed Betterleaks scans. The first
scans the request fields and redacts any finding. A second, fresh process must
then find nothing left. A binary without the packaged scanner refuses to send to
a remote route. The scanner is a pattern scanner: on the reviewed corpus it
found 11 of 14 expected occurrences, and it misses bearer credentials, AWS
secret keys and AWS session tokens. Do not rely on it to make a secret safe to
send. Details are in the
[operations guide](operations.md#secret-scanner-runtime-boundary) and the
[OpenAI provider boundary](openai-provider.md).

## Zero data retention

When both OpenRouter models have zero data retention (ZDR) endpoints, setup
turns it on unless you decline: Open Trestle sends the requirement on every
request and pins the endpoints that qualify. If you continue without it
(`--without-zdr`), the
result carries the limitation `openrouter_zero_data_retention_not_required`, and
the text output prints a line saying so. See
[the OpenRouter profile](openrouter-zdr-profile.md).

## Other network requests

| When | Request | What it sends |
| --- | --- | --- |
| `trestle init`, OpenRouter | One GET of OpenRouter's public model list and one of its zero-data-retention endpoint list | Nothing about you or the repository; no key. |
| `trestle init` and `trestle keys set`, OpenRouter | One GET `/api/v1/key` to check a new key | The key as a bearer credential. No source. It costs nothing. |
| `trestle init`, if you give an evidence page | One HTTPS GET of the public page you name, after you confirm | No key, cookie, repository content or query string. Only its SHA-256 is kept. |
| `trestle init`, Ollama | One GET `/api/tags` to your local Ollama, and with your agreement one fixed test message | Loopback only. |
| The home screen and `trestle review`, packaged install | One GET `https://api.github.com/repos/georgejieh/open-trestle/releases?per_page=20`, at most once a day, cached in the state folder | No credential or identifier, and a fixed `User-Agent: open-trestle-update`. GitHub sees your address. Turn it off with `OPEN_TRESTLE_UPDATE_CHECK=off`. |
| `trestle update` | The same release list, then the build you choose from GitHub's asset hosts | Nothing about you. |

The update check runs only on the packaged install, and it says nothing when it
cannot tell. See [updates](updates.md).

## What is not done

- A review runs no repository code, test or build script today. A planned feature
  that runs generated checks will ask for consent first; see the
  [roadmap](roadmap.md#generated-verification).
- Open Trestle treats repository text, including files that look like
  instructions, as data. See the
  [prompt-injection boundary](prompt-injection-boundary.md).
- Open Trestle does not show or log a key, or put one in a command line, a
  request body, a result or a setup file. See [API keys](keys.md#what-never-happens).

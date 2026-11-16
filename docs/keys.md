# API keys

A remote provider (OpenRouter, Ollama Cloud or OpenCode Go) needs an API key.
This page explains where Open Trestle looks for the key, how to save, list and
remove keys, and how it keeps them private.

Setups and policies name only the key's variable, such as
`OPEN_TRESTLE_PROVIDER_OPENROUTER`, and never the key itself. Open Trestle finds
the key for that variable in this order:

1. the environment variable, when it is set in the shell that runs the review;
2. the key saved in the credential store by `trestle init` or `trestle keys set`;
3. a key typed into the current `trestle init` run and kept for that session
   only.

Model reviews, the setup checks, `trestle usage`, `trestle review` and the home
screen all use this one order. The `trestled` daemon still reads keys from its
own environment only.

## Typing the key in `trestle init`

When the variable has no key yet and standard input is an interactive terminal,
the wizard asks for the key right after you choose the models:

```text
  API key: OPEN_TRESTLE_PROVIDER_OPENROUTER has no key in
  this shell or in ~/.config/open-trestle/credentials. Paste
  the key from your OpenRouter account. It stays hidden while
  you type, and Open Trestle never prints it, logs it or puts
  it in a model request. Press Enter on an empty line to skip.
  API key for OpenRouter (hidden):
  ✓ OpenRouter accepted the key (one GET /api/v1/key, which
    costs nothing and sends no source).
  Save this key for future reviews? (Y/n):
  It will be saved in ~/.config/open-trestle/credentials
  (owner-only, mode 0600) once the setup is saved.
```

The prompt behaves as follows.

- Hidden input: The terminal's echo is turned off while you type (termios on
  Linux and macOS, the console mode on Windows) and turned back on before
  anything else is printed, also when you press Ctrl-C or Ctrl-D. The prompt
  appears only once echo is off. If echo cannot be turned off, no key is read.
  Only Linux has been tested; the macOS and Windows code is untested (see
  [platforms](platforms.md)).
- No terminal, no question: With `--no-input`, or when standard input is a pipe
  or a file, the wizard never asks for a key. The setup check says how to add
  one, as before.
- The check: For OpenRouter, the wizard checks the key with one
  `GET https://openrouter.ai/api/v1/key`, the same free read that
  [spending limits](spending-limits.md#seeing-the-state) use. If OpenRouter
  refuses the key (HTTP 401 or 403), the wizard does not keep it, and you can
  paste it again or press Enter to skip. If the check cannot run (no network,
  or another status), the wizard keeps the key as typed, and the first review
  shows whether it works. Ollama Cloud and OpenCode Go have no call that checks
  a key for free, so the wizard does not check their keys and says so.
- Saving: Enter (yes) saves the key, but only once the setup itself is saved.
  If you decline a declaration or stop early, nothing is written. Answering `n`
  uses the key for this session only (the setup checks and the first review) and
  prints `read -rs NAME && export NAME`, which exports it without showing it.

If you run `trestle init` again in a configured repository and the setup's key
is missing, it asks in the same way and saves the key at once.

## `trestle keys`

```sh
trestle keys                                          # or: trestle keys list
trestle keys set OPEN_TRESTLE_PROVIDER_OPENROUTER     # type the key (hidden), check it, save it
trestle keys remove OPEN_TRESTLE_PROVIDER_OPENROUTER  # delete the saved key
```

`list` shows three groups of variables: every saved key, every
`OPEN_TRESTLE_PROVIDER_` variable set in this shell, and the variables that this
repository's setup names. For each one it says where the key comes from and, for
a key of 24 characters or more, shows its last four characters:

```text
API keys (the environment first, then the keys saved in ~/.config/open-trestle/credentials):
  OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD  from the environment; a saved key exists too, and the environment wins · ends in …9f2c
  OPEN_TRESTLE_PROVIDER_OPENROUTER    saved in ~/.config/open-trestle/credentials · ends in …a41e
Change one: trestle keys set NAME · delete a saved one: trestle keys remove NAME
```

`set` asks for the key with hidden input on a terminal, or reads one line from a
pipe (`pass show openrouter | trestle keys set OPEN_TRESTLE_PROVIDER_OPENROUTER`),
so the key is never an argument. It checks an OpenRouter key as the wizard does,
and it saves nothing when OpenRouter refuses the key (exit 4). A key is one line
of printable ASCII without spaces, at most 4096 bytes.

`remove` deletes only the saved file. A variable set in the shell keeps being
used.

The exit codes of `trestle keys` are:

- `0`: done.
- `1`: the credential folder cannot be used, hidden input is unavailable, or the
  key could not be saved.
- `2`: a usage error, or no key given.
- `4`: OpenRouter refused the key.

See [exit codes](exit-codes.md#keys-usage-and-the-home-screen).

From the [home screen](getting-started.md#running-it-again), "Change the API
key" runs `trestle keys set` for the setup's key variable.

## Where keys are stored

The credential store is `$XDG_CONFIG_HOME/open-trestle/credentials` when
`XDG_CONFIG_HOME` is an absolute path, and otherwise
`~/.config/open-trestle/credentials`.

- The folder is created with mode `0700`. Each key is one file named after its
  variable, with mode `0600`, and holds exactly the key's bytes.
- Open Trestle refuses to use a folder or file with broader permissions, another
  owner, or a parent folder that others can write to. It also refuses a symbolic
  link in place of either. `trestle keys` and the setup check say why.
- To replace a key, Open Trestle writes a new protected temporary file in the same
  folder and renames it, so a reader sees the old key or the new one, never part
  of either. To remove a key, it checks the file first and then syncs the folder.

### Threat model

A saved key is a plaintext file protected only by file permissions, like other
command-line credential files such as `~/.netrc`. The permissions keep the key
from other accounts on the machine. They do not protect it from programs that
run as your account, from the administrator, or from backups and disk images
that copy the folder. If that is not acceptable, keep exporting the key from your
own secret manager instead; the environment always wins over the store. An
operating system keyring is a possible later backend, but it is not used now. On
Windows, the store's ownership checks are not available, so saving is refused
and a typed key is used for the session only.

## What never happens

Open Trestle never shows the key, never writes it to scrollback, never passes it
as a command argument, and never writes it to the setup folder, `NEXT-STEPS.txt`,
the usage ledger, a review result, or any log. It sends the key to the provider
only as the `Authorization` bearer credential, and never in a model request body.

A test saves a canary key, runs a full review in JSON, text and SARIF output
through the production session, and checks that the key is absent from every
request body, the review's output, the setup folder and the usage ledger. The
secret scanner and the prompt-injection boundary are unchanged.

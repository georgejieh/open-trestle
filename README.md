# Open Trestle

Open Trestle is an open-source AI code-review harness for pull requests. Before
it judges a change, it builds an understanding of the whole codebase, works out
what the pull request changes and what depends on that code, and tests the
change. Then it reports the problems it found.

It works with the model providers you choose, including models running on your
own hardware, and it is built to run where your code already lives: in your
terminal, in a desktop app, in CI and in your editor.

Open Trestle is under active development and has no release yet. This README
describes how Open Trestle is designed to work, then what is built today.

## How a review works

Open Trestle pairs fixed, scripted steps with models that work under narrow,
carefully written instructions. The scripts do everything that code can decide
on its own, and the models handle the judgment that code cannot. A review of a
pull request goes through five stages.

1. Understand the codebase. Scripted analysis and an instructed model read
   the repository: how it is structured, the conventions it follows, and the
   tests and CI checks its maintainers already run. Those existing checks show
   what the maintainers care about.
2. Understand the change. Open Trestle works out what the pull request
   changes, which other code depends on the changed code, and how the change fits
   the rest of the codebase.
3. Decide how to test it. It chooses which of the checks that ship with Open
   Trestle, and which of the repository's own tests, to run. It also decides
   whether the pull request needs new tests written for it, and writes them.
4. Test the change and what depends on it. The tests run against the changed
   code and against the code that relies on it, so a change cannot quietly break
   something elsewhere. Code decides whether a test passes, not a model.
5. Review with models from different families. One model looks for problems
   and a second model checks each one. Open Trestle recommends that the second
   model come from a different model family. Only problems that survive this
   check are reported.

The [design rationale](docs/rationale.md) explains why the scripted steps come
first and why the second model should come from another family.

Each review opens with a short account of what was checked, followed by the
confirmed problems, most important first. Problems in code that the pull request
did not touch are listed separately and never block a merge on their own.

### Languages

Open Trestle reads source at the level of its syntax tree for Java, JavaScript,
TypeScript, Python, HTML, C, C++, C#, Swift, Go, Rust, PHP and Ruby. Only Go
also records where a variable, constant or function is used as a value.
Support for the languages used with game engines such as Godot, Unity and
Unreal Engine, and for the custom
languages that large companies build in-house, is planned.

### Privacy

With a model server on your own machine, a review sends your code only to that
server. Open Trestle scans each review request for secrets twice before
sending it, whether the server is local or remote; investigation requests are
not scanned and go only to a local server. It sends no telemetry. The
[privacy](docs/privacy.md) page lists what is sent, when, and to whom.

## Project status

What works today, on Linux and Windows (macOS is not supported; see [platforms](docs/platforms.md)):

- `trestle init` sets up a repository in one guided pass. It asks where the two
  models run, takes API keys through hidden input, and stores them in an
  owner-only credential file.
- `trestle review` reviews every change on your current branch against your
  default branch, which is the same set of changes a pull request shows. Running
  `trestle` on its own opens a home screen with your setup, recent spending and
  the last review.
- A review builds an index of the repository first (`trestle index` builds and
  queries it directly). The models see the definition around each changed hunk,
  the callers and other uses of changed code, the tests that reference it and a
  ranked map of the repository. `trestle profile` reads the repository's tests
  and CI configuration.
- Syntax analysis covers every language listed above.
- With your consent, a review runs the repository's own tests in a sandbox
  with no network, before any model call (`trestle checks on|off|status`). Both
  models receive the outcomes. See [repository checks](docs/repository-checks.md).
- The two-model review in stage 5 works. Results come as text in the terminal,
  or as JSON, SARIF or Markdown for other tools.
- The VS Code extension runs `trestle review` on the current branch and shows
  the findings in the Problems panel. See [VS Code](docs/vscode.md).
- Remote providers (OpenRouter, Ollama Cloud and OpenCode Go) and local model
  servers (Ollama, llama.cpp, vLLM, LM Studio and other OpenAI-compatible
  servers) are supported. Every request except an investigation request (local only) is scanned for
  secrets twice by the secret scan helper before it is sent. A development build with the helper runs on
  Linux and Windows; the packaged install is Linux amd64 only.
- You can set a spending limit for each API key. Open Trestle warns you as you
  approach it and stops sending requests when you reach it. Its totals are
  estimates, so your provider's own limits remain the real safeguard.

What is not built yet:

- Choosing which of the checks that ship with Open Trestle to run, and writing
  new tests for a change (stage 3). Only the repository's own tests run.
- Syntax analysis for the game-engine and in-house languages.
- A desktop app.
- The [GitHub Actions example](examples/github-actions/README.md) has been
  tested offline but has not yet run on GitHub.
- A signed release or download. You build Open Trestle from source. The first
  release is meant to install like any other application: you download an
  installer for your system, run the setup wizard and review your own
  repository.

The [roadmap](docs/roadmap.md) lists what is next.

## Getting started

You need Git, Go 1.26.11 and Python 3, on Linux or Windows. Build a
development build, which includes the secret scan helper:

```sh
python3 tools/package_secret_scanner.py --development DIR
```

Run `DIR/bin/trestle` by its path. A plain `go build` pins no helper and refuses
every review. On Linux amd64 you can build and install the packaged archive
instead. The [install](docs/install.md) guide walks through both options.

Then, inside the Git repository you want to review, with your changes committed
on a branch:

```sh
trestle init      # guided setup; asks for an API key if the provider needs one
trestle review    # review your branch against the default branch
trestle           # home screen with status and next steps
```

[Getting started](docs/getting-started.md) follows a first review from start to
finish, and the [command reference](docs/commands.md) lists every command and
flag.

## Documentation

The [documentation index](docs/README.md) groups every page by task. If a
review fails, [troubleshooting](docs/troubleshooting.md) explains each failure
message and what to do about it. The guide to
[how a review runs today](docs/local-model-review.md) covers the current review
in detail.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before
opening a pull request, and report security problems privately as described in
[SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE) · attribution in [NOTICE](NOTICE)

# Open Trestle

Open Trestle is an open-source AI code reviewer for pull requests. Before it
judges a change, it builds an understanding of the whole codebase, works out what
the pull request changes and what depends on that code, and tests the change.
Only then does it report problems, and every problem it reports comes with the
evidence behind it.

It works with the model providers you choose, including models running on your
own hardware, and it is built to run where your code already lives: in your
terminal, in CI and in your editor.

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
   model come from a different model family, because different families have
   different blind spots. The tests cover the blind spots that all models share.
   Only problems that survive this check are reported.

Each review opens with a short account of what was checked, followed by the
confirmed problems, most important first. Problems in code that the pull request
did not touch are listed separately and never block a merge on their own.

### Languages

The first release is meant to understand every major production language at the
level of its syntax tree: JavaScript, TypeScript, Python, Java, C, C++, C#,
Rust, Go, PHP, Swift, Ruby and HTML. Support for the languages used with game
engines such as Godot, Unity and Unreal Engine, and for the custom languages that
large companies build in-house, is planned after that.

### Privacy

Before any request leaves your machine, Open Trestle scans the source in it for
secrets in a sandboxed process. OpenRouter requests require zero data retention
by default, and Open Trestle sends no telemetry. The [privacy](docs/privacy.md)
page lists exactly what is sent, when, and to whom.

## Project status

What works today, on Linux:

- `trestle init` sets up a repository in one guided pass. It asks where the two
  models run, takes API keys through hidden input, and can store them in an
  owner-only credential file.
- `trestle review` reviews every change on your current branch against your
  default branch, which is the same set of changes a pull request shows. Running
  `trestle` on its own opens a home screen with your setup, recent spending and
  the last review.
- The model review in stage 5 works. The second model must differ from the first,
  but setup does not yet recommend a different model family. Results come as text
  in the terminal, or as JSON, SARIF or Markdown for other tools.
- Remote providers (OpenRouter, Ollama Cloud and OpenCode Go) and local model
  servers (Ollama, llama.cpp, vLLM, LM Studio and other OpenAI-compatible
  servers) are supported. Remote providers require the packaged Linux amd64
  install, because that is the only build that includes the secret scanner.
- You can set a spending limit for each API key. Open Trestle warns you as you
  approach it and stops sending requests when you reach it. Its totals are
  estimates, so your provider's own limits remain the real safeguard.

What is not built yet:

- Codebase understanding, stages 1 and 2, is only partly built. The models read
  any language, and they see the changed code with some of its surrounding
  context, but no repository-wide index or map exists yet, and only Go code gets
  syntax-level analysis of what a change touches.
- Testing, stages 3 and 4, is not built. Open Trestle does not run tests yet.
- macOS and Windows builds compile, but neither has been tested, and some
  features, including remote providers, are refused on both. See
  [platforms](docs/platforms.md).
- The [GitHub Actions example](examples/github-actions/README.md) has been
  tested offline but has not yet run on GitHub. The VS Code extension can show
  the results of a review but cannot start one.
- There is no signed release or download yet. You build Open Trestle from
  source.

The first release is meant to complete stages 1 to 4 for the languages above,
bring the same review to Linux, macOS and Windows, and finish the GitHub Actions
and VS Code integrations. Reviewing an entire codebase, rather than one pull
request, is planned after that. The [roadmap](docs/roadmap.md) has the details.

## Getting started

You need Linux, Git and Go 1.25 or newer. If your models run on your own
machine, a development build is enough:

```sh
go build -o trestle ./cmd/trestle
```

Put the resulting `trestle` binary on your `PATH`. To use a remote provider,
build and install the packaged Linux amd64 archive instead. The
[install](docs/install.md) guide walks through both options.

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

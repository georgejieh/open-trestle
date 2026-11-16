# Open Trestle

Open Trestle is an open-source code reviewer that uses language models to find
problems in a change and then checks each problem before reporting it. It works
with the model provider you choose, including models running on your own
hardware, and it is built to run where your code already lives: in your
terminal today, and in CI and your editor as those integrations mature.

The project is under active development. There is no release yet, and the
interfaces and file formats may still change. The [project status](#project-status)
section below describes what works now and what is still missing.

## How a review works

A review starts from a committed change. Before any model is involved, Open
Trestle computes facts about the change that do not depend on a model: the
changed and removed lines, which Go symbols the change touches, and counts of
newly added lint suppressions and workaround comments.

A first model, the finder, reads that evidence along with the surrounding code
and proposes possible problems. A second, different model, the verifier, then
checks each proposal against the source. Only the problems the verifier
confirms are reported, and each one points to the lines that support it.
Confirmed findings are deduplicated and ranked. Findings in code the change did
not touch are reported separately, so they never block a merge on their own.

Each result opens with a short walkthrough of what was checked, followed by the
findings. You can read it as text in the terminal or write it as JSON, SARIF or
Markdown for other tools. New setups also run a small set of specialist reviews
(security, tests and others) chosen from what the change contains. The
[local model review](docs/local-model-review.md) guide covers the details.

Source code is scanned for secrets in a sandboxed process before any request
leaves your machine. OpenRouter requests require zero data retention by
default. Open Trestle sends no telemetry. The [privacy](docs/privacy.md) page
lists exactly what is sent, when, and to whom.

## Project status

What works today, on Linux:

- `trestle init` sets up a repository in one guided pass. It asks where the two
  models run, takes API keys through hidden input, and can store them in an
  owner-only credential file.
- `trestle review` reviews the latest committed change with the saved setup,
  and `trestle` on its own opens a home screen with the setup, recent spending
  and the last review.
- Remote providers (OpenRouter, Ollama Cloud and OpenCode Go) and local model
  servers (Ollama, llama.cpp, vLLM, LM Studio and other OpenAI-compatible
  servers) are supported. Remote providers require the packaged Linux amd64
  install, because that is the only build that includes the secret scanner.
- You can set a spending limit for each API key. Open Trestle warns you as you
  approach the limit and stops sending requests when you reach it. Its totals
  are estimates, so your provider's own limits remain the real safeguard.

What is not done yet:

- There is no signed release or download. You build Open Trestle from source,
  as described in [install](docs/install.md).
- macOS and Windows builds compile, but neither has been tested, and some
  features, including remote providers, are refused on both. Support for both
  systems is planned for the first release. The [platforms](docs/platforms.md)
  page shows what each system can do now.
- The GitHub Actions workflow in
  [examples/github-actions](examples/github-actions/README.md) has been tested
  offline but has not yet run on GitHub. The VS Code extension can display the
  results of a review, but it cannot start one.
- Review quality has not been measured. The evaluation corpus of 23 synthetic
  cases is waiting for independent human labels, so there are no accuracy
  figures to report yet. See [quality evaluation](docs/quality-evaluation.md).

The first release is meant to complete four things: the same review on Linux,
macOS and Windows; review that draws on the whole codebase, including the
checks its maintainers already run; checks that the models write and Open
Trestle runs in a sandbox; and finished GitHub Actions and VS Code integrations.
The [roadmap](docs/roadmap.md) describes each of these and what comes after.

## Getting started

You need Linux, Git and Go 1.25 or newer. If your models run on your own
machine, a development build is enough:

```sh
go build -o trestle ./cmd/trestle
```

Put the resulting `trestle` binary on your `PATH`. To use a remote provider,
build and install the packaged Linux amd64 archive instead. The
[install](docs/install.md) guide walks through both options.

Then, inside the Git repository you want to review:

```sh
trestle init      # guided setup; asks for an API key if the provider needs one
trestle review    # review the latest committed change
trestle           # home screen with status and next steps
```

[Getting started](docs/getting-started.md) follows a first review from start to
finish, and the [command reference](docs/commands.md) lists every command and
flag.

## Documentation

The [documentation index](docs/README.md) groups every page by task. If a
review fails, [troubleshooting](docs/troubleshooting.md) explains each failure
message and what to do about it.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before
opening a pull request, and report security problems privately as described in
[SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE) · attribution in [NOTICE](NOTICE)

# Local Git debug-output review

`trestle local-git review` compares two commits that you name and checks the change for leftover debug output with the built-in `static-debug-output` rule. It prints the findings and a record of which files it was able to check.

The command runs no model and sends nothing anywhere. Like `local-git inspect` and `local-git change`, it reads loose objects only and does not support packed objects or alternates. To have models review your latest commit, run `trestle init` and then `trestle review` in the repository (see [getting started](getting-started.md#running-it-again) and [local model review](local-model-review.md#reviewing-the-latest-change-with-trestle-review)).

```text
trestle local-git review \
  --objects-root PATH \
  --repository-authority AUTHORITY \
  --repository-namespace SEGMENT[/SEGMENT...] \
  --repository-name NAME \
  --revision-algorithm sha1|sha256 \
  --base-revision-digest FULL_LOWERCASE_HEX \
  --head-revision-digest FULL_LOWERCASE_HEX \
  [--format json|sarif]
```

You must pass all seven repository and revision flags, each exactly once. You can add `--format json|sarif` in any position. The default is `json`, and passing `json` explicitly gives byte-identical output. `PATH` is the loose-object directory itself. The base and head revisions are the two commits you choose, in that order.

The command does not infer a merge base, resolve refs or `HEAD`, read the index or working tree, look for `.git`, run Git, use credentials, or use the network.

The repository authority, namespace and name are labels that you supply to describe the scope. The command does not check them against the repository.

## Review scope and limits

The command applies the `static-debug-output` rule only. The fixed local limits are:

- at most 64 changed entries;
- at most 1 MiB of authenticated head content per supported file;
- at most 64 MiB of authenticated head content in total;
- at most 1,024 findings.

The command checks the limits before it reads any objects. Every supported file in the change gets one of three coverage results: analyzed, unsupported language, or no added lines to check.

An added file counts as supported when its text is not empty, is valid UTF-8 and is within budget. The command compares it against an empty base and covers the whole file. It reports these cases as unsupported: empty additions, removed files, content that is invalid UTF-8 or contains NUL bytes, and entries whose diff is over budget.

## Output

When the review succeeds or is inconclusive, the command writes one `open-trestle/local-git-review-result` version 2 JSON object followed by one newline. Its schema is `schemas/review/local-git-review-result-v2.schema.json`. The object contains:

- the complete nested `open-trestle/local-git-change-result` record;
- the identities of the debug-output review execution and its result, each bound to its inputs;
- the fixed limits and the coverage of each file;
- finding IDs, titles, severities, repository-relative ranges and evidence IDs;
- evidence IDs, kinds, digests of the exact selected bytes, and repository-relative ranges.

The object does not include source content, excerpts, patches, the object-root path, repository label text, raw commit digests, environment data or credentials.

The command does print repository-relative paths, whole-file digests of the head content, and digests of the selected evidence bytes. These can be sensitive, because a digest lets someone test a guess about what a file contains. Decide where the output may be stored and sent.

The status is one of:

- `findings`: there is at least one finding and no unsupported delta entries.
- `inconclusive`: the review ran but the rule found nothing.
- `partial`: there are findings or coverage, together with unsupported delta entries.
- `no_change`: the base and head produced the same accepted manifest.
- `unsupported`: entries changed, but none produced a supported change.

## SARIF output

`--format sarif` renders the same review result as one deterministic SARIF 2.1.0 log with one run. It does not repeat the object reads or the review. Findings map to the `static-debug-output` rule, its severity levels, repository-relative artifact URIs, line regions, finding fingerprints, and the identity and digest properties of the evidence. A report without findings has an empty `results` array.

The run status is verified only when the result is `findings`. Reports with the `partial`, `inconclusive`, `no_change` or `unsupported` status stay inconclusive, with that status as the reason. The command uploads nothing.

## Exit codes

- `0`: the command wrote a findings record in full.
- `1`: a root, acquisition, graph, resource, review, encoding, close or output failure.
- `2`: a command grammar failure or an invalid canonical input.
- `3`: the command wrote an inconclusive, partial, no-change or unsupported record in full.

Operational and usage failures print no success JSON. The command buffers its output and writes it once, after the object root has closed, but a low-level write failure can still truncate it.

## What the command checks

The records state the identities and the behavior of the rule: the acquisition, change, entry, coverage, finding and evidence records. The command does not check repository origin, ref reachability, ancestry or the state of the working tree. It does not fix anything, and it keeps no source bytes after the synchronous review finishes.

## Durable local daemon mode

This mode is not in any release. It lets you submit the same two commits to a daemon that runs the deterministic pipeline and keeps the result. It extends the existing command and the existing `POST /api/v1/runs` endpoint, and adds no source-control adapter, provider route, publication effect or endpoint.

```text
trestle local-git review \
  --objects-root PATH \
  --repository-authority AUTHORITY \
  --repository-namespace SEGMENT[/SEGMENT...] \
  --repository-name NAME \
  --revision-algorithm sha1|sha256 \
  --base-revision-digest FULL_LOWERCASE_HEX \
  --head-revision-digest FULL_LOWERCASE_HEX \
  --tenant TENANT --repository REPOSITORY --run RUN \
  --server http://127.0.0.1:8741
```

Daemon mode requires an HTTP server at a canonical numeric loopback address. The command first reads and verifies both requested revisions in the local object root that you supply. It then sends only the scope, the repository labels, the full revisions and a request time in milliseconds. It does not send the object-root path, credentials, source content, route authority or publication authority. The daemon reads its own object root, which it was bound to at startup.

A successful submission prints the canonical run receipt. The receipt does not claim that the rule passed.

The local plan for the run has exactly four tasks: two source-acquisition tasks, one change task and one deterministic-analysis task. A succeeded run means that those handlers finished and the daemon wrote the durable state. The diagnostic check state reports the outcome separately, as `passed`, `failed`, `incomplete` or `not_applicable`. Version 6 diagnostic observations are rule matches.

To read the same stored result without running the source analysis again:

```text
trestle runs status --tenant TENANT --repository REPOSITORY --run RUN --server http://127.0.0.1:8741
trestle runs status --tenant TENANT --repository REPOSITORY --run RUN --server http://127.0.0.1:8741 --format json
trestle runs status --tenant TENANT --repository REPOSITORY --run RUN --server http://127.0.0.1:8741 --format sarif
```

The JSON result is the canonical stored diagnostic set. The SARIF output carries `trestleStatus: inconclusive`, the disposition of the deterministic check, the qualifier that a human should review it, the exact locations and all evidence references. It does not call an observation verified.

# Static-debug quality evaluation

This page describes the evaluation commands that Open Trestle uses to measure its own review quality. It is for maintainers and contributors who run or change them. It covers a fixed suite for the static-debug rule, a deterministic corpus, a set of model response fixtures, and a corpus for the model-backed reviewer. Apart from the static-debug suite, the corpora and fixtures stay pending until an independent human reviews them.

`trestle evaluate static-debug` runs a fixed local version 1 suite against the changed-range static-debug detector. It reads no repository and makes no network request or model call. It runs no dynamic command, changes no source, and publishes nothing.

The suite has eight cases that you can inspect, and they are compiled into the evaluator. They cover direct and aliased `fmt` imports, a multiline call, a call outside the selected range, a different literal, comment and string text, a dot import, and a shadowed `fmt` identifier. A match is an exact path, start and end range. Three ranges are expected, and five cases are negative.

On success the command writes one canonical `open-trestle/static-debug-evaluation-result` version 1 JSON record followed by a newline. The strict public schema is `schemas/evaluation/static-debug-evaluation-result-v1.schema.json`. The report contains only:

- the suite, evaluator and report identities;
- the rule key and version;
- the aggregate confusion counts;
- precision and recall as integer numerator and denominator pairs;
- the ID, status and counts of each case.

It contains no suite source.

The canonical public report is `evaluation/testdata/static-debug-report-v1.json`. Repository tests regenerate it through the evaluation package. CI runs the real CLI and compares its output byte for byte, so any drift in a metric, identity, field order, case or newline fails verification.

The current identity goldens are:

- suite: `f01adf2b13140ca6958d3d6f5fbce50e1bcf4503069e019e66ba68e24c515c84`;
- evaluator: `41df5d0d0878b75954482e7bcfa67bdacbefb00a22300c3b61e768ff5914cc48`;
- passing report: `87af89b956ad96762bdba67dd8be0d7f7f112cf758b7d985fc1d4f9e3bcc791e`.

The exit codes are:

- `0`: every expected exact range matched, and the command wrote the complete report.
- `1`: the evaluation or the output failed.
- `2`: invalid command usage.
- `3`: at least one expected range and observed range did not match, and the command wrote the complete failed report.

Precision is `true_positive / (true_positive + false_positive)`. Recall is `true_positive / (true_positive + false_negative)`. A zero denominator is written as `0/0` and is not a success.

The report covers one deterministic rule over eight built-in cases. It is not a measure of repository-wide quality or of model quality.


## Pending deterministic corpus candidate

`trestle evaluate deterministic-corpus-candidate` runs a separate corpus of six synthetic cases that is embedded in the binary. It exercises the `static_debug_output` finding rule and six structural analyzer targets through their production Go APIs. The fixture tree, the exact base and head bytes, the changed ranges, the target labels and the pending review record are under `evaluation/testdata/deterministic-corpus-v1/`.

No one has adjudicated the candidate. Its `adjudication.json` has `review_state: pending`, no reviewer identifier and no review date. The CLI report therefore sets `release_evidence_eligible` to false and `golden_status` to `prohibited_pending_human_review`. No golden report for the deterministic corpus is committed. Exit code `3` means that the complete candidate has one or more label or coverage mismatches. Exit code `4` means that the complete candidate matched the pending labels. Neither exit code means approval.

Each evaluation target has its own closed match key and score, and the report does not pool unlike target units into one quality number. For each target:

- `TP = |expected intersection observed|`;
- `FP = |observed - expected|`;
- `FN = |expected - observed|`;
- precision is `TP / (TP + FP)`;
- recall is `TP / (TP + FN)`.

A zero denominator is `0/0`. The report does not derive true negatives, accuracy, specificity, confidence or calibration. Coverage is `analyzed / (analyzed + abstained)`, and the abstention rate is `abstained / (analyzed + abstained)`. Unsupported and not-applicable units stay visible, but they do not enter those denominators. Expected positives in an abstained applicable unit remain false negatives.

The Linux-only Python wrapper `open_trestle_eval.performance` measures the performance of a CLI that you build once. It runs the CLI for at least one warm-up and ten measured processes, and it follows these rules:

- It waits for each process to exit with `os.waitid(WNOWAIT)`. It keeps the direct candidate unreaped until the report is validated and any group signalling has finished. It then reaps the candidate with `os.wait4`, which gives the CPU time and the peak RSS of that one process.
- Wall time uses `time.perf_counter_ns`. It ends after the wrapper has seen the exit and closed the capture, and before it validates the report and does the final reap.
- It checks that every run produced the same candidate output digest and identities.
- It resolves a bare command through `PATH` and follows executable symlinks to their target. It then uses that resolved absolute path for every process and every hash check. It hashes the path before sampling and checks it again after every successful measurement. If the executable changes or becomes unreadable, sampling stops. This detects persistent changes at that path, not a transient replacement or a retargeted symlink.
- A measurement failure keeps its original error. If capture setup or a measurement raises an exception, including an interruption or a rejected report, the wrapper sends SIGKILL to the process group that it owns. It then reaps the direct candidate and passes the error on. It does not join or reap descendants. A successful measurement sends no final group signal.

This assumes that nothing else reaps children and that SIGCHLD reaping is not automatic. A failure after the final reap does not trigger a group signal. The observation depends on the environment. It is not a golden, not a threshold and not release evidence.

A person other than the author of the fixtures must review every base and head diff, every changed range, every positive label, every negative or near-miss label, every expected coverage outcome, and every recorded mismatch, all against the exact corpus identity. Only a later, separate reviewed contract may record that decision. The pending candidate does not satisfy the quality release gate in the roadmap.


## Pending model response contract candidate

`trestle evaluate model-contract-candidate` runs twelve compiled synthetic response fixtures through the production candidate and verification parsers. Eight of them use candidate batch v1, the recorded-readback contract. They cover verified, rejected, inconclusive and empty responses, missing evidence, an out-of-range near miss and a missing verdict. The other four use candidate batch v2 against a version 8 generation context, which is the executable contract. They cover a verified response, an empty response, an unknown category, and a candidate located in a `repository_context` source, which the parser drops and counts. The report records the expected and observed structural outcomes, a corpus identity and a report identity. It contains no source text and no model response text.

The command makes no model call. Its fixtures are synthetic assertions about the contract, not adjudicated findings. `review_state` stays `pending`, `release_evidence_eligible` is false and `quality_measured` is false. Exit code `4` means that the command wrote the candidate report. The `passed` field says whether the structural outcomes matched. The report measures no precision, recall, token cost or model latency.


## Importing declared human review of the deterministic labels

`trestle evaluate adjudication --adjudication PATH --adjudication-sha256 SHA256 --observed PATH` reads a review document that a human wrote, together with the exact deterministic candidate report that was captured earlier. The command makes no model, daemon or network call. It changes no source, label, pending adjudication, configuration or approval state. Each input is limited to 1 MiB, and a captured report may have one more byte for its final LF. The output is one score record followed by an LF. The command does not generate labels, select a reviewer or approve a threshold.

The closed input schema is `schemas/evaluation/evaluation-adjudication-v1.schema.json`. The human must supply:

- the exact corpus, label-set, evaluator and observed-report identities;
- the SHA-256 of the exact bytes of the observed file;
- a reviewer identifier that differs from the declared fixture author;
- the review date;
- a declaration that the review was source-first;
- a declaration of no prior exposure to results and no conflict;
- a confirmation row for every existing case and target.

The rows follow the corpus case order and, within a case, the target order. The ordered list of reviewed material names the base and head sources, the changed ranges, the positive labels, the negative and near-miss labels, the expected coverage and the recorded mismatches. The existing fixture and label bytes do not change. This first import contract does not support a review that is rejected, unresolved, incomplete or exposed, and scoring refuses it. Such a review needs a new corpus revision.

Take `--adjudication-sha256` from the handoff of the human review. It pins the exact bytes of the imported document. A matching hash and a different reviewer identifier do not authenticate a person or show that the review took place or was source-first. These declarations are asserted from outside, and the operator must check where they came from. A model must not supply the human review. A person who has not seen the results must review the source first, then look at the candidate output and reconcile the mismatches, and only then complete the document. Do not record a disclosed exposure as none.

The importer validates the observed report with the existing canonical parser, which recomputes the current output of the embedded corpus. It permits exactly one terminal LF as capture framing, and that byte is part of the observed SHA-256. The human's JSON may have leading, trailing or indentation whitespace, but its exact bytes must match the SHA-256 pin. The importer refuses changed observed metrics, unknown or duplicate fields, and nulls. The corpus identity binds the manifest, the descriptors of sources and labels, and the origin. The label-set identity binds the exact label digests. A complete set of case and target confirmations cannot replace an inspection of those source bytes.

The result schema is `schemas/evaluation/evaluation-adjudication-result-v1.schema.json`. `truth_identity` is the unchanged label-set identity, not newly generated truth. The hash of the imported document binds the reviewer, the date, the declarations about the material, the decisions on each unit and the observed subject. The scorer and report identities bind that input and the recomputed scores. The output keeps the confusion and coverage counts for each target and each case, including the known reference false positives. It does not print the reviewer identifier, claim text or source. `provenance_status` is `externally_asserted`, `acceptance_status` is `not_decided`, and `release_evidence_eligible` is always false. The command infers and evaluates no threshold.

The exit codes are 1 for an input, scoring or output failure; 2 for invalid usage; 3 for a complete imported score whose original result had a mismatch; and 4 for a complete imported score whose original result matched exactly. Neither 3 nor 4 approves quality. The existing evaluation commands keep their historical bytes, their pending status and their exit semantics.

This command only records a human confirmation of the existing deterministic labels. It does not import model candidates or the verified diagnostics of a run, and it does not measure model quality, cost or latency. It does not complete the quality release gate, which needs independent adjudication.


## Pending model-review corpus

`evaluation/testdata/model-corpus-v1/` is an evaluation set for the model-backed reviewer, `trestle local-git model-review`. Its 23 small Go cases are original synthetic material. No one has adjudicated its labels.

| Kind | Cases | What a correct review does |
|---|---|---|
| `defect` | 12 | Reports the defect the head adds: an off-by-one, a nil map write, an ignored error, a lock left held on an early return, a data race on a shared slice, a uint32 size overflow, a path traversal, string-built SQL, a non-constant-time token comparison, `%v` breaking `errors.Is`, an unclosed HTTP body, or slice aliasing through `append`. |
| `deletion_defect` | 3 | Reports a defect whose cause is a removal: a bounds check, an authorization check or a nil guard. The primary label is on the removed base lines, so these cases exercise base-side findings. |
| `near_miss` | 3 | Reports nothing. Each change looks wrong but is correct under the Go version its head `go.mod` declares: removed loop-variable copies under go 1.22, `time.After` in a loop under go 1.23, and a removed nil check before a nil-map read. |
| `clean` | 3 | Reports nothing for a rename, an extracted function or a test-only change. |
| `abstention` | 2 | Abstains. The verdict depends on an external module that is deliberately absent, so no verified finding is supported. |

Each case has exact `base/` and `head/` trees, and each tree has a `go.mod` whose `go` directive states the semantics that the case assumes. When the semantics matter, as in two of the near misses, the head raises the directive inside the diff. Every tree builds, vets and tests with the standard library and without a network, except the two abstention trees, which need a module that does not exist. Each case also has a `README.md` that states its kind, its Go semantics and what changed, and a `labels.json`.

The two near misses that depend on the Go version rest on documented language changes. The [Go 1.22 release notes](https://go.dev/doc/go1.22) state that each loop iteration creates new variables. The [Go 1.23 release notes](https://go.dev/doc/go1.23) state that unreferenced, unstopped `Timer`s and `Ticker`s become eligible for garbage collection, and that timer channels become unbuffered when the `go.mod` `go` line names Go 1.23 or later.

The labels follow the closed schema `schemas/evaluation/model-corpus-labels-v1.schema.json`. A label set names the case kind, the head Go version and its semantics, and the expected outcome: `findings`, `no_finding` or `abstention`. Each expected finding records:

- a path;
- a side (`head`, or `base` for removed lines);
- a line range and any further accepted locations;
- a category, with compatible alternatives;
- an informational severity hint;
- a one-sentence statement of the defect;
- a rationale.

A near miss or an abstention also records false-positive traps, which name the specific wrong finding and why it is wrong. Version 1 accepts only `review_state: pending`, a null `reviewer_identifier` and `review_date`, and the declared fixture author `open-trestle-maintainers`, so a version 1 label set is not adjudicated. `manifest.json` pins every file, README and label set by SHA-256 and derives the corpus identity from them. `adjudication.json` records the corpus review as pending.

To check the corpus, or to inspect one case as a bare Git repository, run these commands from the repository root:

```sh
PYTHONPATH=python/open_trestle_eval/src python3 -m open_trestle_eval.model_corpus verify
PYTHONPATH=python/open_trestle_eval/src python3 -m open_trestle_eval.model_corpus \
  materialize --case near_miss_time_after_go123 --output /owned/new/case.git
git --git-dir /owned/new/case.git log -p base..main
```

`materialize` writes loose SHA-1 objects with fixed, neutral commit metadata, so the base and head revisions are the same on every machine. `refs/heads/base` names the base commit and `refs/heads/main` names the head. After you edit a case, `manifest --write` recomputes the pins and the identity, and `manifest --check` fails while they are stale.

### Adjudication before any run

A person other than the fixture author must adjudicate every case before anyone reads the output of a run. Work source-first:

1. Materialize the case, then read the base and head trees and their diff without looking at `labels.json` or any model output. The case identifier and the README already name the kind of case, so judge the code, not the name.
2. Write down what a correct review should report: each defect with its path, side, lines and category; or that the change is correct; or that the evidence cannot decide it.
3. Compare that with `labels.json`. Confirm, revise or reject each expected finding, each accepted location, the category set, each trap and its reason, the reason for abstaining, and the stated Go semantics. Check version claims against the Go release notes, for example per-iteration loop variables in Go 1.22 and timer collection in Go 1.23, not against the label text.
4. Record one decision per case in a separate record that you write by hand, described in [Recording and pinning the adjudication](#recording-and-pinning-the-adjudication). A case is `confirmed` only when every element in step 3 is confirmed. Otherwise it is `revised`, when a corrected label would stand, or `rejected`, when the case cannot stand, and the record gives the reason. Put a revised label in a new corpus version instead of editing version 1, because every run bundle pins the version 1 label digests.
5. Only then compare the output of a run with the labels. Settle a disagreement by reading the source again, not by changing a label.

A model must not supply this review.

### Recording and pinning the adjudication

The reviewer writes the record by hand, following the closed schema `schemas/evaluation/model-corpus-human-adjudication-v1.schema.json`. No command generates, fills in or edits it. Keep it outside the corpus directory, because the corpus accepts no unlisted file and its `adjudication.json` stays pending. The record holds:

- `contract` `open-trestle/model-corpus-human-adjudication` and `schema_version` 1;
- `corpus_identity`, as `model_corpus verify` prints it, and `manifest_sha256`, the SHA-256 of the exact `manifest.json` bytes that the reviewer read;
- `reviewer_identifier`, the reviewer's own lowercase identifier, which must differ from `fixture_author_identifier`, always `open-trestle-maintainers` for version 1 labels;
- `review_date`, a calendar date written `YYYY-MM-DD`;
- `method` `independent_human_review`, `source_first` `true`, and `prior_run_output_exposure` `none_declared`, which declares that the reviewer saw no model run output for this corpus before completing the review;
- `cases`, one row per case in manifest order: its `case_id`, the `labels_sha256` that `manifest.json` lists for it, and its `decision`. A `confirmed` row holds nothing more. A `revised` or `rejected` row adds a `reason` of 1 to 1024 characters.

The contract has no value for exposure, for a review that was not source-first, or for a review by the fixture author.

The reviewer hands over the record together with the SHA-256 of its exact bytes, for example from `sha256sum`. The reviewer chooses the whitespace, but the pin covers it, so any later edit needs a new pin. To check the record without a bundle, run:

```sh
PYTHONPATH=python/open_trestle_eval/src python3 -m open_trestle_eval.model_adjudication \
  check --adjudication /owned/record.json --adjudication-sha256 "$RECORD_SHA256"
```

`check` prints the pin, the corpus identity, the number of confirmed and excluded cases, and each excluded case with its decision but not its reason. It writes nothing. It exits 0 when the record imports and 1 when it is refused. It refuses a record in any of these cases:

- the record does not match its pin, is over 1 MiB, is not a regular file, or is not strict JSON;
- the record has an unknown, missing, duplicate or null field;
- the record misses, repeats, reorders or adds a case;
- a label digest, the corpus identity or the manifest digest differs from the corpus;
- the record names the fixture author as the reviewer, or gives an impossible date;
- the record does not declare a source-first review without prior exposure to run output.

As with the deterministic labels, a matching pin and a distinct identifier do not authenticate a person. The operator must check where the record and its pin came from.

### Running the driver

`open_trestle_eval.model_runs` makes real model requests. Run it only with a `trestle` binary, routes, credentials and spend that you have approved separately. It writes each selected case as a throwaway repository and runs `trestle local-git model-review --format json` against it. By default it runs each case three times, going round-robin over the cases. The repository labels are `corpus.invalid`, `model-corpus-v1` and `case-NN`, and the commit messages are `base` and `head`, so the driver passes no case identifier to trestle. If you put `--repository-authority` and `--repository-namespace` before `--`, they change the first two labels. `--work-dir` sets the parent directory of the throwaway repositories, which the driver removes afterwards. Pass your existing setup flags after `--`:

```sh
PYTHONPATH=python/open_trestle_eval/src python3 -m open_trestle_eval.model_runs \
  --trestle /approved/trestle --output /owned/new-bundle \
  -- --tenant "$TENANT" --repository "$REPOSITORY_SCOPE" \
  --route-inventory /protected/routes.json --runtime-policy /protected/policy.json \
  --egress local-only --timeout 5m
```

The flags you pass are `--tenant`, `--repository`, `--route-inventory`, `--runtime-policy`, `--egress` and `--timeout`, with an optional `--profile`. The driver sets the source, revision and format flags itself, so it refuses them. It also refuses `--specialists`, `--max-specialists`, `--investigation-policy`, `--retained-memory-input` and `--exit-code-policy`. This corpus does not score the output of the first three, and the advisory memory behind the last two could know these cases. `--runs` (1 to 10) and repeated `--case ID` narrow the batch.

Before anything runs, the driver prints its plan:

- the path and SHA-256 of trestle;
- the number of invocations;
- what the egress mode allows;
- the zone, provider, model and content-logging fields of every route that the inventory declares;
- every `endpoint` that the runtime policy names;
- the changed files and the size of every case.

Without `--confirm-model-calls`, the driver stops after the plan with exit 2 and makes no call. With it, the driver prints the same plan and starts the runs. Exit 0 means that every planned run was recorded. Exit 1 means that the batch failed or was interrupted. Exit 2 means invalid usage or a missing confirmation. None of these codes says anything about the quality of a review.

The default batch is 23 cases by 3 runs, which is 69 invocations. Each invocation normally makes one candidate-generation request and one verification request, and a run that is refused before dispatch makes none. With `--egress local-only`, trestle accepts only local routes on numeric loopback endpoints. With `--egress policy-approved`, trestle selects sanitized, secret-scanned source from each case, and that source leaves the machine for the approved `private_remote` or `brokered_remote` routes, under those providers' terms. The corpus contains no private code. The driver itself opens no network connection. It reads the inventory and the policy only to print the summary, and it passes its environment to trestle so that the credential references in the policy resolve as they do in an ordinary review.

The output directory must be new. `bundle.json` follows `schemas/evaluation/model-corpus-run-bundle-v1.schema.json`, and the driver rewrites it after every run. It binds the corpus identity, the manifest digest, the label digests, the revisions, the trestle digest and the flags you passed. Each run has its exact stdout and stderr in new `0600` files under `runs/CASE/`. The bundle records their SHA-256, the exit status or signal, the wall-clock latency, and the status, `usage_known`, `actual_cost_micro_usd`, any `context_shortfall` and `token_usage` copied from the result.

`token_usage` is the input, output and cached-input tokens that the provider reported, summed by a version 6 result over the route attempts of the run, with its generation and verification shares (see [token usage](local-model-review.md#token-usage)). It is null when the result reports none or reports it in a malformed way. Its counts are absent, never zero, when the result says that they are not known.

If stdout goes beyond 256 KiB, if stderr goes beyond 64 KiB, or if a run lasts longer than the timeout plus 60 seconds, the driver signals the process group and records `output_limit` or `timed_out`. A changed trestle executable stops the batch. [`trestle evaluate model-result`](model-result-evaluation.md) accepts only deterministic corpus cases. The link between a capture and its source is therefore the driver's record of the revisions that it materialized, which anyone can reproduce with `materialize`.

### Scoring and what the numbers mean

```sh
PYTHONPATH=python/open_trestle_eval/src python3 -m open_trestle_eval.model_score \
  --bundle /owned/new-bundle --output /owned/new-score.json
```

The scorer refuses a bundle that does not bind this exact corpus, its label digests and its revisions, and a bundle whose stdout files do not match their pins. It reads the verified diagnostic set and the finding guidance of each result.

A verified finding matches an expected finding when it has the same path and side, its lines overlap the primary location or an accepted location, and its category is in the compatible set. A finding without a category, as in a version 1 result, matches on location alone and is counted in `category_unchecked_true_positive`. The assignment is one-to-one and maximal. A finding that matches nothing is a false positive. It is classed as `duplicate` (a second match for one expected finding), `near_miss` (at a labelled trap), `category_mismatch` (right place, incompatible category) or `other`. An expected finding with no match is a false negative.

A run with verified findings has the outcome `findings`. A run with none and at least one inconclusive verdict is an `abstention`, and any other completed run is `no_finding`. Refused, canceled, failed and unparseable runs are counted under `runs` and are left out of every rate. For each case and in aggregate, the report in `schemas/evaluation/model-corpus-score-v1.schema.json` gives:

- true positives, false positives with their classes, and false negatives;
- precision, `TP / (TP + FP)`, and recall, `TP / (TP + FN)`;
- the false-positive rate, which is the share of completed runs of `no_finding` cases with at least one false positive, and the same rate for near misses at their traps;
- abstention correctness, which is the share of runs on abstention cases that abstained, with the overclaimed and silent runs beside it;
- outcome agreement, and the mean, range and sample standard deviation across runs of latency, known cost, and known input, output and cached-input tokens.

Ratios are integer numerator and denominator pairs, and `0/0` is not a success. Without an imported adjudication, every number carries `label_status: labels_pending_human_review`, `release_evidence_eligible` is false and `golden_status` is `prohibited_pending_human_review`, as in the deterministic corpus tooling. A report that was written exits 4, never 0.

Without an imported adjudication, these numbers describe how far the results agree with pending labels from the fixture author on 23 synthetic cases. With three runs per case, a rate is a count, not an estimate with a confidence interval. A match is an agreement of location and category, so read the matched claims.

Latency is the end-to-end wall-clock time of one command on one machine, including start-up, source acquisition and both model requests. It is not inference latency. Cost is what the route reconciliation of the result reports, and it is unknown when `usage_known` is false. Tokens are the `token_usage` totals that the provider reported over the route attempts of the run. Open Trestle does not tokenize anything itself (`token_counts_provider_reported`). A completed run counts in the `unknown_count` of each token spread, never as zero, if its result says that its tokens are not known, or if its result is earlier than version 6 and reports none. Each run in the report carries the `token_usage` of its result.

The scorer reads the tokens from the pinned stdout, as it does the cost. It refuses a bundle whose recorded `token_usage` copy disagrees with that stdout. A version 6 result without `token_usage`, or an earlier result with it, is unreadable. The report evaluates no threshold and does not verify the sealed identities of the result again.

### Scoring with an imported adjudication

```sh
PYTHONPATH=python/open_trestle_eval/src python3 -m open_trestle_eval.model_score \
  --bundle /owned/new-bundle --adjudication /owned/record.json \
  --adjudication-sha256 "$RECORD_SHA256" --output /owned/new-adjudicated-score.json
```

You pass the two adjudication flags together. The scorer imports the record exactly as `check` does, and it refuses a record that does not bind this corpus, its manifest and the label digest of every case. It checks the bundle against the same digests, so a bundle whose digests differ from the record is refused and never scored. It then writes a report in `schemas/evaluation/model-corpus-adjudicated-score-v1.schema.json` in place of the pending one:

- Confirmed cases are matched and counted by the rules above, and every number carries `label_status: adjudicated_externally_asserted`. `provenance_status` is `externally_asserted`: these are labels that a declared human review confirmed, not verified truth.
- Revised and rejected cases are left out of every number. The scorer still checks their runs against their pins, and `excluded_cases` lists each case with its kind, label digest, decision, the reason from the record, and the number of its runs that were not scored.
- `release_evidence_eligible` is true only when the record confirms every case and a `complete` bundle ran every corpus case. Otherwise it is false, and `release_evidence_blockers` names each reason: `cases_excluded_by_review`, `bundle_omits_cases` or `bundle_not_complete`.
- `adjudication` gives the pinned SHA-256 of the record and its counts of cases, confirmed cases and excluded cases. The digest binds the reviewer identifier and the date, which the report does not repeat.
- `acceptance_status` is `not_decided`. The scorer sets and evaluates no threshold, and a written report still exits 4.

An eligible report is the input to the owner's threshold decision, not that decision. A revised case can be scored only after its corrected labels are published as a new corpus version and reviewed with a record of their own.

# Static-debug quality evaluation

`trestle evaluate static-debug` runs a fixed local version 1 suite against the maintained changed-range static-debug detector. It performs no repository read, network request, model call, dynamic command, source mutation, or publication.

The eight inspectable cases are compiled into the evaluator. They cover direct and aliased `fmt` imports, a multiline call, a call outside the selected range, a different literal, comment and string text, a dot import, and a shadowed `fmt` identifier. Exact path/start/end ranges are the match unit. Three ranges are expected and five cases are negative.

Success writes one canonical `open-trestle/static-debug-evaluation-result` version 1 JSON record followed by a newline. The strict public schema is `schemas/evaluation/static-debug-evaluation-result-v1.schema.json`. The report contains only suite, evaluator, and report identities; rule key/version; aggregate confusion counts; integer precision/recall numerator and denominator pairs; and per-case IDs, status, and counts. It contains no suite source.

The canonical public report is `evaluation/testdata/static-debug-report-v1.json`. Repository tests regenerate it through the evaluation package. CI invokes the real CLI and uses a byte-for-byte comparison, so metric, identity, field-order, case, or newline drift fails verification.

Current identity goldens are:

- suite: `f01adf2b13140ca6958d3d6f5fbce50e1bcf4503069e019e66ba68e24c515c84`;
- evaluator: `41df5d0d0878b75954482e7bcfa67bdacbefb00a22300c3b61e768ff5914cc48`;
- passing report: `87af89b956ad96762bdba67dd8be0d7f7f112cf758b7d985fc1d4f9e3bcc791e`.

Exit codes are:

- `0`: every expected exact range matched and the complete report was written;
- `1`: evaluation or output failed;
- `2`: invalid command usage;
- `3`: at least one expected/observed range mismatch, with the complete failed report written.

Precision is `true_positive / (true_positive + false_positive)`. Recall is `true_positive / (true_positive + false_negative)`. A zero denominator is represented as `0/0`, not as success.

This report evaluates one narrow deterministic rule over eight built-in cases. It does not establish repository-wide quality, calibration, model quality, human equivalence, security, latency, cost, or fitness for approval. Broader versioned evaluations remain required before external quality claims.


## Pending deterministic corpus candidate

`trestle evaluate deterministic-corpus-candidate` runs a separate embedded six-case synthetic corpus. It exercises the maintained `static_debug_output` finding rule and seven structural analyzer targets through their production Go APIs. The fixture tree, exact base and head bytes, changed ranges, target labels, and pending review record are under `evaluation/testdata/deterministic-corpus-v1/`.

The candidate is not adjudicated. Its `adjudication.json` has `review_state: pending`, no reviewer identifier, and no review date. The CLI report therefore sets `release_evidence_eligible` to false and `golden_status` to `prohibited_pending_human_review`. No deterministic-corpus golden report is committed. Exit code `3` means the complete candidate contains one or more label or coverage mismatches. Exit code `4` means the complete candidate matched the pending labels. Neither exit code means approval or release evidence.

Each evaluation target has its own closed match key and score. Unlike target units are not pooled into one quality number. For each target:

- `TP = |expected intersection observed|`;
- `FP = |observed - expected|`;
- `FN = |expected - observed|`;
- precision is `TP / (TP + FP)`;
- recall is `TP / (TP + FN)`.

A zero denominator is `0/0`. The report does not derive true negatives, accuracy, specificity, confidence, or calibration. Coverage is `analyzed / (analyzed + abstained)`. Abstention rate is `abstained / (analyzed + abstained)`. Unsupported and not-applicable units remain visible but do not enter those denominators. Expected positives in an abstained applicable unit remain false negatives.

The current pending labels intentionally distinguish two actual test references from same-name identifiers. The syntactic reference analyzer reports the same-name identifiers as additional candidates, so the candidate report preserves those mismatches rather than changing the labels to make the score clean.

The Linux-only Python wrapper `open_trestle_eval.performance` runs a once-built CLI with at least one warm-up and ten measured processes. It observes exit with `os.waitid(WNOWAIT)` and retains the direct candidate until report validation and any group signalling finish. It then reaps that candidate with `os.wait4` for CPU time and per-process peak RSS. Wall time uses `time.perf_counter_ns`, ending after exit observation and capture closure, before report validation and the final reap. This boundary differs from earlier observations that included an in-loop reap; do not compare those series as equivalent measurements. It verifies identical candidate output digests and identities for every run. It resolves a bare command through `PATH` and follows executable symlinks to their target, then uses the resolved absolute target path for every process and hash check. It hashes that path before sampling and checks it after every successful measurement. A changed or unreadable executable stops sampling. This detects persistent changes at that path, not transient replacement, symlink retargeting, interpreter dependencies, or hostile same-user modification. Measurement failures keep their original error. On capture setup or measurement exceptions, including interruption and report rejection, the wrapper sends SIGKILL to its owned process group before reaping the direct candidate and propagating the error. It does not join or reap descendants. Successful measurements do not send a final group signal. This assumes no external child reaper or automatic SIGCHLD reaping; it does not protect against a second interruption, OS cleanup failures, or processes that escape the owned group. Failures after the final reap do not trigger a group signal. Its observation is environment-specific, nondeterministic, not a golden, not a threshold, and not release evidence.

A person other than the fixture author must review every base/head diff, changed range, positive label, negative or near-miss label, expected coverage outcome, and recorded mismatch against the exact corpus identity. Only a later, separate reviewed contract may record that decision. The pending candidate does not satisfy the roadmap quality release gate.


## Pending model response contract candidate

`trestle evaluate model-contract-candidate` runs twelve compiled synthetic response fixtures through the production candidate and verification parsers. Eight use candidate batch v1, the recorded-readback contract: verified, rejected, inconclusive and empty responses, missing evidence, an out-of-range near miss and a missing verdict. Four use candidate batch v2 against a version 8 generation context, the executable contract: a verified and an empty response, an unknown category, and a candidate located in a `repository_context` source, which is dropped and counted. The report records expected and observed structural outcomes, an exact corpus identity and a report identity. It contains no source text or model response text.

This command makes no model call. Its fixtures are original synthetic contract assertions, not independently adjudicated findings. `review_state` remains `pending`, `release_evidence_eligible` is false and `quality_measured` is false. Exit code `4` means the candidate report was written, not approval. The `passed` field describes only whether the structural outcomes matched. Parser acceptance does not prove that a claim is correct. The report measures no precision, recall, route independence, token cost or model latency, and does not replace the required real-route qualification and adjudicated quality corpus.


## Importing declared human review of the deterministic labels

`trestle evaluate adjudication --adjudication PATH --adjudication-sha256 SHA256 --observed PATH` reads an explicit human-authored review document and the exact captured deterministic candidate report. It performs no model, daemon or network call and changes no source, label, pending adjudication, configuration or approval state. Each input is bounded at 1 MiB, with one additional byte allowed for a captured report's final LF. Output is one score record followed by LF. The command does not generate labels, select a reviewer, approve a threshold or accept a release.

The closed input schema is `schemas/evaluation/evaluation-adjudication-v1.schema.json`. The human must supply the exact corpus, label-set, evaluator and observed report identities, the SHA-256 of the observed file's exact bytes, a reviewer identifier distinct from the declared fixture author, review date, source-first declaration, no declared prior-result exposure or conflict, and a confirmation row for every existing case/target. Rows follow corpus case order and each case's target order. The ordered reviewed-material list names base/head sources, changed ranges, positive labels, negative and near-miss labels, expected coverage and recorded mismatches. Existing fixture and label bytes remain unchanged. A rejected, unresolved, incomplete or exposed review is not supported by this first import contract and refuses scoring; it needs a separate reviewed decision or corpus revision, not altered labels to fit output.

Obtain `--adjudication-sha256` from the independent human review handoff. It pins the exact imported document bytes. A matching hash and different reviewer identifier do not authenticate a person, establish independence, prove source-first ordering or prove that review occurred. These declarations are externally asserted. The operator must inspect their provenance. An AI or model must not supply the human review or impersonate an independent reviewer. An unexposed person must perform source-first review, then inspect candidate output and reconcile mismatches before completing the document. Disclosed exposure must not be relabeled as none to fit this contract.

The importer validates the observed report with the existing canonical parser, which recomputes current embedded-corpus output. Exactly one terminal LF is permitted as capture framing; its byte is included in the observed SHA-256. Human JSON may use leading, trailing or indentation whitespace; the exact document bytes must match the supplied SHA-256 pin. Changed observed metrics, unknown/duplicate fields and nulls refuse. The corpus identity binds the manifest, source and label descriptors and origin; the label-set identity binds the exact label digests. Complete case/target confirmation cannot substitute for inspection of those source bytes.

The result schema is `schemas/evaluation/evaluation-adjudication-result-v1.schema.json`. `truth_identity` is the unchanged label-set identity, not newly generated truth. The imported document hash binds reviewer, date, material declarations, unit decisions and observed subject; scorer/report identities bind that input and recomputed scores. Output preserves per-target and per-case confusion/coverage counts, including the known reference false positives. It emits no reviewer identifier, claim text or source. `provenance_status` is `externally_asserted`, `acceptance_status` is `not_decided`, and `release_evidence_eligible` is always false. No threshold is inferred or evaluated.

Exit codes are 1 for input, scoring or output failure; 2 for invalid usage; 3 for a complete imported score with the original mismatch; and 4 for a complete imported score with original exact match. Neither 3 nor 4 is quality approval. Existing evaluation commands keep their historical bytes, pending status and exit semantics.

This command only records externally declared human confirmation of existing deterministic labels. It does not import actual model candidates or verified run diagnostics, authenticate their production origin, measure model quality/cost/latency, qualify a deployment or complete the independently adjudicated quality release gate. No filled human record or imported score is shipped as release evidence.


## Pending model-review corpus

`evaluation/testdata/model-corpus-v1/` is an evaluation set for the model-backed reviewer, `trestle local-git model-review`. Its 23 small Go cases are original synthetic material. No model has been run against it in this repository, and its labels have not been adjudicated.

| Kind | Cases | What a correct review does |
|---|---|---|
| `defect` | 12 | Reports the defect the head adds: an off-by-one, a nil map write, an ignored error, a lock left held on an early return, a data race on a shared slice, a uint32 size overflow, a path traversal, string-built SQL, a non-constant-time token comparison, `%v` breaking `errors.Is`, an unclosed HTTP body, or slice aliasing through `append`. |
| `deletion_defect` | 3 | Reports a defect whose cause is a removal: a bounds check, an authorization check or a nil guard. The primary label is on the removed base lines, so these cases exercise base-side findings. |
| `near_miss` | 3 | Reports nothing. Each change looks wrong but is correct under the Go version its head `go.mod` declares: removed loop-variable copies under go 1.22, `time.After` in a loop under go 1.23, and a removed nil check before a nil-map read. |
| `clean` | 3 | Reports nothing for a rename, an extracted function or a test-only change. |
| `abstention` | 2 | Abstains. The verdict depends on an external module that is deliberately absent, so no verified finding is supported. |

Each case has exact `base/` and `head/` trees, each with a `go.mod` whose `go` directive states the semantics the case assumes. When the semantics matter, as in two near misses, the head raises the directive inside the diff. Every tree builds, vets and tests with the standard library and no network, except the two abstention trees, which require a module that does not exist. Each case also has a `README.md` stating its kind, Go semantics and what changed, and a `labels.json`.

Labels follow the closed schema `schemas/evaluation/model-corpus-labels-v1.schema.json`. A label set names the case kind, the head Go version and its semantics, and the expected outcome: `findings`, `no_finding` or `abstention`. Each expected finding records a path, a side (`head`, or `base` for removed lines), a line range, any further accepted locations, a category with compatible alternatives, an informational severity hint, a one-sentence defect statement and a rationale. A near miss or abstention also records false-positive traps: the specific wrong finding and why it is wrong. Version 1 admits only `review_state: pending`, a null `reviewer_identifier` and `review_date`, and the declared fixture author `open-trestle-maintainers`, so a version 1 label set is never adjudicated truth. `manifest.json` pins every file, README and label set by SHA-256 and derives the corpus identity from them. `adjudication.json` records the corpus review as pending.

Check the corpus, or inspect one case as a bare Git repository, from the repository root:

```sh
PYTHONPATH=python/open_trestle_eval/src python3 -m open_trestle_eval.model_corpus verify
PYTHONPATH=python/open_trestle_eval/src python3 -m open_trestle_eval.model_corpus \
  materialize --case near_miss_time_after_go123 --output /owned/new/case.git
git --git-dir /owned/new/case.git log -p base..main
```

`materialize` writes loose SHA-1 objects with fixed, neutral commit metadata, so the base and head revisions are the same on every machine. `refs/heads/base` names the base commit and `refs/heads/main` the head. After editing a case, `manifest --write` recomputes the pins and identity; `manifest --check` fails while they are stale.

### Adjudication before any run

A person other than the fixture author must adjudicate every case before its run output is read. Work source-first:

1. Materialize the case and read the base and head trees and their diff, without looking at `labels.json` or any model output. The case identifier and README already name the kind of case; judge the code, not the name.
2. Write down what a correct review should report: each defect with its path, side, lines and category; or that the change is correct; or that the evidence cannot decide it.
3. Compare that with `labels.json`. Confirm, revise or reject each expected finding, each accepted location, the category set, each trap and its reason, the abstention reason and the stated Go semantics. Check version claims against the Go release notes, for example per-iteration loop variables in Go 1.22 and timer collection in Go 1.23, rather than against the label text.
4. Record every decision with its reason, the reviewer, the date, the corpus identity and the label digest in a separate human-authored record. This candidate defines no import for that record, so scores stay `labels_pending_human_review`. Put a revised label in a new corpus version instead of editing version 1, because every run bundle pins the version 1 label digests.
5. Only then compare run output with the labels. Resolve a disagreement by rereading the source, never by changing a label to fit an observed result.

A model must not supply this review or stand in for the reviewer.

### Running the driver

`open_trestle_eval.model_runs` makes real model requests. Run it only with a separately approved `trestle` binary, routes, credentials and spend. It writes each selected case as a throwaway repository and runs `trestle local-git model-review --format json` against it, by default three times per case, round-robin over the cases. The repository labels are `corpus.invalid`, `model-corpus-v1` and `case-NN` and the commit messages are `base` and `head`, so the driver passes no case identifier to trestle. `--repository-authority` and `--repository-namespace` before `--` change the first two labels, and `--work-dir` sets the parent of the throwaway repositories, which are removed afterwards. Pass the operator's existing setup flags after `--`:

```sh
PYTHONPATH=python/open_trestle_eval/src python3 -m open_trestle_eval.model_runs \
  --trestle /approved/trestle --output /owned/new-bundle \
  -- --tenant "$TENANT" --repository "$REPOSITORY_SCOPE" \
  --route-inventory /protected/routes.json --runtime-policy /protected/policy.json \
  --egress local-only --timeout 5m
```

The operator flags are `--tenant`, `--repository`, `--route-inventory`, `--runtime-policy`, `--egress` and `--timeout`, with an optional `--profile`. The driver refuses the source, revision and format flags it sets itself. It also refuses `--specialists`, `--max-specialists`, `--investigation-policy`, `--retained-memory-input` and `--exit-code-policy`, whose output this corpus does not score or whose advisory memory could know these cases. `--runs` (1 to 10) and repeated `--case ID` narrow the batch.

Before anything runs, the driver prints its plan: the trestle path and SHA-256, the number of invocations, what the egress mode allows, the zone, provider, model and content-logging fields of every route the inventory declares, every `endpoint` the runtime policy names, and the changed files and size of every case. Without `--confirm-model-calls` it stops after the plan with exit 2 and makes no call. With it, the same plan is printed and the runs start. Exit 0 means every planned run was recorded, 1 that the batch failed or was interrupted, and 2 invalid usage or missing confirmation. None of these codes says anything about review quality.

The default batch is 23 cases by 3 runs: 69 invocations. Each normally makes one candidate-generation and one verification request; a run refused before dispatch makes none. With `--egress local-only`, trestle admits only local routes on numeric loopback endpoints. With `--egress policy-approved`, sanitized, secret-scanned source that trestle selects from each case leaves the machine for the approved `private_remote` or `brokered_remote` routes, under those providers' terms. The corpus contains no private code, but it is still sent. The driver itself opens no network connection. It reads the inventory and policy only to print the summary, and passes its environment to trestle so the policy's credential references resolve as in an ordinary review.

The output directory must be new. `bundle.json` follows `schemas/evaluation/model-corpus-run-bundle-v1.schema.json` and is rewritten after every run. It binds the corpus identity, manifest digest, label digests, revisions, trestle digest and operator flags. Each run has its exact stdout and stderr in new `0600` files under `runs/CASE/`, their SHA-256, the exit status or signal, the wall-clock latency, and the status, `usage_known`, `actual_cost_micro_usd` and any `context_shortfall` copied from the result. The result records no consumed token counts. Stdout beyond 256 KiB, stderr beyond 64 KiB, or a run longer than the timeout plus 60 seconds signals the process group and is recorded as `output_limit` or `timed_out`. A changed trestle executable stops the batch. [`trestle evaluate model-result`](model-result-evaluation.md) accepts only deterministic corpus cases, so the binding of a capture to its source is the driver's record of the revisions it materialized, which anyone can reproduce with `materialize`.

### Scoring and what the numbers mean

```sh
PYTHONPATH=python/open_trestle_eval/src python3 -m open_trestle_eval.model_score \
  --bundle /owned/new-bundle --output /owned/new-score.json
```

The scorer refuses a bundle that does not bind this exact corpus, its label digests and revisions, or whose stdout files do not match their pins. It reads each result's verified diagnostic set and finding guidance. A verified finding matches an expected finding when it has the same path and side, its lines overlap the primary or an accepted location, and its category is in the compatible set. A finding without a category, as in a version 1 result, matches on location alone and is counted in `category_unchecked_true_positive`. Assignment is one-to-one and maximal. An unmatched finding is a false positive, classed as `duplicate` (a second match for one expected finding), `near_miss` (at a labelled trap), `category_mismatch` (right place, incompatible category) or `other`. An expected finding left unmatched is a false negative.

A run with verified findings has the outcome `findings`. One with none and at least one inconclusive verdict is an `abstention`, and any other completed run is `no_finding`. Refused, canceled, failed and unparseable runs are counted under `runs` and kept out of every rate. For each case and in aggregate, the report in `schemas/evaluation/model-corpus-score-v1.schema.json` gives:

- true positives, false positives with their classes, and false negatives;
- precision, `TP / (TP + FP)`, and recall, `TP / (TP + FN)`;
- the false-positive rate, the share of completed runs of `no_finding` cases with at least one false positive, and the same rate for near misses at their traps;
- abstention correctness, the share of abstention-case runs that abstained, with the overclaimed and silent runs beside it;
- outcome agreement, and the mean, range and sample standard deviation across runs of latency and known cost. Token use is reported as unknown.

Ratios are integer numerator and denominator pairs; `0/0` is not success. Every number carries `label_status: labels_pending_human_review`, `release_evidence_eligible` is false and `golden_status` is `prohibited_pending_human_review`, as in the deterministic corpus tooling. A written report exits 4, never 0.

These numbers describe agreement with pending fixture-author labels on 23 synthetic cases. They are not adjudicated quality, and with three runs per case a rate is a count, not an estimate with a confidence interval. A match is agreement of location and category, not proof that the finding states the labelled defect, so the reviewer should read the matched claims. Latency is the end-to-end wall-clock time of one command, including start-up, source acquisition and both model requests, on one machine. It is not inference latency. Cost is what the result's route reconciliation reports and is unknown when `usage_known` is false. The report evaluates no threshold, does not reverify the result's sealed identities, and does not satisfy the independently adjudicated quality release gate.

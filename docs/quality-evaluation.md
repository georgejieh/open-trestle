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

`trestle evaluate model-contract-candidate` runs eight compiled synthetic response fixtures through the production candidate and verification parsers. Cases cover verified, rejected, inconclusive and empty responses, missing evidence, an out-of-range near miss and a missing verdict. The report records expected and observed structural outcomes, an exact corpus identity and a report identity. It contains no source text or model response text.

This command makes no model call. Its fixtures are original synthetic contract assertions, not independently adjudicated findings. `review_state` remains `pending`, `release_evidence_eligible` is false and `quality_measured` is false. Exit code `4` means the candidate report was written, not approval. The `passed` field describes only whether the structural outcomes matched. Parser acceptance does not prove that a claim is correct. The report measures no precision, recall, route independence, token cost or model latency, and does not replace the required real-route qualification and adjudicated quality corpus.

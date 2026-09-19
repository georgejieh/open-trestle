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

# Importing completed model reviews for evaluation

`trestle evaluate model-result` takes the result of one real local model review and compares it with a case from the deterministic evaluation corpus. It is for maintainers who want to line up a captured review with a known test case. The command reads the exact Git objects through the existing acquisition API, validates the completed result with the existing result wire format and diagnostic parser, and compares both complete source manifests with the case you selected. It does not call a model, use credentials, read a checkout, change source, write labels or approve a release.

## Capture and import

Start by choosing a case under `evaluation/testdata/deterministic-corpus-v1/cases/`. The complete base and head trees of the reviewed repository must contain exactly the files of that case's `base/` and `head/` directories, with the original paths and the exact bytes. The import is refused if there are extra files, missing files, changed content, a different case, or different repository or revision identities. Use a local test repository that you own, and keep its exact Git revisions and its declared repository identity. This first version supports loose Git objects only. It has no journey for packed objects.

Run the existing [local model review](local-model-review.md) only with model routes, source scope and credentials or spend that you have authorized separately. Run it without `--specialists` or `--profile`. By default, `trestle review` and the command that `trestle setup bootstrap` prints run a review set, and the importer refuses that kind of result. Keep the JSON on stdout unchanged, including its final line feed (LF). A completed review can exit with 3 (inconclusive) or 4 (blocked findings). Neither code means that the run failed. In these commands, replace the variables with explicit values that you have authorized:

```sh
trestle local-git model-review \
  --objects-root "$OBJECTS_ROOT" \
  --repository-authority "$AUTHORITY" \
  --repository-namespace "$NAMESPACE" \
  --repository-name "$REPOSITORY" \
  --revision-algorithm sha1 \
  --base-revision-digest "$BASE" --head-revision-digest "$HEAD" \
  --tenant "$TENANT" --repository "$REPOSITORY_SCOPE" \
  --route-inventory "$INVENTORY" --runtime-policy "$POLICY" \
  --egress local-only --timeout 5m --format json > model-result.json

sha256sum model-result.json

trestle evaluate model-result \
  --result model-result.json --result-sha256 "$CAPTURE_SHA256" \
  --case debug_direct_and_multiline \
  --objects-root "$OBJECTS_ROOT" \
  --repository-authority "$AUTHORITY" \
  --repository-namespace "$NAMESPACE" \
  --repository-name "$REPOSITORY" \
  --revision-algorithm sha1 \
  --base-revision-digest "$BASE" --head-revision-digest "$HEAD" \
  > model-evaluation.json
```

Supply `CAPTURE_SHA256` from the exact captured file. The pin identifies bytes. It is not a signature, and it does not authenticate who produced the file. You must keep the provenance of the run and the capture yourself.

The importer refuses the following:

- arbitrary candidate JSON and standalone diagnostic JSON;
- results that are not canonical or are oversized;
- runs that did not start or that failed;
- unsupported investigation v2 results;
- a result from a review set (`--specialists`) or from a single profile (`--profile`);
- diagnostics whose scope, head, context or counts are inconsistent;
- identical generation and verification routes.

The importer keeps the route separation level that the result recorded. It cannot establish provider ownership or model independence from route hashes. It accepts the existing distinct-route, distinct-model and distinct-provider levels and does not add a new minimum.

The input is bounded by the existing `localreview.MaxResultJSONBytes` (256 KiB including the LF). The output is one JSON report plus an LF, bounded by the existing 1 MiB corpus report limit. Exit 4 means that the command wrote the pending report. Exit 1 means that the input, the source binding, the evaluation or the output failed. Exit 2 means invalid usage. No successful exit means approval.

## Report and human handoff

The report keeps the complete result that the review printed. That includes the repository, base and head; the request and plan; the task outputs; the generation and verification route records; the candidate batch and candidate IDs; the verification context; readiness; the audit subjects; source coverage; the identities of the diagnostic and verified sets; locations; claims; and evidence references. The report does not reconstruct raw candidate claims, rejected verdicts or source text that the result does not contain. The SHA-256 of the result covers its exact bytes, including the LF. When the report embeds the JSON, it removes only the capture framing, and `result_sha256` still pins the original bytes.

The report ties the existing corpus identity, label-set identity, selected case and label-file digest to the source manifests and acquisition execution that the command has just read. It embeds the existing deterministic corpus candidate report unchanged. Those scores describe the deterministic analyzer only, not model findings. The corpus labels stay pending: nobody has independently reviewed them as truth. The report does not pool unlike targets, and it does not compute model precision, recall, false negatives, calibration or confidence from those labels.

`adjudication_units` contains blank decision rows for every candidate ID, for the verified set (including an empty set), and for every verified diagnostic ID. The command generates no decision, reviewer, review date or quality label. Before looking at the results, an independent human must review the exact corpus sources, the changes, the positive, negative and near-miss labels, the coverage and the mismatches. That person must then reconcile the captured candidates and diagnostics, including the misses and the rejected or inconclusive outcomes that this report does not show. The worksheet is an input to that review. It is not a completed human declaration, and it does not replace a broader review of each case and its negative labels starting from the source.

The existing [deterministic adjudication command](quality-evaluation.md) remains the separate path for importing a human confirmation of the unchanged deterministic labels. It does not score model findings. This first model-result import deliberately exports pending decisions instead of extending that contract to accept model-generated truth. Model-quality acceptance still requires a completed, independent human adjudication of the model results and thresholds that the owner has approved.

## Cost and performance observations

`cost.known` copies the route reconciliation flag from the completed result. A known zero stays a numeric zero. An unknown cost stays `null` and is never reported as a zero-cost success. The original result and all of its limitations remain visible.

Latency, CPU and peak RSS in the imported report stay explicitly unknown (`known: false`, `value: null`), because the sealed result records none of them. The import duration is not the model latency. Latency estimates in the route inventory are not observations from a run. Repeated deterministic candidate observations from `open_trestle_eval.performance` cannot be attributed to a different model run. Neither the importer nor its tests supply resource values, live findings, human labels or thresholds.

### Capture one authorized process with resource observations

On Linux, the same Python module has a separate `model-review` mode. It launches the command you supply exactly once, with no warmups, retries or repeated samples. It is a wrapper for running the command, and it does not give permission to call models. Approve the command, the source scope, the routes, the credential access and the spend separately before you run it. The module does not inspect the route configuration or the credentials. The command you supply keeps its ordinary authority. Do not use the wrapper with a configured live model only to test the wrapper.

Run the following from the repository root. Replace every placeholder with an explicitly authorized value, and supply the complete model-review arguments described above, not a literal `...`:

```sh
PYTHONPATH=python/open_trestle_eval/src python3 -m open_trestle_eval.performance \
  --mode model-review --timeout 360 \
  --result-output model-result.json --output model-performance.json \
  -- /approved/trestle local-git model-review ... --format json
```

Use new output names in a directory that you own. The wrapper creates both files exclusively with mode 0600. It refuses existing files and symlink path components before it launches the command. If it cannot reserve either path, no review starts. When a later step fails, files that were already reserved can remain empty or incomplete. A failed wrapper is not a completed observation, so inspect and keep its evidence before you choose new names. The command you supplied can have incurred spend even if the capture or the write of the observations fails. The wrapper does not produce a durable receipt, and it does not write the two files in one atomic transaction.

The wrapper accepts only process exit code 3 or 4 and one nonempty, LF-terminated output line of at most 256 KiB including the LF. It keeps that line byte for byte. It does not validate the JSON, the result envelope, the canonical encoding, completion, diagnostics or the source binding. `result_validated: false` states that limit.

Pass the captured file and the sidecar's `result_sha256` to the `trestle evaluate model-result` command shown above. Only an accepted import binds those exact bytes to the corpus and source identities that you selected. A sidecar without an accepted, matching import is not evidence of a model evaluation. Its SHA-256 pins bytes. It does not authenticate anything and is not a signature.

`model-performance.json` records:

- the executable SHA-256;
- `result_sha256`, which includes the LF;
- the exit code and the environment;
- `warmup_count: 0` and `sample_count: 1`;
- `elapsed_ns`, `user_cpu_ns`, `system_cpu_ns` and `max_rss_kib`.

The executable hash covers only the resolved launch executable. It does not cover script arguments, shared libraries, source, model weights or the full runtime. The sidecar contains no command arguments, captured output, cost, human labels or quality score. It stays `release_evidence_eligible: false`, with no percentile or acceptance threshold. In this mode the wrapper refuses an explicit `--warmups` or `--samples`, even when it is set to zero or one. The existing deterministic mode and its defaults do not change.

Wall time runs from before the process is created until it has exited and its output pipes are drained. It therefore includes startup, source acquisition, transport waits and shutdown. It measures the latency of the whole command, not the isolated latency of model inference. CPU time and RSS come from Linux `wait4` for the launched child. The CPU time can include descendants that the child waited for. It excludes independent model servers, CPU time on the provider side or on a remote machine, GPU work, and descendants that were not collected. `max_rss_kib` is the high-water mark that Linux reports for the child. It is not the sum of the process tree and not the simultaneous peak of the whole tree. These are single-run observations that depend on the environment. They are not throughput, a distribution, or a measurement of a model server's resources.

The wrapper timeout must be positive and at most 600 seconds. Choose a value that covers the cleanup of the inner review, not only the model dispatch. If the command times out or writes too much to stdout or stderr, the capture fails and the wrapper signals the process group. The existing stderr limit stays at 64 KiB. The wrapper supports no default paid warmup and no repeated benchmarking.

All reports stay `review_state: pending`, `acceptance_status: not_decided`, `quality_measured: false` and `release_evidence_eligible: false`. Integration tests with a fake loopback model exercise real source acquisition, generation parsing, independent verification, final diagnostics and the CLI import. Their assertions establish only the wiring and the lineage behavior. They say nothing about the quality of findings or about whether a live route qualifies.

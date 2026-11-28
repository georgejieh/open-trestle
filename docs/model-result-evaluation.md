# Importing completed model reviews for evaluation

`trestle evaluate model-result` takes the result of one real local model review and compares it with a case from the deterministic evaluation corpus. It is for maintainers who want to line up a captured review with a known test case. It reads the Git objects through the acquisition API, validates the completed result with the result wire format and diagnostic parser, and compares both complete source manifests with the case you selected. It does not call a model, use credentials, read a checkout, change source or write labels.

## Capture and import

Start by choosing a case under `evaluation/testdata/deterministic-corpus-v1/cases/`. The complete base and head trees of the reviewed repository must contain exactly the files of that case's `base/` and `head/` directories, with the original paths and bytes. The import is refused if files are extra or missing, if content has changed, or if the case or the repository or revision identities differ. Use a local test repository that you own, and keep its exact Git revisions and its declared repository identity. This first version supports loose Git objects only, so packed objects cannot be imported.

Run the [local model review](local-model-review.md) only with model routes, source scope and credentials or spend that you have authorized separately. Run it without `--specialists` or `--profile`. By default, `trestle review` and the command that `trestle setup bootstrap` prints run a review set, and the importer refuses that kind of result. Keep the JSON on stdout unchanged, including its final line feed (LF). A completed review can exit with 3 (inconclusive) or 4 (blocked findings), and neither code means that the run failed. In these commands, replace the variables with explicit values that you have authorized:

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

Supply `CAPTURE_SHA256` from the exact captured file. The pin identifies bytes. It is not a signature and does not show who produced the file, so you must keep the provenance of the run and the capture yourself.

The importer refuses the following:

- arbitrary candidate JSON and standalone diagnostic JSON;
- results that are not canonical or are oversized;
- runs that did not start or that failed;
- unsupported investigation v2 results;
- a result from a review set (`--specialists`) or from a single profile (`--profile`);
- diagnostics whose scope, head, context or counts are inconsistent;
- identical generation and verification routes.

It keeps the route separation level that the result recorded and accepts the distinct-route, distinct-model and distinct-provider levels.

The input is bounded by the existing `localreview.MaxResultJSONBytes` (256 KiB including the LF). The output is one JSON report plus an LF, bounded by the existing 1 MiB corpus report limit. Exit 4 means that the command wrote the pending report. Exit 1 means that the input, the source binding, the evaluation or the output failed. Exit 2 means invalid usage.

## Report and human handoff

The report keeps the complete result that the review printed. This includes the repository, base and head, the request and plan, the task outputs, both route records, the candidate batch and IDs, the verification context, readiness, the audit subjects, source coverage, the diagnostic and verified set identities, locations, claims and evidence references. It contains no raw candidate claims, rejected verdicts or source text beyond what the result holds. The SHA-256 of the result covers its exact bytes, including the LF. When the report embeds the JSON, it removes only the capture framing, and `result_sha256` still pins the original bytes.

The report ties the existing corpus identity, label-set identity, selected case and label-file digest to the source manifests and acquisition execution that the command has just read. It embeds the existing deterministic corpus candidate report unchanged. Those scores describe the deterministic analyzer only, not model findings. The corpus labels stay pending because nobody has independently reviewed them as truth, so the report does not compute model precision, recall or false negatives from them.

`adjudication_units` contains blank decision rows for every candidate ID, for the verified set (including an empty set), and for every verified diagnostic ID. The command generates no decision, reviewer, review date or quality label. Before looking at any results, an independent human must review the exact corpus sources, the changes, the positive, negative and near-miss labels, the coverage and the mismatches. That person must then reconcile the captured candidates and diagnostics, including the misses and the rejected or inconclusive outcomes that this report does not show. The worksheet is an input to that review, not a completed human declaration.

The separate [deterministic adjudication command](quality-evaluation.md) imports a human confirmation of the unchanged deterministic labels, and it does not score model findings. This model-result import exports pending decisions instead.

## Cost and performance observations

`cost.known` copies the route reconciliation flag from the completed result. A known zero stays a numeric zero, and an unknown cost stays `null`.

Latency, CPU and peak RSS in the imported report stay explicitly unknown (`known: false`, `value: null`), because the sealed result records none of them. The import duration is not the model latency, and latency estimates in the route inventory are not observations from a run.

### Capture one authorized process with resource observations

On Linux, the same Python module has a separate `model-review` mode. It launches the command you supply once, with no warmups, retries or repeated samples. It does not give permission to call models. Approve the command, the source scope, the routes, the credential access and the spend separately before you run it. The module does not inspect the route configuration or the credentials.

Run the following from the repository root. Replace every placeholder with an explicitly authorized value, and supply the complete model-review arguments described above, not a literal `...`:

```sh
PYTHONPATH=python/open_trestle_eval/src python3 -m open_trestle_eval.performance \
  --mode model-review --timeout 360 \
  --result-output model-result.json --output model-performance.json \
  -- /approved/trestle local-git model-review ... --format json
```

Use new output names in a directory that you own. The wrapper creates both files exclusively with mode 0600 and refuses existing files and symlink path components before it launches the command. If it cannot reserve either path, no review starts. If a later step fails, files that were already reserved can remain empty or incomplete, so inspect them before you choose new names. A failed wrapper is not a completed observation. The command you supplied can have incurred spend even if the capture or the write of the observations fails, and the wrapper does not write the two files in one atomic transaction.

The wrapper accepts only process exit code 3 or 4 and one nonempty, LF-terminated output line of at most 256 KiB including the LF. It keeps that line byte for byte. It does not validate the JSON or the result, which `result_validated: false` records.

Pass the captured file and the sidecar's `result_sha256` to the `trestle evaluate model-result` command shown above. Only an accepted import binds those bytes to the corpus and source identities that you selected.

`model-performance.json` records:

- the executable SHA-256;
- `result_sha256`, which includes the LF;
- the exit code and the environment;
- `warmup_count: 0` and `sample_count: 1`;
- `elapsed_ns`, `user_cpu_ns`, `system_cpu_ns` and `max_rss_kib`.

The executable hash covers only the resolved launch executable. The sidecar contains no command arguments, captured output, cost, human labels or quality score, and it stays `release_evidence_eligible: false`. In this mode the wrapper refuses an explicit `--warmups` or `--samples`, even when it is set to zero or one.

Wall time runs from before the process is created until it has exited and its output pipes are drained. It therefore includes startup, source acquisition, transport waits and shutdown, and it measures the latency of the whole command, not of model inference. CPU time and RSS come from Linux `wait4` for the launched child. The CPU time can include descendants that the child waited for, but it excludes model servers, provider-side or remote CPU time, GPU work, and descendants that were not collected. `max_rss_kib` is the high-water mark that Linux reports for the child, not the peak of the whole process tree. These single-run observations depend on the environment.

The wrapper timeout must be positive and at most 600 seconds. Choose a value that covers the cleanup of the inner review, not only the model dispatch. If the command times out or writes too much to stdout or stderr, the capture fails and the wrapper signals the process group. The stderr limit stays at 64 KiB.

All reports stay `review_state: pending`, `acceptance_status: not_decided`, `quality_measured: false` and `release_evidence_eligible: false`. Integration tests with a fake loopback model exercise source acquisition, generation parsing, verification, final diagnostics and the CLI import.

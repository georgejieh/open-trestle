# Importing completed model reviews for evaluation

`trestle evaluate model-result` connects one actual captured local model review to an existing deterministic corpus case. It reads exact local Git objects through the existing acquisition API, validates the completed result with the existing result wire and diagnostic parser, and compares both complete source manifests with the selected corpus case. It does not call a model, access credentials, read a checkout, change source, write labels or approve a release.

## Capture and import

First select a case under `evaluation/testdata/deterministic-corpus-v1/cases/`. The reviewed repository's complete base and head trees must contain exactly that case's `base/` and `head/` files, with the original paths and exact bytes. Extra files, missing files, changed content, a different case or different repository/revision identities refuse import. Use an owned local test repository and preserve its exact Git revisions and declared repository identity. This first bridge supports loose Git objects, not a packed-object qualification journey.

Run the existing [local model review](local-model-review.md) only with separately authorized model routes, source scope and any required credentials or spend. Run it without `--specialists` or `--profile`: `trestle review` and the command printed by `trestle setup bootstrap` run a review set by default, and the importer refuses that result. Preserve its JSON stdout unchanged, including its final LF. A completed review can exit 3 (inconclusive) or 4 (blocked findings); neither means execution failed. For example, substitute explicit authorized values in these commands:

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

Supply `CAPTURE_SHA256` from the exact captured file. The pin identifies bytes, not a signature or an authenticated producer. The operator must retain the run/capture provenance separately. The importer refuses arbitrary candidate JSON, standalone diagnostic JSON, noncanonical or oversized results, unstarted or failed runs, unsupported investigation v2 results, a result from a review set (`--specialists`) or a single profile (`--profile`), inconsistent diagnostic scope/head/context/counts, and identical generation/verification routes. It preserves the recorded route separation level; it does not independently establish provider ownership or model independence from route hashes. It accepts the existing distinct-route, distinct-model and distinct-provider levels without inventing a new minimum.

The bounded input is the existing `localreview.MaxResultJSONBytes` (256 KiB including LF). Output is one JSON report plus LF, bounded by the existing 1 MiB corpus report limit. Exit 4 means the pending report was written. Exit 1 means input, source binding, evaluation or output failed; exit 2 means invalid usage. No success exit is approval.

## Report and human handoff

The report retains the complete emitted result, including repository/base/head, request, plan, task outputs, generation/verification route records, candidate batch and candidate IDs, verification context, readiness, audit subjects, source coverage, diagnostic/verified-set identities, locations, claims and evidence references. It does not reconstruct raw candidate claims, rejected verdicts or source text absent from that result. The result's exact-byte SHA-256 includes LF. Embedding JSON removes only capture framing, and `result_sha256` pins the original bytes.

The report binds the existing corpus identity, label-set identity, selected case and label-file digest to the freshly acquired source manifests and acquisition execution. It embeds the existing deterministic corpus candidate report unchanged. Those scores describe only the deterministic analyzer, not model findings. Corpus labels remain pending, not independently reviewed truth. This report does not pool unlike targets or compute model precision, recall, false negatives, calibration or confidence from those labels.

`adjudication_units` contains blank decision rows for every emitted candidate ID, the verified set (including an empty set), and every verified diagnostic ID. No decision, reviewer, review date or quality label is generated. Before inspecting results, an independent human must review the exact existing corpus sources, changes, positive/negative and near-miss labels, coverage and mismatches. That person must then reconcile the exact captured candidates and diagnostics, including misses and rejected/inconclusive outcomes unavailable in this projection. The worksheet is an input to that review, not a filled human declaration or a substitute for broader source-first case/negative-label review.

The existing [deterministic adjudication command](quality-evaluation.md) remains the separate path for importing human confirmation of the unchanged deterministic labels. It does not score model findings. This first model-result bridge deliberately exports pending decisions rather than silently extending that contract to accept model-generated truth. A completed independent human model adjudication and owner-approved thresholds remain required for model-quality acceptance.

## Cost and performance observations

`cost.known` copies the completed result's route reconciliation flag. A known zero remains numeric zero. Unknown cost remains `null`, never zero-cost success. The original result and all limitations remain visible.

Latency, CPU and peak RSS in the imported report remain explicitly unknown (`known: false`, `value: null`) because the sealed result records none of them. Import duration is not model latency. Route-inventory latency estimates are not run observations. Repeated deterministic candidate observations from `open_trestle_eval.performance` cannot be attributed to a different model run. No resource values, live findings, human labels or thresholds are supplied by the importer or its tests.

### Capture one authorized process with resource observations

On Linux, the same Python module has a separate `model-review` mode. It launches the supplied command exactly once, with no warmups, retries or repeated samples. This is an execution wrapper, not permission for model calls. Approve the command, source scope, routes, credential access and spend separately before running it. The module does not inspect route configuration or credentials itself; the supplied command retains its ordinary authority. Do not use it with a configured live model merely to test the wrapper.

From the repository root, replace every placeholder with an explicitly authorized value. Supply the complete model-review arguments described above, not literal `...`:

```sh
PYTHONPATH=python/open_trestle_eval/src python3 -m open_trestle_eval.performance \
  --mode model-review --timeout 360 \
  --result-output model-result.json --output model-performance.json \
  -- /approved/trestle local-git model-review ... --format json
```

Use new output names in an owned directory. Both files are created exclusively with mode 0600; existing files and symlink path components are refused before launching the command. If either path cannot be reserved, no review starts. Files reserved before a later failure may remain empty or incomplete. A failed wrapper is not a completed observation: inspect and retain its evidence before choosing new names. The supplied command can have incurred spend even if capture or observation writing fails. This is not a durable receipt or atomic two-file transaction.

The wrapper accepts only process exit 3 or 4 and one nonempty LF-terminated output line, bounded to 256 KiB including LF. It preserves that line byte-for-byte. It does not validate JSON, the result envelope, canonical encoding, completion, diagnostics or source binding. `result_validated: false` states that boundary. Feed the captured file and the sidecar's `result_sha256` into the existing `trestle evaluate model-result` caller above. Only an accepted import binds those exact bytes to the selected corpus/source identities. A sidecar without an accepted matching import is not model-evaluation evidence. Its SHA-256 is a byte pin, not authentication or a signature.

`model-performance.json` records the executable SHA-256, exact LF-inclusive `result_sha256`, exit code, environment, `warmup_count: 0`, `sample_count: 1`, `elapsed_ns`, `user_cpu_ns`, `system_cpu_ns` and `max_rss_kib`. The executable hash covers only the resolved launch executable, not script arguments, shared libraries, source, model weights or the full runtime. The sidecar contains no command arguments, captured output, cost, human labels or quality score. It remains `release_evidence_eligible: false`, with no percentile or acceptance threshold. Explicit `--warmups` or `--samples` is refused in this mode, even if set to zero or one. The existing deterministic mode and its defaults remain unchanged.

Wall time runs from before process creation until terminal exit and output-pipe draining, including startup, source acquisition, transport waits and closure. It is end-to-end command latency, not isolated model inference latency. CPU and RSS come from Linux `wait4` for the launched child: CPU can include descendants that the child waited for; it excludes independent model servers, remote/provider CPU, GPU work and uncollected descendants. `max_rss_kib` is Linux's child high-water observation, not summed or simultaneous process-tree peak RSS. These are environment-specific single-run observations, not throughput, distribution or model-server resource measurements. The wrapper timeout must be positive and at most 600 seconds; choose it to include the inner review's cleanup, not just model dispatch. Timeout or excessive stdout/stderr fails capture and signals the process group; the existing stderr limit remains 64 KiB. No default paid warmup or repeated benchmarking is supported.

All reports remain `review_state: pending`, `acceptance_status: not_decided`, `quality_measured: false` and `release_evidence_eligible: false`. Fake-loopback integration tests exercise real source acquisition, generation parsing, independent verification, final diagnostics and CLI import. Their assertions establish wiring and lineage behavior only, not finding quality or live-route qualification.

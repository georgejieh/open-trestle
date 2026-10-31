# Importing completed model reviews for evaluation

`trestle evaluate model-result` connects one actual captured local model review to an existing deterministic corpus case. It reads exact local Git objects through the existing acquisition API, validates the completed result with the existing result wire and diagnostic parser, and compares both complete source manifests with the selected corpus case. It does not call a model, access credentials, read a checkout, change source, write labels or approve a release.

## Capture and import

First select a case under `evaluation/testdata/deterministic-corpus-v1/cases/`. The reviewed repository's complete base and head trees must contain exactly that case's `base/` and `head/` files, with the original paths and exact bytes. Extra files, missing files, changed content, a different case or different repository/revision identities refuse import. Use an owned local test repository and preserve its exact Git revisions and declared repository identity. This first bridge supports loose Git objects, not a packed-object qualification journey.

Run the existing [local model review](local-model-review.md) only with separately authorized model routes, source scope and any required credentials or spend. Preserve its JSON stdout unchanged, including its final LF. A completed review can exit 3 (inconclusive) or 4 (blocked findings); neither means execution failed. For example, substitute explicit authorized values in these commands:

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

Supply `CAPTURE_SHA256` from the exact captured file. The pin identifies bytes, not a signature or an authenticated producer. The operator must retain the run/capture provenance separately. The importer refuses arbitrary candidate JSON, standalone diagnostic JSON, noncanonical or oversized results, unstarted or failed runs, unsupported investigation v2 results, inconsistent diagnostic scope/head/context/counts, and identical generation/verification routes. It preserves the recorded route separation level; it does not independently establish provider ownership or model independence from route hashes. It accepts the existing distinct-route, distinct-model and distinct-provider levels without inventing a new minimum.

The bounded input is the existing `localreview.MaxResultJSONBytes` (256 KiB including LF). Output is one JSON report plus LF, bounded by the existing 1 MiB corpus report limit. Exit 4 means the pending report was written. Exit 1 means input, source binding, evaluation or output failed; exit 2 means invalid usage. No success exit is approval.

## Report and human handoff

The report retains the complete emitted result, including repository/base/head, request, plan, task outputs, generation/verification route records, candidate batch and candidate IDs, verification context, readiness, audit subjects, source coverage, diagnostic/verified-set identities, locations, claims and evidence references. It does not reconstruct raw candidate claims, rejected verdicts or source text absent from that result. The result's exact-byte SHA-256 includes LF. Embedding JSON removes only capture framing, and `result_sha256` pins the original bytes.

The report binds the existing corpus identity, label-set identity, selected case and label-file digest to the freshly acquired source manifests and acquisition execution. It embeds the existing deterministic corpus candidate report unchanged. Those scores describe only the deterministic analyzer, not model findings. Corpus labels remain pending, not independently reviewed truth. This report does not pool unlike targets or compute model precision, recall, false negatives, calibration or confidence from those labels.

`adjudication_units` contains blank decision rows for every emitted candidate ID, the verified set (including an empty set), and every verified diagnostic ID. No decision, reviewer, review date or quality label is generated. Before inspecting results, an independent human must review the exact existing corpus sources, changes, positive/negative and near-miss labels, coverage and mismatches. That person must then reconcile the exact captured candidates and diagnostics, including misses and rejected/inconclusive outcomes unavailable in this projection. The worksheet is an input to that review, not a filled human declaration or a substitute for broader source-first case/negative-label review.

The existing [deterministic adjudication command](quality-evaluation.md) remains the separate path for importing human confirmation of the unchanged deterministic labels. It does not score model findings. This first model-result bridge deliberately exports pending decisions rather than silently extending that contract to accept model-generated truth. A completed independent human model adjudication and owner-approved thresholds remain required for model-quality acceptance.

## Cost and performance observations

`cost.known` copies the completed result's route reconciliation flag. A known zero remains numeric zero. Unknown cost remains `null`, never zero-cost success. The original result and all limitations remain visible.

Latency, CPU and peak RSS are explicitly unknown (`known: false`, `value: null`) because the current sealed result records none of them. Import duration is not model latency. Route-inventory latency estimates are not run observations. The existing `open_trestle_eval.performance` captures repeated deterministic candidate processes and pins their report identities; its observations cannot be attributed to this different model run. Do not relabel them. No resource values, live findings, human labels or thresholds are supplied by the importer or its tests.

All reports remain `review_state: pending`, `acceptance_status: not_decided`, `quality_measured: false` and `release_evidence_eligible: false`. Fake-loopback integration tests exercise real source acquisition, generation parsing, independent verification, final diagnostics and CLI import. Their assertions establish wiring and lineage behavior only, not finding quality or live-route qualification.

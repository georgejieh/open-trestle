# Memory retrieval task handler

`handlers/memory` performs bounded advisory retrieval for the exact protected `change_model` dependency. Memory never establishes a finding.

## Authority

A handler installation binds one approved review policy, memory backend identity, actor, canonical path-prefix allowlist, query bound, and total result bound into its handler identity. At execution it requires the plan's exact policy identity and creates a fresh memory scope from:

- the run tenant and repository
- the configured actor and path authorization
- `exact` ref visibility
- the acquired head revision as the ref-set identity

Scope filtering therefore occurs before scoring. A record from another tenant, repository, actor, revision set, or path partition is not queried.

## Retrieval

The handler validates the change artifact and both source snapshots, then issues path-only lexical queries for changed paths. It performs at most 64 queries and retains at most 50 ranked records across the task. Every changed path is represented by a query or an explicit `path_not_authorized`, `query_limit`, or `result_limit` omission.

The output preserves each query identity, index revision, retrieval identity, rank, score components, record identity, kind, taint, path, text, evidence, derivation, counterevidence, producer, validity interval, freshness watermark, and confidence basis. Parsing reconstructs every memory scope, query, record, retrieval-item identity, and retrieval identity. Expired or stale records cannot pass reconstruction.

## Output

The protected `retrieval_result` artifact uses the `memory` origin. Its payload and artifact provenance bind the change, review policy, exact memory scope, and backend identity. Its expiry is capped at one hour and shortened by source expiry and selected record validity or staleness boundaries.

Published schema: `schemas/artifact/memory-retrieval-result-v1.schema.json`.

# Memory retrieval task handler

The memory retrieval handler looks up stored memory records that relate to the files a change touches. It runs in a review run after the change model task, takes the protected `change_model` artifact as its input, and retrieves records as advisory context. Memory is not a finding. The handler lives in `handlers/memory`.

## Authority

This section covers what the handler is allowed to read. A handler installation binds the following into its handler identity, the digest that identifies this implementation:

- one approved review policy;
- the memory backend identity;
- the actor;
- a canonical allowlist of path prefixes;
- a limit on the number of queries; and
- a limit on the total number of results.

At execution, the handler requires the plan's policy identity. It then creates a fresh memory scope from:

- the run's tenant and repository;
- the configured actor and path authorization;
- `exact` ref visibility; and
- the acquired head revision, used as the ref-set identity.

The scope is applied before any scoring, so records from another tenant, repository, actor, revision set or path partition are not queried.

## Retrieval

The handler validates the change artifact and both source snapshots. It then runs path-only lexical queries for the changed paths, making at most 64 queries and keeping at most 50 ranked records across the whole task. Every changed path is either covered by a query or recorded with an explicit omission: `path_not_authorized`, `query_limit` or `result_limit`.

For each retrieved item, the output keeps:

- the query identity, the index revision and the retrieval identity;
- the rank and the score components;
- the record identity, kind, taint, path and text;
- the evidence, derivation and counterevidence;
- the producer, the validity interval and the freshness watermark; and
- the confidence basis.

Parsing the output rebuilds every memory scope, query, record, retrieval-item identity and retrieval identity. Expired or stale records fail that reconstruction.

## Output

The protected `retrieval_result` artifact has the `memory` origin. Its payload and its artifact provenance bind the change, the review policy, the memory scope and the backend identity. Its expiry is capped at one hour, and it is shortened further by the source expiry and by the validity or staleness boundaries of the selected records.

The published schema is `schemas/artifact/memory-retrieval-result-v1.schema.json`.

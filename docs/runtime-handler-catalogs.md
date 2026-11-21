# Runtime handler catalogs

A review run is split into tasks, and a handler is the code that executes one kind of task, such as acquiring source or generating findings. A catalog is the set of handlers a run uses. This page is for contributors who wire handlers together, and for operators who configure which model routes a run may use.

The public `runtimecatalog` package builds a catalog from approved task implementations. The catalog must contain one handler for every task kind that the selected run mode requires. Catalogs end at publication readiness.

Building a catalog fails if a task kind is missing or duplicated, if a handler identity is malformed, or if there are extra handlers. A handler identity identifies one implementation, and the plan records it so that a run is only executed by the handlers it was planned with. The catalog identity is a digest computed from the catalog's content. It covers the run mode, the task kinds, and the handler identities. Callers can use the generic bindings (the records that tie a task kind to its handler) to build a plan for a particular transport.

A `controlplane.TaskHandlerCatalog` returned by this package works with `worker.RepositorySupervisor` or with a scoped remote `worker.Runner`. Source and model credentials stay inside their configured adapters. The catalog holds handler interfaces and identities.

## Route inventory

A route is one way to reach a model. The route inventory is the operator's list of routes, with the facts needed to choose between them.

`runtimeconfig.DecodeRouteInventory` accepts a JSON document that conforms to `schemas/runtime/runtime-route-inventory-v1.schema.json`. Each entry contains:

- a route reference;
- capability and logging declarations;
- pricing, either fixed or unknown;
- a quality evidence tier;
- a registry revision and lifecycle status;
- an inline evidence manifest;
- current health and quota observations; and
- a sampled P95 latency, either known or unknown.

All records in one document must share the same registry and performance revisions.

The decoder limits the document to 8 MiB and 64 routes. It rejects:

- unknown fields;
- duplicate or noncanonical keys;
- trailing values;
- values that are both known and unknown;
- malformed base64;
- duplicate record identities;
- invalid evidence digests; and
- mixed snapshot revisions.

Every record is resolved through the same registry and evidence verification that dynamic registries use. The resulting inventory keeps no evidence content. Its identity covers the identities of the records and every operational and performance observation.

`runtimecatalog.NewGenerationPolicyAuthorizer` and `runtimecatalog.NewVerificationPolicyAuthorizer` use the same validated inventory. As a result, privacy filtering, cost eligibility, ranking and verifier independence all use one snapshot that the operator selected. A static verification inventory still validates each review scope before it issues a snapshot.

A route whose resolved record is not `approved` stays visible in the inventory but fails the eligibility check. Distribute the inventory as a configuration artifact with restricted access, and update its revisions whenever the registry or performance data changes.

## Provider dispatch configuration

Route dispatcher catalogs bind `ConfigurationIdentity()` for every registered adapter, not only its public adapter ID. Production adapters must include all non-secret connection settings in that identity. The OpenAI factory requires coverage of every adapter namespace in its route inventory, and it makes no network request during validation. Credential providers are used only when a request is sent.

## Runtime policy configuration

`runtimeconfig.DecodeRuntimePolicy` loads a versioned runtime policy against one route-inventory identity. The policy versions differ in what they add:

- Version 1 describes Responses connections.
- Version 2 adds verifier grants, Chat connections and an explicit local no-auth mode.
- Version 3 adds the closed [OpenRouter ZDR Chat profile](openrouter-zdr-profile.md), with its brokered route and an operator-declared scope and account window.

A policy binds the following:

- an external review-policy identity;
- model requirements;
- data classification and allowed zones;
- whether content logging is permitted;
- token and micro-USD budgets;
- an optional generation pin and an ordered list of record preferences;
- verifier independence; and
- provider connection authorities.

Preferred and pinned routes are resolved from registry-record identities rather than from repeated route declarations. The pin applies to generation only. For verification, the policy keeps the ordered preferences without the generation pin and first excludes routes that fail the required independence level. It does not relax independence to reuse the pinned generation route. If no eligible route that meets the independence level remains, verification stops with an error.

A provider connection contains an implementation token, an adapter ID, an endpoint, and a credential environment reference. It contains no secret. Credential references must use the reserved `OPEN_TRESTLE_PROVIDER_` namespace, so routing configuration cannot name API, webhook, storage or other daemon secrets. The credential-authority identity is derived from the environment variable name.

The supported OpenAI Responses connection requires HTTPS, or HTTP on a canonical numeric loopback address. Policy decoding, CLI validation and adapter construction all reject:

- user information, query strings and fragments;
- encoded or unclean paths and repeated path separators;
- noncanonical hostnames and ports; and
- remote plaintext.

Policy decoding also rejects unknown fields, duplicate keys, noncanonical keys, records from a different inventory, duplicate preferences or connections, malformed credential references, and all-zero authority identities. `runtimecatalog` converts the decoded policy into generation, verification and OpenAI dispatcher authorities. Credential resolvers return providers that are used at request time and do not read secret values during configuration validation.

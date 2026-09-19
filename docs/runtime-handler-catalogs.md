# Runtime handler catalogs

The public `runtimecatalog` package assembles one exact executable review pipeline from approved task implementations. It accepts exactly one handler for every task kind required by the selected run mode. Advisory and local catalogs end at publication readiness. Required catalogs must also contain one publication handler.

Catalog construction rejects missing kinds, duplicate kinds, malformed handler identities, extra handlers, and publication capability inconsistent with the run mode. The content-derived catalog identity binds the mode, task kinds, and implementation identities. Callers can use the generic bindings to build a transport-specific plan without accepting arbitrary in-process plugins.

A `controlplane.TaskHandlerCatalog` returned by this package is suitable for `worker.RepositorySupervisor` or a scoped remote `worker.Runner`. Source and model credentials remain inside their configured adapters; the catalog stores only handler interfaces and identities.

## Route inventory

`runtimeconfig.DecodeRouteInventory` accepts a bounded JSON document conforming to `schemas/runtime/runtime-route-inventory-v1.schema.json`. Each entry contains an exact route reference, capability and logging declarations, fixed or unknown pricing, quality evidence tier, registry revision and lifecycle status, an inline immutable evidence manifest, current health and quota observations, and known or unknown sampled P95 latency. All records in one document must share the registry and performance revisions.

The decoder limits the document to 8 MiB and 64 routes. It rejects unknown fields, duplicate or noncanonical keys, trailing values, ambiguous known/unknown values, malformed base64, duplicate record identities, invalid evidence digests, and mixed snapshot revisions. It resolves every record through the same registry and evidence verification boundary used by dynamic registries. The resulting inventory retains no evidence content. Its identity binds immutable record identities and every operational or performance observation.

`runtimecatalog.NewGenerationPolicyAuthorizer` and `runtimecatalog.NewVerificationPolicyAuthorizer` consume the same validated inventory. This keeps privacy filtering, cost eligibility, deterministic ranking, and verifier independence anchored to one operator-selected snapshot. A static verification inventory still validates each review scope before issuing a snapshot.

Registry status is data, not an approval shortcut. Routes whose resolved record is not `approved` remain visible in the inventory but fail eligibility. Operators should distribute the inventory as an immutable, access-controlled configuration artifact and update its revisions whenever registry or performance data changes.

## Provider dispatch configuration

Route dispatcher catalogs bind `ConfigurationIdentity()` for every registered adapter, not only its public adapter ID. Production adapters must include all non-secret connection authority in that identity. The OpenAI factory requires complete coverage of the adapter namespaces present in its route inventory and constructs no network request during validation. Credential providers remain request-time capabilities.

## Runtime policy configuration

`runtimeconfig.DecodeRuntimePolicy` loads `schemas/runtime/runtime-policy-v1.schema.json` against one exact route-inventory identity. The policy binds an external review-policy identity, model requirements, data classification and allowed zones, content-logging permission, pessimistic token and micro-USD budgets, an optional generation pin and ordered record preferences, verifier independence, and provider connection authorities. Preferred and pinned routes are resolved from registry-record identities rather than repeated route declarations. The pin selects generation only. Verification retains the ordered preferences without that generation pin and first excludes routes that fail the required independence level. It does not relax independence to reuse the pinned generation route; if no independent eligible route remains, verification fails closed.

Provider connections contain an implementation token, adapter ID, endpoint, and credential environment reference. They never contain a secret. Credential references must use the reserved `OPEN_TRESTLE_PROVIDER_` namespace, so routing configuration cannot name API, webhook, storage, or other daemon secrets. The credential-authority identity is derived from the environment variable name. The supported OpenAI Responses connection requires canonical HTTPS, or HTTP on a canonical numeric loopback address. User information, query strings, fragments, encoded or unclean paths, repeated path separators, noncanonical hostnames and ports, and remote plaintext are rejected during policy decoding, CLI validation, and adapter construction. Unknown fields, duplicate keys, noncanonical keys, cross-inventory records, duplicate preferences or connections, malformed credential references, and all-zero authority identities are rejected. `runtimecatalog` converts the result into generation, verification, and exact OpenAI dispatcher authorities. Credential resolvers return request-time providers and need not read secret values during configuration validation.

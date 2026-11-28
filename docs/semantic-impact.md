# Semantic impact profiles

A semantic impact profile describes how a change affects the structure of the code: which declarations were added, modified or removed, where they are referenced, and which tests might be affected. Open Trestle derives a profile from the base and head snapshots. The first adapter uses Go's syntax tree parser and the graph contract `open-trestle/semantic-impact/go-ast-graph/v2`.

The profile records:

- added, modified and removed top-level functions, methods, types, variables and constants;
- changes to exported declarations, and a separate public-API-change flag based on function signatures rather than bodies;
- source ranges and normalized syntax and API digests; and
- typed gaps for unsupported languages, unavailable source, parser failure and resource limits.

Declaration differences have the `structural` grade. A profile reads only the changed Go files of each side. Uses of changed definitions, related tests and the rest of a review's context come from the [repository index](repository-index.md), for every language it analyzes.

Every profile binds the base snapshot, head snapshot, change model, input file digests, adapter identity and graph schema. That is, the profile records these identities and is valid only for that combination. The order of the inputs does not matter. Inputs are limited to 4,096 files per side, 2 MiB per file and 128 MiB in total. Outputs are limited to 8,192 declaration changes, 4,096 gaps and 16 MiB of encoded JSON. The profile rejects:

- duplicate paths and traversal paths;
- control characters;
- malformed digests;
- identity mismatches;
- noncanonical ordering;
- unknown JSON fields; and
- trailing JSON values.

Declaration coordinates use physical file positions and ignore `//line` remapping. Repeated `init` functions are told apart by their order within a file. Blank identifiers create no named declaration records. Declaration names and keys must fit the profile's encoding limits, and a profile whose output would be too large fails with an error.

The Go parser does not type-check packages or resolve identifiers. The first graph contract leaves out build constraints, generated variants, dependency modules, dynamic dispatch, reflection, cgo, code generation and runtime call paths. A later type-aware adapter may add stronger grades.

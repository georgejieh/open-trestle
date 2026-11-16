# Semantic impact profiles

A semantic impact profile describes how a change affects the structure of the code: which declarations were added, modified or removed, where they are referenced, and which tests might be affected. Open Trestle derives a bounded profile from exact base and head snapshots. The first adapter uses Go's syntax tree parser and the graph contract `open-trestle/semantic-impact/go-ast-graph/v1`.

The profile records:

- added, modified and removed top-level functions, methods, types, variables and constants;
- changes to exported declarations, and a separate public-API-change flag that is based on function signatures rather than bodies;
- source ranges and normalized syntax and API digests;
- name-based reference candidates across the head snapshot;
- affected test candidates, for references found in `_test.go` files; and
- typed gaps for unsupported languages, unavailable source, parser failure and resource limits.

Each kind of result has an evidence grade, which says how much it proves. Declaration differences have the `structural` grade. References and affected-test links have the `syntactic_candidate` grade, because matching an identifier name does not establish symbol resolution, reachability, behavior or test coverage. These candidates can help decide which context to inspect first, but they cannot establish a finding on their own. Before it hashes files, context assembly removes duplicates among exact one-line source ranges. When reference candidates exceed the admission bounds, it keeps exact counts of what it left out.

Every profile binds the exact base snapshot, head snapshot, change model, input file digests, adapter identity and graph schema. Binding means the profile records these identities, so it is valid only for that exact combination. The order of the inputs does not matter. They are limited to 4,096 files per side, 2 MiB per file and 128 MiB in total. Outputs are limited to 8,192 declaration changes, 32,768 reference candidates, 4,096 gaps and 16 MiB of encoded JSON. The profile rejects:

- duplicate paths and traversal paths;
- control characters;
- malformed digests;
- identity mismatches;
- noncanonical ordering;
- unknown JSON fields; and
- trailing JSON values.

Declaration and reference coordinates use physical file positions and ignore `//line` remapping. Repeated `init` functions are told apart by their declaration order within a file. Blank identifiers do not create named declaration records. Declaration names and keys must fit the profile's encoding limits. If the output would be too large, the profile fails with an explicit error instead of returning something that cannot be encoded.

The Go parser does not type-check packages or resolve identifiers. The first graph contract leaves out build constraints, generated variants, dependency modules, dynamic dispatch, reflection, cgo, code generation and runtime call paths. A later approved type-aware adapter may add stronger relationship grades, without upgrading existing syntactic candidates.
